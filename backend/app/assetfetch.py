"""Pull back the files a page loads, and recover the originals.

A crawl records that a page loads `/static/app.4f2c1.js`. That is a
reference, not evidence: nothing has read it. The interesting things
in a web application's own JavaScript -- API routes nothing links
to, internal hostnames, and the keys people paste into a bundle at
build time -- are all in the bytes.

So: fetch it, recover what it was before a bundler got to it, and
keep every file that comes back for the scanners to read.

**Scope: an asset of an in-scope page is in scope.** Operator
ruling. It has to be stated in code because the obvious
implementation gets it backwards: `cdn.example.net/app.js` would
never clear the scope gate on its own hostname, and gating the
fetch on the ASSET's host would refuse exactly the third-party
bundles most worth reading. Authorisation comes from the PAGE that
referenced it, which the gate has already cleared -- so this module
checks the referrer and never the asset host.

That is narrow on purpose, and it is not "anything a page mentions".
It authorises retrieving a file an in-scope page already causes
every one of its visitors to retrieve. We are making the request the
browser was going to make anyway.

**Three origins, kept apart.** `raw` is what the server returned.
`source` is an original file named by a source map -- what the
developer actually wrote. `beautified` is a rendering WE produced
when there was no map. The distinction is not bookkeeping: a line
number in `beautified` points into a file that exists nowhere but
here, and reporting it as though it were the developer's line would
send somebody to the wrong place.

**It never executes anything.** Bundles are parsed as text and
source maps as JSON. Nothing here evaluates JavaScript, and nothing
should ever be added that does.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import posixpath
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger("oddjob.assetfetch")

#: Biggest body we will hold. Bundles are routinely megabytes and
#: source maps several times the bundle, so this is generous -- but
#: it is a limit, because the remote end chooses the size and an
#: unbounded read is how one asset becomes an outage.
MAX_BYTES = 8 * 1024 * 1024

#: Per-request ceiling. A slow asset is not worth a stuck worker.
TIMEOUT = 20.0

#: What is worth fetching. Images and fonts are large, numerous and
#: have nothing for a secret scanner to find; skipping them is most
#: of the bytes for none of the value.
FETCHABLE_KINDS = frozenset({"script", "stylesheet", "other"})

#: `//# sourceMappingURL=app.js.map`, at the end of a bundle. Also
#: accepts the older `//@`. Deliberately not anchored to the last
#: line: minifiers differ on trailing newlines and a map that is one
#: byte from where we expected is still a map.
_SOURCEMAP = re.compile(
    r"(?://|/\*)[#@]\s*sourceMappingURL\s*=\s*(\S+?)\s*(?:\*/|$)",
    re.MULTILINE)


@dataclass
class Recovered:
    """What one fetch produced."""
    status: int | None = None
    content_type: str | None = None
    error: str | None = None
    minified: bool | None = None
    sourcemap_url: str | None = None
    #: (origin, path, body) for every file, raw first.
    files: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.files)


def looks_minified(body: str) -> bool:
    """Whether this looks machine-generated rather than written.

    Line length, not file size: a 2MB hand-written file is unusual
    but readable, while a 20KB bundle on one line is not. Judged on
    the longest line rather than the mean, because a bundle often
    carries a readable banner comment that drags the mean down.
    """
    if not body:
        return False
    lines = body.splitlines() or [body]
    longest = max(len(ln) for ln in lines)
    if longest > 500:
        return True
    # Short file, long-ish lines, almost no newlines: also a bundle.
    return len(lines) <= 3 and len(body) > 2000


def sourcemap_url_in(body: str, asset_url: str) -> str | None:
    """The map a file points at, resolved against the file's own URL.

    Returns None for a `data:` map: those are inline and handled by
    the caller reading the body directly, not by another request.
    """
    # The LAST one wins. A bundle can carry an earlier reference
    # inside a vendored chunk; the one the browser honours is the
    # final one, so that is the one to follow.
    found = _SOURCEMAP.findall(body)
    if not found:
        return None
    ref = found[-1].strip()
    if ref.startswith("data:"):
        return ref
    try:
        return urljoin(asset_url, ref)
    except ValueError:
        return None


def _safe_path(raw: str) -> str:
    """A source-map path, made safe to store and show.

    Source maps are attacker-influenced input: the paths come from
    whatever built the bundle. `webpack:///../../../etc/passwd` is a
    perfectly legal `sources` entry. Nothing here writes to disk, so
    traversal cannot escape anything today -- but this value is shown
    in findings and may one day be joined onto a path, and a value
    that is only safe because of where it is currently used is a trap
    left for the next person.
    """
    s = (raw or "").strip()
    for prefix in ("webpack://", "webpack:///", "file://", "rollup://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    s = s.replace("\\", "/")
    parts = [p for p in s.split("/")
             if p not in ("", ".", "..")]
    return posixpath.join(*parts) if parts else "unnamed"


def sources_from_map(doc: dict) -> list[tuple[str, str]]:
    """-> (path, body) for every original a source map carries.

    Only maps with `sourcesContent` yield anything. A map without it
    names the originals but does not include them, and fetching each
    one is a request per file against the client -- a different and
    noisier decision than reading what we already have.
    """
    out: list[tuple[str, str]] = []
    names = doc.get("sources") or []
    bodies = doc.get("sourcesContent") or []
    for i, name in enumerate(names):
        if i >= len(bodies):
            break
        body = bodies[i]
        if not isinstance(body, str) or not body.strip():
            # A null entry means "this one is not included". Not an
            # empty file, and recording it as one would invent a file
            # the scanners then report as clean.
            continue
        out.append((_safe_path(str(name)), body))
    return out


def _decode_data_url(ref: str) -> dict | None:
    try:
        head, _, payload = ref.partition(",")
        raw = (base64.b64decode(payload) if ";base64" in head
               else payload.encode())
        return json.loads(raw)
    except Exception:                                  # noqa: BLE001
        return None


async def fetch(client: httpx.AsyncClient, url: str, *,
                user_agent: str) -> Recovered:
    """Retrieve one asset and everything recoverable from it.

    Never raises. A fetch that fails is recorded as a failure with
    its reason, because "we could not get it" and "there was nothing
    in it" are different facts and the scanners must not treat the
    first as the second.
    """
    out = Recovered()
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    try:
        r = await client.get(url, headers=headers, timeout=TIMEOUT,
                             follow_redirects=True)
    except Exception as e:                             # noqa: BLE001
        out.error = f"{type(e).__name__}: {e}"[:300]
        return out

    out.status = r.status_code
    out.content_type = (r.headers.get("content-type") or "")[:128] or None
    if r.status_code >= 400:
        out.error = f"HTTP {r.status_code}"
        return out

    raw = r.content[:MAX_BYTES]
    if len(r.content) > MAX_BYTES:
        log.info("assetfetch: %s truncated at %d bytes", url, MAX_BYTES)
    try:
        body = raw.decode("utf-8", "replace")
    except Exception:                                  # noqa: BLE001
        out.error = "not text"
        return out

    name = posixpath.basename(urlparse(url).path) or "index"
    out.files.append(("raw", name, body))
    out.minified = looks_minified(body)

    ref = sourcemap_url_in(body, url)
    doc = None
    if ref and ref.startswith("data:"):
        out.sourcemap_url = "data:"           # not the payload: it is the file
        doc = _decode_data_url(ref)
    elif ref:
        out.sourcemap_url = ref
        try:
            mr = await client.get(ref, headers=headers, timeout=TIMEOUT,
                                  follow_redirects=True)
            if mr.status_code < 400:
                doc = json.loads(mr.content[:MAX_BYTES])
        except Exception as e:                         # noqa: BLE001
            # Not fatal, and not silent. A missing map is extremely
            # common (they are often removed in production, which is
            # itself worth knowing) and the raw file is still useful.
            log.info("assetfetch: no source map at %s (%s)", ref, e)

    if isinstance(doc, dict):
        for path, src in sources_from_map(doc):
            out.files.append(("source", path, src))

    # Beautify only when the map gave us nothing. A recovered
    # original always beats a reformatted bundle, and producing both
    # would double the scanning for a worse copy.
    if out.minified and not any(o == "source" for o, _, _ in out.files):
        pretty = beautify(body)
        if pretty and pretty != body:
            out.files.append(("beautified", name + ".pretty", pretty))
    return out


def beautify(body: str) -> str:
    """A crude reformat: one statement per line.

    Deliberately not a JavaScript parser. This runs over hostile
    input on a server that holds a client's findings, and a parser is
    a much larger attack surface than a handful of newlines. It does
    not need to be correct -- it needs to put a long line into enough
    short ones that a scanner's line numbers mean something and a
    person can read the result.

    Strings are tracked so that a `;` or `{` inside one does not
    become a line break, which would otherwise split a URL or a
    regex across lines and change what a secret scanner sees.
    """
    out: list[str] = []
    line: list[str] = []
    quote: str | None = None
    prev = ""
    for ch in body:
        line.append(ch)
        if quote:
            if ch == quote and prev != "\\":
                quote = None
            prev = ch
            continue
        if ch in "\"'`":
            quote = ch
        elif ch in ";{}":
            out.append("".join(line))
            line = []
        prev = ch
    if line:
        out.append("".join(line))
    return "\n".join(s.strip() for s in out if s.strip())


def digest(body: str) -> tuple[str, int]:
    b = body.encode("utf-8", "replace")
    return hashlib.sha256(b).hexdigest(), len(b)


def now() -> datetime:
    return datetime.now(UTC)
