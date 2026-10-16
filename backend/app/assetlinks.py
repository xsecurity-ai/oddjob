"""Endpoints out of JavaScript — the routes nothing links to.

A crawl finds what the application links to. A bundle contains what
it CALLS: the API routes, the admin paths, the internal hostnames
and the feature-flagged pages that no anchor tag points at. That is
most of the attack surface of a modern application and none of it
is reachable by following links.

Equivalent in intent to the JS endpoint finders that live in a
proxy. Deliberately regex over text and nothing more: no Node, no
parser, no new binary in the image, and no evaluation of any kind.
The input is a client's minified JavaScript, which is hostile by
construction.

**Precision is the whole problem.** A naive `"/..."` pattern over a
minified bundle returns thousands of hits: every regex fragment,
every date format, every CSS selector, every bit of a sourcemap
comment. A finder that reports 10,000 paths has told you nothing
and costs more to triage than reading the file. Everything below
exists to say no: the filters discard far more than they keep, and
the few that get through are the ones worth queueing a scan at.

What it keeps, and nothing else:

    absolute paths   "/api/v2/accounts" — a leading slash, at least
                     one more path segment, and plausible characters
    full URLs        http(s) only
    protocol-relative "//host/path", which is a URL in practice

What it refuses, with reasons in the code: single-segment paths
(`/x` is almost always a regex or a division), anything with a
space or a quote, obvious MIME types and dates, file extensions
belonging to assets rather than routes, and known library noise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: Per file. A bundle matching this many distinct endpoints is a
#: bundle whose matches are noise; reporting the cap is more honest
#: than reporting the noise.
MAX_PER_FILE = 300

#: Longer than this is not a route. Minified code contains very long
#: slash-separated runs that are regexes or base64.
MAX_LEN = 180

#: `"/api/v2/x"` or `'/admin/users'` or `` `/a/b` `` — quoted, which
#: is what distinguishes a path the code USES from a slash that
#: happens to be in an expression. Two segments minimum.
_QUOTED_PATH = re.compile(
    r"""['"`](/[A-Za-z0-9_\-.~%$]+(?:/[A-Za-z0-9_\-.~%${}:]*)+)['"`]""")

#: LinkFinder's endpoint regex (GerbenJavado/LinkFinder), which is
#: the reference implementation for this job and catches three
#: shapes the pattern above does not:
#:
#:   relative with a slash   `js/app/config` — no leading slash, so
#:                           the quoted-path rule never sees it
#:   a file by extension     `admin.php`, `upload.action`
#:   extensionless REST      `api/v2/accounts`
#:
#: Taken as a CANDIDATE source only. LinkFinder on its own is
#: famously noisy -- that is the common complaint about it -- so
#: everything it produces goes through `_plausible` with the rest.
#: Recall from LinkFinder, precision from the filters measured on
#: this estate's real bundles.
_LINKFINDER = re.compile(
    r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})"""
    r"""|((?:/|\.\./|\./)[^"'><,;| *()(%$^/\\\[\]][^"'><,;|()]{1,})"""
    r"""|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}"""
    r"""\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))"""
    r"""|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))"""
    r"""|([a-zA-Z0-9_\-]{1,}"""
    r"""\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)"""
    r"""(?:[\?|#][^"|']{0,}|)))(?:"|')""")

#: Full URLs, http(s) only. Not ftp/ws/data/blob: those are not
#: things to point a scanner at.
_URL = re.compile(r"""['"`](https?://[A-Za-z0-9._~\-]+(?::\d+)?(?:/[^'"`\s]*)?)['"`]""")

#: `//cdn.example.com/x` — a URL in practice.
_PROTO_REL = re.compile(r"""['"`](//[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:/[^'"`\s]*)?)['"`]""")

#: Extensions that are an ASSET, not a route worth probing. The
#: asset pipeline already has these; re-reporting them as endpoints
#: buries the handful that matter.
_ASSET_EXT = (
    ".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp",
    ".mp4", ".webm", ".avif",
)

#: Paths that are a library's internals rather than the
#: application's surface. `node_modules` in particular appears in
#: every source map and is never a route.
_NOISE = (
    "node_modules/", "/webpack/", "/__webpack", "/@babel/", "/core-js/",
    "/regenerator-runtime/", "/rxjs/", "/tslib/",
)

#: Hosts that are never an endpoint, however often they appear.
#:
#: XML namespaces are the big one and they are everywhere: every
#: inline SVG carries `http://www.w3.org/2000/svg`, which is an
#: identifier and not an address anybody serves. Measured on 400
#: real files before this list existed, namespace and licence URLs
#: were the majority of all URL hits and buried the one result that
#: mattered.
_NOISE_HOSTS = (
    "www.w3.org", "w3.org", "schema.org", "purl.org", "xmlns.com",
    "ns.adobe.com", "www.apache.org", "apache.org", "opensource.org",
    "creativecommons.org", "www.gnu.org", "gnu.org", "json-schema.org",
    "www.mozilla.org", "mozilla.org", "docs.oasis-open.org",
    "www.inkscape.org", "sodipodi.sourceforge.net", "sourceforge.net",
    "example.com", "example.org", "localhost",
)

#: A MIME type reads exactly like a two-segment path.
_MIME_HEAD = ("/json", "/javascript", "/html", "/plain", "/xml", "/octet-",
              "/form-data", "/x-www-form", "/css", "/png", "/jpeg", "/gif",
              "/svg+xml", "/pdf", "/zip", "/event-stream", "/csv")

#: `/2024/01/15`, `/01/02`, version runs — dates and numbers, not routes.
#:
#: A character class, NOT `^/(?:\d+/?)+$`. That version nests `\d+`
#: inside `+` and backtracks exponentially: measured at 0.005s for
#: 18 digits and 0.292s for 24, so a bundle containing a long digit
#: run after a slash would hang the worker -- and Python's `re`
#: holds the GIL while it backtracks, so it would hang more than
#: this one task. The input here is a client's minified JavaScript,
#: which is hostile by construction. CodeQL caught it (py/redos).
#:
#: `[\d/]+` expresses the same intent -- digits and slashes only --
#: with no nesting and therefore no backtracking at all.
_ALL_NUMERIC = re.compile(r"^/[\d/]+$")

#: Percent-encoded markup. Inline SVG is routinely embedded as a
#: data URI, and the encoded `></svg>` tail arrives looking like a
#: path: `/%3E%3C/svg%3E`.
_ENCODED_MARKUP = re.compile(r"%3[ceCE]")

#: A random token, not a route. Bot-management and CDN challenge
#: paths are runs of base64-ish segments that differ on every page
#: load, so they are both noise AND unstable -- storing them means a
#: new "endpoint" every sweep for ever.
#:
#: Judged per segment: twelve or more characters mixing upper, lower
#: and digits with no separator is a token, not a word somebody
#: typed. `SessionTimeServlet` survives (no digits);
#: `0aiqGemfFwpl8` does not.
_TOKENISH = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z0-9]{12,}$")


#: Cloud resources named in a bundle, by provider.
#:
#: A front-end that talks to a bucket, a function or a vault names
#: it in the code, and that name identifies a real asset of the
#: estate that no port scan would ever find -- nothing links to it
#: and it is on the provider's address space, not the client's.
#:
#: **Hostnames only, deliberately.** An ARN names the same bucket
#: and is the identifier a console shows, but it is not a host: it
#: cannot be resolved, cannot be requested, and -- the deciding
#: reason -- `scope.classify` refuses it outright, so a target
#: created from one could never be checked against the engagement's
#: scope document. A bucket HOSTNAME is an ordinary FQDN that goes
#: through the same gate as everything else and can actually be
#: tested for public listing.
#:
#: Each pattern is anchored on a domain the provider owns rather
#: than on a shape ordinary code could produce. A false positive
#: here is a target row naming an asset that does not exist, which
#: is worse than a missing one, because it reaches a report.
_CLOUD: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Virtual-hosted bucket: <bucket>.s3.amazonaws.com and the
    # regional spellings <bucket>.s3.<region>.amazonaws.com and
    # <bucket>.s3-<region>.amazonaws.com.
    ("aws", re.compile(
        r"\b([a-z0-9][a-z0-9.-]{1,61}\.s3(?:[.-][a-z0-9-]{3,20})?"
        r"\.amazonaws\.com)\b")),
    ("aws", re.compile(
        r"\b([a-z0-9-]{1,63}\.execute-api\.[a-z0-9-]{3,20}"
        r"\.amazonaws\.com)\b")),
    ("aws", re.compile(r"\b([a-z0-9]{1,30}\.cloudfront\.net)\b")),
    ("azure", re.compile(
        r"\b([a-z0-9]{3,24}\.(?:blob|file|queue|table|dfs)"
        r"\.core\.windows\.net)\b")),
    ("azure", re.compile(r"\b([a-z0-9][a-z0-9-]{1,60}\.azurewebsites\.net)\b")),
    ("azure", re.compile(r"\b([a-z0-9][a-z0-9-]{1,60}\.vault\.azure\.net)\b")),
    ("gcp", re.compile(
        r"\b([a-z0-9][a-z0-9._-]{1,61}\.storage\.googleapis\.com)\b")),
    ("gcp", re.compile(r"\b([a-z0-9][a-z0-9-]{1,60}\.appspot\.com)\b")),
    ("gcp", re.compile(r"\b([a-z0-9-]{1,60}\.cloudfunctions\.net)\b")),
)

#: Path-style S3, which names a bucket without putting it in the
#: hostname: `https://s3.eu-west-1.amazonaws.com/acme-assets/...`.
#: Older SDKs still emit it. Rewritten to the virtual-hosted
#: spelling so one bucket is one target however the code addressed
#: it -- two rows for the same bucket is two sets of findings.
#:
#: The lookbehind is load-bearing. `\b` is satisfied by the dot in
#: `acme-assets.s3.eu-west-1.amazonaws.com/img/logo.png`, so without
#: it this matched inside a VIRTUAL-HOSTED URL and read the first
#: path segment as a bucket -- inventing `img.s3.eu-west-1.
#: amazonaws.com`, a target that does not exist.
_S3_PATH = re.compile(
    r"(?<![a-z0-9.-])s3(?:[.-]([a-z0-9-]{3,20}))?"
    r"\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61})")

#: Buckets and hosts that belong to a provider's own documentation,
#: samples and SDK defaults. They turn up in every bundle that ships
#: a cloud SDK and name nothing of the client's.
_CLOUD_NOISE = frozenset({
    "s3.amazonaws.com", "bucket.s3.amazonaws.com",
    "my-bucket.s3.amazonaws.com", "example.s3.amazonaws.com",
    "examplebucket.s3.amazonaws.com", "mybucket.s3.amazonaws.com",
    "storage.googleapis.com", "example.appspot.com",
    "myproject.appspot.com", "example.blob.core.windows.net",
    "myaccount.blob.core.windows.net",
})


def cloud_resources(body: str, limit: int = 50) -> list[tuple[str, str]]:
    """-> [(provider, identifier)] named in this file, de-duplicated.

    Order is stable (provider order, then first appearance) so a
    re-scan of an unchanged file yields an identical list and the
    caller can store these without rewriting rows every sweep.
    """
    if not body:
        return []
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def take(provider: str, value: str) -> bool:
        """-> True when the caller should stop (limit reached)."""
        low = value.strip().rstrip("/.").lower()
        # 253 is the DNS limit and `Target.host` is 255. A longer
        # value is not a name, it is a match that ran away.
        if not low or len(low) > 253 or low in _CLOUD_NOISE or low in seen:
            return False
        seen.add(low)
        out.append((provider, low))
        return len(out) >= limit

    for provider, rx in _CLOUD:
        for m in rx.finditer(body):
            if take(provider, m.group(1)):
                return out
    for m in _S3_PATH.finditer(body):
        region, bucket = m.group(1), m.group(2)
        # A path segment that is itself the regional endpoint is the
        # URL's own host repeated, not a bucket.
        if bucket.endswith(".amazonaws.com"):
            continue
        host = (f"{bucket}.s3.{region}.amazonaws.com" if region
                else f"{bucket}.s3.amazonaws.com")
        if take("aws", host):
            return out
    return out


@dataclass(frozen=True)
class Endpoint:
    value: str
    #: path | url
    kind: str


def _plausible(p: str) -> bool:
    """Whether a candidate is worth reporting. Says no a lot."""
    if not p or len(p) > MAX_LEN:
        return False
    low = p.lower()
    if any(n in low for n in _NOISE):
        return False
    # Strip the query before judging the extension: `/x.js?v=2` is
    # still an asset.
    head = low.split("?", 1)[0].split("#", 1)[0]
    if head.endswith(_ASSET_EXT):
        return False
    if _ALL_NUMERIC.match(head):
        return False
    if _ENCODED_MARKUP.search(head):
        return False
    # On the ORIGINAL, not `head`: `head` is lower-cased, so a test
    # for mixed case could never match it and this filter silently
    # did nothing. Caught by the Akamai bot-manager paths surviving
    # a measurement that was supposed to remove them.
    raw_head = p.split("?", 1)[0].split("#", 1)[0]
    if any(_TOKENISH.match(seg) for seg in raw_head.split("/") if seg):
        return False
    # A MIME type: `application/json` loses its first word to the
    # quote and arrives here as `/json`.
    if any(head == m or head.startswith(m + ";") for m in _MIME_HEAD):
        return False
    # A template with nothing fixed in it -- `/${a}/${b}` -- names no
    # route we could request.
    without_tpl = re.sub(r"\$\{[^}]*\}|:[A-Za-z_][A-Za-z0-9_]*", "", head)
    return bool(re.search(r"[A-Za-z]", without_tpl.replace("/", "")))


def extract(body: str, limit: int = MAX_PER_FILE) -> list[Endpoint]:
    """-> the endpoints this file references, de-duplicated.

    Order is stable (first appearance) so a re-scan of an unchanged
    file produces an identical list, which is what lets a caller
    store these without re-writing rows every sweep.
    """
    if not body:
        return []
    seen: set[str] = set()
    out: list[Endpoint] = []

    def take(value: str, kind: str) -> None:
        v = value.strip()
        if kind == "path" and not _plausible(v):
            return
        if kind == "url":
            m = re.match(r"https?://([^/:]+)(?::\d+)?(/.*)?$", v)
            if not m:
                return
            host = m.group(1).lower()
            if host in _NOISE_HOSTS or host.endswith(".w3.org"):
                return
            # Judge the URL's PATH, so a CDN's .js is dropped the
            # same way a relative one is.
            tail = m.group(2) or "/"
            if tail != "/" and not _plausible(tail):
                return
        if v in seen:
            return
        seen.add(v)
        out.append(Endpoint(v, kind))

    for m in _URL.finditer(body):
        take(m.group(1), "url")
        if len(out) >= limit:
            return out
    for m in _PROTO_REL.finditer(body):
        take("https:" + m.group(1), "url")
        if len(out) >= limit:
            return out
    for m in _QUOTED_PATH.finditer(body):
        take(m.group(1), "path")
        if len(out) >= limit:
            return out
    # LinkFinder last: it has the widest recall and therefore the
    # most noise, so anything the stricter patterns already found
    # keeps their classification rather than being re-judged here.
    for m in _LINKFINDER.finditer(body):
        v = (m.group(1) or "").strip()
        if not v:
            continue
        if v.startswith(("http://", "https://")):
            take(v, "url")
        elif v.startswith("//"):
            take("https:" + v, "url")
        elif v.startswith("/"):
            take(v, "path")
        else:
            # Relative: `js/app/config`, `admin.php`. Recorded as
            # written, because resolving it needs the page it was
            # served from and guessing a base would invent a route.
            take(v, "path")
        if len(out) >= limit:
            return out
    return out


def hosts_of(endpoints) -> list[str]:
    """Distinct hostnames among the URLs found.

    Separate from the endpoints themselves because a NEW HOST is a
    different kind of result: under the engagement's rules a host
    discovered from an in-scope target may itself be in scope, which
    a path never is.
    """
    out: list[str] = []
    for e in endpoints:
        if e.kind != "url":
            continue
        m = re.match(r"https?://([A-Za-z0-9._\-]+)", e.value)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out
