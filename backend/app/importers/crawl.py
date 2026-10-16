"""Crawl output from the Ghost's in-process katana.

`{"sites": [...], "depth": N, "urls": [...], "by_type": {...}}` — the
shape `tasks/katana.go` writes, and the shape gospider's runner wrote
before it, which is why one importer reads both.

**This did not exist, and the absence was silent.** `katana` and
`gospider` were registered with no `import_as`, so an agent would
crawl a client's site, post several thousand URLs back, and the
server would store the blob on the task and do nothing further with
it. The Web view reads `web_addresses`; nothing wrote there; the page
was empty while 135,597 URLs sat in `agent_tasks.output`. Nothing
errored, because nothing was asked to.

**Everything here is `crawled=False`.** The distinction is already in
the model and it matters more for a crawler than for anything else: a
URL in this list was LINKED TO, not fetched. katana follows links and
reports what it saw referenced, and a referenced URL is a claim by
the page that wrote it, not evidence the resource exists. httpx sets
`crawled=True` because it actually got a response. Marking these as
fetched would turn "the site mentions /admin/backup.sql" into "there
is a /admin/backup.sql", which is exactly the kind of inference a
report must not make on its own.
"""
from __future__ import annotations

import json
import re

from ..weburl import BadUrl
from ..weburl import parse as parse_url
from .model import ImportError_, ParsedAsset, ParsedScan, ParsedWebAddress

#: Anything of the form `scheme:`, which is how a non-web URL in the
#: markup announces itself.
_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")

#: One crawl of a large site can return tens of thousands of URLs.
#: Bounded so a single task cannot write an unbounded number of rows
#: in one transaction; the tail of a crawl that big is near-duplicate
#: pagination anyway, and the count is reported either way.
MAX_URLS = 20000


def looks_like(text: str) -> bool:
    head = text.lstrip()[:2000]
    if not head.startswith("{"):
        return False
    return '"urls"' in head and ('"by_type"' in head or '"sites"' in head)


def parse(text: str) -> ParsedScan:
    scan = ParsedScan(tool="katana")
    try:
        doc = json.loads(text or "")
    except ValueError as e:
        raise ImportError_(f"not a crawl result: {e}") from e
    if not isinstance(doc, dict):
        raise ImportError_("a crawl result is an object")

    # `pages` carries the response the crawler actually got -- verb,
    # status, title, server. `urls` is the older shape, a bare list of
    # addresses, and is still read because tasks delivered before the
    # agent reported the detail are still in the database and their
    # results are still worth having.
    _assets(scan, doc.get("assets"))

    pages = doc.get("pages")
    if isinstance(pages, list) and pages:
        return _from_pages(scan, pages)

    urls = doc.get("urls")
    if not isinstance(urls, list):
        raise ImportError_("a crawl result carries a `urls` list")

    seen: set[str] = set()
    for raw in urls[:MAX_URLS]:
        u = str(raw or "").strip()
        if not u:
            continue
        # Rejected BEFORE parsing, and this is not merely tidiness.
        # `weburl.parse` prepends `http://` to anything with no `://`,
        # so `mailto:nobody@acme.example` becomes
        # `http://mailto:nobody@acme.example` — where `mailto:nobody@`
        # reads as USERINFO and the host becomes whatever follows the
        # `@`. That is correct URL parsing and the wrong answer here.
        #
        # It matters because this input is markup from the client's
        # own site, which an attacker may influence: a crafted href
        # would otherwise invent an inventory row pointing at a host
        # of their choosing, inside an engagement scoped to somebody
        # else's estate. The scope gate would catch it on the way out,
        # but a scanner's inventory should not need saving from its
        # own importer.
        if (m := _SCHEME.match(u)) and m.group(1).lower() not in ("http", "https"):
            continue
        try:
            parsed = parse_url(u)
        except BadUrl:
            # A crawler reports what it found in the markup, which
            # includes `javascript:`, `mailto:` and the occasional
            # template left unrendered. Not an error in the crawl and
            # not worth failing an import of 5,000 good URLs over.
            continue
        if parsed.url in seen:
            continue
        seen.add(parsed.url)
        scan.web.append(ParsedWebAddress(
            url=parsed.url, host=parsed.host, scheme=parsed.scheme,
            port=parsed.port,
            # Linked to, not fetched. See the module docstring.
            crawled=False,
            notes="found by crawling"))

    if not scan.web:
        # An empty crawl is a real answer -- a site that links nowhere
        # -- but it is not an import. Refusing keeps "we crawled it and
        # it had nothing" out of the inventory as a row count of zero
        # rather than as a successful import of nothing.
        raise ImportError_("the crawl returned no usable URLs")
    return scan


def _from_pages(scan: ParsedScan, pages: list) -> ParsedScan:
    """The richer shape: one record per page the crawler requested.

    `crawled` is True here and False in the `urls` branch, and the
    difference is real rather than bookkeeping. A record in `pages`
    has a response: the crawler asked for that address and something
    answered. The old shape could not tell an address that was
    fetched from one that was merely linked to, so everything from it
    is recorded as the weaker claim.
    """
    seen: set[str] = set()
    for rec in pages[:MAX_URLS]:
        if not isinstance(rec, dict):
            continue
        u = str(rec.get("url") or "").strip()
        if not u:
            continue
        if (m := _SCHEME.match(u)) and m.group(1).lower() not in ("http", "https"):
            continue
        try:
            parsed = parse_url(u)
        except BadUrl:
            continue
        if parsed.url in seen:
            continue
        seen.add(parsed.url)
        status = rec.get("status")
        tech = rec.get("tech")
        scan.web.append(ParsedWebAddress(
            url=parsed.url, host=parsed.host, scheme=parsed.scheme,
            port=parsed.port,
            method=(str(rec.get("method") or "").upper()[:12] or None),
            # A status of 0 is the agent saying it had no response,
            # not a status. `omitempty` on the agent side means it is
            # usually absent; this guards the case where it is not.
            status_code=int(status) if isinstance(status, int) and status else None,
            title=(str(rec["title"])[:512] if rec.get("title") else None),
            content_type=(str(rec.get("content_type") or "")[:128] or None),
            content_length=(int(rec["length"])
                            if isinstance(rec.get("length"), int) else None),
            webserver=(str(rec["server"])[:255] if rec.get("server") else None),
            tech=[str(t) for t in tech] if isinstance(tech, list) else [],
            # It answered. See the docstring.
            crawled=bool(rec.get("status")),
            # The exchange itself, so a finding can be shown rather
            # than described. The agent redacts `Cookie` and the
            # other credential headers before it leaves the host --
            # the engagement's own session is not evidence about the
            # client, and this table is read by everyone on the
            # project.
            request=(str(rec["request"])[:200000] if rec.get("request") else None),
            response=(str(rec["response"])[:2000000]
                      if rec.get("response") else None),
            notes=("found by crawling"
                   + (" (response truncated)" if rec.get("truncated") else "")
                   + (" (body not carried: past the task's budget)"
                      if rec.get("body_skipped") else ""))))
    if not scan.web:
        raise ImportError_("the crawl returned no usable URLs")
    return scan


def _assets(scan: ParsedScan, raw) -> None:
    """Third-party scripts and stylesheets the pages pull in.

    Read off the DOM the crawler already had, so nothing was fetched
    to produce these. A missing `version` means the URL did not say
    -- a fingerprinted bundle like `app.a1b2c3.js` -- and that is
    reported as unknown rather than guessed at. A wrong version is
    worse than no version: one is a gap, the other is a finding
    somebody acts on.
    """
    if not isinstance(raw, list):
        return
    seen: set[str] = set()
    for rec in raw[:MAX_URLS]:
        if not isinstance(rec, dict):
            continue
        u = str(rec.get("url") or "").strip()
        if not u or u in seen:
            continue
        if (m := _SCHEME.match(u)) and m.group(1).lower() not in ("http", "https"):
            continue
        try:
            parse_url(u)
        except BadUrl:
            continue
        seen.add(u)
        status = rec.get("status")
        scan.assets.append(ParsedAsset(
            url=u,
            page=(str(rec["page"]) if rec.get("page") else None),
            kind=(str(rec.get("kind") or "script")[:16]),
            name=(str(rec["name"])[:128] if rec.get("name") else None),
            version=(str(rec["version"])[:64] if rec.get("version") else None),
            # Present only when the bundle was pulled back. A hash
            # without a body means the agent read it and the body
            # was dropped in transit; a body without a hash should
            # not happen and is treated as unfetched.
            sha256=(str(rec["sha256"])[:64] if rec.get("sha256") else None),
            bytes=(int(rec["bytes"]) if isinstance(rec.get("bytes"), int) else None),
            content_type=(str(rec.get("content_type") or "")[:128] or None),
            status_code=(int(status) if isinstance(status, int) and status else None),
            body=(str(rec["body"]) if rec.get("body") else None)))
