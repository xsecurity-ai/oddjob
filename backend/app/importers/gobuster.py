"""Content-discovery output from the Ghost's in-process gobuster.

`{"url": ..., "wordlist": ..., "found": [path, ...], "hits": [{...}]}`
-- the shape `tasks/gobuster.go` writes.

**This did not exist, and the absence was silent, for the second
time.** `gobuster` was registered in `TASK_KINDS` with no importer,
exactly as `katana` and `gospider` were before `crawl.py` was
written. The consequence is the same and it is not small: 1,128
content-discovery runs completed against a client, found 36,540
paths between them, and every one of those paths stayed in
`agent_tasks.output` as a JSON blob. The Web view reads
`web_addresses`; nothing wrote there; `sources ILIKE '%gobuster%'`
matched zero rows while the work had already been paid for in
requests at the client.

Nothing errored, because nothing was asked to. That is the shape of
this bug both times, and it is why `TASK_KINDS` now carries a
comment saying a `None` there means "this tool's findings are
discarded".

**Everything here is `crawled=True`**, which is the opposite of
`crawl.py`'s default and for the opposite reason. A path in this
list was REQUESTED: gobuster asked the server for it and the server
answered with a status. That is a response, not a reference. The
distinction is the whole value of the status column -- a 403 on
`/admin` is a finding, and it is only a finding because somebody
actually asked.

**A 401 or a 403 is a result, not a failure.** 25,361 of those
36,540 hits are one of the two. They say the path exists and is
protected, which is frequently the more interesting answer than a
200, and an importer that kept only 200s would throw away two
thirds of what content discovery is for.
"""
from __future__ import annotations

import json

from ..weburl import BadUrl
from ..weburl import parse as parse_url
from .model import ImportError_, ParsedScan, ParsedWebAddress

#: One run is bounded by its wordlist, and the built-in list is 4,751
#: entries. A ceiling well above that is a backstop against a
#: catch-all host turning one task into an unbounded write, not a
#: policy about how many paths are worth keeping.
MAX_HITS = 20000


def looks_like(text: str) -> bool:
    head = text.lstrip()[:2000]
    if not head.startswith("{"):
        return False
    # `"found"` alone is not enough to be sure, and `"urls"` would
    # collide with a crawl result. The wordlist name is the thing only
    # content discovery reports.
    #
    # Except that vhost discovery now writes `found`, `wordlist` AND
    # `hits` too -- same library, same wordlist, different question.
    # Its hits carry `vhost` where these carry `path`, so that is the
    # discriminator. Without this a vhost sweep imports as content
    # discovery and files hostnames as URL paths.
    # `domain` as well as `vhost`: a vhost run that found nothing
    # carries neither hits nor names, so the hit key alone does not
    # identify it -- and a sweep defeated by a wildcard is exactly
    # the run that produces an empty list. Content discovery never
    # writes `domain`.
    if '"vhost"' in head or '"domain"' in head:
        return False
    return '"found"' in head and ('"wordlist"' in head or '"hits"' in head)


def parse(text: str) -> ParsedScan:
    scan = ParsedScan(tool="gobuster")
    try:
        doc = json.loads(text or "")
    except ValueError as e:
        raise ImportError_(f"not a gobuster result: {e}") from e
    if not isinstance(doc, dict):
        raise ImportError_("a gobuster result is an object")

    base = str(doc.get("url") or "").strip()
    if not base:
        raise ImportError_("a gobuster result carries the `url` it ran against")
    try:
        root = parse_url(base)
    except BadUrl as e:
        raise ImportError_(f"the url gobuster ran against is unusable: {e}") from e

    hits = doc.get("hits")
    if isinstance(hits, list) and hits:
        records: list[dict] = [h for h in hits if isinstance(h, dict)]
    else:
        # The older shape, a bare list of paths with no status. Still
        # read, because tasks delivered before the agent reported the
        # detail are in the database and their results are still worth
        # having -- as paths, with the status honestly absent.
        found = doc.get("found")
        if not isinstance(found, list):
            raise ImportError_("a gobuster result carries `hits` or `found`")
        records = [{"path": p} for p in found]

    seen: set[str] = set()
    for rec in records[:MAX_HITS]:
        path = str(rec.get("path") or "").strip()
        if not path:
            continue
        url = _join(root.url, path)
        if url is None:
            continue
        try:
            parsed = parse_url(url)
        except BadUrl:
            continue
        # The host must still be the host we ran against. Nothing in a
        # wordlist should be able to change that, and the check costs
        # one comparison -- but `path` reaches here having been through
        # a merge with the project's own `extra_words`, and an operator
        # pasting a list from somewhere is a more ordinary event than
        # it sounds.
        if parsed.host != root.host or parsed.port != root.port:
            continue
        if parsed.url in seen:
            continue
        seen.add(parsed.url)
        status = rec.get("status")
        size = rec.get("size")
        scan.web.append(ParsedWebAddress(
            url=parsed.url, host=parsed.host, scheme=parsed.scheme,
            port=parsed.port,
            method=(str(rec.get("method") or "").upper()[:12] or None),
            status_code=(int(status)
                         if isinstance(status, int) and status else None),
            content_type=(str(rec.get("content_type") or "")[:128] or None),
            content_length=(int(size) if isinstance(size, int) else None),
            webserver=(str(rec["server"])[:255] if rec.get("server") else None),
            # It answered. See the module docstring.
            crawled=bool(status),
            notes=("found by content discovery"
                   + (f" (redirects to {str(rec['redirect'])[:300]})"
                      if rec.get("redirect") else ""))))

    # NOT an error when empty, which is where this parts company with
    # `crawl.py`. 670 of 1,128 runs found nothing at all, and "the
    # wordlist found nothing here" is the single most common honest
    # outcome of content discovery. Refusing it would file a failed
    # import against the majority of successful runs.
    return scan


def _join(base: str, path: str) -> str | None:
    """`https://h/` + `admin` -> `https://h/admin`, or None.

    Deliberately not `urllib.parse.urljoin`: a wordlist entry of
    `//evil.example/x` is a protocol-relative URL, and urljoin
    resolves that to a DIFFERENT HOST while looking like it did its
    job. Everything here is a path under the base, or it is dropped.
    """
    p = path.strip()
    if not p:
        return None
    # Any `scheme:`, `//host` or backslash form is refused rather than
    # normalised. A wordlist holds paths; anything else in it is a
    # mistake at best.
    if ":" in p.split("/")[0] or p.startswith("//") or "\\" in p:
        return None
    return base.rstrip("/") + "/" + p.lstrip("/")
