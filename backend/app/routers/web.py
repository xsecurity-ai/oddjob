"""Web addresses found on http(s) services.

Its own view rather than a column on Services because a web server is not
one thing: a single :443 routinely carries a login page, an admin console,
an API and a forgotten status endpoint, and "what is reachable" is the
question an operator actually has. A banner cannot answer it.
"""
from __future__ import annotations

import re

# At module scope, not inside the handler: the URL below is built from
# components before the request is made, so the import has to precede
# it, and a deferred import that is now needed in two places is just a
# NameError waiting for whichever one runs first.
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from .. import assetscan, assetsearch, assetwork, takeover
from ..db import get_session
from ..events import broker
from ..filtering import apply_filters
from ..hosts import InvalidHost, validate_host

#: Same caps the importer uses, so a replayed exchange is stored on the
#: same terms as a captured one.
from ..importers.burphistory import REQ_CAP, RESP_CAP
from ..models import (
    Project,
    Service,
    Takeover,
    Target,
    User,
    WebAddress,
    WebAsset,
    WebAssetRef,
)
from ..schemas import Page, WebAddressCreate, WebAddressOut, WebAddressUpdate, WebPacket
from ..scopegate import assert_allowed
from ..security import (
    assert_role_for_target,
    get_current_user,
    require_project,
    visible_project_ids,
)
from ..timeline import record
from ..webtargets import source_clause, web_service_clause
from ..weburl import BadUrl, exchange_key, merge_sources, stable_response, url_key
from ..weburl import parse as parse_url

router = APIRouter(prefix="/api/web", tags=["web"])

#: A Host header, and nothing that could read as anything else. No
#: `@` (userinfo, which moves the real destination), no `/` (a path,
#: which does the same to a careless parser), no whitespace, no
#: control characters. An IPv6 literal keeps its brackets because that
#: is how one appears in a Host header.
#:
#: Deliberately stricter than "what a browser would accept": this
#: pattern decides where the server puts a packet on a client's
#: network, so anything ambiguous is refused rather than interpreted.
_HOST_PORT = re.compile(
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+)(?::(?P<port>\d{1,5}))?")

SORTABLE = {
    "url": WebAddress.url, "path": WebAddress.path, "port": WebAddress.port,
    "status_code": WebAddress.status_code, "title": WebAddress.title,
    "scheme": WebAddress.scheme, "webserver": WebAddress.webserver,
    "crawled": WebAddress.crawled, "host": Target.host,
    "method": WebAddress.method,
    "created_at": WebAddress.created_at, "updated_at": WebAddress.updated_at,
}

#: What a chained column filter may reference. Deliberately a list, not
#: "whatever the model has": a filter is a query the caller composes, so
#: the set of columns it can reach is part of the endpoint's contract.
FILTERABLE = {
    **SORTABLE,
    "project_code": Project.code,
    "content_type": WebAddress.content_type,
    "notes": WebAddress.notes,
    "sources": WebAddress.sources,
}


def _out(row) -> WebAddressOut:
    w, host, code = row[0], row[1], row[2]
    return WebAddressOut(
        **{k: getattr(w, k) for k in _KEYS}, host=host, project_code=code)


#: WebAddressOut has no request/response by design — see WebPacket.
_KEYS = tuple(k for k in WebAddressOut.model_fields
              if k not in ("host", "project_code"))


def _base():
    return (select(WebAddress, Target.host, Project.code)
            .join(Target, Target.id == WebAddress.target_id)
            .join(Project, Project.id == Target.project_id))


@router.get("", response_model=Page[WebAddressOut])
async def list_web(
    project: str | None = Query(None, description="project code; omit for all"),
    host: str | None = Query(None),
    q: str | None = Query(None, description="search url, title, webserver, host"),
    status_code: int | None = Query(None),
    status_in: str | None = Query(
        None, description="comma-separated status codes, e.g. 200,401,403,500"),
    scheme: str | None = Query(None),
    crawled: bool | None = Query(None, description="only addresses actually fetched"),
    found_by: str | None = Query(
        None, pattern="^(crawl|discovery)$",
        description="crawl = a crawler saw it; discovery = content "
                    "discovery found it and no crawler did"),
    filters: str | None = Query(
        None,
        description='chained column filters, as JSON: '
                    '[{"field":"status_code","op":">=","value":500}]'),
    logic: str = Query("and", pattern="^(and|or)$"),
    sort: str = Query("url"), order: str = Query("asc"),
    limit: int = Query(1000, le=10000), offset: int = 0,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Every web address the project has seen.

    Scoped to what the caller may see — a readonly grant on one engagement
    must not reveal the shape of another.
    """
    stmt = await _scoped(session, user, project, host, q, status_code,
                         status_in, scheme, crawled, filters, logic,
                         found_by)
    if stmt is None:
        return Page[WebAddressOut](items=[], total=0, limit=limit, offset=offset)

    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar_one())
    col = SORTABLE.get(sort, WebAddress.url)
    stmt = stmt.order_by(col.desc() if order == "desc" else col.asc())
    rows = (await session.execute(stmt.limit(limit).offset(offset))).all()
    return Page[WebAddressOut](items=[_out(r) for r in rows],
                               total=total, limit=limit, offset=offset)


async def _scoped(session, user, project, host, q, status_code, status_in,
                  scheme, crawled, filters, logic, found_by=None):
    """The filtered query both listings share, or None if out of scope.

    Extracted so the flat listing and the grouped one cannot drift: a
    filter honoured by one and not the other would make the grouped
    count disagree with the rows it expands to.
    """
    stmt = _base()
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = (await session.execute(
            select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
        if pr is None or (vis is not None and pr.id not in vis):
            return None
        stmt = stmt.where(Target.project_id == pr.id)
    if host:
        stmt = stmt.where(Target.host == host.strip().lower())
    if status_code is not None:
        stmt = stmt.where(WebAddress.status_code == status_code)
    if status_in:
        # The UI's "interesting" shortcut is a set of codes, and it has
        # to be applied in SQL: filtering after the fact would only ever
        # see the current page, so the row count and the paging would
        # both be wrong.
        want = [int(x) for x in status_in.replace(" ", "").split(",")
                if x.strip().lstrip("-").isdigit()]
        if want:
            stmt = stmt.where(WebAddress.status_code.in_(want))
    if scheme:
        stmt = stmt.where(WebAddress.scheme == scheme.lower())
    if crawled is not None:
        stmt = stmt.where(WebAddress.crawled.is_(crawled))
    # Who FOUND it, as opposed to `crawled`, which is whether we
    # fetched it. A URL gobuster guessed and we then fetched is
    # `crawled=True` and `found_by=discovery`; the two answer
    # different questions and are deliberately separate filters.
    if (clause := source_clause(found_by or "")) is not None:
        stmt = stmt.where(clause)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(WebAddress.url.ilike(like),
                              WebAddress.title.ilike(like),
                              WebAddress.webserver.ilike(like),
                              WebAddress.notes.ilike(like),
                              Target.host.ilike(like)))

    # Filters are part of the scoped query, so the count and the rows
    # always describe the same set.
    return apply_filters(stmt, filters, FILTERABLE, logic)


class WebGroupOut(WebAddressOut):
    """One URL, standing for every exchange recorded against it.

    The table used to hold one row per address. It now holds one per
    captured exchange, which is the honest unit — the same endpoint
    probed ten ways is ten pieces of evidence. That would make the list
    ten times longer to read, so the list groups them back under the
    URL and `hits` says how many there are. The representative row is
    the earliest, so the display does not change as new hits arrive.
    """
    hits: int = 1
    #: Distinct verbs and status codes across the group, so a reader can
    #: see "this URL answered 200 and 500" without expanding it.
    methods: list[str] = []
    statuses: list[int] = []


@router.get("/grouped", response_model=Page[WebGroupOut])
async def list_web_grouped(
    project: str | None = Query(None),
    host: str | None = Query(None),
    q: str | None = Query(None),
    status_code: int | None = Query(None),
    status_in: str | None = Query(None),
    scheme: str | None = Query(None),
    crawled: bool | None = Query(None),
    found_by: str | None = Query(None, pattern="^(crawl|discovery)$"),
    filters: str | None = Query(None),
    logic: str = Query("and", pattern="^(and|or)$"),
    sort: str = Query("url"), order: str = Query("asc"),
    limit: int = Query(100, le=2000), offset: int = 0,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """The same listing, one row per URL instead of per exchange."""
    scoped = await _scoped(session, user, project, host, q, status_code,
                           status_in, scheme, crawled, filters, logic,
                           found_by)
    if scoped is None:
        return Page[WebGroupOut](items=[], total=0, limit=limit, offset=offset)

    # Group on (target, url_hash): the same path on two hosts is two
    # URLs, and the hash is what is indexed.
    sub = scoped.with_only_columns(
        WebAddress.target_id.label("tid"),
        WebAddress.url_hash.label("uh"),
        func.count().label("hits"),
        func.min(WebAddress.id).label("rep"),
    ).group_by(WebAddress.target_id, WebAddress.url_hash).subquery()

    total = int((await session.execute(
        select(func.count()).select_from(sub))).scalar_one())

    # Order by the representative row's sortable column rather than by
    # the aggregate, so "sort by status" means what it looks like.
    col = SORTABLE.get(sort, WebAddress.url)
    page = (select(sub.c.rep, sub.c.hits)
            .join(WebAddress, WebAddress.id == sub.c.rep)
            .join(Target, Target.id == WebAddress.target_id)
            .order_by(col.desc() if order == "desc" else col.asc())
            .limit(limit).offset(offset))
    pairs = (await session.execute(page)).all()
    if not pairs:
        return Page[WebGroupOut](items=[], total=total, limit=limit, offset=offset)

    reps = dict(pairs)
    rows = {r[0].id: r for r in (await session.execute(
        _base().where(WebAddress.id.in_(list(reps))))).all()}

    # Distinct verbs and codes per group, in one more query rather than
    # one per row.
    keys = [(rows[i][0].target_id, rows[i][0].url_hash) for i in reps if i in rows]
    meta: dict[tuple, tuple[set, set]] = {k: (set(), set()) for k in keys}
    if keys:
        agg = (await session.execute(
            select(WebAddress.target_id, WebAddress.url_hash,
                   WebAddress.method, WebAddress.status_code)
            .where(tuple_(WebAddress.target_id, WebAddress.url_hash).in_(keys))
            .distinct())).all()
        for tid, uh, m, sc in agg:
            if (tid, uh) in meta:
                if m:
                    meta[(tid, uh)][0].add(m)
                if sc is not None:
                    meta[(tid, uh)][1].add(sc)

    items = []
    for rep_id, hits in pairs:
        row = rows.get(rep_id)
        if row is None:
            continue
        base = _out(row)
        m, sc = meta.get((row[0].target_id, row[0].url_hash), (set(), set()))
        items.append(WebGroupOut(**base.model_dump(), hits=hits,
                                 methods=sorted(m), statuses=sorted(sc)))
    return Page[WebGroupOut](items=items, total=total, limit=limit, offset=offset)


# Registered above `/{wid}` and friends on purpose. Starlette matches
# in registration order, so a static path declared after a
# parameterised one is shadowed by it and never runs -- which is
# exactly how `/api/projects/clouds` came to return a 404 for a
# project called "clouds".
@router.get("/source-counts")
async def web_source_counts(
    project: str | None = Query(None),
    host: str | None = Query(None),
    q: str | None = Query(None),
    status_code: int | None = Query(None),
    status_in: str | None = Query(None),
    scheme: str | None = Query(None),
    crawled: bool | None = Query(None),
    filters: str | None = Query(None),
    logic: str = Query("and", pattern="^(and|or)$"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """How many addresses each `found_by` choice would show.

    One query, three numbers, so the chooser can say what it costs
    before it is clicked. Counted under every OTHER filter in force --
    pick a project and the numbers are that project's -- because a
    count that ignored the current filters would disagree with the
    table the moment it was used.

    The two slices are disjoint but do not necessarily cover `all`: a
    URL only ever reported by httpx or nuclei was probed directly
    rather than crawled to or guessed at, and belongs to neither. The
    chooser shows all three numbers rather than deriving one from the
    others, so a gap between them is visible instead of hidden.
    """
    stmt = await _scoped(session, user, project, host, q, status_code,
                         status_in, scheme, crawled, filters, logic)
    if stmt is None:
        return {"all": 0, "crawl": 0, "discovery": 0}
    sub = stmt.subquery()
    row = (await session.execute(select(
        func.count(),
        func.count().filter(source_clause("crawl", sub.c.sources)),
        func.count().filter(source_clause("discovery", sub.c.sources)),
    ).select_from(sub))).one()
    return {"all": int(row[0]), "crawl": int(row[1]),
            "discovery": int(row[2])}


@router.get("/by-url", response_model=Page[WebAddressOut])
async def web_by_url(
    target_id: int = Query(..., description="which host's copy of the URL"),
    url: str = Query(...),
    limit: int = Query(200, le=2000), offset: int = 0,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Every exchange recorded for one URL. Drives the expanded row."""
    t = await session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "no such target")
    vis = await visible_project_ids(session, user)
    if vis is not None and t.project_id not in vis:
        raise HTTPException(404, "no such target")
    stmt = (_base().where(WebAddress.target_id == target_id,
                          WebAddress.url_hash == url_key(url))
            .order_by(WebAddress.id))
    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar_one())
    rows = (await session.execute(stmt.limit(limit).offset(offset))).all()
    return Page[WebAddressOut](items=[_out(r) for r in rows], total=total,
                               limit=limit, offset=offset)


class ReplayIn(BaseModel):
    """An edited request to send again."""
    raw: str = Field(description="The full request: request-line, headers, "
                                 "blank line, body")
    follow_redirects: bool = False
    timeout: float = Field(20.0, ge=1, le=120)
    verify_tls: bool = Field(
        False,
        description="Off by default: an engagement target routinely has a "
                    "certificate that does not validate, and refusing to "
                    "talk to it is not a useful default for a test tool.")


class ReplayOut(BaseModel):
    web: WebAddressOut
    status_code: int | None = None
    elapsed_ms: int = 0
    error: str | None = None


def parse_raw_request(raw: str) -> tuple[str, str, dict[str, str], bytes]:
    """-> (method, path, headers, body) from a raw HTTP request.

    Split on the first blank line. Header values are kept verbatim
    apart from surrounding space: a test is often about what a server
    does with an odd header, so normalising them away would defeat the
    point of being able to edit one.
    """
    text = (raw or "").replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        raise HTTPException(422, "the request is empty")
    bits = lines[0].split()
    if len(bits) < 2:
        raise HTTPException(
            422, f"cannot read the request line: {lines[0][:80]!r}. "
                 f"Expected something like 'GET /path HTTP/1.1'.")
    method, path = bits[0].upper(), bits[1]
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if sep:
            headers[k.strip()] = v.strip()
    return method, path, headers, body.encode("utf-8", "surrogatepass")


@router.post("/{web_id}/replay", response_model=ReplayOut)
async def replay(web_id: int, body: ReplayIn,
                 user: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_session)):
    """Send an edited version of a captured request, and record the result.

    The answer is stored as a NEW row rather than replacing the
    original. That is the whole value of it: the original exchange and
    the edited one sit side by side under the same URL, and the
    difference between the two responses is the finding.

    **Where it may send.** The destination host must already be a
    target in the same engagement. Without that this endpoint is an
    authenticated open proxy — anyone with an account could use the
    server to reach anything it can reach. Editing the path, the verb,
    the headers and the body is unrestricted, which is the part that
    matters for testing.
    """
    row = (await session.execute(_base().where(WebAddress.id == web_id))).first()
    if row is None:
        raise HTTPException(404, "no such web address")
    orig, orig_host, _code = row[0], row[1], row[2]
    target = await session.get(Target, orig.target_id)
    code = await assert_role_for_target(session, user, orig.target_id, "user")

    method, path, headers, payload = parse_raw_request(body.raw)

    # The Host header decides where it goes, as it does on the wire.
    #
    # Parsed, not split. `host.split(":")[0]` is what this used to do,
    # and it is a full bypass of both checks below:
    #
    #   Host: known.example.com:80@evil.example.net
    #     split(":")[0] -> "known.example.com"   passes the target
    #                                            lookup AND the scope
    #                                            gate
    #     the URL built from it resolves to evil.example.net, which is
    #     where the packet actually goes
    #
    # Everything after the colon is userinfo to a URL parser, so the
    # validated name ends up as a username and the real host is
    # whatever follows the `@`. For this tool that is worse than the
    # open proxy the docstring worries about: it sends live traffic to
    # a host the scope gate just said was allowed, under a client's
    # engagement, and the audit trail records the wrong name.
    #
    # So the header is required to be strictly host[:port], the
    # hostname goes through the same validator every other host in the
    # system does, and the URL is rebuilt from the validated parts
    # rather than from anything the caller typed.
    raw_host = (headers.get("Host") or headers.get("host") or orig_host).strip()
    m = _HOST_PORT.fullmatch(raw_host)
    if m is None:
        raise HTTPException(
            400, f"{raw_host!r} is not a bare host or host:port. The Host "
                 f"header decides where this request is sent, so it is held "
                 f"to that shape exactly — credentials, paths and anything "
                 f"else a URL parser would read as a different destination "
                 f"are refused.")
    # An IPv6 literal is bracketed in a Host header and bare
    # everywhere else — in the targets table, in the scope list, and
    # to validate_host. Brackets come off for all of those and go back
    # on for the URL. The old `split(":")[0]` made `[::1]:8080` into
    # `[`, so IPv6 replay never worked; this is the smallest fix that
    # makes it work rather than merely refusing it more politely.
    bare = m.group("host")
    v6 = bare.startswith("[")
    if v6:
        bare = bare[1:-1]
    try:
        hostname = validate_host(bare)
    except InvalidHost as e:
        raise HTTPException(400, str(e)) from e
    port = m.group("port")
    if port is not None and not (0 < int(port) < 65536):
        raise HTTPException(400, f"port {port} is out of range")
    known = (await session.execute(
        select(Target).where(Target.project_id == target.project_id,
                             Target.host == hostname))).scalar_one_or_none()
    if known is None:
        raise HTTPException(
            400,
            f"{hostname!r} is not a target in this engagement. Replay only "
            f"sends to hosts the project already has — otherwise this is an "
            f"open proxy for anyone with an account. Add the host first.")
    # Being a target is not enough. This route puts a real request on the
    # wire, so it is held to the out-of-scope list as well — a host the
    # project acquired before the list said otherwise is still a host
    # nobody may send to.
    await assert_allowed(session, target.project_id, hostname,
                         "replaying to", ip=known.ip_addresses)

    scheme = orig.scheme or "http"
    if not path.startswith("/"):
        path = "/" + path
    # The destination is the target row's own host, read back out of
    # the database — not the string the caller sent, even though the
    # two were just proved equal.
    #
    # Two reasons, and the second is the one that made me change it.
    #
    # It removes the whole class of bug rather than the instance.
    # `known.host` matched `hostname` exactly or this code would not be
    # running, so nothing the caller typed needs to survive as far as
    # the URL. Any future normalisation difference between what gets
    # validated and what gets sent — a case fold, a trailing dot, an
    # IDN form — cannot become a second destination, because there is
    # only one source for it now.
    #
    # And it is a fix a reader can check. The previous version was
    # correct and CodeQL still flagged py/partial-ssrf on it, because
    # `validate_host` is not something taint analysis recognises as a
    # sanitiser. "Correct but unprovable" is a bad place to leave a
    # critical finding: the next person sees an open alert, cannot
    # tell it from a real one, and either dismisses it on faith or
    # re-does this work. A value that comes from a database row needs
    # no argument.
    #
    # The port is the caller's, narrowed to an int by the shape check
    # above, which is the whole of what a port can be.
    #
    # Assembled from components rather than formatted into a string.
    # That is the part that matters: `path` IS caller-controlled and
    # is meant to be — editing it is the point of a replay tool — and
    # an f-string puts it in the same flat piece of text as the
    # authority, where the only thing keeping `//evil.example.net/x`
    # from becoming a destination is that it happens to land after
    # the first slash. Passing host and path as separate arguments
    # means the path cannot reach the authority at all, by
    # construction rather than by argument.
    #
    # Bracketing an IPv6 literal comes free here; httpx does it, and
    # the previous version had to remember to.
    dest = httpx.URL(scheme=scheme, host=known.host,
                     port=int(port) if port is not None else None,
                     raw_path=path.encode())
    # The request is made with the object; `url` is the text form, for
    # storing on the row and putting on the timeline. Deriving the
    # string from the object rather than the other way round means
    # there is no point at which a destination is re-parsed out of
    # text somebody could have shaped.
    url = str(dest)
    # httpx sets these from the body it is given; a stale value from the
    # captured request would contradict what is actually sent.
    for drop in [k for k in headers if k.lower() in
                 ("content-length", "host", "transfer-encoding")]:
        headers.pop(drop)

    import time as _time
    started = _time.perf_counter()
    status = None
    err = None
    resp_text = ""
    try:
        async with httpx.AsyncClient(verify=body.verify_tls,
                                     follow_redirects=body.follow_redirects,
                                     timeout=body.timeout) as client:
            r = await client.request(method, dest, headers=headers,
                                     content=payload or None,
                                     extensions={"sni_hostname": hostname})
            status = r.status_code
            head = f"HTTP/{r.http_version.split('/')[-1]} {r.status_code} {r.reason_phrase}"
            resp_text = (head + "\r\n"
                         + "\r\n".join(f"{k}: {v}" for k, v in r.headers.items())
                         + "\r\n\r\n" + r.text)[:RESP_CAP]
    except Exception as e:                       # noqa: BLE001
        # A replay that fails is a result, not a crash: "this host now
        # refuses the connection" is worth recording.
        err = f"{type(e).__name__}: {e}"[:500]
    elapsed = int((_time.perf_counter() - started) * 1000)

    sent = body.raw[:REQ_CAP]
    # `resp_text` above is the status line, every response header and the
    # body — which means it carries this second's `Date`. Hashed raw, two
    # byte-identical replays a second apart are two different exchanges
    # and the dedup below never fires against a real server. The row still
    # STORES the full text; only the identity is taken over the form with
    # the clock removed. See `stable_response` for the exclusion list and
    # for what choosing it costs.
    xk = exchange_key(method, url, sent, stable_response(resp_text) or None)
    existing = (await session.execute(
        select(WebAddress).where(WebAddress.target_id == known.id,
                                 WebAddress.exchange_hash == xk))).scalar_one_or_none()
    if existing is not None:
        # Byte-identical to something already recorded. Returning it
        # rather than failing on the unique constraint is the useful
        # answer: "you already have this exact exchange".
        return ReplayOut(web=_out((existing, known.host, _code)),
                         status_code=status, elapsed_ms=elapsed, error=err)

    svc = (await session.execute(
        select(Service).where(Service.target_id == known.id,
                              Service.port == orig.port,
                              Service.protocol == "tcp"))).scalar_one_or_none()
    new = WebAddress(
        target_id=known.id, service_id=svc.id if svc else None,
        url=url, url_hash=url_key(url), exchange_hash=xk,
        scheme=scheme, port=orig.port, path=path.split("?")[0][:1024],
        method=method[:12], status_code=status,
        request=sent, response=resp_text or None,
        crawled=status is not None,
        sources=f"replay:{user.username}",
        notes=err or f"replayed by {user.username}",
    )
    session.add(new)
    await session.flush()
    await record(session, known.id, "web",
                 f"request replayed: {method} {url} -> "
                 f"{status if status is not None else err}", actor=user)
    await session.commit()
    await broker.publish("web", action="create", host=known.host, project=code)
    return ReplayOut(web=await _one(session, new.id), status_code=status,
                     elapsed_ms=elapsed, error=err)


@router.get("/stats")
async def web_stats(project: str | None = Query(None),
                    user: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    """Counts for the view header: how much is known, and how much of it
    was actually fetched rather than merely referenced."""
    stmt = _base()
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = (await session.execute(
            select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
        if pr is None or (vis is not None and pr.id not in vis):
            return {"total": 0, "crawled": 0, "hosts": 0, "by_status": {}}
        stmt = stmt.where(Target.project_id == pr.id)
    # Select the three columns by name. Indexing positionally into the
    # wide join is how you end up counting `scheme` as a status code — the
    # offsets move the moment a column is added to the model.
    rows = (await session.execute(
        stmt.with_only_columns(WebAddress.status_code, WebAddress.crawled,
                               Target.host))).all()
    by_status: dict[str, int] = {}
    for status, _crawled, _host in rows:
        key = str(status) if status is not None else "none"
        by_status[key] = by_status.get(key, 0) + 1
    return {
        "total": len(rows),
        "crawled": sum(1 for _s, crawled, _h in rows if crawled),
        "hosts": len({h for _s, _c, h in rows}),
        "by_status": dict(sorted(by_status.items())),
    }


# "Is this a web server" is `webtargets.web_service_clause()` and
# nothing else. The sets moved there first and this module went on
# rebuilding the same `or_()` from them by hand, which is a copy
# however it is spelled -- and it duly drifted. This view's
# applicability check and the Enumerate dialog's list of things to
# crawl now call the one function, so a project whose Web tab appears
# but which offers nothing to crawl is not reachable.


@router.get("/assets", response_model=dict)
async def assets(project: str = Query(...),
                 third_party: bool | None = None,
                 contains: str = Query(
                     "", max_length=assetsearch.MAX_PATTERN,
                     description="narrow to assets whose FILE contains this"),
                 user: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_session)):
    """Everything the project's pages pull in, and what version it is.

    Dependencies, not addresses. The host serving jQuery is usually a
    CDN -- somebody else's infrastructure, barred as a target -- so
    these are recorded against the project rather than as things to
    scan. "Our page loads this" is a fact about our page.

    `version` absent means the URL did not say, which is the case for
    a fingerprinted bundle like `app.a1b2c3.js`. Reported as unknown
    rather than guessed: a wrong version is a finding somebody acts
    on, a missing one is a gap somebody fills.
    """
    # Visibility the same way the rest of this module does it, so a
    # user who cannot see a project cannot read its dependency list
    # either -- it names the client's own hostnames.
    pr = (await session.execute(
        select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
    vis = await visible_project_ids(session, user)
    if pr is None or (vis is not None and pr.id not in vis):
        raise HTTPException(404, "no such project")

    q = select(WebAsset).where(WebAsset.project_id == pr.id)
    if third_party is not None:
        q = q.where(WebAsset.third_party == third_party)
    # Searching the FILE from the table, without the file ever being
    # in the table. The body is the largest text this database holds,
    # so it is matched in SQL and left there: the rows that come back
    # carry no `body` key, exactly as before.
    #
    # A literal, escaped. `ilike` treats % and _ as wildcards, so a
    # search for `100%` or `api_key` would otherwise quietly mean
    # something else -- and `%` alone would match every asset while
    # looking like it had found them.
    if (term := contains.strip()):
        esc = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.where(WebAsset.body.ilike(f"%{esc}%", escape="\\"))
    rows = (await session.execute(
        q.order_by(WebAsset.third_party.desc(), WebAsset.seen_on.desc(),
                   WebAsset.url))).scalars().all()

    # Which pages load what. Sent alongside rather than as a second
    # request, because the two views of this are the same data read
    # from either end -- by library, or by page -- and fetching it
    # twice would let them disagree.
    refs = (await session.execute(
        select(WebAssetRef.asset_id, WebAssetRef.page_url)
        .join(WebAsset, WebAsset.id == WebAssetRef.asset_id)
        .where(WebAsset.project_id == pr.id)
        .order_by(WebAssetRef.page_url))).all()
    by_asset: dict[int, list[str]] = {}
    for aid, page in refs:
        by_asset.setdefault(aid, []).append(page)

    return {
        "refs": [{"asset_id": aid, "page": page} for aid, page in refs],
        "pages": len({p for _, p in refs}),
        "items": [{
            "id": a.id, "url": a.url, "host": a.host, "kind": a.kind,
            "third_party": a.third_party, "name": a.name,
            "version": a.version, "seen_on": a.seen_on,
            "sha256": a.sha256, "bytes": a.bytes,
            "content_type": a.content_type, "status_code": a.status_code,
            "fetched": a.sha256 is not None,
            "first_page": a.first_page,
            "loaded_by": by_asset.get(a.id, []),
        } for a in rows],
        "total": len(rows),
        "third_party": sum(1 for a in rows if a.third_party),
        "versioned": sum(1 for a in rows if a.version),
        "hosts": len({a.host for a in rows if a.host}),
    }


@router.get("/assets/search", response_model=dict)
async def search_assets(project: str = Query(...),
                        q: str = Query("", max_length=assetsearch.MAX_PATTERN),
                        mode: str = Query("text"),
                        third_party: bool | None = None,
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Grep the bundles the project's pages load.

    Two modes: `text` for a literal and `secrets` for the built-in
    patterns, which is what most people came to ask. A caller cannot
    supply a regular expression -- see `app/assetsearch.py`, which
    explains why that is the design and not an omission.

    Only assets whose bytes were actually pulled back can be
    searched, and that is off by default per task (`fetch_assets`),
    because most asset URLs are on third-party hosts the engagement
    does not have. So an empty result has two quite different causes
    and the reply distinguishes them: `searched` is how many bodies
    existed to look at. Zero there means nothing has been fetched,
    not that nothing matched.

    Snippets, never bodies. See app/assetsearch.py.
    """
    pr = (await session.execute(
        select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
    vis = await visible_project_ids(session, user)
    if pr is None or (vis is not None and pr.id not in vis):
        raise HTTPException(404, "no such project")

    want = (mode or "text").strip().lower()
    if want not in ("text", "secrets"):
        raise HTTPException(422, "mode is one of text, secrets")

    pattern = None
    if want != "secrets":
        try:
            pattern = assetsearch.compile_pattern(q, want)
        except assetsearch.BadPattern as e:
            raise HTTPException(422, str(e)) from e

    stmt = (select(WebAsset)
            .where(WebAsset.project_id == pr.id,
                   WebAsset.body.is_not(None)))
    if third_party is not None:
        stmt = stmt.where(WebAsset.third_party == third_party)
    # Narrowed in SQL before anything is read into Python, for the
    # literal case. A project's bundles are the largest text this
    # database holds and most of them will not contain the term.
    if want == "text" and q.strip():
        stmt = stmt.where(WebAsset.body.ilike(f"%{q.strip()}%"))
    rows = (await session.execute(
        stmt.order_by(WebAsset.third_party, WebAsset.url)
        .limit(assetsearch.MAX_ASSETS))).scalars().all()

    out: list[dict] = []
    total = 0
    for a in rows:
        if want == "secrets":
            hits, capped = assetsearch.scan_secrets(a.body or "")
        else:
            hits, capped = assetsearch.search_body(a.body or "", pattern)
        if not hits:
            continue
        total += len(hits)
        out.append({
            "asset_id": a.id, "url": a.url, "host": a.host,
            "third_party": a.third_party, "name": a.name,
            "bytes": a.bytes, "capped": capped,
            "hits": [{"offset": h.offset, "snippet": h.snippet,
                      "rule": h.rule, "confidence": h.confidence}
                     for h in hits],
        })

    # How many bodies there were to look at, which is the difference
    # between "no match" and "nothing has been fetched yet".
    searched = (await session.execute(
        select(func.count()).select_from(WebAsset)
        .where(WebAsset.project_id == pr.id,
               WebAsset.body.is_not(None)))).scalar() or 0
    stored = (await session.execute(
        select(func.count()).select_from(WebAsset)
        .where(WebAsset.project_id == pr.id))).scalar() or 0

    return {"mode": want, "q": q, "assets": out, "matches": total,
            "searched": int(searched), "stored": int(stored),
            "scan_limit": assetsearch.MAX_ASSETS,
            "truncated": len(rows) >= assetsearch.MAX_ASSETS}


#: Largest body this will hand to a browser in one go.
#:
#: Bundles run to megabytes and a minified one is a single line, so a
#: viewer that streams the whole thing is a viewer that locks the tab.
#: Truncated rather than refused: the first two megabytes of a bundle
#: is what somebody reading it wants, and `truncated` says there is
#: more so nobody concludes the file simply ends there.
MAX_BODY_VIEW = 2_000_000


#: What we call ourselves when fetching an asset.
#:
#: The same string the ghost uses by default
#: (ghost/internal/tasks/tasks.go) so a client's logs show one
#: identity for Oddjob whether a request came from an agent or from
#: the server. A project that sets its own `user_agent` overrides it,
#: which is the engagement-attributable case.
DEFAULT_UA = ("OddJob/1.0 (+https://oddjob.dev; "
              "Security Research; Compatible with Chrome/155.0.0.0)")


# ------------------------------------------------- fetch and scan
#
# Registered BEFORE `/assets/{asset_id}` for the reason given below
# it: Starlette matches in registration order, and `{asset_id}`
# would otherwise swallow `/assets/pending` and try to parse
# "pending" as an int.


class SweepOut(BaseModel):
    """What a sweep did. Every number that is not work done is a
    number somebody has to be able to see: `unauthorised` and
    `unattributable` are gaps, not noise, and leaving them to be
    inferred from a difference is how a gap goes unnoticed."""
    considered: int = 0
    fetched: int = 0
    failed: int = 0
    unauthorised: int = 0
    files: int = 0
    scanned: int = 0
    findings: int = 0
    unattributable: int = 0
    #: `Swept` has carried this since endpoint extraction landed and
    #: this schema did not declare it, so Pydantic dropped it on the
    #: way out and the UI has never been able to show it.
    endpoints: int = 0
    #: Cloud resources named in a bundle and added as targets, and
    #: those the scope document does not cover. The second is the
    #: number that matters: a project seeing no new cloud targets
    #: needs to know whether that means none were found or whether
    #: a dozen were found and all belong to somebody else.
    cloud: int = 0
    cloud_refused: int = 0
    #: Assets a bot filter refused rather than the origin, and which
    #: products did it. Inside `failed` too -- the fetch did fail --
    #: but a gap of a different kind, and one that reads as "the
    #: client's servers refuse us" until it is named.
    blocked: int = 0
    blocked_by: dict[str, int] = {}
    notes: list[str] = []
    unfetched: int = 0
    unscanned: int = 0


@router.get("/assets/pending", response_model=dict)
async def assets_pending(pr: Project = Depends(require_project("readonly")),
                         _: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """What is still owed. Changes nothing."""
    out = await assetwork.pending(session, pr.id)
    out["scanners"] = assetscan.available()
    return out


@router.post("/assets/fetch", response_model=SweepOut)
async def assets_fetch(limit: int = 50,
                       pr: Project = Depends(require_project("user")),
                       _: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    """Retrieve assets this project knows of but has never read.

    This SENDS REQUESTS to the client's estate -- one per asset --
    so it is a `user` action and not a readonly one, and it is
    batched rather than unbounded.
    """
    sw = await assetwork.fetch_project(
        session, pr.id, user_agent=(pr.user_agent or DEFAULT_UA),
        limit=max(1, min(int(limit), 500)))
    rest = await assetwork.pending(session, pr.id)
    return SweepOut(**sw.__dict__, **rest)


@router.post("/assets/scan", response_model=SweepOut)
async def assets_scan(limit: int = 200,
                      pr: Project = Depends(require_project("user")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """Run opengrep and detect-secrets over files nothing has read.

    Sends nothing anywhere: the files are already here and both
    scanners run offline. See app/assetscan.py.
    """
    sw = await assetwork.scan_project(
        session, pr.id, limit=max(1, min(int(limit), 2000)))
    rest = await assetwork.pending(session, pr.id)
    return SweepOut(**sw.__dict__, **rest)


# Registered AFTER `/assets/search`, because Starlette matches in
# registration order and `{asset_id}` would otherwise swallow it --
# `/assets/search` would try to parse "search" as an int and 422.
@router.get("/assets/{asset_id}", response_model=dict)
async def asset_detail(asset_id: int,
                       user: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    """One asset, with the file itself.

    Split from the listing deliberately. `/assets` returns every row
    a project has and must never carry `body`: on a project that has
    fetched its bundles that is the largest text in the database, and
    sending it to render a table would be tens of megabytes to show a
    column of filenames.

    So the bytes are fetched when something actually asks to read
    them, which is one asset at a time.
    """
    a = await session.get(WebAsset, asset_id)
    if a is None:
        raise HTTPException(404, "no such asset")
    # Same visibility rule as everything else here: the URL names the
    # client's own hostnames and the body is their code.
    vis = await visible_project_ids(session, user)
    if vis is not None and a.project_id not in vis:
        raise HTTPException(404, "no such asset")

    body = a.body or ""
    return {
        "id": a.id, "url": a.url, "host": a.host, "kind": a.kind,
        "third_party": a.third_party, "name": a.name, "version": a.version,
        "sha256": a.sha256, "bytes": a.bytes, "seen_on": a.seen_on,
        "content_type": a.content_type, "status_code": a.status_code,
        "first_page": a.first_page,
        "loaded_by": [p for (p,) in (await session.execute(
            select(WebAssetRef.page_url)
            .where(WebAssetRef.asset_id == a.id)
            .order_by(WebAssetRef.page_url))).all()],
        # `fetched` is whether the bytes were ever pulled back, which
        # is NOT the same as the body being empty -- a 204 or a
        # zero-length file is a fetched asset with nothing in it, and
        # collapsing the two would report "never fetched" for a file
        # we have definitely seen.
        "fetched": a.sha256 is not None,
        "body": body[:MAX_BODY_VIEW],
        "truncated": len(body) > MAX_BODY_VIEW,
    }


@router.get("/applicable")
async def applicable(project: str | None = Query(None),
                     user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """Whether this project has anything a web view could show.

    The Web entry is hidden until it would have content. An empty view
    under a project with no web services is a dead end that still has to
    be clicked to discover it is empty.
    """
    stmt = (select(func.count()).select_from(Service)
            .join(Target, Target.id == Service.target_id))
    vis = await visible_project_ids(session, user)
    pr = None
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = (await session.execute(
            select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
        if pr is None or (vis is not None and pr.id not in vis):
            return {"applicable": False, "web_services": 0, "web_addresses": 0}
        stmt = stmt.where(Target.project_id == pr.id)

    # `web_service_clause()`, not a second copy of it. These were two
    # spellings of one question and they drifted: this one still said
    # every TLS service is a web server after webtargets stopped
    # saying so, which would have made the Web tab appear for a
    # project whose only "web" services are mail ports -- the exact
    # disagreement webtargets' own comment warns about.
    svc = int((await session.execute(stmt.where(
        Service.state == "open", web_service_clause()))).scalar_one())

    # Scoped the same way, or every project reports the whole estate's
    # count — which is how this read 580 for all nine of them.
    addr_stmt = (select(func.count()).select_from(WebAddress)
                 .join(Target, Target.id == WebAddress.target_id))
    if vis is not None:
        addr_stmt = addr_stmt.where(Target.project_id.in_(vis))
    if project and pr is not None:
        addr_stmt = addr_stmt.where(Target.project_id == pr.id)
    addrs = int((await session.execute(addr_stmt)).scalar_one())

    # Dependencies are counted too, so the nav can show the view only
    # once it would have something in it. An empty view you have to
    # click to discover is empty is worse than no entry -- the same
    # rule the Web entry itself follows.
    asset_stmt = (select(func.count()).select_from(WebAsset))
    if vis is not None:
        asset_stmt = asset_stmt.where(WebAsset.project_id.in_(vis))
    if project and pr is not None:
        asset_stmt = asset_stmt.where(WebAsset.project_id == pr.id)
    assets_n = int((await session.execute(asset_stmt)).scalar_one())

    # Either an http(s) port exists, or something already recorded a URL.
    return {"applicable": bool(svc or addrs),
            "web_services": svc, "web_addresses": addrs,
            "web_assets": assets_n}


@router.post("", response_model=WebAddressOut, status_code=201)
async def add_web(body: WebAddressCreate,
                  user: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Record an address by hand — something found in a browser, say."""
    t = await session.get(Target, body.target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    code = await assert_role_for_target(session, user, body.target_id, "user")
    try:
        u = parse_url(body.url, base_host=t.host)
    except BadUrl as e:
        raise HTTPException(422, str(e)) from e
    method = (body.method or "").upper()[:12]
    dup = (await session.execute(
        select(WebAddress).where(WebAddress.target_id == t.id,
                                 WebAddress.exchange_hash == exchange_key(
                                     method, u.url, None, None)))).scalar_one_or_none()
    if dup is not None:
        dup.sources = merge_sources(dup.sources, user.username)
        await session.commit()
        return (await _one(session, dup.id))
    row = WebAddress(target_id=t.id, url=u.url, url_hash=url_key(u.url),
                     exchange_hash=exchange_key(method, u.url, None, None),
                     scheme=u.scheme, port=u.port,
                     path=u.path, method=method, status_code=body.status_code,
                     title=body.title, notes=body.notes,
                     crawled=bool(body.crawled), sources=user.username)
    session.add(row)
    await session.flush()
    await record(session, t.id, "web", f"web address added: {u.url}", actor=user)
    await session.commit()
    await broker.publish("web", action="create", host=t.host, project=code)
    return await _one(session, row.id)


@router.patch("/{wid}", response_model=WebAddressOut)
async def update_web(wid: int, body: WebAddressUpdate,
                     user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    row = await session.get(WebAddress, wid)
    if row is None:
        raise HTTPException(404, "not found")
    code = await assert_role_for_target(session, user, row.target_id, "user")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(row, k, v)
    await session.commit()
    await broker.publish("web", action="update", project=code)
    return await _one(session, wid)


@router.delete("/{wid}", status_code=204)
async def delete_web(wid: int, user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    row = await session.get(WebAddress, wid)
    if row is None:
        raise HTTPException(404, "not found")
    code = await assert_role_for_target(session, user, row.target_id, "user")
    await session.delete(row)
    await session.commit()
    await broker.publish("web", action="delete", project=code)


async def _one(session: AsyncSession, wid: int) -> WebAddressOut:
    row = (await session.execute(_base().where(WebAddress.id == wid))).first()
    if row is None:
        raise HTTPException(404, "not found")
    return _out(row)


@router.get("/{wid}/packet", response_model=WebPacket)
async def packet(wid: int, user: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_session)):
    """The request and response for one address.

    Its own endpoint rather than a field on the listing: the listing
    returns thousands of rows and these are wanted one at a time.

    Access follows the project, same as everything else. Worth saying
    plainly that what comes back routinely contains session cookies and
    bearer tokens — the viewer warns, and this is not logged.
    """
    row = await session.get(WebAddress, wid)
    if row is None:
        raise HTTPException(404, "not found")
    t = await session.get(Target, row.target_id)
    from ..security import effective_role
    if t is None or await effective_role(session, user, t.project_id) is None:
        raise HTTPException(404, "not found")
    return WebPacket(
        id=row.id, url=row.url, method=row.method, status_code=row.status_code,
        host=t.host, request=row.request, response=row.response,
        truncated=bool(row.truncated), sources=row.sources, notes=row.notes)


# ------------------------------------------------------------ takeovers
# Under /web rather than in a router of its own because this is the
# same question the Web view already answers -- what is reachable on
# this engagement's names -- seen from the DNS side. The UI shows it
# as a third tab beside URLs and Assets.

class TakeoverOut(BaseModel):
    id: int
    hostname: str
    cname: str
    cname_chain: list[str] = Field(default_factory=list)
    provider: str
    claimable: bool
    verdict: str
    evidence: str | None = None
    state: str
    note: str | None = None
    target_id: int | None = None
    seen_at: str | None = None


class TakeoverUpdate(BaseModel):
    """What an operator may change. Everything else is re-derived."""
    state: str | None = Field(None, pattern="^(needs_investigating|true_positive|false_positive)$")
    note: str | None = None


def _takeover_out(t) -> TakeoverOut:
    return TakeoverOut(
        id=t.id, hostname=t.hostname, cname=t.cname,
        cname_chain=[x for x in (t.cname_chain or "").split("\n") if x],
        provider=t.provider, claimable=bool(t.claimable),
        verdict=t.verdict, evidence=t.evidence, state=t.state,
        note=t.note, target_id=t.target_id,
        seen_at=t.seen_at.isoformat() if t.seen_at else None)


@router.get("/takeovers", response_model=Page[TakeoverOut])
async def list_takeovers(
    verdict: str | None = Query(
        None, pattern="^(dangling|fingerprint|live|candidate)$"),
    state: str | None = Query(None),
    q: str | None = Query(None, description="search hostname, cname, provider"),
    sort: str = Query("verdict"), order: str = Query("asc"),
    limit: int = Query(1000, le=10000), offset: int = 0,
    pr: Project = Depends(require_project("readonly")),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Names in this engagement pointing at something unclaimed.

    Read-only and resolves nothing: these rows were decided by
    `app/takeover.py` from CNAMEs the agent already collected. Refresh
    is a separate, explicit call.
    """
    stmt = select(Takeover).where(Takeover.project_id == pr.id)
    if verdict:
        stmt = stmt.where(Takeover.verdict == verdict)
    if state:
        stmt = stmt.where(Takeover.state == state)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Takeover.hostname.ilike(like),
                              Takeover.cname.ilike(like),
                              Takeover.provider.ilike(like)))
    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar_one())

    # `verdict` sorts by strength, not alphabetically. "candidate"
    # sorting above "dangling" would put the rows that prove nothing
    # at the top of a findings table.
    if sort == "verdict":
        # `live` sorts BELOW `candidate`, which is not a typo: it is
        # the only verdict that is a finished answer in the "nothing
        # here" direction, so it is the one row an operator working
        # down this table never needs to reach.
        col = case({"dangling": 0, "fingerprint": 1, "candidate": 2,
                    "live": 3},
                   value=Takeover.verdict, else_=4)
    else:
        col = {"hostname": Takeover.hostname, "provider": Takeover.provider,
               "state": Takeover.state,
               "cname": Takeover.cname}.get(sort, Takeover.hostname)
    stmt = stmt.order_by(col.desc() if order == "desc" else col.asc(),
                         Takeover.hostname.asc())
    rows = (await session.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return Page[TakeoverOut](items=[_takeover_out(t) for t in rows],
                             total=total, limit=limit, offset=offset)


@router.post("/takeovers/refresh", response_model=dict)
async def refresh_takeovers(
    pr: Project = Depends(require_project("user")),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Re-derive the table from the CNAMEs currently on record.

    Sends nothing anywhere -- it reads chains the agent already
    brought back and response bodies already captured. A `user`
    action rather than readonly because it rewrites rows.
    """
    r = await takeover.refresh(session, pr.id)
    await session.commit()
    # `total` is the takeover count. The findings raised are their own
    # number -- adding them in reported eight rows for four.
    return {"counts": r.counts, "total": r.total, "findings_open": r.vulns}


@router.patch("/takeovers/{takeover_id}", response_model=TakeoverOut)
async def update_takeover(
    takeover_id: int, body: TakeoverUpdate,
    pr: Project = Depends(require_project("user")),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Triage one row. Only `state` and `note` -- the rest is DNS."""
    t = (await session.execute(
        select(Takeover).where(Takeover.id == takeover_id,
                               Takeover.project_id == pr.id))).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, "no such takeover")
    if body.state is not None:
        t.state = body.state
    if body.note is not None:
        t.note = body.note or None
    await session.commit()
    await session.refresh(t)
    return _takeover_out(t)
