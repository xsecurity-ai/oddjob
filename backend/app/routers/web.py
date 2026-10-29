"""Web addresses found on http(s) services.

Its own view rather than a column on Services because a web server is not
one thing: a single :443 routinely carries a login page, an admin console,
an API and a forgotten status endpoint, and "what is reachable" is the
question an operator actually has. A banner cannot answer it.
"""
from __future__ import annotations

import base64
import json
import re

# At module scope, not inside the handler: the URL below is built from
# components before the request is made, so the import has to precede
# it, and a deferred import that is now needed in two places is just a
# NameError waiting for whichever one runs first.
#
# `httpx` is still here and no longer sends anything. It is used for
# `httpx.URL`, which assembles a destination from components without
# ever letting a caller-controlled path reach the authority — see the
# note at the call site. The client that used to put replayed traffic
# on the wire from this server is gone; a ghost does that now.
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from .. import assetscan, assetsearch, assetwork, roe, takeover
from ..db import get_session
from ..events import broker
from ..filtering import apply_filters
from ..hosts import InvalidHost, validate_host

#: Same caps the importer uses, so a replayed exchange is stored on the
#: same terms as a captured one.
from ..importers.burphistory import REQ_CAP, RESP_CAP
from ..importers.model import scrub
from ..models import (
    Agent,
    AgentTask,
    FindingSecret,
    Project,
    Service,
    Takeover,
    Target,
    User,
    Vuln,
    WebAddress,
    WebAsset,
    WebAssetRef,
    WebScreenshot,
)
from ..schemas import (
    Page,
    WebAddressCreate,
    WebAddressOut,
    WebAddressUpdate,
    WebPacket,
    WebShot,
)
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

# The dispatcher, imported at module scope. `routers/agents.py` does
# NOT import this file back at module scope -- it reaches `apply_replay`
# with a deferred import inside the one handler that files a result --
# so this direction is the acyclic one and the one a reader can follow
# from the route to the queue.
from .agents import (
    DISPATCH_ABSENT,
    DISPATCH_BUSY,
    DISPATCH_IDLE,
    PRIORITY_INTERACTIVE,
    ROE_STATUS,
    pick_ghost,
)

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
    """An edited request to send again.

    `follow_redirects` used to be here and is gone. The request is now
    sent byte for byte by a ghost over a socket it opened itself, and
    following a redirect means BUILDING A SECOND REQUEST out of the
    first one's parsed fields — which is the one thing this path must
    not do. A 302 is the answer; replay the next hop by hand if that is
    the thing being tested. Unknown fields are ignored rather than
    refused, so a client that still sends it is not broken by this.
    """
    raw: str = Field(description="The full request: request-line, headers, "
                                 "blank line, body")
    timeout: float = Field(20.0, ge=1, le=120)
    verify_tls: bool = Field(
        False,
        description="Off by default: an engagement target routinely has a "
                    "certificate that does not validate, and refusing to "
                    "talk to it is not a useful default for a test tool.")


class ReplayOut(BaseModel):
    """Where a replay went, and — once the ghost reports — what it said.

    The POST answers the first half only. The request leaves from a
    ghost inside the client's estate, not from this server, so at the
    moment the operator presses Send nothing has been sent yet: there
    is a task, addressed to a named agent, waiting for that agent's
    next heartbeat. `GET /api/web/replays/{task_id}` fills in the rest.

    `web` is null until it exists, which is a different thing from an
    empty row and is why it is nullable rather than defaulted.
    """
    #: The agent task carrying it. The handle for the status endpoint.
    task_id: int
    #: Which ghost, by name and id. Part of the result: the egress
    #: address the packet leaves from is the reason this is not sent
    #: from here, so "which one" is evidence and not decoration.
    agent: str
    agent_id: int
    #: idle | busy | absent — see `agents.pick_ghost`.
    dispatch: str
    #: queued | claimed | running | done | failed | cancelled
    state: str = "queued"
    #: One sentence an operator can read without knowing any of the above.
    note: str = ""
    web: WebAddressOut | None = None
    status_code: int | None = None
    elapsed_ms: int = 0
    error: str | None = None


def wire_form(raw: str) -> str:
    """The request as it will go on the wire, from the text in the editor.

    Exactly one transformation, and it is confined to the head: line
    endings become CRLF. Nothing else is touched. Header order, header
    casing, duplicate headers, odd whitespace, a `Content-Length` that
    disagrees with the body and a deliberately malformed request line
    all survive exactly as typed, because every one of those is a thing
    somebody edits a packet in order to test — and a replay tool that
    quietly repairs them is answering a question nobody asked.

    **Why normalise anything at all.** The editor is a browser
    textarea, and a textarea cannot emit a carriage return: everything
    typed into one arrives with bare LF endings. Sending that is not
    "the request as written", it is a different request — RFC 9112
    wants CRLF, and a server lenient about it hides precisely the
    behaviour a header edit is probing. So the one difference the
    editor imposes is undone, and nothing else is.

    **The head only.** A body is bytes. A multipart boundary, a
    protobuf, an upload — none of them are line-oriented, and
    rewriting LF to CRLF inside one corrupts it and changes its
    length. The split is the first blank line, in whichever form it
    appears, because a request pasted from a capture has CRLF and one
    typed here has LF and a file may hold both.
    """
    text = raw or ""
    i_crlf, i_lf = text.find("\r\n\r\n"), text.find("\n\n")
    if i_crlf != -1 and (i_lf == -1 or i_crlf <= i_lf):
        cut, width = i_crlf, 4
    else:
        cut, width = i_lf, 2
    if cut == -1:
        # No blank line: all head, no body. Sent with the terminator
        # added rather than refused — a GET with no body is the common
        # case and the editor's trailing newline is easy to lose.
        head, body = text, ""
    else:
        head, body = text[:cut], text[cut + width:]
    head = "\r\n".join(head.replace("\r\n", "\n").split("\n"))
    return head + "\r\n\r\n" + body


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

    **The packet leaves from a ghost, not from here.** This used to
    open an `httpx.AsyncClient` on the Oddjob server, which was wrong
    for an engagement in three ways at once. The traffic arrived from
    this server's egress address rather than from the one the client
    authorised and allowlisted, so it could be dropped at the border
    or, worse, accepted and attributed to the wrong place. It did not
    appear in `agent_tasks`, so the single question "what did this
    engagement send" had an answer that was missing exactly the
    hand-crafted requests most worth having in it. And it could reach
    only what this server can reach, which on an internal engagement is
    nothing. So the request is handed to a ghost as a task, and this
    route returns a handle rather than a response.

    **Where it may send.** Unchanged, and still checked here before
    anything is queued. The destination host must already be a target
    in the same engagement. Without that this endpoint is an
    authenticated open proxy — anyone with an account could use a ghost
    inside a client's network to reach anything that ghost can reach,
    which is a larger open proxy than the one it was before. Editing
    the path, the verb, the headers and the body is unrestricted, which
    is the part that matters for testing.

    The Host header no longer decides where the bytes go, only what
    they say. The ghost is told the address to dial as a separate
    argument, read out of the target row; the header travels as typed.
    That is a strengthening rather than a change of behaviour — the
    smuggling checks below still refuse a header that could name a
    second destination, because the header is still what nominates the
    target, and a request whose Host no parser can agree on is not one
    this tool should be sending at all.

    **Both gates, both times.** Scope and the rules of engagement are
    checked here, and again by the heartbeat before the task is handed
    over, for the reason `app/roe.py` gives: a task queued inside the
    window and dispatched later runs outside it.
    """
    row = (await session.execute(_base().where(WebAddress.id == web_id))).first()
    if row is None:
        raise HTTPException(404, "no such web address")
    orig, orig_host, _code = row[0], row[1], row[2]
    target = await session.get(Target, orig.target_id)
    code = await assert_role_for_target(session, user, orig.target_id, "user")

    # The body is parsed out and deliberately not used: the bytes that
    # go on the wire are the operator's text, not a reassembly of it.
    # Parsing still happens because the Host header has to be read and
    # validated before anything is queued, and because an unparseable
    # request should be refused here rather than discovered by a
    # process on somebody else's network.
    method, path, headers, _parsed_body = parse_raw_request(body.raw)

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
    # Which port the socket is opened on. The Host header's, when it
    # named one; otherwise the scheme's default, which is what httpx
    # used to supply silently from the same two values.
    #
    # Deliberately NOT `orig.port`, which is what the stored row keeps.
    # The two differ when somebody edits the Host header's port, and
    # they should: the row records the service this exchange belongs
    # under, the dial port records where it actually went.
    dial_port = int(port) if port is not None else (443 if scheme == "https" else 80)

    # The bytes, settled here rather than on the ghost. The agent gets
    # an opaque blob to write to a socket and no opportunity to form an
    # opinion about it -- see `wire_form` for what the one
    # transformation is and why there is exactly one.
    wire = wire_form(body.raw)
    if len(wire.encode("utf-8", "surrogatepass")) > REQ_CAP:
        # Refused rather than truncated. Sending half a request is not
        # a smaller version of the test, it is a different request —
        # and the row would then record bytes that are not the ones
        # that went out.
        raise HTTPException(
            413, f"this request is larger than the {REQ_CAP} byte cap a "
                 f"stored exchange has. Replay records what it sent, and "
                 f"it will not send more than it can record.")

    # The rules of engagement, at queue time, exactly as `create_task`
    # asks them. The heartbeat asks again before handing it over.
    why = roe.refusal(await session.get(Project, target.project_id), "replay")
    if why is not None:
        raise HTTPException(ROE_STATUS,
                            f"a replay on {code} was refused: {why}")

    ghost, where = await pick_ghost(session, target.project_id)
    if ghost is None:
        # A fact about the engagement, reported as one. Not a 500, and
        # NOT quietly sent from this server instead: "nothing is
        # standing inside the client's estate to send this" is the
        # true answer, and the operator is the one who can fix it by
        # deploying a ghost.
        raise HTTPException(
            409,
            f"{code} has no ghost, so there is nothing to send this from. "
            f"A replayed request leaves from an agent inside the client's "
            f"estate — from the egress address the engagement authorised — "
            f"and never from the Oddjob server. Enroll a ghost on this "
            f"project and send it again.")

    args = {
        # What to dial. Read out of the target row, never out of the
        # request text: see the long note above on `known.host`.
        "host": known.host,
        "port": dial_port,
        "scheme": scheme,
        # The name to put in SNI, and in the certificate check when one
        # is asked for. Same source, same reasoning.
        "sni": hostname,
        # `dest_url`, not `url`. `url` is one of `scopegate.TARGET_KEYS`,
        # under which EVERY whitespace- or comma-separated token counts
        # as a host whatever it looks like — so a perfectly ordinary
        # path like `/report/a,b` would offer `b` to the scope gate as
        # a hostname and have the task refused at dispatch on an
        # engagement with an in-scope list. Under any other key the
        # token has to look like a host to be tested, and a whole URL
        # does, so the destination is still checked and the path is
        # not mistaken for one.
        "dest_url": url,
        # Base64, for three reasons that happen to agree. A captured
        # request is bytes and may hold NUL, which Postgres refuses in
        # a text column and which `args` is. It travels through JSON
        # unmangled. And `scopegate.task_hosts` reads every token of
        # every argument looking for hosts — against the raw text it
        # would find the `Referer`, the `Origin` and every domain in a
        # cookie, and refuse the task at dispatch because one of them
        # is not in the engagement. A base64 blob carries no dots and
        # is not mistaken for a hostname.
        "raw_b64": base64.b64encode(
            wire.encode("utf-8", "surrogatepass")).decode("ascii"),
        "timeout_s": max(1, int(body.timeout)),
        "verify_tls": bool(body.verify_tls),
        # How much of the answer to bring back. Sent rather than
        # hardcoded on the agent so the cap has one definition, here,
        # beside the column it has to fit in.
        "resp_cap": RESP_CAP,
        # For the summary line and for `apply_replay`. Parsed here, by
        # the parser that just validated the request, rather than
        # parsed a second time on the agent — two parsers would be free
        # to disagree about which request was sent.
        "method": method,
        "path": path,
        #: The port the row files under, which is the original's. See
        #: `dial_port` above for why it is not always the same number.
        "store_port": orig.port,
    }
    t = AgentTask(agent_id=ghost.id, project_id=target.project_id,
                  requested_by=user.id, kind="replay",
                  args=json.dumps(args),
                  priority=PRIORITY_INTERACTIVE,
                  # No scan file comes back, so no importer reads this.
                  # `apply_replay` does, from `submit_result`.
                  import_as=None, status="queued")
    session.add(t)
    await session.flush()
    note = {
        DISPATCH_IDLE: f"queued on {ghost.name}, which is idle — it will go "
                       f"on that ghost's next heartbeat",
        DISPATCH_BUSY: f"queued on {ghost.name}, which is mid-scan. It is "
                       f"ahead of everything else in that ghost's queue and "
                       f"goes as soon as a slot frees",
        DISPATCH_ABSENT: f"queued on {ghost.name}, which is not currently "
                         f"checking in. It will go when that ghost comes "
                         f"back — nothing else in {code} is beating",
    }[where]
    await record(session, known.id, "web",
                 f"request queued for replay via {ghost.name}: {method} {url}",
                 actor=user)
    await session.commit()
    await broker.publish("agents", action="task", project=code)
    return ReplayOut(task_id=t.id, agent=ghost.name, agent_id=ghost.id,
                     dispatch=where, state="queued", note=note)


@router.get("/replays/{task_id}", response_model=ReplayOut)
async def replay_status(task_id: int,
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Has the ghost sent it yet, and what came back.

    Polled by the dialog. Separate from the POST because the send is no
    longer synchronous with the click — holding the HTTP request open
    until a ghost beats, claims, runs and reports would be a wait of
    unbounded length on a connection that nothing guarantees survives
    it.

    Authorised against the task's own project, not against the web row:
    the task is the thing being read, and a task id is the handle
    somebody could guess.
    """
    t = await session.get(AgentTask, task_id)
    if t is None or t.kind != "replay":
        raise HTTPException(404, "no such replay")
    vis = await visible_project_ids(session, user)
    if vis is not None and t.project_id not in vis:
        raise HTTPException(404, "no such replay")
    pr = await session.get(Project, t.project_id)
    ghost = await session.get(Agent, t.agent_id) if t.agent_id else None
    try:
        res = json.loads(t.import_result) if t.import_result else {}
    except ValueError:
        res = {}
    web = None
    if isinstance(res, dict) and res.get("web_id"):
        web = await _one(session, int(res["web_id"]))
    # Three separate answers, kept apart. `error` on the task is the
    # ghost failing to carry out the instruction; `error` in the filed
    # result is the request going out and the host refusing it, which
    # is a finding; neither being set while the state is still queued
    # is "nobody has tried yet", which is not an error at all.
    err = t.error or (res.get("error") if isinstance(res, dict) else None)
    return ReplayOut(
        task_id=t.id,
        agent=ghost.name if ghost else "(no agent)",
        agent_id=t.agent_id or 0,
        dispatch=DISPATCH_IDLE if t.status in ("claimed", "running", "done")
        else DISPATCH_BUSY,
        state=t.status,
        note=_replay_note(t.status, pr.code if pr else "", ghost),
        web=web,
        status_code=res.get("status_code") if isinstance(res, dict) else None,
        elapsed_ms=int(res.get("elapsed_ms") or 0) if isinstance(res, dict) else 0,
        error=err)


def _replay_note(state: str, code: str, ghost: Agent | None) -> str:
    """One sentence about where a replay has got to."""
    who = ghost.name if ghost else "no ghost"
    return {
        "queued": f"waiting for {who} to check in",
        "claimed": f"handed to {who}",
        "running": f"{who} is sending it",
        "done": f"sent by {who}",
        "failed": f"{who} could not carry it out",
        "cancelled": "cancelled",
    }.get(state, f"{state} on {who}")


async def apply_replay(session: AsyncSession, task: AgentTask,
                       *, actor: str) -> dict:
    """File one ghost's replayed exchange as a new web row.

    Called from `agents.submit_result`, which is the only place a
    result arrives. The row is built here rather than there for the
    same reason the importers are not in that file: this is what a web
    exchange is, and `routers/web.py` is where that is known.

    **Everything that decides WHERE comes from the task, not from the
    ghost.** The agent reports what it received and how long it took,
    and nothing else is read out of its payload. The host is looked up
    again, in the task's own project, so a ghost cannot file an
    exchange against a target in some other engagement — or invent one.
    A ghost is a process on somebody else's network; it is the least
    trusted thing that talks to this server.
    """
    args = json.loads(task.args or "{}")
    out = json.loads(task.output or "{}")
    if not isinstance(args, dict) or not isinstance(out, dict):
        raise ValueError("replay task arguments or output are not an object")

    known = (await session.execute(
        select(Target).where(Target.project_id == task.project_id,
                             Target.host == str(args.get("host") or "")))
    ).scalar_one_or_none()
    if known is None:
        # The target was deleted between queueing and reporting. The
        # exchange stays on the task, which is where the evidence is;
        # there is no row to hang it under.
        raise ValueError("the target this replay was queued against is gone")

    scheme = str(args.get("scheme") or "http")
    url = str(args.get("dest_url") or "")
    method = str(args.get("method") or "GET")
    path = str(args.get("path") or "/")
    store_port = int(args.get("store_port") or 0) or None

    # What was sent: the bytes this server handed the ghost, decoded
    # back. Not anything the ghost echoed — the row is supposed to
    # record what was asked for, and taking it from the reply would
    # record whatever the agent chose to say it sent.
    sent = base64.b64decode(args.get("raw_b64") or "").decode(
        "utf-8", "replace")[:REQ_CAP]

    resp_text = ""
    if out.get("response_b64"):
        resp_text = base64.b64decode(out["response_b64"]).decode(
            "utf-8", "replace")[:RESP_CAP]
    # Postgres refuses NUL in a text column and a response body is
    # arbitrary bytes — a gzip or a PNG decodes to a string holding
    # 0x00. Same substitution the file importers make, for the same
    # reason; see `importers/model.scrub`.
    sent, resp_text = scrub(sent), scrub(resp_text)
    status = out.get("status")
    status = int(status) if isinstance(status, (int, float)) and status else None
    elapsed = int(out.get("elapsed_ms") or 0)
    err = str(out["error"])[:500] if out.get("error") else None

    # Identity over the response with the clock removed, exactly as
    # before: hashed raw, two byte-identical replays a second apart
    # differ only in `Date` and the dedup never fires against a real
    # server. See `stable_response`.
    xk = exchange_key(method, url, sent, stable_response(resp_text) or None)
    existing = (await session.execute(
        select(WebAddress).where(WebAddress.target_id == known.id,
                                 WebAddress.exchange_hash == xk))).scalar_one_or_none()
    if existing is not None:
        # Byte-identical to something already recorded. Pointing at it
        # rather than failing on the unique constraint is the useful
        # answer: "you already have this exact exchange".
        return {"web_id": existing.id, "status_code": status,
                "elapsed_ms": elapsed, "error": err, "duplicate": True}

    who = actor
    if task.requested_by:
        u = await session.get(User, task.requested_by)
        if u is not None:
            who = u.username
    svc = (await session.execute(
        select(Service).where(Service.target_id == known.id,
                              Service.port == store_port,
                              Service.protocol == "tcp"))).scalar_one_or_none()
    new = WebAddress(
        target_id=known.id, service_id=svc.id if svc else None,
        url=url, url_hash=url_key(url), exchange_hash=xk,
        scheme=scheme, port=store_port, path=path.split("?")[0][:1024],
        method=method[:12], status_code=status,
        request=sent, response=resp_text or None,
        crawled=status is not None,
        sources=f"replay:{who}",
        # Which ghost sent it belongs on the row, not only in the task.
        # The egress address is part of the result, and a row that says
        # only "replayed" cannot answer "from where".
        notes=(f"{err} (replayed by {who} via {actor})" if err
               else f"replayed by {who} via {actor}"),
    )
    session.add(new)
    await session.flush()
    pr = await session.get(Project, task.project_id)
    await record(session, known.id, "web",
                 f"request replayed via {actor}: {method} {url} -> "
                 f"{status if status is not None else err}")
    await session.commit()
    if pr is not None:
        await broker.publish("web", action="create", host=known.host,
                             project=pr.code)
    return {"web_id": new.id, "status_code": status, "elapsed_ms": elapsed,
            "error": err, "duplicate": False}


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

    # What each asset is CARRYING. One grouped query rather than a
    # count per row: an estate with four thousand assets would
    # otherwise be four thousand round trips to answer a question
    # that is four columns wide.
    #
    # Severity is counted alongside the total rather than instead of
    # it. "14 findings" and "14 findings, 3 of them critical" are
    # different sentences and only the second tells somebody where
    # to start.
    counts = (await session.execute(
        select(Vuln.asset_id,
               func.count(Vuln.id),
               func.count(Vuln.id).filter(Vuln.severity == "critical"),
               func.count(Vuln.id).filter(Vuln.severity == "high"))
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == pr.id, Vuln.asset_id.is_not(None))
        .group_by(Vuln.asset_id))).all()
    by_id = {aid: (n, c, h) for aid, n, c, h in counts}

    # Secrets separately, because a stored credential is not a
    # severity -- it is the one finding somebody goes looking for
    # by name, and burying it in a total is how it gets missed.
    secret_rows = (await session.execute(
        select(Vuln.asset_id, func.count(FindingSecret.id))
        .join(FindingSecret, FindingSecret.vuln_id == Vuln.id)
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == pr.id, Vuln.asset_id.is_not(None))
        .group_by(Vuln.asset_id))).all()
    secrets_by_id = dict(secret_rows)

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
            # Whether the scanners have READ this file, which is a
            # different question from whether its bytes are here.
            # Without it a zero in the Findings column means both
            # "clean" and "nothing has looked", and on an estate where
            # the sweep has covered a tenth of the files it almost
            # always means the second.
            "scanned": a.scanned_at is not None,
            "first_page": a.first_page,
            "loaded_by": by_asset.get(a.id, []),
            "vulns": by_id.get(a.id, (0, 0, 0))[0],
            "criticals": by_id.get(a.id, (0, 0, 0))[1],
            "highs": by_id.get(a.id, (0, 0, 0))[2],
            "secrets": secrets_by_id.get(a.id, 0),
        } for a in rows],
        "total": len(rows),
        "third_party": sum(1 for a in rows if a.third_party),
        "versioned": sum(1 for a in rows if a.version),
        "findings": sum(n for n, _, _ in by_id.values()),
        "secrets": sum(secrets_by_id.values()),
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
    #: Entropy-only matches dropped from page results — see
    #: assetwork.scan_pages. Visible so "we found nothing" and "we
    #: discarded 118 of them on purpose" are different answers.
    entropy_skipped: int = 0
    notes: list[str] = []
    unfetched: int = 0
    unscanned: int = 0
    #: 2xx response bodies nothing has read yet. A separate backlog
    #: from `unscanned`, which counts asset files, because the two
    #: drain at different rates and one number covering both would
    #: hide whichever is behind.
    unscanned_pages: int = 0


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


@router.post("/pages/scan", response_model=SweepOut)
async def pages_scan(limit: int = 200,
                     pr: Project = Depends(require_project("user")),
                     _: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """Run the same two scanners over 2xx response bodies.

    The asset sweep reads the files a page pulls in. This reads the
    page: an API key inlined in a `<script>` block or a token in a
    JSON response is the same finding as the same string in a
    bundle, and the bundle was the one being read.

    2xx only. A 404 body is the server's error template, identical
    across a thousand URLs, and reading it would file one finding a
    thousand times.

    Sends nothing anywhere: every response here was already
    retrieved, by a ghost, against a target that cleared the scope
    gate at the time. Both scanners run offline.
    """
    sw = await assetwork.scan_pages(
        session, pr.id, limit=max(1, min(int(limit), 2000)))
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
#: Worst first. A `case` rather than ordering on the string, which
#: would put "critical" after "high" alphabetically and quietly
#: invert the one thing this ordering exists to get right.
_SEV_ORDER = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
    value=Vuln.severity, else_=5)


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
        # What the scanners found IN this asset, so the Findings and
        # Secrets counts in the table are something you can open
        # rather than a number you have to go and look for in Vulns.
        #
        # `line` comes from FindingSecret where there is one -- it is
        # the only place the position is kept as a column rather than
        # buried in the description -- and is what lets the viewer
        # scroll to the finding instead of handing back the whole
        # bundle and wishing you luck.
        "findings": [
            {"id": v.id, "title": v.title, "severity": v.severity,
             "scanner": v.scanner, "external_id": v.external_id,
             "status": v.status, "triage": v.triage,
             "line": line, "path": path}
            for v, line, path in (await session.execute(
                select(Vuln, FindingSecret.line, FindingSecret.path)
                .outerjoin(FindingSecret, FindingSecret.vuln_id == Vuln.id)
                .where(Vuln.asset_id == a.id)
                # Worst first: the list is read top-down and the
                # question is always what to look at.
                .order_by(_SEV_ORDER, Vuln.id))).all()
        ],
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
        truncated=bool(row.truncated), sources=row.sources, notes=row.notes,
        screenshot=await _shot_for(session, row))


async def _shot_for(session: AsyncSession, row: WebAddress) -> WebShot | None:
    """The picture of this URL, without its bytes.

    Looked up by `(target, url_hash)` rather than by `web_address_id`,
    and that is deliberate: `web_addresses` is keyed on the EXCHANGE,
    so one URL has a row per capture, and the screenshot is linked to
    whichever of them existed when it was imported. Keying the lookup
    on the id would show the picture on one row of ten and leave the
    other nine looking as though nothing had ever been photographed.

    `image` is never selected here. It is a deferred column and this
    builds the columns by hand, so neither path can drag a megabyte
    into a listing by accident.
    """
    s = (await session.execute(
        select(WebScreenshot).where(
            WebScreenshot.target_id == row.target_id,
            WebScreenshot.url_hash == row.url_hash))).scalar_one_or_none()
    if s is None:
        return None
    return WebShot(
        id=s.id, url=s.url, final_url=s.final_url, status_code=s.status_code,
        title=s.title, width=s.width, height=s.height, bytes=s.bytes or 0,
        sha256=s.sha256, sources=s.sources,
        captured_at=s.captured_at.isoformat() if s.captured_at else None)


@router.get("/screenshots/{shot_id}/image")
async def screenshot_image(shot_id: int,
                           user: User = Depends(get_current_user),
                           session: AsyncSession = Depends(get_session)):
    """The PNG itself.

    Its own endpoint, serving bytes, because that is what an `<img>`
    needs: the browser asks for it with the session cookie it already
    has, and nothing base64-encodes a megabyte into a JSON document
    to get it onto a page.

    Access follows the project, like everything else here. A missing
    row and a row in somebody else's project answer the same 404 --
    an id that is not yours must not be distinguishable from an id
    that does not exist.

    `private` rather than public: this is a picture of a client's
    internal application, and an intermediary caching it is a copy of
    engagement data somewhere nobody chose.

    Deliberately NOT `immutable`, and the max-age is short. A
    re-shoot replaces the bytes under the same id -- that is the
    whole point of keying one picture per URL -- so an id's content
    does change, and telling the browser otherwise would show
    yesterday's page after somebody re-photographed it to see what
    had changed.
    """
    from fastapi.responses import Response
    from sqlalchemy.orm import undefer

    # `undefer`, explicitly. The column is deferred so that no other
    # query drags it in, and on an async session a deferred attribute
    # touched after the fact does not lazily load -- it raises,
    # because the IO would happen outside the await. Asking for it in
    # the query is the only way to have it here.
    s = (await session.execute(
        select(WebScreenshot)
        .options(undefer(WebScreenshot.image))
        .where(WebScreenshot.id == shot_id))).scalar_one_or_none()
    if s is None:
        raise HTTPException(404, "not found")
    t = await session.get(Target, s.target_id)
    from ..security import effective_role
    if t is None or await effective_role(session, user, t.project_id) is None:
        raise HTTPException(404, "not found")
    return Response(
        content=s.image, media_type=s.content_type or "image/png",
        headers={"Cache-Control": "private, max-age=60",
                 # Shown, never downloaded-as-something-else. The
                 # filename is the row id and not the URL: a URL in a
                 # Content-Disposition header is a client's hostname
                 # in a filename on somebody's laptop.
                 "Content-Disposition": f'inline; filename="shot-{s.id}.png"'})


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
    #: How hard it would actually be to take the name: easy, medium,
    #: hard or impossible. See `takeover.difficulty_for`.
    difficulty: str = "medium"
    #: The severity this difficulty implies, so a reader does not have
    #: to hold the mapping in their head to know what a row means.
    severity: str = "low"
    #: What an operator would do, in order. Present whatever the
    #: difficulty -- an impossible row carries the reason and what to
    #: do instead.
    steps: list[str] = Field(default_factory=list)


class TakeoverUpdate(BaseModel):
    """What an operator may change. Everything else is re-derived."""
    state: str | None = Field(None, pattern="^(needs_investigating|true_positive|false_positive)$")
    note: str | None = None


def _takeover_out(t) -> TakeoverOut:
    # Difficulty is DERIVED here, not stored. It is a function of the
    # provider, `claimable` and the verdict -- all of which are on the
    # row -- so a column would be a fourth copy that can disagree with
    # the other three. Deriving also means re-rating a provider in
    # `app/takeover.py` corrects every existing row at once, instead of
    # leaving a migration to backfill judgements made months ago.
    cand = takeover.Candidate(
        hostname=t.hostname, cname=t.cname, chain=[], provider=t.provider,
        claimable=bool(t.claimable), verdict=t.verdict, evidence=t.evidence)
    return TakeoverOut(
        id=t.id, hostname=t.hostname, cname=t.cname,
        cname_chain=[x for x in (t.cname_chain or "").split("\n") if x],
        provider=t.provider, claimable=bool(t.claimable),
        verdict=t.verdict, evidence=t.evidence, state=t.state,
        note=t.note, target_id=t.target_id,
        seen_at=t.seen_at.isoformat() if t.seen_at else None,
        difficulty=takeover.difficulty_for(cand),
        severity=takeover.severity_for(cand),
        steps=takeover.steps_for(cand))


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
