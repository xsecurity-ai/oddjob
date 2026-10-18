"""Targets: the asset table, scoped to a project, with live counts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import addresses, lifecycle, webtargets
from ..db import get_session
from ..events import broker
from ..hosts import normalise_host
from ..models import (
    Event,
    Implant,
    Poc,
    PortScanCoverage,
    Project,
    Service,
    Target,
    TargetAddress,
    TargetOrigin,
    User,
    Vuln,
    WebAssetRef,
    target_address_links,
)
from ..models import Poc as PocM
from ..models import Service as SvcM
from ..models import Vuln as VulnM
from ..portcoverage import LEVELS, Range, needed, parse_ports
from ..query import apply_search, apply_sort, paginate
from ..schemas import (
    EventCreate,
    EventOut,
    ImplantOut,
    Page,
    PocOut,
    ServiceOut,
    TargetCreate,
    TargetDetail,
    TargetOriginOut,
    TargetOut,
    TargetUpdate,
    VulnOut,
)
from ..scopegate import assert_allowed, index_for
from ..security import get_current_user, require_project, visible_project_ids
from ..tasking import tasked_subjects
from ..timeline import describe_changes, record
from ..webtargets import PROBE_KINDS, WEB_KINDS
from ..weburl import BadUrl
from ..weburl import parse as parse_url
from .projects import resolve_project

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _counts_query():
    v = (select(Vuln.target_id.label("tid"),
                func.count().label("total_vulns"),
                func.sum(case((Vuln.severity == "critical", 1), else_=0)).label("total_criticals"),
                func.sum(case((Vuln.severity == "high", 1), else_=0)).label("total_highs"))
         .group_by(Vuln.target_id).subquery())
    p = (select(Poc.target_id.label("tid"), func.count().label("total_pocs"))
         .group_by(Poc.target_id).subquery())
    s = (select(Service.target_id.label("tid"), func.count().label("total_ports"))
         .where(Service.state == "open").group_by(Service.target_id).subquery())
    stmt = (select(Target, Project.code,
                   func.coalesce(v.c.total_vulns, 0).label("total_vulns"),
                   func.coalesce(v.c.total_criticals, 0).label("total_criticals"),
                   func.coalesce(v.c.total_highs, 0).label("total_highs"),
                   func.coalesce(p.c.total_pocs, 0).label("total_pocs"),
                   func.coalesce(s.c.total_ports, 0).label("total_ports"))
            .join(Project, Project.id == Target.project_id)
            .outerjoin(v, v.c.tid == Target.id)
            .outerjoin(p, p.c.tid == Target.id)
            .outerjoin(s, s.c.tid == Target.id))
    return stmt, v, p, s


# Derived from the schema rather than written out, so a column added to the
# model reaches the client without anyone remembering to extend a tuple here.
# The excluded names are the ones that come from the query, not the ORM row.
def _keys(model, *computed) -> tuple[str, ...]:
    return tuple(k for k in model.model_fields if k not in computed)


_TARGET_KEYS = _keys(TargetOut, "project_code", "total_vulns", "total_criticals",
                     "total_highs", "total_pocs", "total_ports")
_SERVICE_KEYS = _keys(ServiceOut, "host", "project_code")
# The lifecycle three are DERIVED -- worked out from the sweep table
# per request, not columns on the row -- so they are excluded here
# alongside the query-supplied names and filled in below. Leaving them
# in made `getattr(vuln, "lifecycle")` a 500 on every target detail,
# which is `_keys` doing exactly its job: a field added to the schema
# reaches the client without anyone remembering a tuple, and that cuts
# both ways.
_VULN_KEYS = _keys(VulnOut, "host", "project_code",
                   "lifecycle", "lifecycle_why", "last_looked_at")
_POC_KEYS = _keys(PocOut, "host", "project_code")
_IMPLANT_KEYS = _keys(ImplantOut, "host", "project_code")
# `pages` and `pages_total` are read from `web_asset_refs` per request,
# not columns on the row.
_ORIGIN_KEYS = _keys(TargetOriginOut, "pages", "pages_total")


#: Sentinel for "the caller did not send this key". `None` cannot do
#: the job: clearing a target's address is a legitimate PATCH and sends
#: exactly that.
_UNSET = object()


def _address_like(needle):
    """Does any of this target's addresses contain the search text?

    EXISTS rather than a join, because a target with four addresses
    matching the needle must come back once. A join would return it
    four times and the row count would be wrong before anyone noticed
    the duplicates.
    """
    return (select(TargetAddress.id)
            .join(target_address_links,
                  target_address_links.c.address_id == TargetAddress.id)
            .where(target_address_links.c.target_id == Target.id,
                   func.lower(TargetAddress.address).like(needle))
            .exists())


def _first_address():
    """The address to sort on: the first one observed.

    The same one `Target.ip_address` shows, so sorting the column sorts
    by what the column displays. Sorting by "any address" would put a
    row in a different place depending on which of its four the
    database reached first.
    """
    return (select(TargetAddress.address)
            .join(target_address_links,
                  target_address_links.c.address_id == TargetAddress.id)
            .where(target_address_links.c.target_id == Target.id)
            .order_by(target_address_links.c.id).limit(1)
            .scalar_subquery())


def _out(row) -> TargetOut:
    t = row[0]
    return TargetOut(
        **{k: getattr(t, k) for k in _TARGET_KEYS},
        project_code=row[1],
        total_vulns=row[2], total_criticals=row[3], total_highs=row[4],
        total_pocs=row[5], total_ports=row[6],
    )


@router.get("", response_model=Page[TargetOut])
async def list_targets(
    project: str | None = Query(None, description="project code or id; omit for all projects"),
    q: str | None = Query(None, description="full search across host, ip, os, notes, tags"),
    hacked: bool | None = Query(None),
    alive: bool | None = Query(None),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(5000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt, v, p, s = _counts_query()
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    if hacked is not None:
        stmt = stmt.where(Target.hacked == hacked)
    if alive is not None:
        stmt = stmt.where(Target.alive == alive)
    stmt = apply_search(stmt, q, [Target.host, Target.os,
                                  Target.notes, Target.tags, Project.code],
                        extra=_address_like)
    stmt = apply_sort(stmt, sort, order, {
        "host": Target.host, "ip_address": _first_address(),
        "ip_addresses": _first_address(), "alive": Target.alive,
        "hacked": Target.hacked, "os": Target.os, "updated_at": Target.updated_at,
        "project_code": Project.code,
        "total_vulns": func.coalesce(v.c.total_vulns, 0),
        "total_criticals": func.coalesce(v.c.total_criticals, 0),
        "total_highs": func.coalesce(v.c.total_highs, 0),
        "total_pocs": func.coalesce(p.c.total_pocs, 0),
        "total_ports": func.coalesce(s.c.total_ports, 0),
    })
    rows, total = await paginate(session, stmt, limit, offset)
    return Page[TargetOut](items=[_out(r) for r in rows], total=total,
                           limit=limit, offset=offset)


async def _one(session: AsyncSession, target_id: int) -> TargetOut:
    """Build a TargetOut for one target.

    Endpoint functions must not be called internally: they carry Depends()
    defaults, so a positional call silently binds the wrong argument -- that
    is how `session` ended up on an ACL parameter and surfaced as
    "'Depends' object has no attribute 'execute'".
    """
    stmt, *_ = _counts_query()
    return _out((await session.execute(stmt.where(Target.id == target_id))).first())


async def _find(session: AsyncSession, project: str, host: str) -> Target:
    pr = await resolve_project(session, project)
    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == normalise_host(host)))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, f"no target {host!r} in project {pr.code}")
    return t


#: How many pages one origin lists before it stops and says how many
#: there are. One bundle is loaded by hundreds of pages; a row that
#: printed all of them would be the whole panel.
_ORIGIN_PAGES = 8


async def _origins_for(session: AsyncSession,
                       target_ids: list[int]) -> dict[int, list[TargetOriginOut]]:
    """Where each of these targets came from. -> {target_id: [origin]}

    A target missing from the result has NO recorded origin, which is
    not the same as having come from nowhere: provenance is written
    only by whatever discovered the target, and only the asset sweep
    does so. Callers must keep the two apart — the UI says "not
    recorded" for the first and would be lying if it said "none".

    Two queries whatever the number of targets. The pages are read
    live from `web_asset_refs` rather than snapshotted, because a page
    added to the crawl later genuinely is another site this resource
    was found on.
    """
    if not target_ids:
        return {}
    rows = (await session.execute(
        select(TargetOrigin)
        .where(TargetOrigin.target_id.in_(target_ids))
        .order_by(TargetOrigin.target_id, TargetOrigin.id))).scalars().all()
    if not rows:
        return {}

    asset_ids = {o.asset_id for o in rows if o.asset_id is not None}
    pages: dict[int, list[str]] = {}
    if asset_ids:
        for aid, page in (await session.execute(
                select(WebAssetRef.asset_id, WebAssetRef.page_url)
                .where(WebAssetRef.asset_id.in_(asset_ids))
                .order_by(WebAssetRef.asset_id, WebAssetRef.id))).all():
            pages.setdefault(aid, []).append(page)

    out: dict[int, list[TargetOriginOut]] = {}
    for o in rows:
        seen = pages.get(o.asset_id, []) if o.asset_id is not None else []
        # `first_page` belongs in the list too — it is a page this was
        # found on, and on an asset nothing has re-crawled it is the
        # only one. Deduplicated, order preserved.
        full: list[str] = []
        for u in ([o.page_url] if o.page_url else []) + seen:
            if u and u not in full:
                full.append(u)
        out.setdefault(o.target_id, []).append(TargetOriginOut(
            **{k: getattr(o, k) for k in _ORIGIN_KEYS},
            pages=full[:_ORIGIN_PAGES], pages_total=len(full)))
    return out


@router.get("/origins", response_model=dict[int, list[TargetOriginOut]])
async def target_origins(
    project: str | None = Query(None, description="project code or id; "
                                                  "omit for every visible project"),
    limit: int = Query(5000, ge=0, le=50000),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Where this project's targets came from, keyed by target id.

    One request for a whole page of rows, because the Targets view
    renders thousands and a fetch per row is a fetch per row.

    **A target absent from the mapping has no recorded origin.** That
    means nothing wrote down where it came from — a hand-made target,
    a scan import, or any row created before provenance was kept. It
    does NOT mean the target was found nowhere, and a client that
    renders it that way is wrong.
    """
    stmt = select(Target.id)
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    # Only the targets that HAVE one, so the cap is spent on rows that
    # say something rather than on the thousands that do not.
    stmt = stmt.where(select(TargetOrigin.id).where(
        TargetOrigin.target_id == Target.id).exists()).limit(limit)
    ids = [i for (i,) in (await session.execute(stmt)).all()]
    return await _origins_for(session, ids)


@router.get("/unscanned", response_model=dict)
async def unscanned(technique: str | None = None,
                    ports: str = "",
                    kitchen_sink: bool = False,
                    pr: Project = Depends(require_project("readonly")),
                    _: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    """Hosts this project has never run nmap or masscan against.

    `kitchen_sink` asks a different question: every host the project
    knows, whether or not anything has run against it. It is the same
    gate, the same mobile exclusion and the same ordering -- only the
    task-history filter is dropped -- so that "scan everything" and
    "scan what is unscanned" cannot disagree about what the estate is.
    It ignores `technique` and `ports`, because a coverage gap is not
    what is being asked about.

    With `technique` (syn | connect | version) the question becomes a
    sharper one: not "has anything ever been run here" but "has THIS
    been run, on these ports". A host swept with `-sS` is finished as
    far as the default answer is concerned and still owes a `-sT`,
    because the two learn different things — see app.portcoverage for
    the ordering and why it is a total one.

    `ports` is an nmap-style spec and defaults to the top ports a
    quick scan covers. The reply then carries, per host, exactly which
    ports still need the technique, so the caller queues the gap
    rather than the whole range again.

    **Never TASKED, not "has no ports."** The two are different and the
    difference is the point:

      * a host nmap scanned that answered on nothing has no services,
        so "no ports recorded" would offer it again on every pass --
        for ever, at a client, for a question already answered
      * a host whose services came from an imported report has ports
        and has never been scanned by us at all

    So this reads task history. `tasked_subjects` is the same function
    the standing orders use, deliberately: two implementations of "has
    this been done" would disagree, and the disagreement would be
    invisible -- one quietly re-scanning what the other considered
    finished.

    Mobile applications are left out. There is no address to send a
    packet to, and offering them inflates a count somebody is about to
    act on.

    Out-of-scope hosts are counted but not offered. The queue path
    gates every host anyway, so including them would mean a dialog
    that says 40 and queues 31 with no explanation.
    """
    rows = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.kind != "mobile")
        .order_by(Target.host))).scalars().unique().all()

    if kitchen_sink:
        # Every host, gated. Checked first: asked for everything, a
        # technique filter would quietly return a subset and the
        # caller would have no way to see that it had.
        never = list(rows)
    elif technique:
        return await _unscanned_by_technique(session, pr, rows, technique, ports)
    else:
        done = await tasked_subjects(session, pr.id, ("nmap", "masscan"))
        never = [t for t in rows
                 if ("nmap", t.host.lower()) not in done
                 and ("masscan", t.host.lower()) not in done]

    idx = await index_for(session, pr.id)
    hosts, refused = [], 0
    for t in never:
        if idx.check(t.host, ip=[a.address for a in t.addresses]).allowed:
            hosts.append(t.host)
        else:
            refused += 1

    return {"hosts": hosts, "count": len(hosts),
            "out_of_scope": refused, "considered": len(rows),
            "kitchen_sink": bool(kitchen_sink)}


@router.get("/web-pending", response_model=dict)
async def web_pending(mode: str = "both",
                      kitchen_sink: bool = False,
                      pr: Project = Depends(require_project("readonly")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """URLs that still owe web discovery, and which kinds they owe.

    A URL rather than a host, because that is the unit both tools
    take: one host can serve several sites and neither katana nor
    gobuster can be pointed at a bare hostname.

    Two sources, merged and normalised identically -- URLs already
    recorded against the project, and URLs derived from open web
    services. The derived half is the point: a target with 443 open
    and nothing recorded has never been looked at, and is the one most
    worth looking at.

    **Owed, not scanned/unscanned.** katana follows what the
    application links to; gobuster asks for paths nothing links to.
    Neither subsumes the other, so a URL crawled with katana still
    owes a gobuster run under `mode=both`, and the reply says which
    kinds are outstanding per URL rather than collapsing it to a flag.

    `kitchen_sink` returns every URL owing every kind the mode names,
    which is a deliberate re-run of work already done.

    Out-of-scope URLs are counted but not offered, for the same reason
    `/unscanned` does it: a dialog that says 40 and queues 31 with no
    explanation is worse than one that says 31.
    """
    want = (mode or "").strip().lower()
    if want not in WEB_KINDS:
        raise HTTPException(
            422, f"mode is one of {', '.join(sorted(WEB_KINDS))}")

    pending = await webtargets.owed(session, pr.id, want,
                                    kitchen_sink=kitchen_sink)
    idx = await index_for(session, pr.id)
    urls: list[dict] = []
    refused = 0
    for url in sorted(pending):
        # Gated on the HOST the URL belongs to. The scope document
        # names hosts and addresses, not URLs, and asking it about a
        # URL string would refuse everything.
        try:
            host = parse_url(url).host
        except BadUrl:
            refused += 1
            continue
        if idx.check(host).allowed:
            urls.append({"url": url, "host": host, "owes": pending[url]})
        else:
            refused += 1

    by_kind: dict[str, int] = {}
    for row in urls:
        for k in row["owes"]:
            by_kind[k] = by_kind.get(k, 0) + 1

    # How much of this has been done before. Zero by construction
    # without `kitchen_sink`, so it is only worth a query with it --
    # and with it, it is the number that matters: the count alone is
    # identical either way, which makes ticking the box look free
    # when it is a repeat of every crawl in the project.
    #
    # One real sweep: 1,230 URLs offered, 1,230 of them already
    # crawled, queued four times in 45 hours. Each of those is real
    # traffic to a client re-asking a question that had an answer.
    repeats = 0
    if kitchen_sink:
        done = await tasked_subjects(session, pr.id, WEB_KINDS[want])
        repeats = sum(1 for r in urls for k in r["owes"]
                      if (k, r["url"].lower()) in done)

    return {"urls": urls, "count": len(urls), "out_of_scope": refused,
            "considered": len(pending), "mode": want,
            "tasks": sum(len(r["owes"]) for r in urls),
            "by_kind": by_kind, "kitchen_sink": bool(kitchen_sink),
            "repeats": repeats}


@router.get("/probe-pending", response_model=dict)
async def probe_pending(tool: str = "httpx",
                        kitchen_sink: bool = False,
                        pr: Project = Depends(require_project("readonly")),
                        _: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Subjects `httpx` or `nuclei` has not been pointed at yet.

    Both tools have been runnable, importable and storable since
    long before this endpoint, and neither had ever run on any
    install: the frontend listed them in a constant nothing read, so
    there was no way to launch one short of calling the API by hand.

    httpx takes a HOST -- discovering what answers on the web ports
    is the job -- and nuclei takes a URL already known to be there.
    `webtargets.PROBE_KINDS` is where that distinction lives.

    Out-of-scope subjects are counted and not offered, as everywhere
    else: a dialog that says 40 and queues 31 with no explanation is
    worse than one that says 31.
    """
    want = (tool or "").strip().lower()
    if want not in PROBE_KINDS:
        raise HTTPException(
            422, f"tool is one of {', '.join(sorted(PROBE_KINDS))}")

    pending = await webtargets.probe_owed(session, pr.id, want,
                                          kitchen_sink=kitchen_sink)
    idx = await index_for(session, pr.id)
    subjects: list[str] = []
    refused = 0
    for s in pending:
        # Gated on the HOST either way. The scope document names
        # hosts and addresses, never URLs, so a URL subject has to be
        # reduced before it is asked about.
        host = s
        if PROBE_KINDS[want] == "url":
            try:
                host = parse_url(s).host
            except BadUrl:
                refused += 1
                continue
        if idx.check(host).allowed:
            subjects.append(s)
        else:
            refused += 1

    repeats = 0
    if kitchen_sink:
        done = await tasked_subjects(session, pr.id, (want,))
        repeats = sum(1 for s in subjects if (want, s.lower()) in done)

    return {"tool": want, "subjects": subjects, "count": len(subjects),
            "out_of_scope": refused, "considered": len(pending),
            "takes": PROBE_KINDS[want],
            "kitchen_sink": bool(kitchen_sink), "repeats": repeats}


#: What a technique-aware ask covers when the caller names no ports.
#: nmap's `-F` list is 100 ports chosen by frequency and is not a
#: contiguous range, so a default of "1-1024" would claim coverage of
#: ports -F never touches. The top 20 by frequency, written out,
#: is defensible as a default and small enough to be quick.
DEFAULT_PORTS = ("21,22,23,25,53,80,110,111,135,139,143,443,445,"
                 "993,995,1723,3306,3389,5900,8080")


async def _unscanned_by_technique(session: AsyncSession, pr: Project,
                                  rows: list[Target], technique: str,
                                  ports: str) -> dict:
    """Which hosts still owe `technique` on which ports.

    Split out rather than branching inside `unscanned` because the two
    answer genuinely different questions and share only the target
    list: one reads task history, this reads what the scanners
    reported they did.
    """
    if technique not in LEVELS:
        raise HTTPException(
            400, f"unknown technique {technique!r}; "
                 f"expected one of {', '.join(sorted(LEVELS))}")
    want_ports = [p for lo, hi in parse_ports(ports or DEFAULT_PORTS)
                  for p in range(lo, hi + 1)]
    if not want_ports:
        raise HTTPException(400, f"no usable ports in {ports!r}")

    # One query for the whole project rather than one per host: a
    # project with four thousand targets would otherwise make four
    # thousand round trips to answer a dialog.
    by_target: dict[int, list[Range]] = {}
    cov = (await session.execute(
        select(PortScanCoverage).where(
            PortScanCoverage.target_id.in_([t.id for t in rows]),
            PortScanCoverage.protocol == "tcp"))).scalars().all()
    for c in cov:
        by_target.setdefault(c.target_id, []).append(
            Range(c.technique, c.port_lo, c.port_hi))

    idx = await index_for(session, pr.id)
    hosts: list[dict] = []
    refused = 0
    for t in rows:
        gap = needed(want_ports, by_target.get(t.id, []), technique)
        if not gap:
            continue
        if not idx.check(t.host, ip=[a.address for a in t.addresses]).allowed:
            refused += 1
            continue
        hosts.append({"host": t.host, "ports": _spec(gap), "count": len(gap)})

    # Not "detail": that is the key FastAPI puts an error message in,
    # so a client could not tell a refusal from a result.
    return {"technique": technique, "hosts": [h["host"] for h in hosts],
            "gaps": hosts, "count": len(hosts),
            "out_of_scope": refused, "considered": len(rows),
            "ports_asked": len(want_ports)}


def _spec(ports: list[int]) -> str:
    """Ports back into an nmap spec, collapsing runs.

    A gap of 998 individual ports is a command line nmap will refuse
    on length alone, and "1-1024" is the same request in eleven
    characters.
    """
    out: list[str] = []
    for p in sorted(ports):
        if out and p == _hi(out[-1]) + 1:
            out[-1] = f"{_lo(out[-1])}-{p}"
        else:
            out.append(str(p))
    return ",".join(out)


def _lo(part: str) -> int:
    return int(part.split("-")[0])


def _hi(part: str) -> int:
    return int(part.split("-")[-1])


@router.get("/{project}/{host}", response_model=TargetOut)
async def get_target(project: str, host: str,
                     _: Project = Depends(require_project("readonly")),
                     session: AsyncSession = Depends(get_session)):
    t = await _find(session, project, host)
    return await _one(session, t.id)


@router.get("/{project}/{host}/detail", response_model=TargetDetail)
async def target_detail(project: str, host: str,
                        _: Project = Depends(require_project("readonly")),
                        session: AsyncSession = Depends(get_session)):
    """Target plus its services, vulns and PoCs — one request for the modal."""
    t = await _find(session, project, host)
    svcs = (await session.execute(
        select(SvcM).where(SvcM.target_id == t.id)
        .order_by(SvcM.protocol, SvcM.port))).scalars().all()
    # Worst-first, so the modal opens on what matters. Severity is a string in
    # the column, so order by an explicit rank rather than alphabetically --
    # "critical" < "high" < "info" < "low" alphabetically is nonsense.
    rank = case({s: i for i, s in enumerate(
        ("critical", "high", "medium", "low", "info"))}, value=VulnM.severity, else_=9)
    vulns = (await session.execute(
        select(VulnM).where(VulnM.target_id == t.id)
        .order_by(rank, VulnM.title))).scalars().all()
    pocs = (await session.execute(
        select(PocM).where(PocM.target_id == t.id).order_by(PocM.title))).scalars().all()
    imps = (await session.execute(
        select(Implant).where(Implant.target_id == t.id)
        .order_by(Implant.last_seen.desc().nullslast(),
                  Implant.framework))).scalars().all()

    code = (await session.get(Project, t.project_id)).code
    # One query for this host's sweeps, then a verdict per finding.
    # The target page is where "is this still there" gets asked most
    # directly, so it is worth the one round trip.
    sweeps = await lifecycle.sweeps_for_targets(session, [t.id])

    def _vuln(x):
        vd = lifecycle.verdict_for(x, sweeps)
        return VulnOut(**{k: getattr(x, k) for k in _VULN_KEYS},
                       host=t.host, project_code=code,
                       lifecycle=vd.state, lifecycle_why=vd.why,
                       last_looked_at=vd.last_looked)

    return TargetDetail(
        target=await _one(session, t.id),
        services=[ServiceOut(**{k: getattr(x, k) for k in _SERVICE_KEYS},
                             host=t.host, project_code=code) for x in svcs],
        vulns=[_vuln(x) for x in vulns],
        pocs=[PocOut(**{k: getattr(x, k) for k in _POC_KEYS},
                     host=t.host, project_code=code) for x in pocs],
        implants=[ImplantOut(**{k: getattr(x, k) for k in _IMPLANT_KEYS},
                             host=t.host, project_code=code) for x in imps],
        # Empty means nothing recorded where this target came from,
        # not that it came from nowhere. The modal says which.
        origins=(await _origins_for(session, [t.id])).get(t.id, []),
    )


@router.post("", response_model=TargetOut, status_code=201)
async def create_target(body: TargetCreate, project: str = Query(..., description="project code"),
                        pr: Project = Depends(require_project("user")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    dup = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == body.host))).scalar_one_or_none()
    if dup:
        raise HTTPException(409, f"target {body.host!r} already in project {pr.code}")
    # Every address, not just the first: a host whose second address is
    # on the out-of-scope list is an out-of-scope host, and gating on
    # one of four would be a gate with three holes in it.
    await assert_allowed(session, pr.id, body.host,
                         f"adding {body.host!r} to {pr.code}",
                         ip=body.ip_addresses)
    fields = body.model_dump(exclude={"ip_address", "ip_addresses"})
    t = Target(project_id=pr.id, **fields)
    session.add(t)
    await session.flush()
    await addresses.attach(session, t, body.ip_addresses)
    await record(session, t.id, "discovered", f"added to {pr.code} by hand",
                 detail=t.notes or None, actor=user)
    await session.commit()
    await broker.publish("targets", action="create", host=t.host, project=pr.code)
    return await _one(session, t.id)


@router.patch("/{project}/{host}", response_model=TargetOut)
async def update_target(project: str, host: str, body: TargetUpdate,
                        _: Project = Depends(require_project("user")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    t = await _find(session, project, host)
    patch = body.model_dump(exclude_unset=True)
    # Addresses are not a column and `Target.ip_address` is read-only,
    # so they come out of the patch before the setattr loop and go
    # through `addresses.replace`. Folded into one key for the diff
    # below, because "ip_addresses: 203.0.113.9 → 203.0.113.9,
    # 203.0.113.10" is the change somebody wants to read; two near-
    # identical lines because the caller happened to send both spellings
    # is not.
    wants = patch.pop("ip_addresses", None)
    one = patch.pop("ip_address", _UNSET)
    if wants is None and one is not _UNSET:
        wants = [one] if one else []
    before = {k: getattr(t, k) for k in patch}
    for k, v in patch.items():
        setattr(t, k, v)
    if wants is not None:
        was = list(t.ip_addresses)
        added, removed, invalid = await addresses.replace(session, t, wants)
        if added or removed:
            patch["ip_addresses"] = ", ".join(t.ip_addresses) or None
            before["ip_addresses"] = ", ".join(was) or None
        if invalid:
            # Said out loud rather than silently dropped. "I pasted four
            # addresses and three arrived" is the kind of thing that is
            # only noticed weeks later, if at all.
            await record(session, t.id, "note",
                         "not recorded, not an IP address: "
                         + ", ".join(invalid), actor=user)

    # A note is the thing people most want to find later, so it gets its own
    # entry carrying the text rather than being flattened into a field diff.
    if "notes" in patch and patch["notes"] != before.get("notes"):
        body_text = (patch["notes"] or "").strip()
        await record(session, t.id, "note",
                     body_text.splitlines()[0] if body_text else "note cleared",
                     detail=body_text or None, actor=user)
    if "hacked" in patch and patch["hacked"] != before.get("hacked"):
        await record(session, t.id, "status",
                     "marked as compromised" if patch["hacked"]
                     else "no longer marked as compromised", actor=user)
    if (diff := describe_changes(before, patch,
                                 tuple(k for k in patch if k not in ("notes", "hacked")))):
        await record(session, t.id, "change", diff, actor=user)
    await session.commit()
    await broker.publish("targets", action="update", host=t.host, project=project)
    return await _one(session, t.id)


@router.delete("/{project}/{host}", status_code=204)
async def delete_target(project: str, host: str,
                        _: Project = Depends(require_project("user")),
                        session: AsyncSession = Depends(get_session)):
    t = await _find(session, project, host)
    h = t.host
    await session.delete(t)          # cascades to services/vulns/pocs
    await session.commit()
    await broker.publish("targets", action="delete", host=h, project=project)


# ---------------------------------------------------------------- timeline
@router.get("/{project}/{host}/timeline", response_model=Page[EventOut])
async def target_timeline(project: str, host: str,
                          kind: str | None = Query(None, description="filter to one kind"),
                          limit: int = Query(200, le=1000), offset: int = 0,
                          _: Project = Depends(require_project("readonly")),
                          session: AsyncSession = Depends(get_session)):
    """Everything found and done to this target, newest first.

    Includes notes, field edits, scan results, NSE output, services appearing
    or changing, findings and PoCs — the engagement narrative for one asset.
    """
    t = await _find(session, project, host)
    stmt = select(Event).where(Event.target_id == t.id)
    if kind:
        stmt = stmt.where(Event.kind == kind)
    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar_one())
    rows = (await session.execute(
        stmt.order_by(Event.at.desc(), Event.id.desc())
            .limit(limit).offset(offset))).scalars().all()
    return Page[EventOut](items=[EventOut.model_validate(r) for r in rows],
                          total=total, limit=limit, offset=offset)


@router.post("/{project}/{host}/timeline", response_model=EventOut, status_code=201)
async def add_timeline_note(project: str, host: str, body: EventCreate,
                            _: Project = Depends(require_project("user")),
                            user: User = Depends(get_current_user),
                            session: AsyncSession = Depends(get_session)):
    """Add an entry by hand — a note, or a record of something done offline.

    Only `note` and `scan` may be written this way. The rest are produced by
    the code that actually performed the change, and letting them be forged
    by hand would make the timeline unreliable as a record of what happened.
    """
    if body.kind not in ("note", "scan"):
        raise HTTPException(
            422, f"{body.kind!r} entries are recorded automatically; "
                 f"you can add 'note' or 'scan'")
    t = await _find(session, project, host)
    ev = await record(session, t.id, body.kind, body.summary,
                      detail=body.detail, actor=user, source=body.source)
    await session.commit()
    await session.refresh(ev)
    await broker.publish("targets", action="timeline", host=t.host, project=project)
    return EventOut.model_validate(ev)
