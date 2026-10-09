"""Targets: the asset table, scoped to a project, with live counts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import addresses
from ..automation import tasked_subjects
from ..db import get_session
from ..events import broker
from ..hosts import normalise_host
from ..models import (
    Event,
    Implant,
    Poc,
    Project,
    Service,
    Target,
    TargetAddress,
    User,
    Vuln,
    target_address_links,
)
from ..models import Poc as PocM
from ..models import Service as SvcM
from ..models import Vuln as VulnM
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
    TargetOut,
    TargetUpdate,
    VulnOut,
)
from ..scopegate import assert_allowed, index_for
from ..security import get_current_user, require_project, visible_project_ids
from ..timeline import describe_changes, record
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
_VULN_KEYS = _keys(VulnOut, "host", "project_code")
_POC_KEYS = _keys(PocOut, "host", "project_code")
_IMPLANT_KEYS = _keys(ImplantOut, "host", "project_code")


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


@router.get("/unscanned", response_model=dict)
async def unscanned(pr: Project = Depends(require_project("readonly")),
                    _: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    """Hosts this project has never run nmap or masscan against.

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
            "out_of_scope": refused, "considered": len(rows)}


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
    return TargetDetail(
        target=await _one(session, t.id),
        services=[ServiceOut(**{k: getattr(x, k) for k in _SERVICE_KEYS},
                             host=t.host, project_code=code) for x in svcs],
        vulns=[VulnOut(**{k: getattr(x, k) for k in _VULN_KEYS},
                       host=t.host, project_code=code) for x in vulns],
        pocs=[PocOut(**{k: getattr(x, k) for k in _POC_KEYS},
                     host=t.host, project_code=code) for x in pocs],
        implants=[ImplantOut(**{k: getattr(x, k) for k in _IMPLANT_KEYS},
                             host=t.host, project_code=code) for x in imps],
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
