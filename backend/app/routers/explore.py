"""Explore a port or a service name across the estate.

Answers "what does 443 actually look like here" without making the caller
eyeball 1,300 grid rows: how many hosts expose it, what is actually listening
on it, which products and banners appear, and what has been found on it.

Scoped by the same per-project ACL as everything else -- an explore that
reached across projects the caller cannot see would be a neat way to
enumerate the estate sideways.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Project, Service, Target, User, Vuln
from ..schemas import ExploreOut, NameCount, ExploreHost
from ..security import get_current_user, visible_project_ids
from .projects import resolve_project

router = APIRouter(prefix="/api/explore", tags=["explore"])

SEV_ORDER = ("critical", "high", "medium", "low", "info")


async def _scope(session: AsyncSession, user: User, project: str | None):
    """-> list of project ids to restrict to, or None for 'everything visible'."""
    vis = await visible_project_ids(session, user)
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        return [pr.id]
    return vis


def _top(rows, limit=25) -> list[NameCount]:
    return [NameCount(name=str(n) if n is not None else "(none)", count=int(c))
            for n, c in rows][:limit]


@router.get("", response_model=ExploreOut)
async def explore(
    dimension: str = Query(..., pattern="^(port|service)$"),
    value: str = Query(..., description="a port number, or a service name"),
    project: str | None = Query(None),
    protocol: str | None = Query(None, description="narrow a port to tcp or udp"),
    limit_hosts: int = Query(3000, ge=1, le=20000),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    pids = await _scope(session, user, project)

    base = (select(Service)
            .join(Target, Target.id == Service.target_id))
    if pids is not None:
        base = base.where(Target.project_id.in_(pids))

    if dimension == "port":
        try:
            port = int(value)
        except ValueError:
            raise HTTPException(422, f"{value!r} is not a port number")
        base = base.where(Service.port == port)
        if protocol:
            base = base.where(Service.protocol == protocol.lower())
    else:
        # Service names are stored lowercase-ish from scanners but not
        # guaranteed, so compare case-insensitively.
        base = base.where(func.lower(Service.name) == value.strip().lower())

    sub = base.subquery()

    async def scalar(stmt):
        return int((await session.execute(stmt)).scalar_one() or 0)

    total = await scalar(select(func.count()).select_from(sub))
    if total == 0:
        raise HTTPException(404, f"no {dimension} {value!r} in scope")

    hosts = await scalar(select(func.count(func.distinct(sub.c.target_id))).select_from(sub))
    states = dict((await session.execute(
        select(sub.c.state, func.count()).group_by(sub.c.state))).all())

    # Distribution columns: what is listening, from whom, saying what.
    svc_names = (await session.execute(
        select(sub.c.name, func.count().label("n")).group_by(sub.c.name)
        .order_by(func.count().desc()))).all()
    ports = (await session.execute(
        select(sub.c.port, sub.c.protocol, func.count().label("n"))
        .group_by(sub.c.port, sub.c.protocol).order_by(func.count().desc()))).all()
    products = (await session.execute(
        select(sub.c.product, func.count().label("n")).where(sub.c.product.is_not(None))
        .group_by(sub.c.product).order_by(func.count().desc()))).all()
    banners = (await session.execute(
        select(sub.c.banner, func.count().label("n")).where(sub.c.banner.is_not(None))
        .group_by(sub.c.banner).order_by(func.count().desc()))).all()

    # Findings recorded against the same port on the same target. Vulns carry
    # a port but not a service name, so for the service dimension we match
    # through the (target, port) pairs this service actually occupies.
    pairs = select(sub.c.target_id, sub.c.port).distinct().subquery()
    vq = (select(Vuln.severity, func.count())
          .join(pairs, (pairs.c.target_id == Vuln.target_id) & (pairs.c.port == Vuln.port))
          .group_by(Vuln.severity))
    by_sev = {s: 0 for s in SEV_ORDER}
    for sev, n in (await session.execute(vq)).all():
        if sev in by_sev:
            by_sev[sev] = int(n)

    # Per-host rows, worst-first so the interesting ones are on screen.
    vuln_counts = (
        select(Vuln.target_id.label("tid"),
               func.count().label("n"),
               func.sum(case((Vuln.severity == "critical", 1), else_=0)).label("crit"))
        .group_by(Vuln.target_id).subquery())
    rows = (await session.execute(
        select(Target.host, Project.code, sub.c.port, sub.c.protocol, sub.c.state,
               sub.c.name, sub.c.banner,
               func.coalesce(vuln_counts.c.n, 0), func.coalesce(vuln_counts.c.crit, 0))
        .select_from(sub)
        .join(Target, Target.id == sub.c.target_id)
        .join(Project, Project.id == Target.project_id)
        .outerjoin(vuln_counts, vuln_counts.c.tid == Target.id)
        .order_by(func.coalesce(vuln_counts.c.crit, 0).desc(),
                  func.coalesce(vuln_counts.c.n, 0).desc(), Target.host)
        .limit(limit_hosts))).all()

    return ExploreOut(
        dimension=dimension, value=value, protocol=protocol,
        total_services=total, total_hosts=hosts,
        by_state={str(k): int(v) for k, v in states.items()},
        service_names=_top(svc_names), ports=[
            NameCount(name=f"{p}/{pr}", count=int(n)) for p, pr, n in ports][:25],
        products=_top(products), banners=_top(banners),
        vulns_total=sum(by_sev.values()), vulns_by_severity=by_sev,
        hosts=[ExploreHost(host=h, project_code=c, port=p, protocol=pr, state=st,
                           name=nm, banner=bn, vulns=int(v), criticals=int(cr))
               for h, c, p, pr, st, nm, bn, v, cr in rows],
        truncated=len(rows) >= limit_hosts,
    )
