"""The nested resource tree.

    /api/projects
    /api/projects/{project}
    /api/projects/{project}/targets
    /api/projects/{project}/targets/{target}
    /api/projects/{project}/targets/{target}/services
    /api/projects/{project}/targets/{target}/services/{protocol}/{port}
    /api/projects/{project}/targets/{target}/web
    /api/projects/{project}/targets/{target}/vulns
    /api/projects/{project}/targets/{target}/timeline
    /api/projects/{project}/targets/{target}/implants

The flat collections (`/api/targets?project=…`) are what the grids use —
they filter, sort and page across a whole estate, which a nested path
cannot express. This tree is for the other half: addressing one thing,
and finding what hangs off it without reading the documentation.

Every response carries `_links`, so the tree can be walked from the root
with nothing but a browser. That is the part that makes it browsable
rather than merely nested: a reader who lands on a service should be able
to get back to its host without knowing how the URL is built.

`{target}` accepts either the hostname or the numeric id. A path is
something people type and paste, and refusing `…/targets/web01.corp.com`
because the canonical form is `…/targets/4821` is pedantry.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import (Event, Implant, Poc, Project, Service, Target, User,
                      Vuln, WebAddress)
from ..security import (effective_role, get_current_user, require_project,
                        visible_project_ids)

router = APIRouter(prefix="/api/projects", tags=["rest"])


def _links(request: Request, **paths: str | None) -> dict:
    """Absolute links, so a reply can be followed without reassembling it."""
    base = str(request.base_url).rstrip("/")
    return {k: f"{base}{v}" for k, v in paths.items() if v}


async def _target(session: AsyncSession, project: Project, ref: str) -> Target:
    """By hostname or by id — whichever the caller had to hand."""
    r = (ref or "").strip().rstrip(".").lower()
    t = (await session.execute(
        select(Target).where(Target.project_id == project.id,
                             Target.host == r))).scalar_one_or_none()
    if t is None and r.isdigit():
        t = (await session.execute(
            select(Target).where(Target.project_id == project.id,
                                 Target.id == int(r)))).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, f"no target {ref!r} in {project.code}")
    return t


def _jsonish(v, fallback):
    if not v:
        return fallback
    try:
        out = json.loads(v)
    except (TypeError, ValueError):
        return fallback
    return out if isinstance(out, type(fallback)) else fallback


# NOTE: `/api/projects` and `/api/projects/{code}` already belong to
# routers/projects.py, which the grids use and whose shape they depend
# on. The tree therefore starts at `/targets` and is reachable from the
# index at `/api`, rather than taking those two paths over.

# -------------------------------------------------------------- targets
@router.get("/{project}/targets")
async def list_targets(project: str, request: Request,
                       q: str | None = Query(None, description="match the host"),
                       limit: int = Query(500, le=5000), offset: int = 0,
                       pr: Project = Depends(require_project("readonly")),
                       session: AsyncSession = Depends(get_session)):
    stmt = select(Target).where(Target.project_id == pr.id)
    if q:
        stmt = stmt.where(Target.host.ilike(f"%{q.strip()}%"))
    total = int((await session.execute(
        select(func.count()).select_from(stmt.subquery()))).scalar_one())
    rows = (await session.execute(
        stmt.order_by(Target.host).limit(limit).offset(offset))).scalars().all()
    base = f"/api/projects/{pr.code}/targets"
    return {
        "count": total, "limit": limit, "offset": offset,
        "targets": [{
            "id": t.id, "host": t.host, "ip": t.ip_address,
            "alive": t.alive, "compromised": t.hacked, "os": t.os,
            "_links": _links(request, self=f"{base}/{t.host}",
                             services=f"{base}/{t.host}/services",
                             web=f"{base}/{t.host}/web",
                             vulns=f"{base}/{t.host}/vulns",
                             timeline=f"{base}/{t.host}/timeline"),
        } for t in rows],
        "_links": _links(request, self=base, project=f"/api/projects/{pr.code}"),
    }


@router.get("/{project}/targets/{target}")
async def get_target(project: str, target: str, request: Request,
                     pr: Project = Depends(require_project("readonly")),
                     session: AsyncSession = Depends(get_session)):
    t = await _target(session, pr, target)
    base = f"/api/projects/{pr.code}/targets/{t.host}"

    async def n(model):
        return int((await session.execute(
            select(func.count()).select_from(model)
            .where(model.target_id == t.id))).scalar_one())

    return {
        "id": t.id, "host": t.host, "ip": t.ip_address,
        "alive": t.alive, "compromised": t.hacked,
        "os": t.os, "os_accuracy": t.os_accuracy,
        "mac": t.mac_address, "mac_vendor": t.mac_vendor,
        "hostnames": _jsonish(t.hostnames, []),
        "notes": t.notes, "tags": t.tags,
        "extra": _jsonish(t.extra, {}),
        "counts": {"services": await n(Service), "web_addresses": await n(WebAddress),
                   "vulns": await n(Vuln), "pocs": await n(Poc),
                   "implants": await n(Implant), "timeline": await n(Event)},
        "_links": _links(
            request, self=base, services=f"{base}/services", web=f"{base}/web",
            vulns=f"{base}/vulns", timeline=f"{base}/timeline",
            implants=f"{base}/implants",
            project=f"/api/projects/{pr.code}",
            targets=f"/api/projects/{pr.code}/targets"),
    }


# ------------------------------------------------------------- services
@router.get("/{project}/targets/{target}/services")
async def list_services(project: str, target: str, request: Request,
                        state: str | None = Query(None),
                        pr: Project = Depends(require_project("readonly")),
                        session: AsyncSession = Depends(get_session)):
    t = await _target(session, pr, target)
    stmt = select(Service).where(Service.target_id == t.id)
    if state:
        stmt = stmt.where(Service.state == state.lower())
    rows = (await session.execute(
        stmt.order_by(Service.protocol, Service.port))).scalars().all()
    base = f"/api/projects/{pr.code}/targets/{t.host}"
    return {
        "count": len(rows),
        "services": [{
            "id": s.id, "port": s.port, "protocol": s.protocol,
            "state": s.state, "service": s.name, "version": s.banner,
            "_links": _links(request,
                             self=f"{base}/services/{s.protocol}/{s.port}"),
        } for s in rows],
        "_links": _links(request, self=f"{base}/services", target=base),
    }


@router.get("/{project}/targets/{target}/services/{protocol}/{port}")
async def get_service(project: str, target: str, protocol: str, port: int,
                      request: Request,
                      pr: Project = Depends(require_project("readonly")),
                      session: AsyncSession = Depends(get_session)):
    """One service. The leaf the whole path exists to reach."""
    t = await _target(session, pr, target)
    s = (await session.execute(
        select(Service).where(Service.target_id == t.id,
                              Service.protocol == protocol.lower(),
                              Service.port == port))).scalar_one_or_none()
    if s is None:
        raise HTTPException(
            404, f"{t.host} has no {protocol.lower()}/{port} recorded")

    base = f"/api/projects/{pr.code}/targets/{t.host}"
    # What else is known about this port, so the leaf is not a dead end.
    web = (await session.execute(
        select(WebAddress).where(WebAddress.service_id == s.id)
        .order_by(WebAddress.url).limit(200))).scalars().all()
    vulns = (await session.execute(
        select(Vuln).where(Vuln.target_id == t.id,
                           Vuln.port == s.port))).scalars().all()

    return {
        "id": s.id, "host": t.host, "port": s.port, "protocol": s.protocol,
        "state": s.state, "service": s.name, "version": s.banner,
        "product": s.product, "version_detail": s.version,
        "extrainfo": s.extrainfo, "tunnel": s.tunnel,
        "method": s.method, "confidence": s.confidence, "reason": s.reason,
        "cpe": _jsonish(s.cpe, []),
        "scripts": _jsonish(s.scripts, {}),
        "notes": s.notes,
        "web_addresses": [{
            "id": w.id, "method": w.method, "url": w.url,
            "status": w.status_code, "title": w.title,
            "_links": _links(request, packet=f"/api/web/{w.id}/packet"),
        } for w in web],
        "vulns": [{"id": v.id, "title": v.title, "severity": v.severity,
                   "status": v.status} for v in vulns],
        "_links": _links(request,
                         self=f"{base}/services/{s.protocol}/{s.port}",
                         services=f"{base}/services", target=base,
                         project=f"/api/projects/{pr.code}"),
    }


# ------------------------------------------------- the rest of the leaves
@router.get("/{project}/targets/{target}/web")
async def target_web(project: str, target: str, request: Request,
                     pr: Project = Depends(require_project("readonly")),
                     session: AsyncSession = Depends(get_session)):
    t = await _target(session, pr, target)
    rows = (await session.execute(
        select(WebAddress).where(WebAddress.target_id == t.id)
        .order_by(WebAddress.url))).scalars().all()
    base = f"/api/projects/{pr.code}/targets/{t.host}"
    return {
        "count": len(rows),
        "web_addresses": [{
            "id": w.id, "method": w.method, "url": w.url,
            "status": w.status_code, "title": w.title,
            "crawled": w.crawled, "sources": w.sources,
            # The exchange is a separate fetch; see app/routers/web.py.
            "_links": _links(request, packet=f"/api/web/{w.id}/packet"),
        } for w in rows],
        "_links": _links(request, self=f"{base}/web", target=base),
    }


@router.get("/{project}/targets/{target}/vulns")
async def target_vulns(project: str, target: str, request: Request,
                       pr: Project = Depends(require_project("readonly")),
                       session: AsyncSession = Depends(get_session)):
    from ..models import SEVERITIES
    t = await _target(session, pr, target)
    rows = (await session.execute(
        select(Vuln).where(Vuln.target_id == t.id))).scalars().all()
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda v: (rank.get(v.severity, 9), v.title))
    base = f"/api/projects/{pr.code}/targets/{t.host}"
    return {
        "count": len(rows),
        "vulns": [{
            "id": v.id, "title": v.title, "severity": v.severity,
            "status": v.status, "port": v.port, "protocol": v.protocol,
            "external_id": v.external_id, "description": v.description,
            "remediation": v.remediation,
            "remediation_source": v.remediation_source,
        } for v in rows],
        "_links": _links(request, self=f"{base}/vulns", target=base),
    }


@router.get("/{project}/targets/{target}/timeline")
async def target_timeline(project: str, target: str, request: Request,
                          limit: int = Query(200, le=2000),
                          pr: Project = Depends(require_project("readonly")),
                          session: AsyncSession = Depends(get_session)):
    t = await _target(session, pr, target)
    rows = (await session.execute(
        select(Event).where(Event.target_id == t.id)
        .order_by(Event.at.desc()).limit(limit))).scalars().all()
    base = f"/api/projects/{pr.code}/targets/{t.host}"
    return {
        "count": len(rows),
        "events": [{"at": e.at, "kind": e.kind, "summary": e.summary,
                    "actor": e.actor, "source": e.source,
                    "detail": e.detail} for e in rows],
        "_links": _links(request, self=f"{base}/timeline", target=base),
    }


@router.get("/{project}/targets/{target}/implants")
async def target_implants(project: str, target: str, request: Request,
                          pr: Project = Depends(require_project("readonly")),
                          session: AsyncSession = Depends(get_session)):
    t = await _target(session, pr, target)
    rows = (await session.execute(
        select(Implant).where(Implant.target_id == t.id))).scalars().all()
    base = f"/api/projects/{pr.code}/targets/{t.host}"
    return {
        "count": len(rows),
        "implants": [{
            "id": i.id, "framework": i.framework, "implant_id": i.implant_id,
            "user": i.user, "domain": i.domain, "integrity": i.integrity,
            "process": i.process, "pid": i.pid, "listener": i.listener,
            "internal_ip": i.internal_ip, "external_ip": i.external_ip,
            "active": i.active, "last_seen": i.last_seen,
        } for i in rows],
        "_links": _links(request, self=f"{base}/implants", target=base),
    }
