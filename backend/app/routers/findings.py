"""Vulns and PoCs.

Supporting tables: they exist because the Targets grid shows live counts of
them. Full CRUD so the API is complete and bulk import has somewhere to land.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import slack
from ..db import get_session
from ..events import broker
from ..hosts import normalise_host
from ..models import Poc, Project, Target, User, Vuln
from ..query import apply_search, apply_sort, paginate
from ..schemas import Page, PocCreate, PocOut, VulnCreate, VulnOut
from ..security import (
    assert_role_for_target,
    get_current_user,
    require_project,
    visible_project_ids,
)
from .projects import resolve_project

router = APIRouter(prefix="/api", tags=["findings"])


def _base(model):
    return (select(model, Target.host, Project.code)
            .join(Target, Target.id == model.target_id)
            .join(Project, Project.id == Target.project_id))


def _vuln_out(row) -> VulnOut:
    v = row[0]
    return VulnOut(
        **{k: getattr(v, k) for k in
           ("id", "target_id", "title", "severity", "status", "port", "protocol",
            "description", "remediation", "external_id", "created_at",
            "updated_at")},
        host=row[1], project_code=row[2])


def _poc_out(row) -> PocOut:
    p = row[0]
    return PocOut(
        **{k: getattr(p, k) for k in
           ("id", "target_id", "title", "status", "path", "exit_code", "notes",
            "created_at", "updated_at")},
        host=row[1], project_code=row[2])


async def _target_for(session, project: str, host: str) -> Target:
    pr = await resolve_project(session, project)
    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == normalise_host(host)))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, f"no target {host!r} in {pr.code} — create it, or use /api/bulk")
    return t


@router.get("/vulns", response_model=Page[VulnOut])
async def list_vulns(
    project: str | None = Query(None),
    q: str | None = Query(None),
    host: str | None = Query(None),
    severity: str | None = Query(None),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(20000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = _base(Vuln)
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    if host:
        stmt = stmt.where(Target.host == normalise_host(host))
    if severity:
        stmt = stmt.where(Vuln.severity == severity.lower())
    stmt = apply_search(stmt, q, [Target.host, Project.code, Vuln.title, Vuln.severity,
                                  Vuln.status, Vuln.description, Vuln.external_id])
    stmt = apply_sort(stmt, sort, order, {
        "host": Target.host, "project_code": Project.code, "title": Vuln.title,
        "severity": Vuln.severity, "status": Vuln.status, "port": Vuln.port,
        "updated_at": Vuln.updated_at,
    }).order_by(Vuln.id)
    rows, total = await paginate(session, stmt, limit, offset)
    return Page[VulnOut](items=[_vuln_out(r) for r in rows], total=total,
                         limit=limit, offset=offset)


class VulnOccurrence(BaseModel):
    """One host this finding was recorded on."""
    id: int
    target_id: int
    host: str
    project_code: str
    port: int | None = None
    protocol: str | None = None
    status: str = "open"
    severity: str = "info"


class VulnDetail(VulnOut):
    """One finding, with every host carrying the same issue.

    The table has a row per (finding, host), because that is what the
    scanners report and what gets fixed. But the question a reader
    actually has in front of a finding is "where else is this?", and
    answering it by eye across 7,076 rows is not reasonable.

    Matched on `external_id` when there is one -- a CVE is the same
    issue wherever it appears -- and on the exact title otherwise.
    Scoped to the finding's own project: two engagements sharing a
    scanner's wording are not one finding.
    """
    occurrences: list[VulnOccurrence] = []
    #: Whether the match was by identifier or by title, so a reader can
    #: judge how much to trust the grouping.
    grouped_by: str = "title"


@router.get("/vulns/{vuln_id}", response_model=VulnDetail)
async def get_vuln(vuln_id: int,
                   user: User = Depends(get_current_user),
                   session: AsyncSession = Depends(get_session)):
    """One finding in full, plus every other host it was found on."""
    row = (await session.execute(_base(Vuln).where(Vuln.id == vuln_id))).first()
    if row is None:
        raise HTTPException(404, "no such vulnerability")
    vuln = row[0]
    target = await session.get(Target, vuln.target_id)
    vis = await visible_project_ids(session, user)
    if target is None or (vis is not None and target.project_id not in vis):
        raise HTTPException(404, "no such vulnerability")

    same = _base(Vuln).where(Target.project_id == target.project_id)
    if vuln.external_id:
        same = same.where(Vuln.external_id == vuln.external_id)
        grouped = f"external_id {vuln.external_id}"
    else:
        same = same.where(Vuln.title == vuln.title)
        grouped = "title"
    rows = (await session.execute(same.order_by(Target.host, Vuln.port))).all()

    return VulnDetail(
        **_vuln_out(row).model_dump(),
        grouped_by=grouped,
        # `_base` selects (Vuln, Target.host, Project.code) — the second
        # and third are strings, not ORM objects.
        occurrences=[
            VulnOccurrence(id=v.id, target_id=v.target_id, host=host,
                           project_code=code, port=v.port, protocol=v.protocol,
                           status=v.status, severity=v.severity)
            for (v, host, code) in rows],
    )


@router.post("/vulns", response_model=VulnOut, status_code=201)
async def create_vuln(body: VulnCreate, project: str = Query(...),
                      pr: Project = Depends(require_project("user")),
                      session: AsyncSession = Depends(get_session)):
    t = await _target_for(session, project, body.host)
    v = Vuln(target_id=t.id, **body.model_dump(exclude={"host"}))
    session.add(v)
    await session.commit()
    await broker.publish("vulns", action="create", host=t.host, project=project)

    # Announced here as well as on import. Wiring only the import path
    # meant a finding an operator recorded by hand — which is how you
    # log something you found yourself, and usually the most important
    # kind — went to Slack silently. Caught by posting a real critical
    # into a real channel and watching nothing arrive.
    #
    # No severity floor, unlike an import: a person filing one finding
    # has already decided it is worth recording, where a scanner
    # filing six thousand has not.
    await slack.announce_finding(
        session, pr, severity=v.severity, host=t.host, title=v.title,
        port=v.port, protocol=v.protocol, detail=v.description)

    return _vuln_out((await session.execute(_base(Vuln).where(Vuln.id == v.id))).first())


@router.delete("/vulns/{vuln_id}", status_code=204)
async def delete_vuln(vuln_id: int, user: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    v = await session.get(Vuln, vuln_id)
    if not v:
        raise HTTPException(404, f"no vuln {vuln_id}")
    await assert_role_for_target(session, user, v.target_id, "user")
    await session.delete(v)
    await session.commit()
    await broker.publish("vulns", action="delete")


@router.get("/pocs", response_model=Page[PocOut])
async def list_pocs(
    project: str | None = Query(None),
    q: str | None = Query(None),
    host: str | None = Query(None),
    status: str | None = Query(None),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(20000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = _base(Poc)
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    if host:
        stmt = stmt.where(Target.host == normalise_host(host))
    if status:
        stmt = stmt.where(Poc.status == status.lower())
    stmt = apply_search(stmt, q, [Target.host, Project.code, Poc.title, Poc.status,
                                  Poc.path, Poc.notes])
    stmt = apply_sort(stmt, sort, order, {
        "host": Target.host, "project_code": Project.code, "title": Poc.title,
        "status": Poc.status, "exit_code": Poc.exit_code, "updated_at": Poc.updated_at,
    }).order_by(Poc.id)
    rows, total = await paginate(session, stmt, limit, offset)
    return Page[PocOut](items=[_poc_out(r) for r in rows], total=total,
                        limit=limit, offset=offset)


@router.post("/pocs", response_model=PocOut, status_code=201)
async def create_poc(body: PocCreate, project: str = Query(...),
                     _: Project = Depends(require_project("user")),
                     session: AsyncSession = Depends(get_session)):
    t = await _target_for(session, project, body.host)
    p = Poc(target_id=t.id, **body.model_dump(exclude={"host"}))
    session.add(p)
    await session.commit()
    await broker.publish("pocs", action="create", host=t.host, project=project)
    return _poc_out((await session.execute(_base(Poc).where(Poc.id == p.id))).first())


@router.delete("/pocs/{poc_id}", status_code=204)
async def delete_poc(poc_id: int, user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    p = await session.get(Poc, poc_id)
    if not p:
        raise HTTPException(404, f"no poc {poc_id}")
    await assert_role_for_target(session, user, p.target_id, "user")
    await session.delete(p)
    await session.commit()
    await broker.publish("pocs", action="delete")
