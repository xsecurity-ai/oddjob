"""Services, and the Ports view over the same rows.

/api/services  every row, any state, service name included
/api/ports     the same table filtered to state='open'

One table because a port and its service are one fact. See models.py.
Rows join through Target to carry host and project_code, since the service
itself only stores target_id.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..hosts import normalise_host
from ..models import Project, Service, Target, User
from ..query import apply_search, apply_sort, paginate
from ..schemas import Page, ServiceCreate, ServiceOut, ServiceUpdate
from ..security import (
    assert_role_for_target,
    get_current_user,
    require_project,
    visible_project_ids,
)
from .projects import resolve_project

# Taken from the schema so a new column cannot be forgotten here; `host` and
# `project_code` come from the joined row rather than the Service itself.
_SERVICE_KEYS = tuple(k for k in ServiceOut.model_fields
                      if k not in ("host", "project_code"))

router = APIRouter(prefix="/api", tags=["services"])

SORTABLE = {
    "host": Target.host, "project_code": Project.code, "port": Service.port,
    "protocol": Service.protocol, "state": Service.state, "name": Service.name,
    "product": Service.product, "version": Service.version,
    "banner": Service.banner, "updated_at": Service.updated_at,
}
SEARCHABLE = [Target.host, Project.code, Service.port, Service.protocol, Service.state,
              Service.name, Service.product, Service.version, Service.banner]


def _base():
    return (select(Service, Target.host, Project.code)
            .join(Target, Target.id == Service.target_id)
            .join(Project, Project.id == Target.project_id))


def _out(row) -> ServiceOut:
    s = row[0]
    return ServiceOut(
        **{k: getattr(s, k) for k in _SERVICE_KEYS},
        host=row[1], project_code=row[2],
    )


async def _list(session, user, project, q, state, host, sort, order, limit, offset,
                port=None, name=None):
    stmt = _base()
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    if state:
        stmt = stmt.where(Service.state == state.lower())
    if host:
        stmt = stmt.where(Target.host == normalise_host(host))
    # Exact filters, distinct from `q`: q is a substring match across every
    # column, so q=443 also matches a banner mentioning 443.
    if port is not None:
        stmt = stmt.where(Service.port == port)
    if name:
        stmt = stmt.where(func.lower(Service.name) == name.strip().lower())
    stmt = apply_search(stmt, q, SEARCHABLE)
    stmt = apply_sort(stmt, sort, order, SORTABLE)
    # Stable secondary key, so equal sort values do not reshuffle on refetch.
    stmt = stmt.order_by(Target.host, Service.port, Service.protocol)
    rows, total = await paginate(session, stmt, limit, offset)
    return Page[ServiceOut](items=[_out(r) for r in rows], total=total,
                            limit=limit, offset=offset)


@router.get("/services", response_model=Page[ServiceOut])
async def list_services(
    project: str | None = Query(None),
    q: str | None = Query(None, description="full search across every column"),
    state: str | None = Query(None, description="open | closed | filtered"),
    host: str | None = Query(None),
    port: int | None = Query(None, description="exact port"),
    name: str | None = Query(None, description="exact service name"),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(20000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    return await _list(session, user, project, q, state, host, sort, order, limit,
                       offset, port, name)


@router.get("/ports", response_model=Page[ServiceOut])
async def list_ports(
    project: str | None = Query(None),
    q: str | None = Query(None),
    host: str | None = Query(None),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(20000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Open ports only -- state is pinned here, not client-supplied."""
    return await _list(session, user, project, q, "open", host, sort, order, limit, offset)


@router.post("/services", response_model=ServiceOut, status_code=201)
async def create_service(body: ServiceCreate, project: str = Query(...),
                         pr: Project = Depends(require_project("user")),
                         session: AsyncSession = Depends(get_session)):
    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == body.host))).scalar_one_or_none()
    if not t:
        raise HTTPException(
            404, f"no target {body.host!r} in {pr.code} — create it, or use /api/bulk")
    dup = (await session.execute(
        select(Service).where(Service.target_id == t.id, Service.port == body.port,
                              Service.protocol == body.protocol))).scalar_one_or_none()
    if dup:
        raise HTTPException(409, f"{body.host} {body.port}/{body.protocol} already exists")
    data = body.model_dump(exclude={"host"})
    s = Service(target_id=t.id, **data)
    session.add(s)
    await session.commit()
    await broker.publish("services", action="create", host=t.host, project=pr.code)
    row = (await session.execute(_base().where(Service.id == s.id))).first()
    return _out(row)


@router.patch("/services/{service_id}", response_model=ServiceOut)
async def update_service(service_id: int, body: ServiceUpdate,
                         user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    s = await session.get(Service, service_id)
    if not s:
        raise HTTPException(404, f"no service {service_id}")
    await assert_role_for_target(session, user, s.target_id, "user")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(s, k, v)
    await session.commit()
    await broker.publish("services", action="update")
    return _out((await session.execute(_base().where(Service.id == s.id))).first())


@router.delete("/services/{service_id}", status_code=204)
async def delete_service(service_id: int, user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    s = await session.get(Service, service_id)
    if not s:
        raise HTTPException(404, f"no service {service_id}")
    await assert_role_for_target(session, user, s.target_id, "user")
    await session.delete(s)
    await session.commit()
    await broker.publish("services", action="delete")
