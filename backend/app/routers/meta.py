"""Health, stats and the SSE change stream."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker, event_stream
from ..models import SEVERITIES, Poc, Project, Service, Target, User, Vuln
from ..schemas import Stats
from ..security import get_current_user, visible_project_ids

router = APIRouter(prefix="/api", tags=["meta"])


@router.get("/health")
async def health(session: AsyncSession = Depends(get_session)):
    await session.execute(select(1))
    return {"ok": True, "sse_subscribers": broker.subscriber_count}


@router.get("/stats", response_model=Stats)
async def stats(project: str | None = None,
                user: User = Depends(get_current_user),
                session: AsyncSession = Depends(get_session)):
    """Counts the caller is entitled to see. A readonly user on one project
    must not learn the size of the rest of the estate from the header."""
    vis = await visible_project_ids(session, user)

    def scope_targets(stmt):
        return stmt if vis is None else stmt.where(Target.project_id.in_(vis))

    def scope_children(stmt, model):
        stmt = stmt.join(Target, Target.id == model.target_id)
        return stmt if vis is None else stmt.where(Target.project_id.in_(vis))

    if project:
        pr = (await session.execute(
            select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
        if pr and (vis is None or pr.id in vis):
            vis = [pr.id]

    async def count(stmt):
        return int((await session.execute(stmt)).scalar_one())

    by_sev = {
        sev: await count(scope_children(
            select(func.count(Vuln.id)), Vuln).where(Vuln.severity == sev))
        for sev in SEVERITIES
    }
    n_projects = (len(vis) if vis is not None
                  else await count(select(func.count()).select_from(Project)))
    return Stats(
        projects=n_projects,
        targets=await count(scope_targets(select(func.count()).select_from(Target))),
        hacked=await count(scope_targets(
            select(func.count()).select_from(Target)).where(Target.hacked.is_(True))),
        services=await count(scope_children(select(func.count(Service.id)), Service)),
        open_ports=await count(scope_children(
            select(func.count(Service.id)), Service).where(Service.state == "open")),
        vulns=await count(scope_children(select(func.count(Vuln.id)), Vuln)),
        by_severity=by_sev,
        pocs=await count(scope_children(select(func.count(Poc.id)), Poc)),
    )


@router.get("/events")
async def events(user: User = Depends(get_current_user)):
    """SSE stream. The UI subscribes once and refetches whatever changed.

    Authenticated: the events name hosts and project codes, so an open stream
    would leak the shape of the estate to anyone who could reach the port.
    EventSource cannot set an Authorization header, which is exactly why login
    also sets an httpOnly cookie — that is what carries this request.

    X-Accel-Buffering:no matters: behind nginx, the default proxy_buffering on
    holds the stream in a buffer and events arrive late and in bursts, which
    looks exactly like the feature being broken.
    """
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
