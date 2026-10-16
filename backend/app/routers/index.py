"""The API index.

One place to start from. `/api` lists the projects with links into the
nested tree, so the whole resource graph can be walked with a browser and
no documentation — which is the difference between an API that is nested
and one that is browsable.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Project, User
from ..security import get_current_user, visible_project_ids

router = APIRouter(prefix="/api", tags=["rest"])


@router.get("")
async def index(request: Request, user: User = Depends(get_current_user),
                session: AsyncSession = Depends(get_session)):
    base = str(request.base_url).rstrip("/")
    vis = await visible_project_ids(session, user)
    stmt = select(Project).order_by(Project.code)
    if vis is not None:
        stmt = stmt.where(Project.id.in_(vis))
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "service": "Oddjob",
        "you": user.username,
        "projects": [{
            "code": p.code, "name": p.name, "client": p.client,
            "_links": {
                "self": f"{base}/api/projects/{p.code}",
                "targets": f"{base}/api/projects/{p.code}/targets",
                "reports": f"{base}/api/reports?project={p.code}",
            },
        } for p in rows],
        "_links": {
            "self": f"{base}/api",
            # The flat collections the grids use: filtered, sorted and
            # paged across a whole estate, which a nested path cannot do.
            "all_targets": f"{base}/api/targets",
            "all_services": f"{base}/api/services",
            "all_web": f"{base}/api/web",
            "all_vulns": f"{base}/api/vulns",
            "stats": f"{base}/api/stats",
            "import_formats": f"{base}/api/scans/formats",
            "docs": f"{base}/docs",
        },
    }
