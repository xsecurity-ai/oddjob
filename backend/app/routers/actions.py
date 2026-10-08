"""Request an action against a service, and read its outcome.

The POST returns immediately with a `pending` job; the runner executes in the
background and publishes an SSE change when it settles, which is what makes
the grid update itself. Nothing blocks on a probe that may take minutes.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..actions import RUNNERS, Subject
from ..db import SessionLocal, get_session
from ..events import broker
from ..models import Action, Project, Service, Target, User
from ..query import apply_sort, paginate
from ..schemas import ActionOut, ActionRequest, Page
from ..scopegate import assert_allowed
from ..security import assert_role_for_target, get_current_user, visible_project_ids

router = APIRouter(prefix="/api", tags=["actions"])


async def _run(action_id: int) -> None:
    """Execute one job. Runs detached, so it owns its own session —
    the request's session is long gone by the time this finishes."""
    async with SessionLocal() as session:
        a = await session.get(Action, action_id)
        if a is None:
            return
        svc = await session.get(Service, a.service_id)
        if svc is None:
            a.status, a.error = "failed", "service no longer exists"
            a.finished_at = datetime.now(UTC)
            await session.commit()
            await broker.publish("actions", action=a.kind, status=a.status)
            return

        tgt = await session.get(Target, svc.target_id)
        proj = await session.get(Project, tgt.project_id)
        a.status = "running"
        await session.commit()
        await broker.publish("actions", action=a.kind, status="running")

        try:
            res = await RUNNERS[a.kind](Subject(
                host=tgt.host, port=svc.port, protocol=svc.protocol,
                service_id=svc.id, project_code=proj.code))
        except Exception as e:                      # a runner must never kill the loop
            a.status, a.error = "failed", f"{type(e).__name__}: {e}"
        else:
            a.status, a.result, a.error = res.status, res.result, res.error
            # Only a successful run writes back to the service. An
            # `unavailable` result must not blank out a banner that an import
            # already established.
            if res.status == "done" and res.patch:
                for k, v in res.patch.items():
                    if hasattr(svc, k):
                        setattr(svc, k, v)
        a.finished_at = datetime.now(UTC)
        await session.commit()
        await broker.publish("actions", action=a.kind, status=a.status,
                             service_id=a.service_id)


@router.post("/services/{service_id}/actions", response_model=ActionOut, status_code=202)
async def request_action(service_id: int, body: ActionRequest,
                         user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    if body.kind not in RUNNERS:
        raise HTTPException(422, f"unknown action {body.kind!r}; known: {sorted(RUNNERS)}")
    svc = await session.get(Service, service_id)
    if not svc:
        raise HTTPException(404, f"no service {service_id}")
    # An active probe changes the record and touches someone else's host, so
    # it needs write authority on the project, not merely read.
    await assert_role_for_target(session, user, svc.target_id, "user")

    # And the project's scope lists, which are a different question from
    # authority. `actions.is_in_scope` still refuses everything on its
    # own account — see the interlock there — so this is the earlier and
    # more useful refusal, not the only one: a barred host is told so
    # here rather than queueing a job that comes back "unavailable".
    tgt = await session.get(Target, svc.target_id)
    if tgt is not None:
        await assert_allowed(session, tgt.project_id, tgt.host,
                             f"probing {tgt.host}", ip=tgt.ip_address)

    busy = (await session.execute(
        select(Action).where(Action.service_id == service_id, Action.kind == body.kind,
                             Action.status.in_(("pending", "running"))))).scalar_one_or_none()
    if busy:
        # Returning the in-flight job rather than queueing a second one: a
        # double-click should not mean two scans of the same host.
        return ActionOut.model_validate(busy)

    a = Action(kind=body.kind, service_id=service_id, requested_by=user.id, status="pending")
    session.add(a)
    await session.commit()
    asyncio.create_task(_run(a.id))
    return ActionOut.model_validate(a)


@router.get("/actions", response_model=Page[ActionOut])
async def list_actions(
    service_id: int | None = Query(None),
    status: str | None = Query(None),
    sort: str | None = Query("id"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(500, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = (select(Action)
            .join(Service, Service.id == Action.service_id)
            .join(Target, Target.id == Service.target_id))
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if service_id is not None:
        stmt = stmt.where(Action.service_id == service_id)
    if status:
        stmt = stmt.where(Action.status == status.lower())
    stmt = apply_sort(stmt, sort, order,
                      {"id": Action.id, "kind": Action.kind, "status": Action.status,
                       "created_at": Action.created_at})
    rows, total = await paginate(session, stmt, limit, offset)
    return Page[ActionOut](items=[ActionOut.model_validate(r[0]) for r in rows],
                           total=total, limit=limit, offset=offset)
