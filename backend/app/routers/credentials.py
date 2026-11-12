"""Credentials captured during an engagement.

Secrets are withheld from `readonly` callers. A reviewer who can read the
findings does not automatically need the live password out of them, and the
role names already say which side of that line each person is on. The row is
still listed, with `secret_set` telling them one exists — hiding the
existence of a credential would make the finding count misleading.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..models import ROLE_ORDER, Credential, Project, Target, TargetCredential, User
from ..query import apply_search, apply_sort, paginate
from ..schemas import (CredentialCreate, CredentialOut, CredentialUpdate, Page,
                       TargetAssignCreds)
from ..security import effective_role, get_current_user, require_project, visible_project_ids

router = APIRouter(prefix="/api/credentials", tags=["credentials"])

SORTABLE = {"host": Credential.host, "username": Credential.username,
            "kind": Credential.kind, "service": Credential.service,
            "port": Credential.port, "validated": Credential.validated,
            "updated_at": Credential.updated_at, "project_code": Project.code}
SEARCHABLE = [Credential.host, Credential.username, Credential.service,
              Credential.kind, Credential.source, Credential.notes, Project.code]


def _out(c: Credential, code: str, reveal: bool) -> CredentialOut:
    return CredentialOut(
        **{k: getattr(c, k) for k in
           ("id", "project_id", "host", "service", "port", "username", "kind",
            "source", "validated", "notes", "created_at", "updated_at")},
        project_code=code,
        secret=c.secret if reveal else None,
        secret_set=bool(c.secret),
    )


@router.get("", response_model=Page[CredentialOut])
async def list_credentials(
    project: str | None = Query(None),
    q: str | None = Query(None),
    validated: str | None = Query(None),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(5000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Credential, Project.code).join(Project, Project.id == Credential.project_id)
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Credential.project_id.in_(vis))
    if project:
        pr = (await session.execute(
            select(Project).where(Project.code == project.upper()))).scalar_one_or_none()
        if not pr or (vis is not None and pr.id not in vis):
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Credential.project_id == pr.id)
    if validated:
        stmt = stmt.where(Credential.validated == validated.lower())
    stmt = apply_search(stmt, q, SEARCHABLE)
    stmt = apply_sort(stmt, sort, order, SORTABLE).order_by(Credential.id)
    rows, total = await paginate(session, stmt, limit, offset)

    # Reveal per project, since a caller may be `user` on one and `readonly`
    # on another in the same response.
    reveal: dict[int, bool] = {}
    items = []
    for c, code in rows:
        if c.project_id not in reveal:
            role = await effective_role(session, user, c.project_id)
            reveal[c.project_id] = bool(role and ROLE_ORDER[role] >= ROLE_ORDER["user"])
        items.append(_out(c, code, reveal[c.project_id]))
    return Page[CredentialOut](items=items, total=total, limit=limit, offset=offset)


@router.post("", response_model=CredentialOut, status_code=201)
async def create_credential(body: CredentialCreate, project: str = Query(...),
                            pr: Project = Depends(require_project("user")),
                            session: AsyncSession = Depends(get_session)):
    c = Credential(project_id=pr.id, **body.model_dump())
    session.add(c)
    await session.commit()
    # The event names the project, never the secret.
    await broker.publish("credentials", action="create", project=pr.code)
    return _out(c, pr.code, True)


@router.patch("/{cred_id}", response_model=CredentialOut)
async def update_credential(cred_id: int, body: CredentialUpdate,
                            user: User = Depends(get_current_user),
                            session: AsyncSession = Depends(get_session)):
    c = await session.get(Credential, cred_id)
    if not c:
        raise HTTPException(404, f"no credential {cred_id}")
    role = await effective_role(session, user, c.project_id)
    if role is None:
        raise HTTPException(404, f"no credential {cred_id}")
    if ROLE_ORDER[role] < ROLE_ORDER["user"]:
        raise HTTPException(403, f"user required; you have {role}")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(c, k, v)
    await session.commit()
    code = (await session.get(Project, c.project_id)).code
    await broker.publish("credentials", action="update", project=code)
    return _out(c, code, True)


@router.delete("/{cred_id}", status_code=204)
async def delete_credential(cred_id: int, user: User = Depends(get_current_user),
                            session: AsyncSession = Depends(get_session)):
    c = await session.get(Credential, cred_id)
    if not c:
        raise HTTPException(404, f"no credential {cred_id}")
    role = await effective_role(session, user, c.project_id)
    if role is None:
        raise HTTPException(404, f"no credential {cred_id}")
    if ROLE_ORDER[role] < ROLE_ORDER["user"]:
        raise HTTPException(403, f"user required; you have {role}")
    code = (await session.get(Project, c.project_id)).code
    await session.delete(c)
    await session.commit()
    await broker.publish("credentials", action="delete", project=code)


@router.put("/targets/{project}/{host}", response_model=list[CredentialOut])
async def assign_target_credentials(project: str, host: str, body: TargetAssignCreds,
                                    _: Project = Depends(require_project("user")),
                                    user: User = Depends(get_current_user),
                                    session: AsyncSession = Depends(get_session)):
    """Replace the credentials assigned to this target.

    Lives under /api/credentials because it manages CREDENTIALS; the path
    carries the target because that is what they are being assigned to.

    The set is replaced rather than appended so that removing one is the
    same call as adding one and a slow client cannot leave half-edited
    state behind. Credentials whose host already names this target still
    apply without a row here — see `app/credauth.py` — so this only ever
    ADDS coverage, never removes what the importers recorded.
    """
    from ..hosts import normalise_host
    t = (await session.execute(
        select(Target).where(Target.project_id == _.id,
                             Target.host == normalise_host(host)))).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, f"no target {host!r} in project {_.code}")
    want = set(body.credential_ids)
    have = {r.credential_id for r in (await session.execute(
        select(TargetCredential).where(
            TargetCredential.target_id == t.id))).scalars().all()}
    for cid in sorted(want):
        c = await session.get(Credential, cid)
        if c is None or c.project_id != t.project_id:
            raise HTTPException(404, f"no credential {cid} in this project")
    for cid in have - want:
        row = (await session.execute(
            select(TargetCredential).where(
                TargetCredential.target_id == t.id,
                TargetCredential.credential_id == cid))).scalar_one()
        await session.delete(row)
    for cid in want - have:
        session.add(TargetCredential(target_id=t.id, credential_id=cid))
    await session.flush()
    from ..timeline import record
    if want - have:
        await record(session, t.id, "credential",
                     "assigned to this target: " + ", ".join(
                         f"credential {c}" for c in sorted(want - have)), actor=user)
    if have - want:
        await record(session, t.id, "credential",
                     "unassigned from this target: " + ", ".join(
                         f"credential {c}" for c in sorted(have - want)),
                     actor=user)
    await session.commit()
    await broker.publish("credentials", action="update", project=_.code)
    rows = (await session.execute(
        select(Credential).where(Credential.id.in_(want)).order_by(Credential.id)
    )).scalars().all() if want else []
    return [CredentialOut(
        **{k: getattr(c, k) for k in
           ("id", "project_id", "host", "service", "port", "username",
            "kind", "source", "validated", "notes", "created_at", "updated_at")},
        project_code=_.code,
        secret=c.secret, secret_set=bool(c.secret)) for c in rows]
