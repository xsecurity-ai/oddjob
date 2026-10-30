"""Shell sessions: the list, the transcript, and typing at one.

The Ghost holds the socket and `app/shellhub.py` holds the route to
it. This is what a browser talks to.

**Every byte in both directions is written to the database**, which
is the point of running a shell through here rather than through
netcat on a laptop. A shell is the strongest evidence an engagement
produces about a host and is routinely the worst recorded -- it
lives in one operator's scrollback and then it is gone.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..db import get_session
from ..events import broker
from ..models import Agent, Project, ShellExchange, ShellSession, Target, User
from ..security import get_current_user, require_project
from ..shellhub import hub

log = logging.getLogger("oddjob.c2")

router = APIRouter(prefix="/api/c2", tags=["c2"])

#: Most transcript rows one read returns. A long session is thousands
#: of exchanges and the terminal shows the tail.
MAX_TAIL = 500


class SessionOut(BaseModel):
    id: int
    project_code: str
    host: str | None
    target_id: int | None
    agent_name: str | None
    peer: str | None
    listen_port: int | None
    state: str
    label: str | None
    #: Whether THIS process can currently reach it. A session can be
    #: `open` in the database and unreachable here -- the tunnel went
    #: away and the shell may be perfectly alive -- and an operator
    #: about to type needs to know which.
    connected: bool
    exchanges: int
    opened_at: str | None
    last_seen_at: str | None


class ExchangeOut(BaseModel):
    id: int
    seq: int
    command: str | None
    output: str | None
    actor: str | None
    at: str | None


class InputIn(BaseModel):
    #: What to type. A newline is appended if absent: every shell
    #: needs one to act and an operator pressing Enter has already
    #: expressed that.
    data: str = Field(min_length=1, max_length=65536)


def _out(s: ShellSession, host: str | None, agent: str | None,
         code: str, n: int) -> SessionOut:
    return SessionOut(
        id=s.id, project_code=code, host=host, target_id=s.target_id,
        agent_name=agent, peer=s.peer, listen_port=s.listen_port,
        state=s.state, label=s.label, connected=hub.holds(s.id),
        exchanges=n,
        opened_at=s.created_at.isoformat() if s.created_at else None,
        last_seen_at=s.last_seen_at.isoformat() if s.last_seen_at else None)


@router.get("/sessions", response_model=list[SessionOut])
async def list_sessions(project: str = Query(...),
                        active: bool = Query(
                            True, description="Only sessions that are open. "
                                              "False includes closed ones, "
                                              "which stay for the record."),
                        pr: Project = Depends(require_project("readonly")),
                        _: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Every shell on this engagement, newest first.

    Active by default: a long engagement accumulates closed sessions
    and the question on opening this page is almost always "what can
    I type at right now". The closed ones are a tick away and are
    never deleted -- what was done on a host is part of the record.

    `readonly` to LOOK. Typing needs `user`; see `send`.
    """
    q = (select(ShellSession, Target.host, Agent.name,
                func.count(ShellExchange.id))
         .outerjoin(Target, Target.id == ShellSession.target_id)
         .outerjoin(Agent, Agent.id == ShellSession.agent_id)
         .outerjoin(ShellExchange,
                    ShellExchange.session_id == ShellSession.id)
         .where(ShellSession.project_id == pr.id)
         .group_by(ShellSession.id, Target.host, Agent.name)
         .order_by(ShellSession.id.desc()))
    if active:
        q = q.where(ShellSession.state == "open")
    rows = (await session.execute(q)).all()
    return [_out(s, host, agent, pr.code, n) for s, host, agent, n in rows]


async def _session(session: AsyncSession, sid: int,
                   pr: Project) -> ShellSession:
    s = await session.get(ShellSession, sid)
    if s is None or s.project_id != pr.id:
        # Scoped to the project like every other id in this
        # application: a session id must not be a way to read another
        # engagement's shell.
        raise HTTPException(404, f"no session {sid} in {pr.code}")
    return s


@router.get("/sessions/{sid}", response_model=list[ExchangeOut])
async def transcript(sid: int, project: str = Query(...),
                     limit: int = Query(MAX_TAIL, ge=1, le=5000),
                     after: int = Query(
                         0, description="Only exchanges after this seq. "
                                        "What the terminal polls with."),
                     pr: Project = Depends(require_project("readonly")),
                     _: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """What was typed on this session and what came back.

    `after` makes this pollable without re-sending the whole session:
    a terminal asks for everything past the last seq it has.
    """
    await _session(session, sid, pr)
    rows = (await session.execute(
        select(ShellExchange, User.username)
        .outerjoin(User, User.id == ShellExchange.actor_id)
        .where(ShellExchange.session_id == sid, ShellExchange.seq > after)
        .order_by(ShellExchange.seq)
        .limit(limit))).all()
    return [ExchangeOut(
        id=e.id, seq=e.seq, command=e.command, output=e.output, actor=who,
        at=e.created_at.isoformat() if e.created_at else None)
        for e, who in rows]


@router.post("/sessions/{sid}/input", response_model=dict)
async def send(sid: int, body: InputIn, project: str = Query(...),
               pr: Project = Depends(require_project("user")),
               user: User = Depends(get_current_user),
               session: AsyncSession = Depends(get_session)):
    """Type at a shell.

    **`user`, not `readonly`.** This runs a command on a host in the
    client's estate, which is the most impactful thing this
    application can do -- more so than any scan, because what it does
    is whatever was typed. It is audited with the command itself for
    the same reason.

    The exchange row is written BEFORE the bytes go down. If the
    write fails the record still says what was attempted, which is
    the honest order: a command that may or may not have run is a
    thing the engagement needs to know about.
    """
    s = await _session(session, sid, pr)
    if s.state != "open":
        raise HTTPException(
            409, f"session {sid} is {s.state}. What was done on it is still "
                 f"readable, but there is nothing listening any more.")
    if not hub.holds(sid):
        # Open in the database, unreachable from here. Said as the
        # different thing it is: the shell may be alive and the route
        # to it gone, and "closed" would be a claim about the host.
        raise HTTPException(
            409, f"session {sid} is open but this server is not holding its "
                 f"tunnel right now — the Ghost may have reconnected. It "
                 f"should come back on its own.")

    data = body.data if body.data.endswith("\n") else body.data + "\n"
    nxt = ((await session.execute(
        select(func.coalesce(func.max(ShellExchange.seq), 0))
        .where(ShellExchange.session_id == sid))).scalar_one()) + 1
    row = ShellExchange(session_id=sid, seq=nxt, command=data.rstrip("\n"),
                        actor_id=user.id)
    session.add(row)
    s.last_seen_at = datetime.now(UTC)
    await session.commit()

    live = hub.live(sid)
    if live is not None:
        # Output from here belongs to this command until it goes
        # quiet. See shellhub's docstring on what that does and does
        # not claim.
        live.command = row.command
        live.buf = []
    ok = await hub.write(sid, data.encode())

    await audit.record(
        session, "ui", "c2.command", user=user, commit=True,
        project_code=pr.code,
        detail=f"session {sid}: {row.command[:300]}")
    await broker.publish("c2", action="input", project=pr.code, session=sid)
    return {"seq": nxt, "sent": ok}


@router.post("/sessions/{sid}/close", response_model=dict)
async def close(sid: int, project: str = Query(...),
                pr: Project = Depends(require_project("user")),
                user: User = Depends(get_current_user),
                session: AsyncSession = Depends(get_session)):
    """End a session. The transcript stays."""
    s = await _session(session, sid, pr)
    if s.state == "open":
        s.state = "closed"
        s.closed_at = datetime.now(UTC)
        await session.commit()
    await audit.record(session, "ui", "c2.close", user=user, commit=True,
                       project_code=pr.code, detail=f"closed session {sid}")
    await broker.publish("c2", action="closed", project=pr.code, session=sid)
    return {"ok": True, "state": s.state}


class LabelIn(BaseModel):
    label: str = ""


@router.post("/sessions/{sid}/label", response_model=dict)
async def relabel(sid: int, body: LabelIn, project: str = Query(...),
                  pr: Project = Depends(require_project("user")),
                  _: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Name a session. Blank clears it back to the host and peer."""
    s = await _session(session, sid, pr)
    s.label = (body.label or "").strip()[:200] or None
    await session.commit()
    return {"ok": True, "label": s.label}
