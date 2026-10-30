"""Turning shell tunnel frames into rows.

The frames arrive on the websocket in `routers/agents.py`; this is
what they mean. Kept out of the router because the router's job is
the socket and this is the engagement record -- and because a frame
handler that also does authentication is a frame handler nobody can
test without a websocket.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import proxytunnel
from .events import broker
from .models import Agent, Project, ShellExchange, ShellSession, Target
from .shellhub import FLUSH_AFTER, MAX_PENDING, hub, now

log = logging.getLogger("oddjob.shellwork")


async def _code(session: AsyncSession, project_id: int) -> str | None:
    """The engagement code a C2 event belongs to.

    The broker filters subscribers on the code, not on the id, so an
    event published with the id reaches site admins and nobody else --
    the project's own people never see the session appear. Resolving
    it is one identity-map hit in the common case.
    """
    pr = await session.get(Project, project_id)
    return pr.code if pr else None


async def on_frame(session: AsyncSession, agent: Agent,
                   frame: proxytunnel.Frame) -> None:
    """One frame from a Ghost's shell tunnel."""
    if frame.kind == proxytunnel.ARRIVED:
        await _arrived(session, agent, frame)
    elif frame.kind == proxytunnel.DATA:
        await _data(session, agent, frame)
    elif frame.kind == proxytunnel.CLOSE:
        await _closed(session, agent, frame)


async def _arrived(session: AsyncSession, agent: Agent,
                   frame: proxytunnel.Frame) -> None:
    """A callback landed on the Ghost's listener."""
    peer = frame.payload.decode("utf-8", "replace")[:64]
    host = peer.rsplit(":", 1)[0].strip("[]")

    # File it against the target it came from, where the project has
    # one. A callback from an address the inventory does not know is
    # still a shell and is still kept -- refusing it would mean
    # losing a live session because the inventory was behind.
    target = (await session.execute(
        select(Target).where(Target.project_id == agent.project_id,
                             Target.host == host))).scalar_one_or_none()

    s = ShellSession(
        project_id=agent.project_id,
        target_id=target.id if target else None,
        agent_id=agent.id, peer=peer, state="open",
        last_seen_at=datetime.now(UTC))
    session.add(s)
    await session.commit()

    hub.attach(agent.id, frame.stream, s.id)
    log.info("shell session %d: %s via %s", s.id, peer, agent.name)
    await broker.publish("c2", action="arrived",
                         project=await _code(session, agent.project_id),
                         session=s.id, peer=peer,
                         host=target.host if target else None)


async def _data(session: AsyncSession, agent: Agent,
                frame: proxytunnel.Frame) -> None:
    """Output from a shell."""
    t = hub.tunnel(agent.id)
    live = t.streams.get(frame.stream) if t else None
    if live is None:
        # A stream we have no session for. Dropped rather than
        # guessed at: writing it to whichever session was last would
        # put one host's output in another host's transcript.
        return

    text = frame.payload.decode("utf-8", "replace")
    live.buf.append(text)
    pending = "".join(live.buf)

    # Written out when it has been quiet, or when holding more would
    # mean holding a lot. A `find /` is megabytes and pairing it with
    # one command is not worth buffering megabytes to do.
    quiet = live.last_at and (now() - live.last_at) > FLUSH_AFTER
    live.last_at = now()
    if len(pending) < MAX_PENDING and not quiet:
        return
    await flush(session, live.session_id, live)


async def flush(session: AsyncSession, session_id: int, live) -> None:
    """Write buffered output to the transcript."""
    if not live.buf:
        return
    text = "".join(live.buf)
    live.buf = []

    s = await session.get(ShellSession, session_id)
    if s is None:
        return
    # Attach to the command that was waiting, if one still is. Past
    # that the output stands on its own with a NULL command -- see
    # the pairing note on `ShellExchange`.
    row = None
    if live.command is not None:
        row = (await session.execute(
            select(ShellExchange)
            .where(ShellExchange.session_id == session_id,
                   ShellExchange.command == live.command,
                   ShellExchange.output.is_(None))
            .order_by(ShellExchange.seq.desc()).limit(1))).scalars().first()
    if row is not None:
        row.output = (row.output or "") + text
    else:
        nxt = ((await session.execute(
            select(func.coalesce(func.max(ShellExchange.seq), 0))
            .where(ShellExchange.session_id == session_id))).scalar_one()) + 1
        session.add(ShellExchange(session_id=session_id, seq=nxt,
                                  command=None, output=text))
    s.last_seen_at = datetime.now(UTC)
    await session.commit()
    await broker.publish("c2", action="output",
                         project=await _code(session, s.project_id),
                         session=session_id)


async def _closed(session: AsyncSession, agent: Agent,
                  frame: proxytunnel.Frame) -> None:
    """The shell on the far end went away."""
    t = hub.tunnel(agent.id)
    live = t.streams.get(frame.stream) if t else None
    if live is not None:
        await flush(session, live.session_id, live)
    sid = hub.detach(agent.id, frame.stream)
    if sid is None:
        return
    s = await session.get(ShellSession, sid)
    if s is not None and s.state == "open":
        s.state = "closed"
        s.closed_at = datetime.now(UTC)
        await session.commit()
        await broker.publish("c2", action="closed",
                             project=await _code(session, s.project_id),
                             session=sid)


async def mark_lost(session: AsyncSession, session_ids: list[int]) -> None:
    """The tunnel went, not the shells.

    `lost` and not `closed`, because they are different facts and
    only one of them is about the host: the shell may be perfectly
    alive and what vanished is our route to it. A Ghost that
    reconnects brings its live streams back.
    """
    for sid in session_ids:
        s = await session.get(ShellSession, sid)
        if s is not None and s.state == "open":
            s.state = "lost"
            await session.commit()
            await broker.publish("c2", action="lost",
                                 project=await _code(session, s.project_id),
                                 session=sid)
