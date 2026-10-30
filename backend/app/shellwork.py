"""Turning shell tunnel frames into rows.

The frames arrive on the websocket in `routers/agents.py`; this is
what they mean. Kept out of the router because the router's job is
the socket and this is the engagement record -- and because a frame
handler that also does authentication is a frame handler nobody can
test without a websocket.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import hosts, proxytunnel, shellprobe
from .db import SessionLocal
from .events import broker
from .models import Agent, Project, ShellExchange, ShellSession, Target
from .shellhub import FLUSH_IDLE, MAX_PENDING, hub, now
from .shellprobe import PROBE
from .timeline import record

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


def _announcement(payload: bytes) -> tuple[str, str | None, int | None, bool]:
    """`(peer, protocol, port, encrypted)` out of an ARRIVED frame.

    JSON from an agent that knows which of its listeners caught the
    callback, a bare address from one that does not. Both are
    accepted: a Ghost holding one port predates holding several, and
    an upgrade that silently stopped recording sessions would be a
    worse failure than not knowing the port.
    """
    raw = payload.decode("utf-8", "replace")
    if raw.startswith("{"):
        try:
            doc = json.loads(raw)
            port = doc.get("port")
            return (str(doc.get("peer") or "")[:64],
                    str(doc.get("protocol") or "") or None,
                    int(port) if isinstance(port, int) else None,
                    bool(doc.get("tls")))
        except (ValueError, TypeError):
            pass
    # A bare address, from a Ghost that predates any of this. Not
    # encrypted: that Ghost does not terminate TLS, so it is a fact
    # about it rather than a default.
    return raw[:64], None, None, False


async def _arrived(session: AsyncSession, agent: Agent,
                   frame: proxytunnel.Frame) -> None:
    """A callback landed on the Ghost's listener."""
    peer, proto, port, encrypted = _announcement(frame.payload)
    host = peer.rsplit(":", 1)[0].strip("[]")

    # File it against the target it came from, where the project has
    # one. A callback from an address the inventory does not know is
    # still a shell and is still kept -- refusing it would mean
    # losing a live session because the inventory was behind.
    target = (await session.execute(
        select(Target).where(Target.project_id == agent.project_id,
                             Target.host == host))).scalar_one_or_none()
    if target is None:
        target = await _target_for_peer(session, agent.project_id, host)

    s = ShellSession(
        project_id=agent.project_id,
        target_id=target.id if target else None,
        agent_id=agent.id, peer=peer, listen_port=port,
        encrypted=encrypted, state="open",
        last_seen_at=datetime.now(UTC))
    session.add(s)
    await session.flush()

    where = f"{proto or 'tcp'}/{port}" if port else "the ghost's listener"
    if encrypted:
        where += " over TLS"
    if target is not None:
        # A shell IS the compromise. Nothing else an engagement
        # produces is better evidence that a host is owned, so this
        # sets the same flag an imported Cobalt Strike beacon sets --
        # and like that one it is never cleared here: losing a shell
        # is not evidence the access is gone.
        newly = not target.hacked
        target.hacked = True
        await record(session, target.id,
                     "status" if newly else "note",
                     f"compromised — shell caught on {where}" if newly
                     else f"another shell caught on {where}",
                     detail=f"session {s.id} from {peer}, via {agent.name}",
                     actor=f"ghost:{agent.name}", source="c2")
    await session.commit()

    live = hub.attach(agent.id, frame.stream, s.id)
    log.info("shell session %d: %s on %s via %s", s.id, peer, where, agent.name)

    # One harmless command, to find out whether anything on the far
    # end is a shell at all. A reverse shell says nothing until it
    # is typed at, so silence is the only thing that distinguishes
    # it from a port scanner -- and the answer names the box, which
    # is worth having on its own.
    #
    # `command` is set so the reply pairs with it in the transcript,
    # and the actor is Oddjob rather than a person: this is traffic
    # WE generated and the record should not suggest otherwise.
    live.command = PROBE.decode().strip()
    if await hub.write(s.id, PROBE):
        session.add(ShellExchange(session_id=s.id, seq=1,
                                  command=live.command, output=None,
                                  actor_id=None))
        await session.commit()
    _arm_probe(live, s.id)
    code = await _code(session, agent.project_id)
    await broker.publish("c2", action="arrived", project=code,
                         session=s.id, peer=peer,
                         host=target.host if target else None)
    if target is not None:
        # The pill lives on the target, so the Targets grid and the
        # host modal have to be told too. Publishing `c2` alone left
        # a host that had just been owned still reading as clean
        # until something else happened to refresh it.
        await broker.publish("targets", action="update", project=code,
                             host=target.host)


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

    # The FIRST bytes decide what this peer is. Only the first: a
    # `cat` of a certificate later in a real session would
    # otherwise re-classify it as a scanner halfway through.
    if not live.judged:
        live.judged = True
        state, why = shellprobe.classify(frame.payload)
        if state != shellprobe.PENDING:
            await _judge(live.session_id, state, why)

    text = frame.payload.decode("utf-8", "replace")
    live.buf.append(text)
    live.last_at = now()

    # Straight out when holding more would mean holding a lot. A
    # `find /` is megabytes and pairing it with one command is not
    # worth buffering megabytes to do.
    if sum(len(x) for x in live.buf) >= MAX_PENDING:
        _disarm(live)
        await flush(session, live.session_id, live)
        return

    # Otherwise wait a moment for the rest of it, and write it out
    # when the shell stops talking.
    #
    # On a TIMER. This used to compare the arrival time of the NEXT
    # frame against the last one -- so the final chunk of every
    # command's output was never written, because nothing else
    # arrived to make the comparison. `ls` produced a few hundred
    # bytes that sat in this buffer for ever and the operator saw an
    # empty terminal. It only looked like it worked at all because a
    # 256 KB dump crosses MAX_PENDING on its own.
    _arm(live)


def _disarm(live) -> None:
    t = live.timer
    live.timer = None
    if t is not None:
        t.cancel()


def _arm(live) -> None:
    """(Re)start the debounce for this stream."""
    _disarm(live)
    live.timer = asyncio.create_task(_after_quiet(live))


async def _after_quiet(live) -> None:
    """Write the buffer once the shell has stopped talking.

    Its OWN session. The websocket handler's session belongs to a
    coroutine that is concurrently reading frames, and two tasks on
    one AsyncSession is a corruption bug that shows up as something
    else entirely.
    """
    try:
        await asyncio.sleep(FLUSH_IDLE)
    except asyncio.CancelledError:
        return
    live.timer = None
    try:
        async with SessionLocal() as s:
            await flush(s, live.session_id, live)
    except Exception as e:                                   # noqa: BLE001
        # Never raises into the task runner: a shell that loses one
        # flush is better than a background exception nobody sees,
        # and the next chunk re-arms the timer anyway.
        log.warning("flushing session %d: %s", live.session_id, e)


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
        # Disarmed first: the flush below writes everything, and a
        # timer firing afterwards would be a second write of nothing.
        _disarm(live)
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
    alive and what vanished is our route to it.

    It does NOT come back. This said "a Ghost that reconnects brings
    its live streams back", and the agent does the opposite -- a
    dropped tunnel makes it release its listeners and close every
    socket on them, because a listener bound to a dead mux catches
    callbacks that go nowhere (see `shell.Manager`). So `lost` means
    gone, and the UI must not promise a recovery that the agent is
    not written to perform.
    """
    for sid in session_ids:
        s = await session.get(ShellSession, sid)
        if s is not None and s.state == "open":
            s.state = "lost"
            await session.commit()
            await broker.publish("c2", action="lost",
                                 project=await _code(session, s.project_id),
                                 session=sid)


async def adopt_orphans(session: AsyncSession) -> int:
    """Mark sessions this process cannot be holding. -> how many.

    Called at startup. A row saying `open` is a claim that a socket
    is live on a Ghost and that THIS process has a tunnel to it --
    and at boot it holds no tunnels at all, so every such row is a
    claim nothing backs.

    Nothing reconciled them before: the websocket handler marks its
    own sessions lost when it disconnects, but a server that is
    killed or redeployed never runs that handler. The rows survived
    the restart, the in-memory hub did not, and the UI showed
    "open, but this server is not holding its tunnel right now -- it
    should come back on its own" for ever. It does not come back:
    the Ghost closed those sockets when the tunnel dropped.

    `lost`, not `closed`, for the same reason as `mark_lost`: we
    know our route is gone, not that the shell died. Operators
    terminate a session when they want to assert the second.
    """
    rows = (await session.execute(
        select(ShellSession).where(ShellSession.state == "open"))).scalars().all()
    if not rows:
        return 0
    for s in rows:
        s.state = "lost"
    await session.commit()
    log.info("marked %d shell session(s) lost: this process holds no "
             "tunnels at startup", len(rows))
    return len(rows)


async def _judge(session_id: int, state: str, why: str) -> None:
    """Record what the far end turned out to be. Its own session.

    Never overwrites a decision already made: the first answer is
    the one taken, for the reason in `_data`.
    """
    try:
        async with SessionLocal() as s:
            row = await s.get(ShellSession, session_id)
            if row is None or row.probe != shellprobe.PENDING:
                return
            row.probe = state
            row.probe_note = why[:200] or None
            await s.commit()
            log.info("session %d looks like a %s: %s", session_id, state, why)
            await broker.publish("c2", action="probe",
                                 project=await _code(s, row.project_id),
                                 session=session_id, probe=state)
    except Exception as e:                                   # noqa: BLE001
        log.warning("judging session %d: %s", session_id, e)


def _arm_probe(live, session_id: int) -> None:
    """Call it silent if nothing comes back in time."""
    live.probe_timer = asyncio.create_task(_probe_deadline(session_id))


async def _probe_deadline(session_id: int) -> None:
    try:
        await asyncio.sleep(shellprobe.WINDOW)
    except asyncio.CancelledError:
        return
    # `silent`, not `scanner`. Nothing answered, which is not the
    # same as something answering wrongly -- a real shell can be
    # slow, speak its own protocol, or never have received the
    # probe at all. The list shows these; it only hides the ones
    # positively identified as something else.
    await _judge(session_id, shellprobe.SILENT,
                 "nothing came back within "
                 f"{int(shellprobe.WINDOW)}s of being asked")


async def _target_for_peer(session: AsyncSession, project_id: int,
                           host: str) -> Target | None:
    """Make a target for an address that called back. -> it, or None.

    **A callback is the strongest evidence an engagement produces
    that a host exists and is reachable**, which is a better claim
    than most rows in the inventory have. So the address gets a
    target rather than a session filed against nothing.

    The caution this replaces was that the source of a callback is
    as often a NAT egress as the box that was popped, and a target
    invented from one is a host nobody can find. That is still true
    and it is why the row says where it came from -- and why
    "merge with target" exists, so an operator who knows the real
    name can re-point the session at it.

    Refused addresses are still refused: `0.0.0.0`, loopback,
    link-local and the rest cannot be targets however they arrive,
    and a callback from one is a Ghost talking to itself.
    """
    if (why := hosts.address_refusal(host)) is not None:
        log.info("callback from %s gets no target: %s", host, why)
        return None
    # `alive` is a fact we just observed: it connected to us. The
    # address itself IS the host here, so there is no separate
    # address column to fill -- see `target_addresses`, which is
    # populated by resolution rather than by a callback.
    t = Target(project_id=project_id, host=host, kind="host", alive=True,
               notes="Created from a C2 callback: this address connected "
                     "to a listener, which is evidence it exists and is "
                     "reachable. It may be a NAT egress rather than the "
                     "host itself -- re-point the session if you know "
                     "the real name.")
    session.add(t)
    try:
        await session.flush()
    except Exception as e:                                   # noqa: BLE001
        # A race with anything else creating the same host. Take
        # theirs: the unique key is (project_id, host) and either
        # row is the same fact.
        await session.rollback()
        log.info("target for %s already exists (%s)", host, e)
        return (await session.execute(
            select(Target).where(Target.project_id == project_id,
                                 Target.host == host))).scalar_one_or_none()
    await record(session, t.id, "status",
                 f"created from a C2 callback from {host}",
                 actor="oddjob", source="c2")
    log.info("created target %s from a callback", host)
    return t
