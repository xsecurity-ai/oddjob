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

import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, hosts, listeners
from ..db import SessionLocal, get_session
from ..events import broker
from ..models import Agent, Project, ShellExchange, ShellListener, ShellSession, Target, User
from ..security import COOKIE, decode_token, effective_role, get_current_user, require_project
from ..shellhub import hub
from ..timeline import record

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
    #: WHOSE address that is: country, city, ASN, organisation.
    #:
    #: Looked up on read, like a ghost's own address and for the same
    #: reasons -- there are few sessions and a stored answer would go
    #: stale. None when geolocation is off, no database is installed,
    #: or the address is private.
    #:
    #: Here because "is this our payload or somebody scanning the
    #: internet" is the first question a callback raises, and a bare
    #: address does not answer it. A listener on 443 open to the
    #: world catches both, and telling them apart by squinting at an
    #: octet is how a real shell gets dismissed as noise -- or noise
    #: gets written up as a shell.
    peer_geo: dict | None
    #: pending | shell | scanner | silent. Whether anything on the
    #: far end behaves like a shell -- see `app/shellprobe.py`.
    #: Whether the Ghost terminated TLS for this callback. One
    #: listener takes both, so this is per session rather than per
    #: port -- and it says whether the shell crossed the client's
    #: network in cleartext.
    encrypted: bool
    probe: str
    probe_note: str | None
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


def _peer_geo(peer: str | None) -> dict | None:
    """Where a callback came from, and whose network it is.

    `peer` is `host:port` as the Ghost saw it, so the port is
    stripped first -- and an IPv6 peer is `[::1]:4444`, which is why
    this splits on the LAST colon and unwraps the brackets rather
    than taking the first field.
    """
    if not peer:
        return None
    host = peer.rsplit(":", 1)[0].strip("[]")
    if not host:
        return None
    try:
        from .. import geoip
        loc = geoip.lookup(host)
    except Exception:                            # noqa: BLE001
        # Geolocation being unavailable is ordinary and is not worth
        # failing a session listing over.
        return None
    if not loc.known:
        return None
    return {"country": loc.country, "country_name": loc.country_name,
            "city": loc.city, "asn": loc.asn, "org": loc.organisation}


def _out(s: ShellSession, host: str | None, agent: str | None,
         code: str, n: int) -> SessionOut:
    return SessionOut(
        id=s.id, project_code=code, host=host, target_id=s.target_id,
        agent_name=agent, peer=s.peer, peer_geo=_peer_geo(s.peer),
        encrypted=bool(s.encrypted),
        probe=s.probe, probe_note=s.probe_note,
        listen_port=s.listen_port,
        state=s.state, label=s.label, connected=hub.holds(s.id),
        exchanges=n,
        opened_at=s.created_at.isoformat() if s.created_at else None,
        last_seen_at=s.last_seen_at.isoformat() if s.last_seen_at else None)


@router.get("/sessions", response_model=list[SessionOut])
async def list_sessions(project: str = Query(...),
                        state: str = Query(
                            "live", pattern="^(live|ended|all)$",
                            description="live: still open. ended: closed or "
                                        "lost, which are kept for the "
                                        "record. all: both."),
                        scans: bool = Query(
                            False, description="Include peers identified as "
                                               "port scanners. They are kept "
                                               "either way; this only hides "
                                               "them."),
                        pr: Project = Depends(require_project("readonly")),
                        _: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Every shell on this engagement, newest first.

    Live by default: a long engagement accumulates ended sessions
    and the question on opening this page is almost always "what can
    I type at right now". The ended ones are a tab away and are
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
    if state == "live":
        q = q.where(ShellSession.state == "open")
    elif state == "ended":
        # `closed` and `lost` together. They are different facts --
        # one is a shell that ended, the other is a route that went
        # -- and the row says which, but both answer "not live", so
        # separating them into two more tabs would be splitting on
        # a distinction the operator is not browsing by.
        q = q.where(ShellSession.state != "open")
    if not scans:
        # Only the ones POSITIVELY identified as something else --
        # an HTTP request, a TLS handshake, an SSH banner. `silent`
        # stays visible: nothing answered, which is not the same as
        # something answering wrongly, and a real shell can be slow
        # or speak its own protocol. Hiding those would make an
        # absence of evidence into evidence.
        q = q.where(ShellSession.probe != "scanner")
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
        live.exchange_id = row.id
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
    """Terminate a session. The transcript stays.

    **This kills the shell, it does not merely file the row.** A
    CLOSE frame goes down the tunnel and the Ghost closes the
    socket, which is what ends `nc -e /bin/sh` on the host. Marking
    the row closed on its own left our own shell running on a
    client's machine while Oddjob said the session had ended, and
    that is the worse direction for the record to be wrong in: the
    thing still running belongs to us.

    `terminated` says whether the signal was delivered. False means
    the row is closed here and the far end was not reached -- which
    is a real outcome on an engagement and has to be reported as
    itself rather than folded into success.
    """
    s = await _session(session, sid, pr)
    terminated = await hub.terminate(sid)
    if s.state in ("open", "lost"):
        s.state = "closed"
        s.closed_at = datetime.now(UTC)
        await session.commit()
    await audit.record(
        session, "ui", "c2.close", user=user, commit=True,
        project_code=pr.code,
        detail=f"terminated session {sid}"
               + ("" if terminated else " (no route; row closed only)"))
    await broker.publish("c2", action="closed", project=pr.code, session=sid)
    return {"ok": True, "state": s.state, "terminated": terminated,
            "note": "The shell was closed on the host."
                    if terminated else
                    "Recorded as closed here. There was no route to the "
                    "ghost, so if that shell is still alive it will stay "
                    "alive until something on the host ends it."}


class RetargetIn(BaseModel):
    #: The host to file this session against. Created if the
    #: project has no target for it.
    host: str = Field(min_length=1, max_length=255)


@router.post("/sessions/{sid}/target", response_model=dict)
async def retarget(sid: int, body: RetargetIn, project: str = Query(...),
                   pr: Project = Depends(require_project("user")),
                   user: User = Depends(get_current_user),
                   session: AsyncSession = Depends(get_session)):
    """File this session against a different host.

    A callback arrives from an ADDRESS, and the address is as often
    a NAT egress as the box that was popped. The operator is the
    one who knows which -- usually because the shell just told
    them -- so this re-points the session at the real host.

    **Only a host the project already has.** Creating one from here
    was wrong in a way that is quiet: a typo makes a second target
    one character different from the real one, the session goes to
    it, and the engagement now has two rows for one machine with the
    evidence split between them. The inventory is where a host is
    added, deliberately and once.

    A callback still CREATES a target for the address it came from,
    on arrival -- so there is always something to move away from.
    That one is a fact we observed; this one would be a guess an
    operator typed.

    **The compromise follows the session.** Moving a shell to a
    host means that host is the one with a shell on it, so the
    pwned flag and a timeline entry go with it. The flag is not
    removed from the old target: it was true when it was set, and
    nothing here has learned otherwise.
    """
    s = await _session(session, sid, pr)
    # `validate_host` is the one place that decides what can be a
    # target -- addresses and names both, with the refusals that
    # keep `0.0.0.0` and `localhost` out. Branching on the shape
    # here would be a second opinion that drifts from it.
    try:
        host = hosts.validate_host(body.host)
    except hosts.InvalidHost as e:
        raise HTTPException(422, str(e)) from e

    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == host))).scalar_one_or_none()
    if t is None:
        raise HTTPException(
            404, f"{pr.code} has no target {host!r}. A session can only be "
                 f"moved to a host the engagement already knows -- add it "
                 f"on the Targets page first, so one machine does not end "
                 f"up as two rows a character apart.")

    was = s.target_id
    s.target_id = t.id
    # A shell on a host is the compromise, wherever the session was
    # filed before. Set here as well as on arrival because this is
    # the point at which we learn WHICH host it was.
    newly = not t.hacked
    t.hacked = True
    await record(session, t.id, "status" if newly else "note",
                 f"compromised — shell session {sid} moved here"
                 if newly else f"shell session {sid} moved here",
                 detail=f"from {s.peer}", actor=user, source="c2")
    await session.commit()
    await audit.record(
        session, "ui", "c2.retarget", user=user, commit=True,
        project_code=pr.code,
        detail=f"session {sid}: target {was} -> {t.id} ({host})")
    await broker.publish("c2", action="retargeted", project=pr.code,
                         session=sid)
    await broker.publish("targets", action="update", project=pr.code,
                         host=host)
    return {"ok": True, "host": host, "target_id": t.id}


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


#: How much typing to hold before writing it to the transcript.
#:
#: A terminal sends a keystroke at a time, and a row per keystroke
#: would be a transcript nobody can read and a database nobody
#: should have. Buffered and written as a line, which is the unit
#: an operator thinks in.
TYPING_IDLE = 0.6


@router.websocket("/sessions/{sid}/ws")
async def terminal(ws: WebSocket, sid: int, project: str = Query(...),
                   session: AsyncSession = Depends(get_session)):
    """A live terminal on one session.

    Raw bytes both ways, which is what a terminal is. The polled
    transcript stays as the engagement record and is a different
    view of the same session -- this is for working the shell, that
    is for reading what was done.

    **Authenticated from the cookie.** A WebSocket cannot carry an
    Authorization header any more than an EventSource can, which is
    why login sets an httpOnly cookie; this is the same path
    `/api/events` takes. `user` on the project, not `readonly`:
    everything typed here runs on a host in the client's estate.

    What is typed is recorded, buffered into lines. A row per
    keystroke would be a transcript nobody can read -- but dropping
    attribution entirely would mean the record cannot say who ran
    what, and on an engagement that is the question that matters.
    """
    user = await _ws_user(ws, session)
    if user is None:
        await ws.accept()
        await ws.close(code=1008, reason="not authenticated")
        return
    pr = await _ws_project(session, user, project)
    if pr is None:
        await ws.accept()
        await ws.close(code=1008, reason=f"no write access to {project}")
        return
    s = await session.get(ShellSession, sid)
    if s is None or s.project_id != pr.id:
        await ws.accept()
        await ws.close(code=1008, reason=f"no session {sid} in {project}")
        return

    await ws.accept()

    async def push(data: bytes) -> None:
        await ws.send_bytes(data)

    hub.watch(sid, push)
    typed: list[str] = []
    flusher: asyncio.Task | None = None

    async def record_typing() -> None:
        """Write what was typed, once it stops."""
        try:
            await asyncio.sleep(TYPING_IDLE)
        except asyncio.CancelledError:
            return
        text, typed[:] = "".join(typed), []
        if not text.strip():
            return
        async with SessionLocal() as own:
            nxt = ((await own.execute(
                select(func.coalesce(func.max(ShellExchange.seq), 0))
                .where(ShellExchange.session_id == sid))).scalar_one()) + 1
            own.add(ShellExchange(session_id=sid, seq=nxt,
                                  command=text.rstrip("\r\n"),
                                  actor_id=user.id))
            await own.commit()
        await audit.record(
            session, "ui", "c2.command", user=user, commit=True,
            project_code=pr.code,
            detail=f"session {sid}: {text.rstrip()[:300]}")

    try:
        while True:
            data = await ws.receive_bytes()
            if not await hub.write(sid, data):
                # No route. Said rather than swallowed: an operator
                # typing into a dead session needs to know, and the
                # alternative is characters that vanish.
                await ws.send_bytes(
                    b"\r\n[oddjob] no route to this shell right now\r\n")
                continue
            typed.append(data.decode("utf-8", "replace"))
            if flusher is not None:
                flusher.cancel()
            flusher = asyncio.create_task(record_typing())
    except WebSocketDisconnect:
        pass
    except Exception as e:                                   # noqa: BLE001
        log.info("terminal for session %d ended: %s", sid, e)
    finally:
        hub.unwatch(sid, push)
        if flusher is not None:
            flusher.cancel()
        # Whatever was mid-flight still gets recorded: a tab closed
        # after typing is not a reason to lose what was typed.
        if typed:
            with suppress(Exception):
                await record_typing()


async def _ws_user(ws: WebSocket, session: AsyncSession) -> User | None:
    """The signed-in user behind a websocket, from the cookie.

    The same token the rest of the application takes, read from the
    place a browser can actually put it. Returns None rather than
    raising: the socket is not accepted yet, so there is nothing to
    send a status on.
    """
    token = ws.cookies.get(COOKIE)
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    u = await session.get(User, int(payload.get("sub", 0)))
    return u if u and u.is_active else None


async def _ws_project(session: AsyncSession, user: User,
                      code: str) -> Project | None:
    """The project, if this user may WRITE to it."""
    pr = (await session.execute(
        select(Project).where(Project.code == code))).scalar_one_or_none()
    if pr is None:
        return None
    role = await effective_role(session, user, pr.id)
    return pr if role in ("user", "admin") else None


# ------------------------------------------------------------ listeners
#
# A listener is the thing that makes a callback possible at all, and
# until now it was implicit: a port came up because a task asked for
# one and went away when the task finished. That is the wrong
# lifetime for a shell. A payload already sent calls back on its own
# schedule -- minutes later, or at 2am when cron fires -- and the port
# has to be there when it does.


class ListenerOut(BaseModel):
    id: int
    agent_id: int
    agent_name: str | None
    #: Whether Oddjob is holding that Ghost's shell tunnel right now.
    #: A listener on a Ghost nothing can reach is not catching
    #: anything, and the row has to say so rather than showing the
    #: last state it reported before it went away.
    agent_online: bool
    #: Where a payload is told to call back TO. The Ghost's public
    #: address, and what it is called from a public resolver --
    #: together, because an operator writing a payload needs one of
    #: them and which one depends on the target.
    agent_ip: str | None
    agent_name_public: str | None
    #: Why there is no name, when there is none. "no PTR record" and
    #: "the resolver could not be reached" are different facts and
    #: only the first is about the address.
    agent_name_note: str | None
    #: False when the Ghost says it cannot bind below 1024. NULL
    #: means it has not told us, which is not the same.
    agent_can_bind_privileged: bool | None
    protocol: str
    port: int
    enabled: bool
    state: str
    state_detail: str | None
    state_at: str | None
    note: str | None
    #: How many shells have landed on it. The number that says whether
    #: a listener is doing its job.
    sessions: int


class ListenerIn(BaseModel):
    agent_id: int
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")
    #: Several at once, because an operator setting up a catch opens
    #: the handful of ports a client's egress filter is likely to
    #: allow rather than one and then another.
    ports: list[int] = Field(min_length=1, max_length=32)
    note: str | None = Field(default=None, max_length=300)


class ListenerPatch(BaseModel):
    enabled: bool | None = None
    note: str | None = Field(default=None, max_length=300)


def _listener_out(r: ShellListener, agent: Agent | None,
                  sessions: int) -> ListenerOut:
    return ListenerOut(
        id=r.id, agent_id=r.agent_id,
        agent_name=agent.name if agent else None,
        agent_online=hub.has_tunnel(r.agent_id),
        agent_ip=agent.outbound_ip if agent else None,
        agent_name_public=agent.public_name if agent else None,
        agent_name_note=agent.public_name_note if agent else None,
        agent_can_bind_privileged=(
            agent.can_bind_privileged if agent else None),
        protocol=r.protocol, port=r.port, enabled=bool(r.enabled),
        state=r.state, state_detail=r.state_detail,
        state_at=r.state_at.isoformat() if r.state_at else None,
        note=r.note, sessions=sessions)


@router.get("/listeners", response_model=list[ListenerOut])
async def list_listeners(project: str = Query(...),
                         pr: Project = Depends(require_project("readonly")),
                         _: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """Which Ghost is holding which port on this engagement.

    Counting sessions by `(agent, port)` rather than by a foreign key
    to the listener row: a session is evidence and outlives the
    configuration that caught it, so deleting a listener must not
    take its shells with it or renumber what they landed on.
    """
    rows = (await session.execute(
        select(ShellListener, Agent)
        .outerjoin(Agent, Agent.id == ShellListener.agent_id)
        .where(ShellListener.project_id == pr.id)
        .order_by(Agent.name, ShellListener.protocol,
                  ShellListener.port))).all()
    counts = {(a, p): n for a, p, n in (await session.execute(
        select(ShellSession.agent_id, ShellSession.listen_port,
               func.count(ShellSession.id))
        .where(ShellSession.project_id == pr.id)
        .group_by(ShellSession.agent_id, ShellSession.listen_port))).all()}
    return [_listener_out(r, agent, counts.get((r.agent_id, r.port), 0))
            for r, agent in rows]


@router.post("/listeners", response_model=dict)
async def add_listeners(body: ListenerIn, project: str = Query(...),
                        pr: Project = Depends(require_project("user")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Tell a Ghost to hold these ports.

    `user`, not `readonly`: this binds a port on infrastructure the
    engagement owns and invites a connection to it.

    Nothing is pushed. The Ghost picks it up on its next heartbeat,
    which is seconds, and the row says `pending` until it reports --
    saying "listening" the moment the row is written would be a claim
    about a bind that has not happened.
    """
    a = await session.get(Agent, body.agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, f"no ghost {body.agent_id} in {pr.code}")
    if a.status == "disabled":
        # A retired Ghost will never beat again, so the row would sit
        # at `pending` for ever looking like a slow agent.
        raise HTTPException(409, f"{a.name} is retired and will not take a listener")

    made, refused = await listeners.add(session, a, body.protocol, body.ports,
                                        note=body.note, actor=user)
    if made:
        await session.commit()
        await audit.record(
            session, "ui", "c2.listener.add", user=user, commit=True,
            project_code=pr.code,
            detail=f"{a.name}: {body.protocol} "
                   + ", ".join(str(r.port) for r in made))
        await broker.publish("c2", action="listeners", project=pr.code,
                             agent=a.id)
    return {"ok": True, "added": [r.port for r in made], "refused": refused,
            "note": f"{a.name} picks this up on its next heartbeat."}


@router.patch("/listeners/{lid}", response_model=dict)
async def patch_listener(lid: int, body: ListenerPatch,
                         project: str = Query(...),
                         pr: Project = Depends(require_project("user")),
                         user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """Turn one off, or back on, or retitle it."""
    r = await session.get(ShellListener, lid)
    if r is None or r.project_id != pr.id:
        raise HTTPException(404, f"no listener {lid} in {pr.code}")
    if body.enabled is not None and bool(body.enabled) != bool(r.enabled):
        r.enabled = bool(body.enabled)
        # Back to pending either way: what the Ghost last said was
        # about a port it is no longer being asked to hold, and
        # showing "bound" against a disabled listener is a lie the
        # operator would have no way to catch.
        r.state, r.state_detail, r.state_at = "pending", None, None
    if body.note is not None:
        r.note = body.note or None
    await session.commit()
    await audit.record(
        session, "ui", "c2.listener.patch", user=user, commit=True,
        project_code=pr.code,
        detail=f"{r.protocol}/{r.port} on ghost {r.agent_id}: "
               + ("enabled" if r.enabled else "disabled"))
    await broker.publish("c2", action="listeners", project=pr.code,
                         agent=r.agent_id)
    return {"ok": True, "enabled": bool(r.enabled)}


@router.delete("/listeners/{lid}", status_code=204)
async def delete_listener(lid: int, project: str = Query(...),
                          pr: Project = Depends(require_project("user")),
                          user: User = Depends(get_current_user),
                          session: AsyncSession = Depends(get_session)):
    """Stop holding the port.

    The sessions it caught stay. They are evidence about a host and
    have nothing to do with the configuration that happened to catch
    them -- see the note on counting in `list_listeners`.
    """
    r = await session.get(ShellListener, lid)
    if r is None or r.project_id != pr.id:
        raise HTTPException(404, f"no listener {lid} in {pr.code}")
    agent_id, what = r.agent_id, f"{r.protocol}/{r.port}"
    await session.delete(r)
    await session.commit()
    await audit.record(
        session, "ui", "c2.listener.delete", user=user, commit=True,
        project_code=pr.code, detail=f"{what} on ghost {agent_id}")
    await broker.publish("c2", action="listeners", project=pr.code,
                         agent=agent_id)
