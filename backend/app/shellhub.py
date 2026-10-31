"""The server end of a Ghost's shell tunnel.

A Ghost holds a port open on infrastructure the engagement chose and
relays whatever calls back (see `ghost/internal/shell`). This is the
other end: it turns an arriving stream into a `ShellSession`, writes
every byte that crosses in either direction to `ShellExchange`, and
carries what an operator types back down.

# Why there is a registry at all

The websocket belongs to the Ghost's process on this server, and the
thing that wants to write to it is an HTTP request from a browser
somewhere else entirely. The registry is the one place they meet. It
is per-process and deliberately not shared: a second uvicorn worker
holding the same agent's tunnel would be two servers both believing
they own the socket.

# The pairing, and what it does not claim

`sh` emits nothing that says "the output of your last command ends
here". So an exchange is opened when a command is sent and output is
attributed to it until the next command goes down. Output with
nothing in front of it gets an exchange with a NULL command rather
than being glued to whichever command happened to be last.

That is why `flush_after` exists: output stops being attributed to a
command once it has been quiet for a moment, so a shell that prints
something a minute later does not have it recorded as the answer to
whatever was typed before.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import proxytunnel

log = logging.getLogger("oddjob.shellhub")

#: How long output goes on being attributed to the last command. Past
#: this it is recorded on its own -- see the module docstring.
FLUSH_AFTER = 2.0

#: How long to wait for more bytes before writing what we have.
#:
#: A DEBOUNCE, armed by a timer. It used to be `FLUSH_AFTER` tested
#: against the arrival of the NEXT frame, which meant the last chunk
#: of every command's output was never written at all -- nothing
#: else arrived to trigger the test, so `ls` produced a few hundred
#: bytes that sat in memory for ever and an operator saw an empty
#: terminal.
#:
#: Short, because this is interactive. Long enough to coalesce the
#: chunks of one `ls` into one row, short enough that output appears
#: while the operator is still looking at the screen.
FLUSH_IDLE = 0.3

#: Most output held for one exchange before it is written out. A
#: `find /` produces megabytes and holding it all to pair it with one
#: command would be holding megabytes.
MAX_PENDING = 256 * 1024

Send = Callable[[bytes], Awaitable[None]]


def _cancel(live: Live) -> None:
    """Stop a stream's pending flush, if it has one."""
    for name in ("timer", "probe_timer"):
        t = getattr(live, name, None)
        setattr(live, name, None)
        if t is not None and hasattr(t, "cancel"):
            t.cancel()


@dataclass
class Live:
    """One open stream: a shell somebody can type at."""
    session_id: int
    stream: int
    agent_id: int
    #: What was last typed, waiting for its output.
    command: str | None = None
    #: The exchange row it was written to.
    #:
    #: The ROW, not the text. Pairing by `command == live.command`
    #: looked equivalent and is not: run the same command twice and
    #: both rows match, the newest wins, and the first is left with
    #: no output for ever. An operator sees their command listed
    #: twice with one answer and reasonably concludes the first one
    #: did not run.
    exchange_id: int | None = None
    buf: list[str] = field(default_factory=list)
    last_at: float = 0.0
    #: The debounce in flight, if any. Cancelled and re-armed on
    #: every chunk, and cancelled when the stream goes -- a timer
    #: firing against a detached stream would open a session to
    #: write nothing.
    timer: object | None = None
    #: The "did anything answer" deadline, and whether the first
    #: bytes back have already been classified. See shellprobe.
    probe_timer: object | None = None
    judged: bool = False


@dataclass
class Tunnel:
    """One Ghost's shell tunnel."""
    agent_id: int
    send: Send
    #: stream id -> the live session on it
    streams: dict[int, Live] = field(default_factory=dict)


class Hub:
    """Every shell tunnel this process is holding."""

    def __init__(self) -> None:
        #: session id -> browsers watching it live. In memory and
        #: per process, like the tunnels: a websocket is only ever
        #: true of the process holding it.
        self._watchers: dict[int, list[Send]] = {}
        self._tunnels: dict[int, Tunnel] = {}
        self._by_session: dict[int, tuple[int, int]] = {}

    def register(self, agent_id: int, send: Send) -> Tunnel:
        """Take over as the tunnel for this agent.

        Replaces any existing one. A Ghost that reconnects has a new
        socket and the old one is already dead; keeping the first
        would mean writing commands into a closed connection and
        reporting them as sent.
        """
        self.drop(agent_id)
        t = Tunnel(agent_id=agent_id, send=send)
        self._tunnels[agent_id] = t
        return t

    def drop(self, agent_id: int) -> list[int]:
        """Forget this agent's tunnel. -> the sessions it was holding.

        The caller marks them lost. They are not closed: the shell on
        the far end may be perfectly alive and the thing that went is
        our route to it, and "the tunnel dropped" is a different fact
        from "the shell exited".
        """
        t = self._tunnels.pop(agent_id, None)
        if t is None:
            return []
        for sid in list(t.streams):
            self._by_session.pop(t.streams[sid].session_id, None)
            _cancel(t.streams[sid])
        return [live.session_id for live in t.streams.values()]

    def attach(self, agent_id: int, stream: int, session_id: int) -> Live:
        t = self._tunnels[agent_id]
        live = Live(session_id=session_id, stream=stream, agent_id=agent_id)
        t.streams[stream] = live
        self._by_session[session_id] = (agent_id, stream)
        return live

    def detach(self, agent_id: int, stream: int) -> int | None:
        t = self._tunnels.get(agent_id)
        if t is None:
            return None
        live = t.streams.pop(stream, None)
        if live is None:
            return None
        # A debounce still in flight would wake up, open a session
        # and write into a stream nobody is holding. Callers flush
        # before detaching, so there is nothing left for it to do.
        _cancel(live)
        self._by_session.pop(live.session_id, None)
        return live.session_id

    def live(self, session_id: int) -> Live | None:
        found = self._by_session.get(session_id)
        if found is None:
            return None
        t = self._tunnels.get(found[0])
        return t.streams.get(found[1]) if t else None

    def holds(self, session_id: int) -> bool:
        return self.live(session_id) is not None

    def watch(self, session_id: int, send: Send) -> None:
        """A browser wants this session's output as it happens.

        Separate from the transcript, which is written on a debounce
        and is the engagement record. A terminal needs the bytes
        NOW -- a prompt that arrives 300ms late is a prompt that
        arrives after you have typed the next thing.

        Several watchers per session on purpose: two operators on
        one shell is a normal way to work an engagement, and the
        alternative is the second one silently seeing nothing.
        """
        self._watchers.setdefault(session_id, []).append(send)

    def unwatch(self, session_id: int, send: Send) -> None:
        got = self._watchers.get(session_id)
        if not got:
            return
        with suppress(ValueError):
            got.remove(send)
        if not got:
            self._watchers.pop(session_id, None)

    async def fanout(self, session_id: int, data: bytes) -> None:
        """Push raw bytes to everyone watching this session.

        Failures drop the watcher rather than raising: a browser
        that closed its tab must not break the relay for the shell
        or for anybody else looking at it.
        """
        for send in list(self._watchers.get(session_id, ())):
            try:
                await send(data)
            except Exception:                            # noqa: BLE001
                self.unwatch(session_id, send)

    def watchers(self, session_id: int) -> int:
        return len(self._watchers.get(session_id, ()))

    def has_tunnel(self, agent_id: int) -> bool:
        """Whether THIS process is holding that Ghost's shell tunnel.

        Distinct from the agent being online: a Ghost beats over HTTP
        and tunnels over a websocket, and it is perfectly possible to
        be heartbeating while the tunnel is down. A listener on a
        Ghost whose tunnel is gone may well be bound and catching
        nothing we can see, so the Listeners tab shows this rather
        than letting the last reported state stand in for it.
        """
        return agent_id in self._tunnels

    async def write(self, session_id: int, data: bytes) -> bool:
        """Send bytes down to a shell. -> whether there was a route.

        False rather than an exception: a session whose tunnel went
        away is an ordinary thing on an engagement, and the caller
        reports it as "not connected" rather than as a server error.
        """
        found = self._by_session.get(session_id)
        if found is None:
            return False
        agent_id, stream = found
        t = self._tunnels.get(agent_id)
        if t is None:
            return False
        await t.send(proxytunnel.encode(proxytunnel.DATA, stream, data))
        return True

    async def terminate(self, session_id: int) -> bool:
        """Close the shell on the far end. -> whether the signal went.

        A CLOSE frame, not a row update: the Ghost closes the socket
        when it gets one, and closing the socket is what kills
        `nc -e /bin/sh` on the host. Marking the row closed without
        this left the shell running on the client's machine while
        Oddjob said the session had ended -- which is the wrong half
        of the engagement record to get wrong, because the thing
        still running is OURS.

        False when there is no route. The caller records what it
        could and says the far end was not reached, rather than
        claiming a kill nobody delivered.
        """
        found = self._by_session.get(session_id)
        if found is None:
            return False
        agent_id, stream = found
        t = self._tunnels.get(agent_id)
        if t is None:
            return False
        await t.send(proxytunnel.encode(proxytunnel.CLOSE, stream, b""))
        # Detached here rather than waiting for the Ghost's own CLOSE
        # to come back: the operator asked for this one to end, and a
        # session that lingers in the map until a reply arrives is a
        # session they can still type at.
        self.detach(agent_id, stream)
        return True

    def tunnel(self, agent_id: int) -> Tunnel | None:
        return self._tunnels.get(agent_id)

    def session_ids(self) -> list[int]:
        return list(self._by_session)


hub = Hub()


def now() -> float:
    return asyncio.get_running_loop().time()


def stamp() -> datetime:
    return datetime.now(UTC)
