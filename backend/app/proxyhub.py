"""The live tunnels, and the streams running over them.

One `Tunnel` per connected Ghost, many `Stream`s over each. This is
the stateful middle of the proxy: `socks.py` decides, `proxytunnel.py`
frames, the Ghost relays, and this routes frames to the stream that
is waiting for them.

**Memory only, and that is correct.** A tunnel is a live socket held
by one process; a row in a database describing it would be a claim
about a connection some other worker might not have. When the
process restarts the tunnels are gone and the Ghosts redial, which
is the behaviour you want from a thing that is only true while it is
connected.

# Stream ids belong to the server

The Ghost only ever echoes one back. Two sides allocating into one
space collide eventually, and the symptom is one browser tab reading
another's bytes -- which looks like corruption rather than like a
routing bug, and is therefore the kind of thing worth making
impossible rather than unlikely.

Ids are not reused inside a tunnel. A 32-bit counter at even a
thousand streams a second lasts seven weeks; a tunnel lives hours,
and wrapping would mean a late frame for a dead stream landing in a
live one.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .proxytunnel import (
    CLOSE,
    DATA,
    FAILED,
    OPEN,
    OPENED,
    Frame,
    encode,
    encode_open,
)

log = logging.getLogger("oddjob.proxy")

#: How long to wait for a Ghost to report back on a dial. A SOCKS
#: client is a browser with its own patience, and holding the socket
#: past this teaches the operator the proxy is broken rather than
#: that the target is.
DIAL_TIMEOUT = 20.0

#: Per-stream inbound queue depth, in frames. Backpressure rather
#: than buffering: a browser that is not reading should slow the
#: target down, not make this process hold its response in memory.
QUEUE_DEPTH = 64

Sender = Callable[[bytes], Awaitable[None]]


class TunnelGone(Exception):
    """The Ghost's tunnel ended while something was using it."""


@dataclass
class Stream:
    """One proxied connection, from this side."""
    id: int
    tunnel: Tunnel
    #: Which credential opened it. Carried so a revocation can reach
    #: the connections that credential is already holding: `decide`
    #: runs once per CONNECT, so without this a revoked credential
    #: keeps relaying over any tunnel it established beforehand --
    #: and revocation is usually the response to a credential having
    #: leaked, which is the moment that matters most.
    #:
    #: None for a stream opened before the grant was known, which
    #: nothing does today; a revocation leaves those alone rather
    #: than guessing they belong to it.
    grant_id: int | None = None
    inbox: asyncio.Queue[bytes | None] = field(
        default_factory=lambda: asyncio.Queue(QUEUE_DEPTH))
    #: Resolved when the Ghost says the dial worked or did not.
    opened: asyncio.Future[str | None] = field(default_factory=asyncio.Future)
    closed: bool = False

    async def send(self, data: bytes) -> None:
        """Push bytes towards the target."""
        if self.closed:
            raise TunnelGone("stream is closed")
        await self.tunnel.send(encode(DATA, self.id, data))

    async def recv(self) -> bytes | None:
        """Next bytes from the target, or None once it is over."""
        return await self.inbox.get()

    async def close(self) -> None:
        """Tell the Ghost to drop it, and stop reading."""
        if self.closed:
            return
        self.closed = True
        with contextlib.suppress(Exception):
            await self.tunnel.send(encode(CLOSE, self.id, b""))
        self._finish()

    def _finish(self) -> None:
        """Mark it over for whoever is reading."""
        self.closed = True
        with contextlib.suppress(asyncio.QueueFull):
            self.inbox.put_nowait(None)
        if not self.opened.done():
            self.opened.set_result("the tunnel ended")


class Tunnel:
    """One Ghost's WebSocket, and the streams over it."""

    def __init__(self, agent_id: int, send: Sender) -> None:
        self.agent_id = agent_id
        self._send = send
        self._streams: dict[int, Stream] = {}
        self._next = 1
        self._gone = False
        # Writes are serialised. The websocket library on the other
        # side is safe for concurrent writes; this one is not
        # guaranteed to be, and several streams write at once by
        # design.
        self._lock = asyncio.Lock()

    @property
    def live(self) -> int:
        return len(self._streams)

    async def send(self, raw: bytes) -> None:
        if self._gone:
            raise TunnelGone("the ghost's tunnel has ended")
        async with self._lock:
            await self._send(raw)

    async def open(self, host: str, port: int,
                   timeout: float = DIAL_TIMEOUT,
                   grant_id: int | None = None) -> tuple[Stream | None, str]:
        """Ask the Ghost to dial. -> (stream, why not).

        The caller gets a stream only when the Ghost reported the
        dial succeeded. A SOCKS client that is told OK and then finds
        nothing there is worse than one told no.
        """
        if self._gone:
            return None, "the ghost's tunnel has ended"
        s = Stream(id=self._take_id(), tunnel=self, grant_id=grant_id)
        self._streams[s.id] = s
        try:
            await self.send(encode_open(s.id, host, port))
        except Exception as e:                           # noqa: BLE001
            self._drop(s.id)
            return None, f"could not reach the ghost: {e}"

        try:
            why = await asyncio.wait_for(s.opened, timeout)
        except TimeoutError:
            self._drop(s.id)
            # Said as a timeout rather than a refusal: the operator
            # needs to know the Ghost never answered, which is a
            # different problem from the target refusing.
            return None, f"the ghost did not answer within {timeout:g}s"
        if why is not None:
            self._drop(s.id)
            return None, why
        return s, ""

    def _take_id(self) -> int:
        i = self._next
        # Not reused. See the module docstring: a late frame for a
        # dead stream landing in a live one is the failure this
        # avoids.
        self._next += 1
        return i

    def _drop(self, sid: int) -> None:
        s = self._streams.pop(sid, None)
        if s is not None:
            s._finish()

    def on_frame(self, f: Frame) -> None:
        """Route one decoded frame. Never raises at the caller.

        A frame for a stream that has gone is NORMAL on a multiplexed
        tunnel -- both ends can close at once -- so it is dropped
        rather than treated as an error.
        """
        s = self._streams.get(f.stream)
        if f.kind == OPENED:
            if s is not None and not s.opened.done():
                s.opened.set_result(None)
            return
        if f.kind == FAILED:
            if s is not None and not s.opened.done():
                why = f.payload.decode("utf-8", "replace")[:200]
                s.opened.set_result(why or "the ghost could not dial it")
            return
        if f.kind == DATA:
            if s is None or s.closed:
                return
            try:
                s.inbox.put_nowait(f.payload)
            except asyncio.QueueFull:
                # The reader is not keeping up. Dropping bytes would
                # corrupt the stream silently, so the stream ends
                # instead -- a failed request is debuggable, a
                # truncated TLS record is not.
                log.warning("proxy stream %d on agent %d outran its reader",
                            f.stream, self.agent_id)
                self._drop(f.stream)
            return
        if f.kind == CLOSE:
            self._drop(f.stream)
            return
        if f.kind == OPEN:
            # Travels the other way. A Ghost sending one is confused
            # or is not our Ghost; either way there is nothing here
            # to act on.
            log.warning("agent %d sent an OPEN up the tunnel", self.agent_id)

    def shutdown(self) -> None:
        """The tunnel ended. Finish every stream waiting on it."""
        self._gone = True
        live, self._streams = self._streams, {}
        for s in live.values():
            s._finish()

    def drop_grant(self, grant_id: int) -> int:
        """End the live streams one credential opened. -> how many.

        The tunnel itself stays up and other credentials on the same
        Ghost are untouched: revoking one operator's access is not a
        reason to cut another's.

        Local to this process. A deployment running several API
        workers has a tunnel in exactly one of them -- the Ghost
        holds one WebSocket -- so this reaches the connections that
        exist, but it is not a distributed broadcast and does not
        claim to be.
        """
        hit = [s for s in self._streams.values() if s.grant_id == grant_id]
        for s in hit:
            self._streams.pop(s.id, None)
            s._finish()
        return len(hit)


class Hub:
    """Which Ghosts have a tunnel up, right now, in this process."""

    def __init__(self) -> None:
        self._tunnels: dict[int, Tunnel] = {}

    def register(self, agent_id: int, send: Sender) -> Tunnel:
        """Attach a tunnel, replacing any older one for that agent.

        Replacing rather than refusing: a Ghost that reconnects after
        a network drop has a tunnel the server still believes in, and
        refusing the new one would leave it unable to proxy until
        something noticed the old was dead.
        """
        old = self._tunnels.get(agent_id)
        if old is not None:
            old.shutdown()
        t = Tunnel(agent_id, send)
        self._tunnels[agent_id] = t
        return t

    def drop(self, agent_id: int, t: Tunnel | None = None) -> None:
        """Detach. `t` guards against a late close racing a reconnect."""
        cur = self._tunnels.get(agent_id)
        if cur is None:
            return
        if t is not None and cur is not t:
            # A newer tunnel took this agent's slot while the old one
            # was finishing. Leaving it alone is the whole point of
            # the guard.
            return
        self._tunnels.pop(agent_id, None)
        cur.shutdown()

    def get(self, agent_id: int) -> Tunnel | None:
        return self._tunnels.get(agent_id)

    def drop_grant(self, agent_id: int, grant_id: int) -> int:
        """Cut what one credential is holding. -> streams ended."""
        t = self._tunnels.get(agent_id)
        return t.drop_grant(grant_id) if t is not None else 0

    @property
    def agents(self) -> list[int]:
        return sorted(self._tunnels)


#: One per process. A tunnel is only true where its socket is, so
#: this is deliberately not shared, cached or persisted.
hub = Hub()
