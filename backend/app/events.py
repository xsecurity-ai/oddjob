"""Server-Sent Events broadcaster -- how the UI knows to refresh.

SSE rather than WebSockets because the traffic is one-way and tiny: the server
says "targets changed", the client refetches. That needs no handshake, no
reconnect logic (EventSource reconnects on its own) and no extra dependency.

Each subscriber gets a bounded queue. If a client stalls and its queue fills,
its oldest event is dropped rather than letting one dead browser tab grow
unbounded in memory -- losing a nudge is harmless, because the payload carries
no data and the client refetches the authoritative state either way.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import suppress

# A slow client only ever needs to know that *something* changed, so a short
# queue is plenty.
QUEUE_SIZE = 64
HEARTBEAT_SECS = 20


class Broker:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue[str]] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=QUEUE_SIZE)
        async with self._lock:
            self._subs.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        async with self._lock:
            self._subs.discard(q)

    async def publish(self, kind: str, **data) -> None:
        """kind is the resource that changed: targets | services | vulns | pocs | bulk."""
        payload = json.dumps({"kind": kind, **data})
        async with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                with suppress(asyncio.QueueEmpty):
                    q.get_nowait()          # drop oldest, keep newest
                with suppress(asyncio.QueueFull):
                    q.put_nowait(payload)

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)


broker = Broker()


async def event_stream() -> AsyncIterator[str]:
    q = await broker.subscribe()
    try:
        # Tell the client we are live immediately, so it can show a connected
        # state without waiting for the first real change.
        yield f"event: hello\ndata: {json.dumps({'ok': True})}\n\n"
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=HEARTBEAT_SECS)
                yield f"event: change\ndata: {payload}\n\n"
            except TimeoutError:
                # Comment frame. Keeps idle connections off proxy/browser
                # idle timeouts without the client treating it as an event.
                yield ": keepalive\n\n"
    finally:
        await broker.unsubscribe(q)
