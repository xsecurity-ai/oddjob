"""Server-Sent Events broadcaster -- how the UI knows to refresh.

SSE rather than WebSockets because the traffic is one-way and tiny: the server
says "targets changed", the client refetches. That needs no handshake, no
reconnect logic (EventSource reconnects on its own) and no extra dependency.

Each subscriber gets a bounded queue. If a client stalls and its queue fills,
its oldest event is dropped rather than letting one dead browser tab grow
unbounded in memory -- losing a nudge is harmless, because the payload carries
no data and the client refetches the authoritative state either way.

------------------------------------------------------------- who gets what

"The payload carries no data" was never quite true. An event names the
engagement it belongs to and often the host that changed, and for a long time
every authenticated subscriber received every one of them -- so anyone with a
login learned the shape of every other engagement in the installation: its
code, its hostnames, when somebody was working on it. Authenticating the
stream closed the open-port case and not this one.

So delivery is filtered per subscriber, and the filter is `project`:

  * an event with a project goes to the subscribers who can read that project
  * an event WITHOUT one is treated as installation-wide and goes to site
    admins only

That second rule is the one that matters, because it decides what a mistake
costs. A call site that forgets to say which engagement it is talking about
becomes *less* visible, not more: the worst case is a table that does not
refresh until the next poll, rather than a hostname in a stranger's browser.
The reverse default would make every new `publish` call a disclosure waiting
for someone to notice it.

`project` is keyword-only and explicit for the same reason -- it cannot be
passed by accident in `**data`, and it reads at the call site as a decision.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import suppress
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .db import SessionLocal
from .models import Project, User
from .security import visible_project_ids

# A slow client only ever needs to know that *something* changed, so a short
# queue is plenty.
QUEUE_SIZE = 64
HEARTBEAT_SECS = 20


@dataclass(eq=False)
class Sub:
    """One live stream, and what it is allowed to hear.

    `codes` is None for a site admin, meaning every project and the
    installation-wide events too. Otherwise it is the set of project codes the
    subscriber can read, and it is *mutated in place* by the stream as access
    changes -- see `event_stream`. Identity comparison (`eq=False`) keeps it
    usable in a set even though it holds a mutable field.
    """
    queue: asyncio.Queue[str] = field(
        default_factory=lambda: asyncio.Queue(maxsize=QUEUE_SIZE))
    codes: frozenset[str] | None = frozenset()

    def may_hear(self, project: str | None) -> bool:
        if self.codes is None:          # site admin: everything
            return True
        if project is None:             # installation-wide: admins only
            return False
        return project in self.codes


class Broker:
    def __init__(self) -> None:
        self._subs: set[Sub] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self, codes: frozenset[str] | None = frozenset()) -> Sub:
        s = Sub(codes=codes)
        async with self._lock:
            self._subs.add(s)
        return s

    async def unsubscribe(self, s: Sub) -> None:
        async with self._lock:
            self._subs.discard(s)

    async def publish(self, kind: str, *, project: str | None = None, **data) -> None:
        """kind is the resource that changed: targets | services | vulns | pocs | bulk.

        `project` is the engagement code the change belongs to. Omitting it
        says "this is installation-wide", which means site admins only -- so
        omit it only for things that genuinely are (settings, the user list),
        never because the code happens to be inconvenient to reach.
        """
        payload = json.dumps(
            {"kind": kind, **({"project": project} if project else {}), **data})
        async with self._lock:
            subs = list(self._subs)
        for s in subs:
            if not s.may_hear(project):
                continue
            try:
                s.queue.put_nowait(payload)
            except asyncio.QueueFull:
                with suppress(asyncio.QueueEmpty):
                    s.queue.get_nowait()    # drop oldest, keep newest
                with suppress(asyncio.QueueFull):
                    s.queue.put_nowait(payload)

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)


broker = Broker()


async def visible_codes(user_id: int) -> tuple[bool, frozenset[str] | None]:
    """`(still_allowed, codes)` for this user, read fresh.

    `codes` is None for a site admin. `still_allowed` is False once the
    account is gone or disabled, which is a different answer from "can read
    nothing": the first ends the stream, the second leaves it open and silent.

    Opens its own session rather than borrowing the request's: an SSE response
    outlives the request that started it, so by the time this is called again
    the dependency-injected session is long closed.
    """
    async with SessionLocal() as session:
        user = (await session.execute(
            select(User).where(User.id == user_id)
            .options(selectinload(User.groups)))).scalar_one_or_none()
        if user is None or not user.is_active:
            return False, frozenset()
        ids = await visible_project_ids(session, user)
        if ids is None:
            return True, None
        if not ids:
            return True, frozenset()
        return True, frozenset((await session.execute(
            select(Project.code).where(Project.id.in_(ids)))).scalars().all())


async def event_stream(user_id: int) -> AsyncIterator[str]:
    """SSE frames for one subscriber, filtered to what they may read.

    Access is re-read on every heartbeat rather than snapshotted at subscribe
    time. The reason is revocation: one of these streams can stay open for
    hours, so a snapshot would keep feeding an engagement's events to somebody
    whose access to it was removed this morning, until they happened to
    reload. Twenty seconds of staleness is a different thing from a day of it,
    and the query is a two-table read against the primary key.
    """
    alive, codes = await visible_codes(user_id)
    if not alive:
        return
    s = await broker.subscribe(codes)
    try:
        # Tell the client we are live immediately, so it can show a connected
        # state without waiting for the first real change.
        yield f"event: hello\ndata: {json.dumps({'ok': True})}\n\n"
        while True:
            try:
                payload = await asyncio.wait_for(s.queue.get(), timeout=HEARTBEAT_SECS)
                yield f"event: change\ndata: {payload}\n\n"
            except TimeoutError:
                alive, s.codes = await visible_codes(user_id)
                if not alive:
                    return
                # Comment frame. Keeps idle connections off proxy/browser
                # idle timeouts without the client treating it as an event.
                yield ": keepalive\n\n"
    finally:
        await broker.unsubscribe(s)
