"""Enforcing a project's scope lists.

`app/scope.py` decides whether a host is in scope. This decides what
happens about it: it loads a project's entries, caches the index for the
length of one operation, and refuses the request.

**Why one module and not a check per route.** A gate on five of six paths
is worse than no gate at all, because the five make people believe the
sixth is covered too. Everything that creates a target or sends a packet
goes through `assert_allowed` or `index_for`, so the list of places scope
is enforced is the list of callers of this file:

    routers/targets.py      create_target
    routers/bulk.py         target rows, child rows and autocreated orphans
    routers/domains.py      promote (candidate -> target)
    importers/policy.py     every scan import, via Policy.resolve
    routers/agents.py       create_task, create_pooled_task, heartbeat hand-out
    routers/web.py          replay (the one route that sends live traffic)
    routers/actions.py      request_action (active probes)
    agent/tools.py          add_target, task_drone

Reads are deliberately NOT gated. Looking at a host the project already
has is not touching it, and hiding existing rows because a list changed
would lose the record of work that really happened.

**Two refusals, not one.** BARRED means the host is on the out-of-scope
list: nothing may touch it, new or existing. OUTSIDE means an in-scope
list exists and this host is not on it: nothing NEW. An out-of-scope
ruling is a 403 — the operator is not permitted to do this — and an
outside-the-allowlist ruling is a 422, because it is a fact about the
request that a change to the scope list would fix.
"""
from __future__ import annotations

import ipaddress
import re

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ProjectScope
from .scope import BARRED, Ruling, ScopeIndex

#: Status codes for each refusal. Distinct so a caller — and a test —
#: can tell "you may never do this" from "not with this list in force".
BARRED_STATUS = 403
OUTSIDE_STATUS = 422


async def index_for(session: AsyncSession, project_id: int) -> ScopeIndex:
    """Load one project's scope, ready to be asked about many hosts.

    Built per operation rather than cached across requests. The rows are
    a single indexed SELECT, and a cache would have to be invalidated by
    every scope edit from every worker — a stale allowlist is exactly the
    failure this feature exists to prevent.
    """
    rows = (await session.execute(
        select(ProjectScope).where(
            ProjectScope.project_id == project_id))).scalars().all()
    return ScopeIndex(rows)


def refuse(ruling: Ruling, what: str) -> HTTPException:
    """The exception for a ruling, naming the entry that caused it."""
    status = BARRED_STATUS if ruling.verdict == BARRED else OUTSIDE_STATUS
    return HTTPException(status, f"{what} refused: {ruling.reason}")


async def assert_allowed(session: AsyncSession, project_id: int, host: str,
                         what: str, ip: str | None = None) -> None:
    """Raise unless this project may do something new with `host`.

    For the single-host paths. Anything handling a list should take an
    index once with `index_for` and check against it, or it issues one
    query per host.
    """
    idx = await index_for(session, project_id)
    ruling = idx.check(host, ip)
    if not ruling.allowed:
        raise refuse(ruling, what)


# ---------------------------------------------------------------- drone
#: Where a task's targets live in its args. Drone runners take `targets`;
#: the rest is defensive — a kind added later that names its hosts
#: differently must not silently become an ungated path.
TARGET_KEYS = ("targets", "target", "hosts", "host", "url", "urls")


def task_hosts(args: dict | None) -> list[str]:
    """Every host a queued task would touch, out of its arguments.

    Permissive on shape because the args are a free JSON object: a
    string, a list, or a comma/space separated run of them all appear.
    A host this misses is a host that gets scanned unchecked, so the
    parsing errs towards finding more rather than fewer.
    """
    out: list[str] = []

    def take(v) -> None:
        if isinstance(v, str):
            out.extend(p for p in re.split(r"[\s,]+", v) if p)
        elif isinstance(v, (list, tuple)):
            for item in v:
                take(item)

    for k in TARGET_KEYS:
        if isinstance(args, dict) and k in args:
            take(args[k])
    return out


def as_host(raw: str) -> str:
    """The host part of a task target, for a scope question.

    A Drone target may be written as a URL or as host:port — both are
    things nmap and httpx accept — so the rest is stripped. A CIDR keeps
    its prefix; `_probes` deals with ranges.
    """
    s = (raw or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s and not _is_cidr(s):
        s = s.split("/", 1)[0]
    s = s.rstrip(".")
    # host:port, but not an IPv6 literal, which has several colons.
    if s.count(":") == 1:
        head, _, tail = s.partition(":")
        if tail.isdigit():
            s = head
    return s.strip("[]").lower()


def _is_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        return False
    return "/" in s


def check_task_targets(idx: ScopeIndex, args: dict | None) -> Ruling | None:
    """-> the first refusing ruling among a task's targets, or None.

    Every target has to pass. A task naming ten hosts of which one is
    barred is a task that scans a barred host, and refusing the whole
    task is the only answer that does not require the agent to be
    trusted to drop one entry from its own command line.

    A CIDR argument is expanded to its network and broadcast addresses
    and both are checked — not every address in it, which for a /8 is not
    a check anybody is going to wait for. That is a partial answer and is
    said so here: a range whose edges are in scope may still contain a
    barred address, and the apply report is what finds those.
    """
    for raw in task_hosts(args):
        for probe in _probes(raw):
            ruling = idx.check(probe)
            if not ruling.allowed:
                return ruling
    return None


def _probes(raw: str) -> list[str]:
    s = as_host(raw)
    if not s:
        return []
    if _is_cidr(s):
        net = ipaddress.ip_network(s, strict=False)
        return sorted({str(net.network_address), str(net.broadcast_address)})
    return [s]
