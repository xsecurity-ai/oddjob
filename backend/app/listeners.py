"""Which ports a Ghost has been told to hold, and what came of it.

One module because there are two ways in -- the Ghost's own edit
dialog sets the whole list, the C2 page adds one at a time -- and two
ways to write the same table is how the two drift into disagreeing
about what a valid port is.

The heartbeat reads `desired()` and the agent reconciles against it:
open what is new, close what is gone, leave the rest alone. Nothing
here reaches out to an agent. A listener appears on the Ghost at its
next beat and not before, which is seconds, and saying so in the UI
is better than pretending the write was the binding.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Agent, ShellListener, User

#: Both, because a payload that can only reach you over UDP is a
#: payload you otherwise cannot catch at all.
PROTOCOLS = ("tcp", "udp")

#: Below this a bind needs CAP_NET_BIND_SERVICE on the Ghost. Not
#: refused -- `ghost/docker-compose.yml` grants exactly that, and 443
#: is the port most worth having, because client egress is usually
#: filtered to browser ports. It is reported so an operator whose
#: Ghost was started without the capability is told why it failed
#: rather than guessing.
PRIVILEGED_BELOW = 1024


def port_refusal(port: int) -> str | None:
    """Why this cannot be a listener port, or None.

    Says which port it is refusing. "invalid port" on a form with six
    boxes in it is a message that makes the operator check all six.
    """
    if not isinstance(port, int) or isinstance(port, bool):
        return "a port has to be a number"
    if port == 0:
        # Not pedantry: 0 binds whatever is free, and a port you
        # cannot predict cannot be written into a payload. The
        # ephemeral fallback in the task-level callback feature is a
        # different thing -- there the agent reports back what it
        # got, and here the operator chose the number first.
        return "0 means “any free port”, which is not something a payload can call back to"
    if port < 0 or port > 65535:
        return f"{port} is not a port; they run 1 to 65535"
    return None


def protocol_refusal(protocol: str) -> str | None:
    if protocol not in PROTOCOLS:
        return f"{protocol!r} is not a protocol; use tcp or udp"
    return None


async def for_agent(session: AsyncSession, agent_id: int) -> list[ShellListener]:
    """Every listener configured on one Ghost, enabled or not."""
    return list((await session.execute(
        select(ShellListener)
        .where(ShellListener.agent_id == agent_id)
        .order_by(ShellListener.protocol, ShellListener.port))).scalars().all())


async def desired(session: AsyncSession, agent_id: int) -> list[dict]:
    """What the heartbeat tells this Ghost to be holding.

    Enabled rows only. A disabled listener is one the operator turned
    off and keeping it in the beat would have the agent hold a port
    the UI says is closed.
    """
    rows = (await session.execute(
        select(ShellListener)
        .where(ShellListener.agent_id == agent_id,
               ShellListener.enabled.is_(True))
        .order_by(ShellListener.protocol, ShellListener.port))).scalars().all()
    return [{"id": r.id, "protocol": r.protocol, "port": r.port} for r in rows]


async def add(session: AsyncSession, agent: Agent, protocol: str,
              ports: list[int], *, note: str | None = None,
              actor: User | None = None) -> tuple[list[ShellListener], list[str]]:
    """Add listeners to a Ghost. Returns what was made and what was not.

    Both halves, because a form with six ports in it where one is
    already configured should add the five and say so, not refuse the
    lot. Caller commits.
    """
    if (why := protocol_refusal(protocol)) is not None:
        return [], [why]

    existing = {(r.protocol, r.port): r for r in await for_agent(session, agent.id)}
    made: list[ShellListener] = []
    refused: list[str] = []
    seen: set[int] = set()
    for port in ports:
        if (why := port_refusal(port)) is not None:
            refused.append(why)
            continue
        if port in seen:
            continue                      # the same port twice in one form
        seen.add(port)
        if (row := existing.get((protocol, port))) is not None:
            # Already asked for. Re-enable rather than refuse: an
            # operator re-adding a port they switched off plainly
            # wants it on, and "already exists" would be a refusal
            # that reads as an error and fixes nothing.
            if not row.enabled:
                row.enabled = True
                row.state, row.state_detail, row.state_at = "pending", None, None
                made.append(row)
            else:
                refused.append(f"{protocol}/{port} is already configured on {agent.name}")
            continue
        row = ShellListener(project_id=agent.project_id, agent_id=agent.id,
                            protocol=protocol, port=port, enabled=True,
                            note=note, created_by_id=actor.id if actor else None)
        session.add(row)
        made.append(row)
    return made, refused


async def set_for_agent(session: AsyncSession, agent: Agent, *,
                        tcp: list[int] | None, udp: list[int] | None,
                        actor: User | None = None) -> list[str]:
    """Make this Ghost's listeners be exactly these. Returns refusals.

    Declarative, because the Ghost's edit dialog shows a list and
    saving it means "this is the list". `None` for a protocol is "no
    opinion" and leaves that protocol alone; an empty list is "none
    of these", which is how the last listener is removed. Those two
    have to be different or an older client that omits the field
    would silently close every port.

    Caller commits.
    """
    refused: list[str] = []
    current = await for_agent(session, agent.id)
    for protocol, wanted in (("tcp", tcp), ("udp", udp)):
        if wanted is None:
            continue
        keep: set[int] = set()
        for port in wanted:
            if (why := port_refusal(port)) is not None:
                refused.append(why)
                continue
            keep.add(port)
        have = {r.port: r for r in current if r.protocol == protocol}
        for port, row in have.items():
            if port not in keep:
                # Deleted, not disabled. The dialog's list IS the
                # configuration, so a port removed from it is a port
                # the operator removed -- leaving a disabled row
                # behind would have it reappear, switched off, in a
                # list that is supposed to be what was just saved.
                await session.delete(row)
        for port in sorted(keep - set(have)):
            session.add(ShellListener(
                project_id=agent.project_id, agent_id=agent.id,
                protocol=protocol, port=port, enabled=True,
                created_by_id=actor.id if actor else None))
        for port in sorted(keep & set(have)):
            row = have[port]
            if not row.enabled:
                row.enabled = True
                row.state, row.state_detail, row.state_at = "pending", None, None
    return refused


async def report(session: AsyncSession, agent_id: int,
                 said: list[dict]) -> None:
    """Record what the Ghost says it managed to bind.

    Only rows the agent names are touched. An agent that reports
    nothing -- because it is offline, or predates listeners -- leaves
    every row at `pending`, which is the honest answer: nobody has
    told us. Writing `failed` for silence would put a red cross
    against a port that is very likely fine.

    Caller commits.
    """
    if not said:
        return
    rows = {r.id: r for r in await for_agent(session, agent_id)}
    now = datetime.now(UTC)
    for item in said:
        row = rows.get(item.get("id") or 0)
        if row is None:
            # A listener the operator removed while the agent was
            # mid-beat. The agent closes it on the next beat; there
            # is nothing to record against.
            continue
        bound = bool(item.get("bound"))
        detail = (item.get("error") or "").strip() or None
        row.state = "bound" if bound else "failed"
        row.state_detail = None if bound else (detail or "the ghost did not say why")[:300]
        row.state_at = now
