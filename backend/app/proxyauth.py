"""Who may proxy, through which Ghost, to where.

`socks.py` decides what the bytes mean. This decides whether to act
on them, and it is the file to read when asking what stops this
feature being a way into a client's network.

Three gates, in this order, because each one is cheaper and more
certain than the next:

  1. the credential         -- a `ProxyGrant`, hashed, revocable,
                               expiring, bound to ONE agent
  2. the agent              -- proxying must be switched on for it,
                               and it must not be disabled
  3. the destination        -- `scopegate`, the same ruling a task
                               gets, on the host the client asked for

A refusal at any of them is RECORDED. A proxy that logs only what it
allowed cannot answer "did anyone try to reach that", and on this
feature that is the question somebody will eventually ask.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Agent, ProxyConnection, ProxyGrant
from .security import _hash_key
from .socks import NOT_ALLOWED, OK

#: Prefix so a leaked credential is recognisable for what it is in a
#: log or a paste, the way `ghost_` does for agent keys.
GRANT_PREFIX = "oddsocks_"


@dataclass(frozen=True)
class Decision:
    """What to do with one CONNECT, and what to write down."""
    allowed: bool
    #: A `socks` reply code. Only meaningful when not allowed.
    code: int = OK
    #: `allowed` | `refused_auth` | `refused_scope` | `refused_agent`
    outcome: str = "allowed"
    reason: str | None = None
    grant_id: int | None = None
    agent_id: int | None = None
    project_id: int | None = None


def new_grant() -> tuple[str, str, str]:
    """-> (username, password, password hash).

    The username is random rather than chosen. A person naming these
    produces `brandon` on three engagements, and the username is the
    lookup key across the whole installation.
    """
    user = GRANT_PREFIX + secrets.token_hex(6)
    raw = secrets.token_urlsafe(32)
    return user, raw, _hash_key(raw)


async def resolve(session: AsyncSession, username: str,
                  password: str) -> tuple[ProxyGrant | None, str]:
    """Find and check a credential. -> (grant or None, why not).

    Constant-time on the password. The username is a lookup and leaks
    existence by timing regardless, which is why it carries 48 bits of
    randomness instead of being something guessable.
    """
    if not username or not password:
        return None, "no credential offered"
    g = (await session.execute(
        select(ProxyGrant)
        .where(ProxyGrant.username == username))).scalar_one_or_none()
    if g is None:
        # Still do the work, so a missing username and a wrong
        # password do not answer at visibly different speeds.
        _hash_key(password)
        return None, "no such proxy credential"
    if not secrets.compare_digest(_hash_key(password), g.password_hash):
        return None, "wrong password"
    if g.revoked_at is not None:
        return None, "this credential was revoked"
    if g.expires_at is not None and g.expires_at <= datetime.now(UTC):
        return None, "this credential has expired"
    return g, ""


async def decide(session: AsyncSession, username: str, password: str,
                 host: str, port: int) -> Decision:
    """Rule on one CONNECT. Writes nothing; see `record`.

    Separated from the recording so the decision can be tested without
    a database write, and so the caller cannot accidentally act on a
    decision it never wrote down.
    """
    grant, why = await resolve(session, username, password)
    if grant is None:
        # The username tried goes in the reason; the password never
        # does. Without the username "somebody failed to authenticate"
        # cannot be told apart from "somebody is working through
        # guesses" or "a real issued credential is being hammered",
        # and those three call for three different responses. The
        # username is already written in the audit line that issued
        # it, so it is not the half being protected here.
        #
        # Attacker-controlled, so it is clipped and quoted rather
        # than pasted into a sentence that reads as our own.
        u = (username or "").strip()[:64]
        return Decision(False, NOT_ALLOWED, "refused_auth",
                        f"{why} (tried {u!r})" if u else why)

    agent = await session.get(Agent, grant.agent_id)
    if agent is None:
        return Decision(False, NOT_ALLOWED, "refused_agent",
                        "the ghost this credential belongs to is gone",
                        grant.id, None, grant.project_id)
    if agent.status == "disabled":
        return Decision(False, NOT_ALLOWED, "refused_agent",
                        "that ghost is disabled", grant.id, agent.id,
                        grant.project_id)
    if not getattr(agent, "proxy_enabled", False):
        return Decision(False, NOT_ALLOWED, "refused_agent",
                        "proxying is not switched on for that ghost",
                        grant.id, agent.id, grant.project_id)

    # The same ruling a task gets, on the host as ASKED FOR. A name is
    # not resolved here: the Ghost is elsewhere and resolves it where
    # it sits, and gating the name is gating what the operator typed.
    from .scopegate import index_for
    idx = await index_for(session, grant.project_id)
    ruling = idx.check(host)
    if not ruling.allowed:
        return Decision(False, NOT_ALLOWED, "refused_scope",
                        ruling.reason or "out of scope", grant.id,
                        agent.id, grant.project_id)

    return Decision(True, OK, "allowed", None, grant.id, agent.id,
                    grant.project_id)


async def record(session: AsyncSession, d: Decision, host: str,
                 port: int) -> None:
    """Write the connection down, allowed or not.

    Called for every decision. The destination is stored as the client
    asked for it and no body or byte content is kept -- the traffic is
    the client's and does not belong in this database.
    """
    # A credential nobody could resolve has no engagement to file the
    # attempt against, and the project stays NULL rather than being
    # invented -- a row on the wrong project is worse than no row.
    #
    # But the row is written. This used to return here, which meant
    # every failed credential attempt against the internet-facing TLS
    # port left nothing behind at all: a sustained brute force
    # produced zero rows in the one table somebody asking "did
    # anybody try" would look in, while this module's own docstring
    # said refusals were the more interesting half. `refused_command`
    # went the same way, so an unauthenticated client probing BIND
    # and UDP-ASSOCIATE was invisible too.
    session.add(ProxyConnection(
        project_id=d.project_id, agent_id=d.agent_id, grant_id=d.grant_id,
        host=host[:253], port=port, outcome=d.outcome,
        reason=(d.reason or None), at=datetime.now(UTC)))
    if d.allowed and d.grant_id is not None:
        g = await session.get(ProxyGrant, d.grant_id)
        if g is not None:
            g.last_used_at = datetime.now(UTC)
    await session.flush()
