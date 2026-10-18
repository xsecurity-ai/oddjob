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
    agent/tools.py          add_target, task_ghost

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

from .models import ProjectScope, Target, TargetAddress, target_address_links
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
    idx = ScopeIndex(rows)

    # Scope travels between a name and the address it was seen at.
    #
    # An operator whose scope says `*.corp.com` and who then scans the
    # address that `www.corp.com` resolves to is not going outside it;
    # refusing that made the gate read as broken, because the thing
    # being refused is the same machine under a different label.
    #
    # Only pairs this project has already OBSERVED, from its own
    # targets. Not a live lookup: resolving here would send traffic
    # from the gate and make a scope decision depend on what a resolver
    # happened to say. A name nothing has resolved yet inherits
    # nothing, which is the honest answer.
    #
    # Two columns, loaded once per operation like the rows above — now
    # over the join, because a target has many addresses and an address
    # has many targets. One row per observed pair.
    #
    # **This is where many-to-many could have become scope inheritance,
    # and does not.** The pairs are richer than they used to be: a CDN
    # address now links to every name the project has recorded at it,
    # where before one target held one string. `ScopeIndex.check` walks
    # these links exactly one step and asks whether the PARTNER matches
    # the scope document DIRECTLY — never whether the partner is itself
    # allowed, which would chain. So an in-scope name vouches for its
    # CDN address, and that address vouches for nothing further: the
    # other tenants sharing it match no entry of ours and stay outside.
    # `tests/scopetest.py` pins this rather than leaving it to be true
    # by construction.
    for host, addr in (await session.execute(
            select(Target.host, TargetAddress.address)
            .join(target_address_links,
                  target_address_links.c.target_id == Target.id)
            .join(TargetAddress,
                  TargetAddress.id == target_address_links.c.address_id)
            .where(Target.project_id == project_id))).all():
        idx.link(host, addr)
    return idx


def refuse(ruling: Ruling, what: str) -> HTTPException:
    """The exception for a ruling, naming the entry that caused it."""
    status = BARRED_STATUS if ruling.verdict == BARRED else OUTSIDE_STATUS
    return HTTPException(status, f"{what} refused: {ruling.reason}")


async def assert_allowed(session: AsyncSession, project_id: int, host: str,
                         what: str, ip=None) -> None:
    """Raise unless this project may do something new with `host`.

    `ip` is one address or a list of them — a host has as many as it
    has, and all of them bear on the decision. See `ScopeIndex.check`.

    For the single-host paths. Anything handling a list should take an
    index once with `index_for` and check against it, or it issues one
    query per host.
    """
    idx = await index_for(session, project_id)
    ruling = idx.check(host, ip)
    if not ruling.allowed:
        raise refuse(ruling, what)


# ---------------------------------------------------------------- ghost
#: Where a task's targets live in its args. Ghost runners take `targets`;
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

    A Ghost target may be written as a URL or as host:port — both are
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


# ------------------------------------------------- the CNAME carve-out
#
# A name the client's own DNS points at, resolved and nothing else.
#
# `author.corporate.acme.example` is in scope. Its CNAME chain ends
# at `d111111abcdef8.cloudfront.net`, which is not and should not be
# -- that is AWS's infrastructure, the engagement does not cover it,
# and putting it on the scope list would authorise nmap and nuclei
# against it too.
#
# But the takeover detector cannot settle anything without resolving
# that hop. `dangling` means "the chain reached a name that does not
# resolve", and with no lookup there is no answer: on the engagement
# this was built for, 35 hops were refused and 18 rows stayed
# permanently undetermined as a result.
#
# So: a DNS lookup of a hop in an in-scope host's own chain is
# allowed, and nothing else is.
#
#   * One task kind. `nslookup` sends no packet to the named host at
#     all -- it asks a resolver, which is what every browser visiting
#     the client's site already does. A port scan of that hop would
#     be touching a third party and stays refused.
#   * The candidate set is not open. It is the hops already recorded
#     in THIS project's `takeovers` table, which the detector derived
#     from in-scope targets' own CNAMEs. A name nobody's chain
#     mentions is not reachable through this at all.
#   * Recorded as its own ruling, so an audit shows a lookup allowed
#     by the carve-out and not by the scope list.
#
# The chain is attacker-influenced in the sense that DNS answers
# are, which is the reason the permission granted is this small.
# Resolving a name is not testing it.

#: The only kind this applies to. Deliberately a set of one, and it
#: should stay that way: everything else sends something.
RESOLVE_ONLY_KINDS = frozenset({"nslookup"})


async def cname_hops(session: AsyncSession, project_id: int) -> set[str]:
    """Names this project's in-scope hosts point at, via CNAME.

    Read from `takeovers`, which the detector rebuilds from targets
    the project already holds -- so this set cannot name anything no
    in-scope host's own DNS does.
    """
    from .models import Takeover

    rows = (await session.execute(
        select(Takeover.cname, Takeover.cname_chain)
        .where(Takeover.project_id == project_id))).all()
    out: set[str] = set()
    for cname, chain in rows:
        if cname:
            out.add(cname.strip().lower().rstrip("."))
        for hop in (chain or "").split("\n"):
            hop = hop.strip().lower().rstrip(".")
            if hop:
                out.add(hop)
    return out


def resolvable_hop(kind: str, subject: str, hops: set[str]) -> bool:
    """Whether the carve-out covers this one task.

    Both halves required: the kind must send nothing, and the name
    must be one an in-scope host actually points at.
    """
    if kind not in RESOLVE_ONLY_KINDS:
        return False
    name = (as_host(subject) or subject or "").strip().lower().rstrip(".")
    return bool(name) and name in hops
