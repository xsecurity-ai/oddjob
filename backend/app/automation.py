"""Standing orders: the follow-up work a project does without being asked.

Four policies, set per engagement, each of which answers one obvious
"and now do the next thing" that an operator otherwise has to remember:

    auto_amass        hand every in-scope zone to amass, once
    auto_resolve_ips  resolve any hostname with no address recorded
    auto_reverse_dns  find names for any address-named host that has none
    auto_nmap         scan hosts that have never been scanned
                      ("off" | "top100" | "full")

All four are off by default and each one puts packets on a client's
estate, so three things are true of everything in this file.

**Every candidate goes through the scope gate on its own.** Not the
project, not the batch -- each name, every cycle. An automation that
could queue one out-of-scope host is worse than no automation, because
by definition nobody is watching it go out.

**One attempt per subject, ever.** A lookup that comes back empty leaves
the host exactly as it was -- still no address, still no name -- so a
policy phrased as "anything missing X" would re-queue it on the next
cycle and every cycle after that, forever, against a client. Having
been *tried* is what counts here, not having succeeded. Re-running a
failed lookup is a deliberate act and stays a manual one.

**Paced.** PER_CYCLE candidates per policy per project per cycle, so
switching a policy on in a project with four thousand hosts drains over
hours rather than queueing four thousand scans in one go. The drone
queue would survive that; the client's network is the thing that would
not.

They are standing orders rather than triggers on insert, which is a
deliberate difference. A trigger only ever covers what arrives after it
is switched on, so turning one on would appear to do nothing and the
operator would conclude it was broken. These are evaluated against
whatever is outstanding, including the backlog.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import domains as gen
from .db import SessionLocal
from .events import broker
from .lookups import is_ip
from .models import (
    NMAP_CHOICES,
    Agent,
    AgentTask,
    DomainSearch,
    Project,
    ProjectScope,
    Target,
)
from .scopegate import index_for

log = logging.getLogger(__name__)

#: Candidates per policy, per project, per cycle. Small on purpose --
#: see the module docstring. At one cycle a minute this is 1,500 an
#: hour per policy, which drains a large backlog overnight without ever
#: looking like an incident from the other end.
PER_CYCLE = 25

#: How often to look. Long enough that a quiet installation costs
#: nothing, short enough that adding a host and seeing it resolve feels
#: like the feature working rather than a cron job.
CYCLE_SECS = 60

#: Backoff after an iteration raises, so a broken database does not
#: become a tight loop.
ERROR_SLEEP = 60

#: The nmap profiles the toggle offers, as task args.
#:
#: `top100` is nmap's own `-F`, which is exactly the hundred commonest
#: ports -- not a list maintained here that would drift from nmap's.
#: `full` names the range explicitly, because `-p-` and `-F` are
#: mutually exclusive and nmap exits 1 on the pair while still writing
#: a successful-looking XML file of zero hosts.
NMAP_PROFILES: dict[str, dict] = {
    "top100": {"profile": "quick"},
    "full": {"ports": "1-65535"},
}

#: `NMAP_CHOICES` lives in models.py, where schemas.py can validate
#: against it without importing this module. They have to agree, and
#: the test asserts that they do rather than trusting two lists.
assert set(NMAP_CHOICES) == {"off", *NMAP_PROFILES}


@dataclass(frozen=True)
class Candidate:
    """One task a policy would like to queue, before the gate sees it."""
    kind: str
    subject: str
    args: dict = field(default_factory=dict)
    policy: str = ""


@dataclass
class Snapshot:
    """Everything `plan` needs, read once per project per cycle.

    A plain-data argument rather than a session, so the decision can be
    tested against a described estate instead of a database -- which is
    the only way the "never twice" rule gets exercised, since it is
    about what happened on a previous cycle.
    """
    auto_amass: bool = False
    auto_resolve_ips: bool = False
    auto_reverse_dns: bool = False
    auto_nmap: str = "off"
    #: (host, has_address) for every target in the project.
    targets: list[tuple[str, bool]] = field(default_factory=list)
    #: Zones already handed to amass (`DomainSearch.domain`).
    searched: set[str] = field(default_factory=set)
    #: Zones the scope list NAMES with a wildcard. These are candidates
    #: in their own right, not only the zones derived from hostnames:
    #: `registrable("one.zone.acme.example")` is `acme.example`, which
    #: `*.zone.acme.example` does not cover, so deriving from hosts
    #: alone means the engagement never enumerates the zone it was
    #: actually authorised against. Same reasoning as `domainRoots`.
    scope_zones: set[str] = field(default_factory=set)
    #: (kind, subject) this project has ever tasked. See "one attempt
    #: per subject" in the module docstring.
    tasked: set[tuple[str, str]] = field(default_factory=set)


def plan(s: Snapshot, limit: int = PER_CYCLE) -> list[Candidate]:
    """What the policies would like to do, before the gate is consulted.

    Pure. Returns at most `limit` candidates per policy, in a stable
    order, so a cycle that is interrupted resumes where it was rather
    than starting from a different place each time.
    """
    out: list[Candidate] = []

    if s.auto_amass:
        zones: list[str] = []
        seen: set[str] = set()
        derived = [gen.registrable(h) for h, _ in s.targets if not is_ip(h)]
        for z in list(s.scope_zones) + derived:
            if not z or "." not in z or z in seen:
                continue
            seen.add(z)
            if z in s.searched or ("amass", z) in s.tasked:
                continue
            zones.append(z)
        out += [Candidate("amass", z, {"domain": z, "mode": "passive"},
                          "auto_amass")
                for z in sorted(zones)[:limit]]

    if s.auto_resolve_ips:
        want = sorted(
            h for h, has_addr in s.targets
            if not has_addr and not is_ip(h) and ("nslookup", h) not in s.tasked)
        out += [Candidate("nslookup", h, {}, "auto_resolve_ips")
                for h in want[:limit]]

    if s.auto_reverse_dns:
        # Named by its address, so by definition it has no name of its
        # own. `has_addr` is not the question here and is not asked.
        want = sorted(
            h for h, _ in s.targets
            if is_ip(h) and ("reverse_ip", h) not in s.tasked)
        out += [Candidate("reverse_ip", h, {}, "auto_reverse_dns")
                for h in want[:limit]]

    if s.auto_nmap in NMAP_PROFILES:
        args = NMAP_PROFILES[s.auto_nmap]
        want = sorted(h for h, _ in s.targets if ("nmap", h) not in s.tasked)
        out += [Candidate("nmap", h, dict(args), "auto_nmap")
                for h in want[:limit]]

    return out


async def snapshot(session: AsyncSession, pr: Project) -> Snapshot:
    """Read one project's state into a `Snapshot`."""
    rows = (await session.execute(
        select(Target).where(Target.project_id == pr.id)
        .order_by(Target.host))).scalars().unique().all()
    targets = [(t.host, bool(t.addresses)) for t in rows]

    searched = set((await session.execute(
        select(DomainSearch.domain).where(
            DomainSearch.project_id == pr.id))).scalars().all())

    # A wildcard names its zone outright. Excluded entries are left out
    # here as well as refused by the gate later: offering work that is
    # certain to be refused is noise in every cycle for ever.
    scope_zones = {
        v.strip().lstrip("*.").lower()
        for v, inc in (await session.execute(
            select(ProjectScope.value, ProjectScope.included).where(
                ProjectScope.project_id == pr.id,
                ProjectScope.kind == "wildcard"))).all()
        if inc and (v or "").strip()}

    # Every subject this project has ever tasked, for the kinds the
    # policies use. `args` is JSON, so it is parsed here rather than
    # matched in SQL -- a LIKE against a serialised blob would match
    # `a.example` inside `xa.example` and silently skip a host.
    tasked: set[tuple[str, str]] = set()
    for kind, raw in (await session.execute(
            select(AgentTask.kind, AgentTask.args).where(
                AgentTask.project_id == pr.id,
                AgentTask.kind.in_(("amass", "nslookup", "reverse_ip", "nmap"))
            ))).all():
        try:
            a = json.loads(raw or "{}")
        except ValueError:
            continue
        if kind == "amass":
            if d := a.get("domain"):
                tasked.add(("amass", str(d).lower()))
            continue
        for sub in (a.get("targets") or []):
            tasked.add((kind, str(sub).lower()))

    return Snapshot(
        auto_amass=bool(pr.auto_amass),
        auto_resolve_ips=bool(pr.auto_resolve_ips),
        auto_reverse_dns=bool(pr.auto_reverse_dns),
        auto_nmap=str(pr.auto_nmap or "off"),
        targets=targets, searched=searched, tasked=tasked,
        scope_zones=scope_zones)


async def run_once(session: AsyncSession, pr: Project) -> dict[str, int]:
    """Evaluate one project's policies and queue what the gate allows.

    Returns a count per policy, which is what the log line and the
    tests read. An empty dict means there was nothing to do, which is
    the normal case and is not logged.
    """
    snap = await snapshot(session, pr)
    want = plan(snap)
    if not want:
        return {}

    # Nothing is queued at all with no drone to run it. The tasks would
    # sit in the queue and be perfectly valid, but "25 queued" against
    # an empty fleet every minute is a queue nobody asked for by the
    # time anyone brings an agent up.
    live = (await session.execute(
        select(Agent.id).where(Agent.project_id == pr.id,
                               Agent.status == "online").limit(1))).first()
    if live is None:
        return {}

    idx = await index_for(session, pr.id)
    queued: dict[str, int] = {}
    for c in want:
        # A zone handed to amass is asked `check_zone`; everything else
        # is a host something will be done TO, and gets `check`. The two
        # disagree on exactly one input -- the apex of a wildcard -- and
        # collapsing them would let a standing order queue a scan at a
        # host the wildcard never covered, with nobody watching.
        ruling = (idx.check_zone(c.subject) if c.kind == "amass"
                  else idx.check(c.subject))
        if not ruling.allowed:
            # Not an error and not logged per candidate: a project whose
            # scope is narrower than its target list refuses the same
            # names every cycle, and that would be the whole log.
            continue
        args = dict(c.args) if c.kind == "amass" else {**c.args,
                                                       "targets": [c.subject]}
        t = AgentTask(agent_id=None, project_id=pr.id, requested_by=None,
                      kind=c.kind, args=json.dumps(args),
                      import_as=_import_as(c.kind), status="queued")
        session.add(t)
        queued[c.policy] = queued.get(c.policy, 0) + 1

    if queued:
        await session.commit()
        await broker.publish("agents", action="task", project=pr.code)
        log.info("standing orders for %s queued %s", pr.code,
                 ", ".join(f"{n} {p}" for p, n in sorted(queued.items())))
    return queued


def _import_as(kind: str) -> str | None:
    """What the result should be imported as, matching TASK_KINDS.

    Imported lazily from the router rather than duplicated: two lists
    of which tools produce importable output would disagree, and the
    one that matters is whichever is consulted.
    """
    from .routers.agents import TASK_KINDS
    return TASK_KINDS.get(kind)


class Worker:
    """The single background loop. Started once, at application startup."""

    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.running = False
        self.last: str | None = None

    async def _cycle(self) -> None:
        async with SessionLocal() as session:
            # Only projects with something switched on, so an
            # installation that uses none of this does one cheap query
            # a minute and nothing else.
            rows = (await session.execute(
                select(Project).where(
                    Project.status == "active",
                    (Project.auto_amass.is_(True))
                    | (Project.auto_resolve_ips.is_(True))
                    | (Project.auto_reverse_dns.is_(True))
                    | (Project.auto_nmap != "off")))).scalars().all()
            if not rows:
                self.last = "no project has a standing order"
                return
            total: dict[str, int] = {}
            for pr in rows:
                for policy, n in (await run_once(session, pr)).items():
                    total[policy] = total.get(policy, 0) + n
            self.last = (", ".join(f"{n} {p}" for p, n in sorted(total.items()))
                         if total else "nothing outstanding")

    async def _loop(self) -> None:
        log.info("standing-orders worker started")
        while True:
            try:
                await self._cycle()
                await asyncio.sleep(CYCLE_SECS)
            except asyncio.CancelledError:
                log.info("standing-orders worker stopped")
                raise
            except Exception:
                # The worker must outlive any single failure. A crashed
                # background task fails silently and forever, and this
                # one failing silently means an operator believes
                # scanning is happening when it is not.
                log.exception("standing-orders iteration failed")
                await asyncio.sleep(ERROR_SLEEP)

    def start(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop())
            self.running = True


worker = Worker()
