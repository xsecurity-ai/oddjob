"""Standing orders: the follow-up work a project does without being asked.

Policies set per engagement, each of which answers one obvious "and
now do the next thing" that an operator otherwise has to remember:

    auto_amass        hand every in-scope zone to amass, once
    auto_resolve_ips  resolve any hostname with no address recorded
    auto_reverse_dns  find names for every address the estate answers on
    auto_nmap         scan hosts that have never been scanned
                      ("off" | "top100" | "full")
    auto_web          crawl and/or content-discover every web URL
    auto_nuclei       template scanning, and CVE confirmation
    auto_vhost        ask each origin what other names it answers to
    auto_httpx        probe every URL and record what answered
    auto_poc          prove every finding at or above a severity floor
                      ("off" | "critical" | "high" | "medium" | "low"
                      | "info")

All of them are off by default and each one puts packets on a
client's estate, so three things are true of everything in this file.

`auto_poc` is the one that does something the others do not: the rest
send a scanner's own traffic, and that one asks a model to WRITE a
check for a specific finding and then fires it. What goes at the
client is therefore something nobody reviewed first, which is why its
floor is explicit rather than a boolean and why it is not in
`KITCHEN_SINK`.

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

**A cycle queues the whole backlog.** It used to take PER_CYCLE
candidates per policy per cycle, on the reasoning that queueing four
thousand scans at once was something "the client's network would not
survive". That reasoning was wrong, and worth spelling out so it is
not reinstated by someone reading the old comment:

* Queueing is not scanning. Tasks sit in the database until a Ghost
  asks for work, and a Ghost only ever takes what `max_parallel`
  allows -- which is itself clamped by the host's free memory, and
  clamped again for heavy kinds like amass by `heavy_allowance`. The
  client-facing rate is set there, at dispatch, and is identical
  whether the queue holds 25 items or four thousand.
* So the cap paced the *queue*, not the network, and the only thing it
  actually achieved was leaving work undone -- a backlog that needed
  N more cycles, where the operator had already said to do all of it.

What the cap did protect against is a single enormous transaction, and
that is handled where it belongs: the candidates are gated and inserted
in batches, so one cycle drains everything without one giant write.

Scope is re-checked when a task is handed out, not only when it is
queued (`scope_refusal` in routers/agents.py), so a deep queue cannot
outlive a scope change.

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
from dataclasses import dataclass, field, replace

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import domains as gen
from . import geoip
from .db import SessionLocal
from .events import broker
from .hosts import dns_subject
from .lookups import is_ip
from .models import (
    NMAP_CHOICES,
    NUCLEI_CHOICES,
    WEB_CHOICES,
    Agent,
    AgentTask,
    DomainSearch,
    Poc,
    Project,
    Target,
    TargetAddress,
    Vuln,
)
from .roots import enumerable_roots
from .scope import ScopeIndex
from .scopegate import as_host, index_for
from .tasking import outstanding_subjects, tasked_subjects
from .webtargets import WEB_KINDS, crawl_seeds, discoverable

log = logging.getLogger(__name__)

#: How many candidates to gate and insert in one database round trip.
#:
#: NOT a cap on how much a cycle does -- a cycle does all of it. This
#: only stops a backlog of thousands becoming one enormous statement,
#: which is the single real cost the old per-cycle cap was covering
#: for. See the module docstring.
BATCH = 250

#: How many web-discovery candidates one cycle may queue, per kind.
#:
#: The other policies are bounded by the estate: a project has the
#: targets it has. The web estate is bounded by what has been FOUND,
#: and finding more is what the policy does, so it is the one policy
#: whose input grows as it runs. That is survivable with a correct
#: "already done" check and catastrophic without one -- 1,109 queued
#: tasks became 97,959 in under an hour when the check missed.
#:
#: This does not withhold work; the next cycle takes the next batch.
#: It bounds how wrong a single cycle can be.
WEB_PER_CYCLE = 250

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
#:
#: `full` also asks for `ssl-cert`, and only `full` does. A scan of
#: all 65,535 ports is already the expensive, thorough option, and the
#: certificate is the single highest-value thing to collect while we
#: are there: it names every host it is valid for, which is the
#: richest source of names on an estate and frequently the only
#: evidence that an address serves something we have no name for.
#:
#: It costs one extra handshake per port that negotiates TLS -- the
#: script's own portrule decides, so a port with no TLS is not probed
#: -- against a scan that has already touched every port on the host.
#:
#: Named explicitly rather than taken via `-sC`, which would turn on
#: the whole `default` category: dozens of scripts, several of which
#: write to the target. This asks for one read-only script by name.
NMAP_PROFILES: dict[str, dict] = {
    "top100": {"profile": "quick"},
    # No `extra`. It used to carry `--script ssl-cert`, and that is
    # now actively harmful: the ghost adds `--script` itself with
    # every -sV, and nmap honours only the LAST --script on the line,
    # so a profile naming its own set SUPPRESSES the rest. This is
    # the profile FALCON runs, so the scripts added in #115 reached
    # nothing at all until this line went. ssl-cert is still run --
    # it is named in the ghost's own set.
    "full": {"ports": "1-65535"},
}

assert set(WEB_CHOICES) == {"off", *WEB_KINDS}

#: The two nuclei runs, as the extra arguments each one adds.
#:
#: Separate tasks rather than one, because the filters are mutually
#: exclusive: every technology-detection template is `info` severity,
#: so `-severity critical,high` discards all 1,228 of them. One task
#: carrying both sets of flags would run the CVE half and silently
#: skip the other.
#:
#: `-etags authenticated` on the vulnerability run. This is a
#: black-box engagement with no credentials, so a template that needs
#: a login cannot do anything except send requests that are certain
#: to fail -- traffic at a client, in their logs, for no possible
#: result.
#:
#: `-tags tech` is what `-tech-detect` became. That flag does not
#: exist in nuclei v3: asking v3.11.1 for its own help shows `-td` is
#: now `-template-display`, and technology detection moved to the
#: `tech`-tagged templates.
#: A STRING, not a list. The agent reads this with its `str()`
#: helper and splits on whitespace; handed a list, that helper
#: returns "" and every flag here would be dropped without an error
#: anywhere -- the run would go out unfiltered, which for the
#: vulnerability profile means every template nuclei has rather than
#: the CVE ones. No value may contain a space.
NUCLEI_PROFILES: dict[str, str] = {
    "nuclei": "-severity critical,high -tags cve -etags authenticated",
    "nuclei_tech": "-tags tech",
    # No `-tags` and no `-severity`. The template set for this one is
    # named outright with `-id`, per URL, from the CVEs the local
    # corpus already matched to a service on that host -- see
    # `vulnfeed.suspected_cves`. A severity filter on top would drop
    # a suspected CVE for scoring below the line, which is the one
    # thing a confirmation run must not do: the question is "is this
    # specific lead real", not "is it bad enough to ask".
    "nuclei_confirm": "-etags authenticated",
}
assert not any(" " in v for p in NUCLEI_PROFILES.values()
               for v in p.split()[1::2]), "no argument value may contain a space"

#: Which task kinds each choice runs.
NUCLEI_KINDS: dict[str, tuple[str, ...]] = {
    "vuln": ("nuclei",),
    "tech": ("nuclei_tech",),
    "both": ("nuclei", "nuclei_tech"),
    #: Confirmation only: ask nuclei about the CVEs already suspected
    #: on each host and nothing else. Seconds rather than minutes per
    #: URL, and every hit is evidence for a lead that already existed
    #: rather than a new claim to triage.
    #:
    #: Needs a version to have been detected -- a CPE match without
    #: one is product-wide -- so a URL whose services gave no version
    #: produces no task at all. That is the intended behaviour and
    #: why this does not replace `vuln`.
    "confirm": ("nuclei_confirm",),
    "both+confirm": ("nuclei", "nuclei_tech", "nuclei_confirm"),
}

assert set(NUCLEI_CHOICES) == {"off", *NUCLEI_KINDS}
assert set(NUCLEI_PROFILES) == {k for ks in NUCLEI_KINDS.values() for k in ks}


#: Every kind `plan()` asks "has this already been tasked" about.
#:
#: Derived from the policy tables rather than typed out, because the
#: cost of the two disagreeing is silent and open-ended: the check
#: simply never matches and the policy re-queues for ever. The
#: standing orders are "once ever per subject" for every policy, so
#: this is every kind any of them can emit.
TASKED_KINDS: tuple[str, ...] = tuple(sorted({
    "amass", "nslookup", "reverse_ip", "nmap", "vhost", "httpx",
    *{k for ks in WEB_KINDS.values() for k in ks},
    *{k for ks in NUCLEI_KINDS.values() for k in ks},
}))

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
    auto_web: str = "off"
    auto_nuclei: str = "off"
    auto_vhost: bool = False
    auto_httpx: bool = False
    #: "off" or the lowest severity to prove. See models.POC_CHOICES.
    auto_poc: str = "off"
    #: Findings at or above that floor with no proof recorded. Counted
    #: in `snapshot` rather than derived here, because "has a PoC" is
    #: a join and a Snapshot is meant to be the answer, not the query.
    poc_backlog: int = 0
    #: Everything on, at its most thorough. Resolved by `effective`
    #: rather than copied into the fields above, so switching it off
    #: returns the project to whatever was set before.
    kitchen_sink: bool = False
    #: (host, has_address) for every target in the project.
    targets: list[tuple[str, bool]] = field(default_factory=list)
    #: Of those, the ones whose identifier is not a DNS name — a cloud
    #: resource id, a mobile bundle id. See `hosts.dns_subject`.
    #:
    #: A set beside `targets` rather than a third element in the tuple
    #: because `targets` is what the port-scanning policy reads and it
    #: wants all of them: a cloud resource usually has an address and
    #: is perfectly scannable. It is only the NAME that is not a name,
    #: so only the name-based policies subtract this.
    not_dns_named: set[str] = field(default_factory=set)
    #: Every address the project has OBSERVED, from `target_addresses`
    #: -- what resolution, port scanning and the importers recorded,
    #: as opposed to the addresses somebody typed in as a target.
    #:
    #: Separate from `targets` because the two are different facts. A
    #: target named `10.0.0.1` is an address an operator entered; a row
    #: here is an address the estate was found to answer on. The
    #: reverse-DNS policy wants both and used to see only the first.
    addresses: set[str] = field(default_factory=set)
    #: Zones already handed to amass (`DomainSearch.domain`).
    searched: set[str] = field(default_factory=set)
    #: Zones the scope list NAMES with a wildcard. These are candidates
    #: in their own right, not only the zones derived from hostnames:
    #: `registrable("one.zone.acme.example")` is `acme.example`, which
    #: `*.zone.acme.example` does not cover, so deriving from hosts
    #: alone means the engagement never enumerates the zone it was
    #: actually authorised against. Same reasoning as `domainRoots`.
    scope_zones: set[str] = field(default_factory=set)
    #: Every web address in the project, as a url. The subject
    #: a crawl or a content-discovery run actually needs.
    web_urls: set[str] = field(default_factory=set)
    #: {origin: [CVE, ...]} the local corpus already links to a
    #: service on that origin's host, with an EXACT CPE version
    #: match. Read once per cycle so `plan` stays pure data.
    #:
    #: Empty for an origin whose services gave no version, which is
    #: not a gap to fill: a product-wide CPE match is every CVE that
    #: vendor ever had, and a confirmation run built from that is the
    #: unfiltered scan this avoids.
    suspected: dict[str, list[str]] = field(default_factory=dict)
    #: The project's scope gate. `gaps` and `plan`'s caller both ask
    #: it, so what is reported outstanding and what actually gets
    #: queued cannot disagree -- see `cleared`.
    #:
    #: None means there is no gate to ask and everything passes, which
    #: is what a Snapshot built by hand in a test wants. It does NOT
    #: mean "a project with an empty scope document": an empty
    #: `ScopeIndex` answers that case for itself, and differently.
    scope: ScopeIndex | None = None
    #: {origin: [url, ...]} -- paths content discovery found that no
    #: crawl has started from. See `webtargets.crawl_seeds`, which
    #: explains at length why this one source is allowed to point a
    #: crawler at something other than an origin.
    seeds: dict[str, list[str]] = field(default_factory=dict)
    #: (kind, subject) this project has ever tasked. See "one attempt
    #: per subject" in the module docstring.
    tasked: set[tuple[str, str]] = field(default_factory=set)


#: What each policy is set to when the kitchen sink is open.
#:
#: The most thorough value of each, not merely "on": a sink that
#: left `auto_nmap` at `top100` would be a switch whose name
#: promised one thing and did another.
#:
#: Certificate Transparency and archived-URL lookups are NOT here.
#: They send a client's domain to a third party and are gated by an
#: explicit site decision; a convenience switch that routed around a
#: vendor-approval gate would be the gate not existing. See
#: app/ctlogs.py, which argues it at length.
#: `auto_poc` is deliberately NOT here, for the same reason the
#: Certificate Transparency lookups are not: a convenience switch
#: must not quietly start doing the one thing somebody would want to
#: decide on purpose. Every other entry turns a scanner up; this one
#: would begin writing payloads for findings and firing them.
KITCHEN_SINK: dict[str, object] = {
    "auto_amass": True,
    "auto_resolve_ips": True,
    "auto_reverse_dns": True,
    "auto_vhost": True,
    "auto_httpx": True,
    "auto_nmap": "full",
    "auto_web": "both",
    "auto_nuclei": "both+confirm",
}


def effective(s: Snapshot) -> Snapshot:
    """The policies as they will actually be applied.

    One place that resolves `kitchen_sink`, so nothing downstream has
    to remember it exists. `plan` calls this; so does the gap report,
    so the two cannot disagree about what was supposed to happen.
    """
    if not s.kitchen_sink:
        return s
    return replace(s, **KITCHEN_SINK)       # type: ignore[arg-type]


def name_subjects(s: Snapshot) -> list[tuple[str, bool]]:
    """The targets a NAME-based policy may take as a subject.

    `auto_amass` enumerates under a zone and `auto_resolve_ips` asks a
    resolver about a name; both derive their subject from the
    identifier in `Target.host`, and for a cloud resource or a mobile
    app that identifier is not a name — see `hosts.dns_subject`, which
    is the one statement of that rule.

    One function rather than the same filter written at each policy.
    Two copies of a rule is how they come to disagree, which is the
    bug `roots.py` was extracted to end and this is the same lesson:
    the gap report below and `plan` must subtract exactly the same
    targets, or the report shows work outstanding that the planner
    will never queue, for ever.

    The port-scanning policies are deliberately not filtered through
    this. A bucket with an address is a thing to scan; it is only
    unaskable ABOUT BY NAME.
    """
    return [(h, has) for h, has in s.targets if h not in s.not_dns_named]


@dataclass(frozen=True)
class Gap:
    """Something a standing order was supposed to cover and has not."""
    policy: str
    #: What is still owed, in the operator's words.
    what: str
    outstanding: int


def cleared(idx: ScopeIndex | None, kind: str, subject: str) -> bool:
    """Would the scope gate let a task of this kind at this subject in?

    One implementation, asked by both `gaps` and `run_once`, because
    they used to answer differently: `run_once` consulted the gate and
    the gap report did not. A project whose scope is narrower than its
    target list then reports a backlog that can never be worked off,
    and the operator with the toggle on goes and runs it by hand --
    which is the exact complaint this function exists to end, and the
    third time this file has been bitten by two readings of one
    question (`tasked_subjects`, `enumerable_roots`, now this).

    It is not a small discrepancy. One engagement reported 3,827
    outstanding items across nine policies; the gate allowed none of
    them. The standing orders had in fact finished every host they
    were permitted to touch, and no surface could say so.

    A zone handed to amass is asked `check_zone`; everything else is a
    host something will be done TO, and gets `check`. The two disagree
    on exactly one input -- the apex of a wildcard -- and collapsing
    them would let a standing order queue a scan at a host the
    wildcard never covered. `as_host` because a web subject is a URL
    and the scope document names hosts.
    """
    if idx is None:
        return True
    if kind == "amass":
        return idx.check_zone(subject).allowed
    return idx.check(as_host(subject) or subject).allowed


def gaps(s: Snapshot) -> list[Gap]:
    """What the policies that are ON have still not done.

    The point of a switch that says "everything" is that somebody
    stops checking. So it has to be able to answer "is it actually
    done", and the only honest answer is derived from the estate
    rather than from whether the worker ran.

    Reads `effective`, the same resolution `plan` uses, and `cleared`,
    the same gate `run_once` applies. Two readings of what a project
    asked for is how they come to differ, and a gap report that
    disagreed with the planner would be worse than none: it would be
    a clean bill of health for work nobody did -- or, as it actually
    shipped, a permanent backlog of work nobody is allowed to do.

    An empty list means every policy that is on has nothing
    outstanding that the project is permitted to touch. It does NOT
    mean the estate is fully enumerated -- a policy that is off has no
    gap by definition, which is why the report names the policy and
    not just the number.
    """
    s = effective(s)
    out: list[Gap] = []

    def add(policy: str, what: str, n: int) -> None:
        if n:
            out.append(Gap(policy, what, n))

    if s.auto_poc != "off":
        add("auto_poc",
            f"finding(s) at {s.auto_poc} or worse with no proof",
            s.poc_backlog)
    # Every count below is filtered by the gate as well as by what
    # has been tasked, because a subject the gate refuses is not work
    # outstanding -- it is work that will never happen, and reporting
    # it as a gap is how an operator ends up doing by hand what the
    # automation was right to leave alone. See `cleared`.
    def owed(kind: str, subjects) -> int:
        return len([x for x in subjects
                    if (kind, x.lower()) not in s.tasked
                    and cleared(s.scope, kind, x)])

    if s.auto_amass:
        add("auto_amass", "in-scope zone(s) never handed to amass",
            len([z for z in {z for z in s.scope_zones if z} - s.searched
                 if cleared(s.scope, "amass", z)]))
    if s.auto_resolve_ips:
        add("auto_resolve_ips", "hostname(s) with no address recorded",
            owed("nslookup", [h for h, has in name_subjects(s) if not has]))
    if s.auto_reverse_dns:
        add("auto_reverse_dns", "address(es) with no reverse lookup",
            owed("reverse_ip", s.addresses))
    if s.auto_nmap != "off":
        add("auto_nmap", "host(s) never port scanned",
            owed("nmap", [h for h, _ in s.targets]))
    for flag, kind, label in (
            (s.auto_vhost, "vhost", "URL(s) never asked for virtual hosts"),
            (s.auto_httpx, "httpx", "URL(s) never probed")):
        if flag:
            add(f"auto_{kind}", label, owed(kind, s.web_urls))
    if s.auto_web in WEB_KINDS:
        for kind in WEB_KINDS[s.auto_web]:
            add("auto_web", f"URL(s) with no {kind} run",
                owed(kind, s.web_urls))
    if s.auto_nuclei in NUCLEI_KINDS:
        for kind in NUCLEI_KINDS[s.auto_nuclei]:
            # `nuclei_confirm` is owed only where a version was
            # actually detected: a CPE match without one is
            # product-wide, and counting every URL as a gap would
            # report work that is not supposed to happen.
            pool = (set(s.suspected) if kind == "nuclei_confirm"
                    else s.web_urls)
            add("auto_nuclei", f"URL(s) with no {kind} run",
                owed(kind, pool))
    return out


def plan(s: Snapshot, limit: int | None = None) -> list[Candidate]:
    """What the policies would like to do, in the order they would do it.

    Pure. `limit` is per policy and defaults to None, meaning all of
    them: an operator who switched a policy on wants the backlog done,
    not a page of it. Callers may still pass one, and the slices below
    read `[:None]` as "everything", which is exactly the wanted
    behaviour rather than a trick.

    The order is stable regardless, so an interrupted cycle resumes
    where it was rather than starting somewhere different.

    **Every candidate is gated here as well as in `run_once`, and it
    has to happen before the cap.** `run_once` remains the authority
    on what may be touched; this only decides what is worth proposing.
    Skipping it here does not queue anything forbidden, but it does
    let refused names eat a whole cycle's budget and starve the work
    that would have passed -- see `allow`.

    A Snapshot with no `scope` is not filtered, which is what a test
    describing an estate wants and what every caller got before the
    gate was available here.
    """
    # The kitchen sink is resolved HERE and not at the call sites.
    # Two readings of what a project asked for is how they come to
    # differ, and the gap report below reads the same function.
    s = effective(s)
    out: list[Candidate] = []

    def allow(kind: str, subjects: list[str]) -> list[str]:
        """The ones the gate will take -- BEFORE the cap, not after.

        This order is the whole point. Every policy below sorts its
        backlog and takes the first N; `run_once` then asks the gate
        about each and drops what it refuses. With the cap applied
        first, a project whose scope is narrower than its target list
        spends its entire per-cycle budget on candidates that are
        about to be refused, queues nothing, and makes no progress --
        for ever, because the list is sorted and the same refused
        names come up first every single time.

        That is not a rounding error. One engagement had 1,027
        in-scope URLs owed an `httpx` probe and a cycle proposing 250
        candidates, of which the gate cleared ZERO: the first 250
        names in sort order were all out of scope, and the in-scope
        work sat behind them indefinitely with the toggle on.

        `run_once` still gates every candidate on the way out. This
        does not replace that check -- it stops the budget being
        spent before the check is reached.
        """
        return [x for x in subjects if cleared(s.scope, kind, x)]

    if s.auto_amass:
        zones: list[str] = []
        seen: set[str] = set()
        # Redundant against a snapshot built by `snapshot()`, whose
        # scope_zones already covers every known host. Kept so `plan`
        # stays a total function of its Snapshot rather than depending
        # on one particular caller having filled a field -- the unit
        # tests construct Snapshots directly, and so would anyone
        # reasoning about this in isolation.
        derived = [gen.registrable(h) for h, _ in name_subjects(s)
                   if not is_ip(h)]
        for z in list(s.scope_zones) + derived:
            if not z or "." not in z or z in seen:
                continue
            seen.add(z)
            if z in s.searched or ("amass", z) in s.tasked:
                continue
            zones.append(z)
        out += [Candidate("amass", z, {"domain": z, "mode": "passive"},
                          "auto_amass")
                for z in allow("amass", sorted(zones))[:limit]]

    if s.auto_resolve_ips:
        want = sorted(
            h for h, has_addr in name_subjects(s)
            if not has_addr and not is_ip(h) and ("nslookup", h) not in s.tasked)
        out += [Candidate("nslookup", h, {}, "auto_resolve_ips")
                for h in allow("nslookup", want)[:limit]]

    if s.auto_reverse_dns:
        # Two sources, and for a long time only the first was read.
        #
        # A target NAMED by its address has no name of its own, so it
        # is the obvious candidate -- `has_addr` is not the question
        # here and is not asked. But that is the case an operator
        # creates by typing an address in, and on an engagement run
        # from a scope list of hostnames and CIDRs it does not happen:
        # the production estate had 1,038 targets, ZERO of them
        # address-named, and 1,857 observed addresses. The policy was
        # switched on and correct and could never queue anything.
        #
        # The addresses the estate was found to answer on are the ones
        # worth asking about, because that is where a name we do not
        # have yet lives -- shared hosting, a load balancer's own
        # name, a management interface on a neighbouring address.
        #
        # Every one still goes through the scope gate individually,
        # like every other candidate here. An observed address is not
        # in scope by virtue of having been observed; `run_once` is
        # what decides, and a discovered address that the gate refuses
        # is simply not queued.
        want = sorted(
            {h for h, _ in s.targets if is_ip(h)} | s.addresses)
        want = [h for h in want if ("reverse_ip", h) not in s.tasked]
        out += [Candidate("reverse_ip", h, {}, "auto_reverse_dns")
                for h in allow("reverse_ip", want)[:limit]]

    if s.auto_web in WEB_KINDS:
        # Queued per ORIGIN. Neither tool can be pointed at a bare
        # hostname, and neither gains anything from being pointed at a
        # path: katana walks out from wherever it starts and gobuster
        # applies its wordlist from the root. `webtargets.origin_of`
        # is what collapses them, and the reason is in its docstring.
        for kind in WEB_KINDS[s.auto_web]:
            # `u.lower()`, because `tasked_subjects` lowercases what it
            # records. Without it a subject whose spelling carried any
            # uppercase never matched as already-done and was queued
            # again on every single cycle -- which is how one project
            # reached 97,959 queued tasks from 1,109, with individual
            # subjects queued five times over. Origins are lowercased
            # at the source now, so this is belt and braces; it is
            # here because the cost of the two sides disagreeing again
            # is measured in requests at a client.
            want = sorted(u for u in s.web_urls
                          if (kind, u.lower()) not in s.tasked)
            # Capped per cycle regardless of `limit`. The policies
            # above are bounded by the size of the estate; this one is
            # bounded by how much of the web estate has been found,
            # which grows as it runs. A cap does not withhold work --
            # the next cycle takes the next batch -- it just stops a
            # single miscount from becoming six figures of queued
            # scanning before anybody looks.
            cap = WEB_PER_CYCLE if limit is None else min(limit, WEB_PER_CYCLE)
            out += [Candidate(kind, u, {"targets": [u]}, "auto_web")
                    for u in allow(kind, want)[:cap]]

        # Crawls seeded with what content discovery found, which only
        # applies when crawling is part of the mode: `gobuster` on its
        # own is the operator asking for paths, not for the crawler to
        # follow them.
        #
        # The subject is the ORIGIN, not the seeds, because the origin
        # is what the scope gate is asked about and every seed in the
        # group is on it by construction. The seeds ride in `targets`,
        # where `tasked_subjects` records each of them -- so running
        # this task is also what stops it being queued again.
        if "katana" in WEB_KINDS[s.auto_web]:
            cap = WEB_PER_CYCLE if limit is None else min(limit, WEB_PER_CYCLE)
            seeded = [(o, u) for o, u in sorted(s.seeds.items()) if u
                      and cleared(s.scope, "katana", o)]
            out += [Candidate("katana", o, {"targets": list(urls)},
                              "auto_web_seeded")
                    for o, urls in seeded[:cap]]

    # What else does this address answer to? A host serving twelve
    # virtual hosts is twelve applications behind one socket, and
    # eleven of them are invisible to everything else here: content
    # discovery asks what PATHS exist on a site, and this asks what
    # SITES exist on a host.
    #
    # Per origin, like the web policies, and once ever per origin --
    # the answer is a property of the server's configuration, not of
    # the moment.
    if s.auto_vhost:
        want = sorted(u for u in s.web_urls
                      if ("vhost", u.lower()) not in s.tasked)
        cap = WEB_PER_CYCLE if limit is None else min(limit, WEB_PER_CYCLE)
        out += [Candidate("vhost", u, {"targets": [u]}, "auto_vhost")
                for u in allow("vhost", want)[:cap]]

    # And the cheapest thing in the catalogue: ask every known URL
    # what it answers with. It is what decides whether anything
    # heavier is worth queueing against a URL at all, which is why
    # it is worth doing to everything rather than to a selection.
    if s.auto_httpx:
        want = sorted(u for u in s.web_urls
                      if ("httpx", u.lower()) not in s.tasked)
        cap = WEB_PER_CYCLE if limit is None else min(limit, WEB_PER_CYCLE)
        out += [Candidate("httpx", u, {"targets": [u]}, "auto_httpx")
                for u in allow("httpx", want)[:cap]]

    if s.auto_nuclei in NUCLEI_KINDS:
        # Per URL, like auto_web and for the same reason: nuclei takes
        # a URL already known to answer (`PROBE_KINDS["nuclei"]`), and
        # a bare hostname gives it nothing to request.
        #
        # The two kinds dedupe INDEPENDENTLY. They are separate
        # entries in `tasked` because they are separate kinds, which
        # is the whole reason `nuclei_tech` is its own kind rather
        # than an argument on `nuclei`: one kind would mean running
        # the vulnerability templates marked the URL done and the
        # technology run never happened.
        for kind in NUCLEI_KINDS[s.auto_nuclei]:
            want = sorted(u for u in s.web_urls
                          if (kind, u.lower()) not in s.tasked)
            # Capped like the web policy. The subject list here is the
            # same growing one -- discovered web addresses -- so it
            # carries the same risk of a miscount becoming six figures
            # of queued scanning.
            cap = WEB_PER_CYCLE if limit is None else min(limit, WEB_PER_CYCLE)
            if kind == "nuclei_confirm":
                # Per URL, because the template set IS per URL. A URL
                # with nothing suspected produces no task: asking
                # nuclei to confirm an empty list would be a full
                # template run wearing a confirmation's name.
                out += [Candidate(kind, u,
                                  {"targets": [u],
                                   # Sorted HERE as well as in
                                   # `suspected_cves`. The snapshot is
                                   # plain data that a caller or a test
                                   # builds, so the command line must
                                   # not depend on who assembled it --
                                   # two runs over the same estate have
                                   # to be comparable.
                                   "extra": NUCLEI_PROFILES[kind]
                                            + " -id "
                                            + ",".join(sorted(set(ids)))},
                                  "auto_nuclei")
                        for u in allow(kind, want)[:cap]
                        if (ids := s.suspected.get(u))]
            else:
                out += [Candidate(kind, u,
                                  {"targets": [u],
                                   "extra": NUCLEI_PROFILES[kind]},
                                  "auto_nuclei")
                        for u in allow(kind, want)[:cap]]

    if s.auto_nmap in NMAP_PROFILES:
        args = NMAP_PROFILES[s.auto_nmap]
        want = sorted(h for h, _ in s.targets if ("nmap", h) not in s.tasked)
        out += [Candidate("nmap", h, dict(args), "auto_nmap")
                for h in allow("nmap", want)[:limit]]

    return out


#: Worst first. The `auto_poc` value is a FLOOR, so "medium" means
#: this list up to and including medium -- which is the whole reason
#: the setting is a severity and not a boolean.
POC_SEVERITIES = ("critical", "high", "medium", "low", "info")


def poc_severities(floor: str) -> tuple[str, ...]:
    """The severities a floor covers. Empty for "off" or nonsense.

    Empty rather than "everything" on an unrecognised value. A floor
    nobody can parse must do nothing: the alternative is a typo in a
    settings field quietly widening what gets a payload written for
    it, which is the opposite of what an explicit floor is for.
    """
    floor = (floor or "off").strip().lower()
    if floor not in POC_SEVERITIES:
        return ()
    return POC_SEVERITIES[:POC_SEVERITIES.index(floor) + 1]


async def poc_backlog(session: AsyncSession, project_id: int,
                      floor: str) -> int:
    """How many findings at or above `floor` still have no proof.

    The backlog, not the new arrivals: a standing order is evaluated
    against whatever is outstanding, which is what makes switching
    one on do something rather than appearing to be broken. See the
    module docstring.

    Counted with a NOT EXISTS rather than an outer join so one
    finding with three PoCs against it is one row and not three --
    the number is "findings owed a proof", and a join would make a
    well-covered finding inflate the figure it is supposed to reduce.
    """
    wanted = poc_severities(floor)
    if not wanted:
        return 0
    has_poc = (select(Poc.id)
               .where(Poc.vuln_id == Vuln.id)
               .exists())
    return int((await session.execute(
        select(func.count(Vuln.id))
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == project_id,
               Vuln.severity.in_(wanted),
               ~has_poc))).scalar_one())


async def snapshot(session: AsyncSession, pr: Project) -> Snapshot:
    """Read one project's state into a `Snapshot`."""
    rows = (await session.execute(
        select(Target).where(Target.project_id == pr.id)
        .order_by(Target.host))).scalars().unique().all()
    targets = [(t.host, bool(t.addresses)) for t in rows]
    # Read here rather than inferred from the host string later. A
    # bucket name has no punctuation that gives it away -- `acme-backups`
    # is a perfectly well-formed hostname and simply is not one -- so
    # the kind column is the only thing that actually knows.
    not_dns_named = {t.host for t in rows if not dns_subject(t.kind)}

    # Observed addresses, for `auto_reverse_dns`. Read from the table
    # rather than walked off `rows`, so an address recorded against a
    # target the eager load did not bring back is still seen, and so
    # the cost is one query instead of one per target.
    addresses = {a for a in (await session.execute(
        select(TargetAddress.address).where(
            TargetAddress.project_id == pr.id).distinct())).scalars().all()
        if a}

    searched = set((await session.execute(
        select(DomainSearch.domain).where(
            DomainSearch.project_id == pr.id))).scalars().all())

    # Every zone worth enumerating, from the same function the
    # "Search for more domains" dialog uses.
    #
    # This used to read only `kind == "wildcard"` and derive the rest
    # from `Target.host`. Both halves were too narrow, and on a real
    # project both mattered: one had three scope entries, all `fqdn`
    # and no wildcards, so this set came back EMPTY and the only
    # authorised domains were invisible to the automation meant to
    # enumerate them; and 626 of its 1,038 targets carried alternate
    # names or TLS SANs that only the dialog's wider sweep read.
    #
    # The symptom was an operator with auto_amass on still finding
    # domains waiting every single time they opened the dialog.
    scope_zones = await enumerable_roots(session, pr.id)

    # DERIVED, not hand-listed. A kind missing from this tuple has no
    # entry in `tasked`, so its "have we already done this" check can
    # never be true and the policy re-queues the same subject on every
    # cycle for ever.
    #
    # That is not hypothetical: `vhost`, `httpx`, `nuclei` and
    # `nuclei_tech` were all absent, and on one engagement each URL
    # had been re-scanned between 13 and 68 times over two weeks. It
    # did not look like a runaway because `outstanding_subjects`
    # stops a second copy stacking while the first is in flight -- so
    # instead of exploding it idled at a few hundred tasks and simply
    # never finished, re-sending the same scans at the client. The
    # kinds that WERE listed sat at 1.0-2.1 runs per subject, which
    # is what this is supposed to do.
    #
    # `TASKED_KINDS` is built from the same tables `plan()` reads, so
    # adding a policy kind cannot miss this again -- see the guard in
    # `automationtest.py`, which checks the two agree.
    tasked = await tasked_subjects(session, pr.id, TASKED_KINDS)

    # Everywhere web discovery could be pointed. A crawl and a
    # content-discovery run both need a URL to start from -- "scan
    # example.com" is not a thing either can do -- and one host can
    # serve several sites.
    #
    # This read `web_addresses` alone, and that was the whole policy's
    # blind spot: a project that had been port-scanned but never
    # crawled has no rows there, so a switch set to `both` looked at
    # an empty set and queued nothing, for ever, without saying so.
    # The case it could not see is the only case it exists for.
    #
    # `discoverable` adds the URLs derived from open web services, so
    # the standing order now starts from the same places the Enumerate
    # dialog offers. The policy's own filter is unchanged and still
    # does the real work: of everywhere it could go, queue the ones
    # nothing has been run against yet.
    origins = await discoverable(session, pr.id)
    web_urls = set(origins)
    # Only when something will use it. The lookup is a query per
    # distinct (product, version) in the project, and a project not
    # running confirmation has no use for the answer.
    suspected: dict[str, list[str]] = {}
    if pr.auto_nuclei in ("confirm", "both+confirm"):
        from .vulnfeed import suspected_cves
        suspected = await suspected_cves(session, pr.id, origins)

    # Read whatever the switch is set to, rather than only when a
    # crawl is wanted: `plan` is where the policy lives, and a
    # snapshot that quietly omits part of the estate depending on a
    # setting is how `web_urls` came to be narrower than the dialog's
    # list without anybody noticing.
    seeds = await crawl_seeds(session, pr.id)

    return Snapshot(
        auto_amass=bool(pr.auto_amass),
        auto_resolve_ips=bool(pr.auto_resolve_ips),
        auto_reverse_dns=bool(pr.auto_reverse_dns),
        auto_nmap=str(pr.auto_nmap or "off"),
        auto_web=str(getattr(pr, "auto_web", None) or "off"),
        auto_nuclei=str(getattr(pr, "auto_nuclei", None) or "off"),
        auto_vhost=bool(getattr(pr, "auto_vhost", False)),
        auto_httpx=bool(getattr(pr, "auto_httpx", False)),
        auto_poc=str(getattr(pr, "auto_poc", None) or "off"),
        poc_backlog=await poc_backlog(session, pr.id,
                                      str(getattr(pr, "auto_poc", None)
                                          or "off")),
        kitchen_sink=bool(getattr(pr, "kitchen_sink", False)),
        targets=targets, not_dns_named=not_dns_named, addresses=addresses,
        searched=searched, tasked=tasked,
        scope_zones=scope_zones, web_urls=web_urls, seeds=seeds,
        suspected=suspected,
        # Loaded here with the rest of the estate so `gaps` can ask it
        # without a session, and so `run_once` does not load it twice.
        scope=await index_for(session, pr.id))


async def run_once(session: AsyncSession, pr: Project) -> dict[str, int]:
    """Evaluate one project's policies and queue what the gate allows.

    Returns a count per policy, which is what the log line and the
    tests read. An empty dict means there was nothing to do, which is
    the normal case and is not logged.
    """
    # Geolocation, if it is switched on and has databases. Done here
    # because this loop is already the project's "follow-up work"
    # cycle and runs on a timer; a lookup is a memory-mapped tree walk
    # against a local file, so it costs nothing to ask and nothing
    # leaves this machine.
    #
    # Bounded inside `tag_missing`: a project with forty thousand
    # addresses does them over several cycles rather than in one.
    try:
        if n := await geoip.tag_missing(session, pr.id):
            log.info("geoip: located %d address(es) in %s", n, pr.code)
    except Exception as e:                       # noqa: BLE001
        # Never fatal to the standing orders. Geolocation is a nicety;
        # the scans are the job.
        log.warning("geoip: %s", e)

    snap = await snapshot(session, pr)
    want = plan(snap)
    if not want:
        return {}

    # Nothing is queued at all with no ghost to run it. The tasks would
    # sit in the queue and be perfectly valid, but "25 queued" against
    # an empty fleet every minute is a queue nobody asked for by the
    # time anyone brings an agent up.
    live = (await session.execute(
        select(Agent.id).where(Agent.project_id == pr.id,
                               Agent.status == "online").limit(1))).first()
    if live is None:
        return {}

    # The gate the snapshot already loaded. One per cycle, and the
    # same object `gaps` answered from, so the report an operator
    # reads and the decision made here come from one list.
    idx = snap.scope if snap.scope is not None else await index_for(
        session, pr.id)
    # The same floor the queueing path enforces, for the same reason.
    # `plan()` filters on what has ever been tasked and that filter
    # was once wrong by a lowercase; this makes a second outstanding
    # copy impossible rather than merely unplanned.
    in_flight = await outstanding_subjects(
        session, pr.id, tuple({c.kind for c in want}))
    queued: dict[str, int] = {}
    pending = 0
    for c in want:
        # What this task will actually be pointed at. Almost every
        # policy names one subject and scans exactly it; a crawl
        # seeded from content discovery names the origin as its
        # subject and carries the unlinked paths underneath it.
        #
        # Both the gate and the in-flight floor are applied to this
        # list rather than to `c.subject`, so the rule stays "every
        # address a task will touch was cleared and is not already
        # being touched" -- which is the property the single-subject
        # form had by accident and this form has to keep on purpose.
        aimed = ([c.subject] if c.kind == "amass"
                 else [str(x) for x in (c.args.get("targets") or [c.subject])])
        if any((c.kind, a.lower()) in in_flight for a in aimed):
            continue
        # `cleared` holds which question each kind is asked and why.
        # It is shared with the gap report so the two cannot drift.
        if c.kind == "amass":
            allowed = cleared(idx, "amass", c.subject)
        else:
            # EVERY aimed address, not just the first. A task that
            # carries several is only as cleared as its least-cleared
            # entry, and "the subject passed" would be a gate that
            # checks one URL and scans twenty-five.
            allowed = all(cleared(idx, c.kind, a) for a in aimed)
        if not allowed:
            # Not an error and not logged per candidate: a project whose
            # scope is narrower than its target list refuses the same
            # names every cycle, and that would be the whole log.
            continue
        args = dict(c.args) if c.kind == "amass" else {**c.args,
                                                       "targets": aimed}
        t = AgentTask(agent_id=None, project_id=pr.id, requested_by=None,
                      kind=c.kind, args=json.dumps(args),
                      import_as=_import_as(c.kind), status="queued")
        session.add(t)
        queued[c.policy] = queued.get(c.policy, 0) + 1
        pending += 1
        # Flushed in batches rather than accumulating the whole backlog
        # in one statement. A project switching a policy on for four
        # thousand hosts is now one cycle, not a hundred and sixty, and
        # that only works if the write is chunked.
        if pending >= BATCH:
            await session.flush()
            pending = 0

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
                    | (Project.auto_nmap != "off")
                    # `auto_web` was missing from this list. A project
                    # with web discovery as its ONLY standing order
                    # was never selected, so the policy did nothing
                    # and said nothing -- the worker reported "no
                    # project has a standing order" while one was set.
                    # It went unnoticed because the only project using
                    # it had the other four on as well, which selected
                    # it for unrelated reasons.
                    | (Project.auto_web != "off")
                    | (Project.auto_nuclei != "off")
                    # The two added later, and the switch that
                    # implies every one of them. A project selected
                    # by none of these predicates is a project the
                    # worker never looks at, which is how `auto_web`
                    # did nothing and said nothing for a month.
                    | (Project.auto_vhost.is_(True))
                    | (Project.auto_httpx.is_(True))
                    | (Project.kitchen_sink.is_(True))))).scalars().all()
            if not rows:
                self.last = "no project has a standing order"
                return
            total: dict[str, int] = {}
            outstanding: list[str] = []
            for pr in rows:
                for policy, n in (await run_once(session, pr)).items():
                    total[policy] = total.get(policy, 0) + n
                # The point of a switch that says "everything" is
                # that somebody stops checking, so it has to be able
                # to answer "is it actually done". Derived from the
                # estate rather than from whether the worker ran.
                if pr.kitchen_sink:
                    g = gaps(await snapshot(session, pr))
                    if g:
                        outstanding.append(
                            f"{pr.code}: " + "; ".join(
                                f"{x.outstanding} {x.what}" for x in g[:4])
                            + (f" (+{len(g) - 4} more)" if len(g) > 4 else ""))
            self.last = (", ".join(f"{n} {p}" for p, n in sorted(total.items()))
                         if total else "nothing outstanding")
            # Said separately from what was queued. "Queued 40" and
            # "still owes 4,000" are different facts and the second
            # is the one somebody who turned the sink on wants.
            if outstanding:
                self.last += " | still owed — " + " | ".join(outstanding)

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
