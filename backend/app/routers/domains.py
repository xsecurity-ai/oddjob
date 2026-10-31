"""Suggesting hostnames worth trying, and remembering what has been tried.

Generation is offline — see `app/domains.py` for why. These routes add the
memory: which domains have been run, what they produced, and what was
accepted or rejected, so a second run returns what is genuinely new rather
than the same list with the same names in it.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import clouds
from .. import domains as gen
from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..models import (
    DomainCandidate,
    DomainSearch,
    Project,
    Target,
    User,
    WebAddress,
)
from ..roots import known_hosts, scope_roots
from ..schemas import DomainCandidateOut, PromoteRequest
from ..scopegate import index_for
from ..security import get_current_user, require_project
from ..tasking import tasked_subjects
from ..timeline import record


def _conflict_insert(session, model):
    """An INSERT that can carry `on_conflict_do_nothing`.

    Postgres and SQLite both support it, from different modules, and
    the generic `insert()` supports it from neither. Chosen per
    session so the same code runs against the deployment database and
    the test one.
    """
    if session.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as _ins
    else:
        from sqlalchemy.dialects.sqlite import insert as _ins
    return _ins(model)


router = APIRouter(prefix="/api/domains", tags=["domains"])


@router.get("/roots")
async def roots(project: str = Query(...),
                pr: Project = Depends(require_project("readonly")),
                session: AsyncSession = Depends(get_session)):
    """Registrable domains this engagement covers, commonest first.

    Two sources, because either alone leaves a real engagement with an
    empty list:

      targets   what the estate already touches, commonest first. The
                best signal, and the only one that exists mid-engagement.
      scope     the FQDNs the engagement was authorised against. These
                matter MOST on day one, which is exactly when there are
                no targets yet — a fresh project used to report "no root
                domains" while its scope named a dozen.

    There was a third: domains the offline generator had already
    guessed under. That generator is gone — enumeration is amass on a
    ghost now, and whether it has run is a question about tasks, not
    about a table here.

    `searched` answers that question. It used to be hardcoded empty,
    with the comment above correctly identifying where the answer
    lived and then not going and getting it, so every domain in this
    list read as never enumerated for ever. An operator with
    `auto_amass` on therefore had no way to tell the finished zones
    from the waiting ones, and went through them one at a time
    re-running work the fleet had already done. That is the whole
    complaint this field exists to answer.

    `known_hosts` is the count from targets only, so a root that is in
    scope and otherwise untouched still reads as 0 and sorts last
    without being hidden.
    """
    hosts = await known_hosts(session, pr.id)

    # Enumerated, or already asked for: the same disjunction the
    # standing order skips a zone on (`automation.plan`). Asked
    # through `tasked_subjects` rather than with a second query, so
    # this list and the automation cannot answer differently about
    # the same zone -- which is the failure mode `roots.py` was
    # extracted to end, arriving here by a third door.
    #
    # A completed `DomainSearch` is the record of a walk that
    # finished. An amass task is the record of one that was asked
    # for, which is enough: queueing a second is the duplicate the
    # standing order is careful never to raise.
    searched = set((await session.execute(
        select(DomainSearch.domain).where(
            DomainSearch.project_id == pr.id))).scalars().all())
    searched |= {sub for _, sub in
                 await tasked_subjects(session, pr.id, ("amass",))}

    counts = dict(gen.roots_in(hosts))
    origin = dict.fromkeys(counts, "targets")

    # Never a provider's own zone, from either source.
    #
    # `enumerable_roots` has always dropped these for the auto_amass
    # standing order; this list did not, so the dialog offered
    # `amazonaws.com` -- usually at the TOP, because an estate inside a
    # cloud has more provider-named hosts than chosen ones -- while the
    # automation refused to walk it. Picking it enumerated AWS, not the
    # client. Same predicate, so the two cannot drift again.
    counts = {d: n for d, n in counts.items() if not clouds.is_cloud_domain(d)}
    origin = {d: o for d, o in origin.items() if d in counts}

    # The same function the auto_amass standing order uses. They
    # disagreed before — this offered zones the automation could not
    # see, so an operator with the toggle on kept finding work here.
    scoped = await scope_roots(session, pr.id)
    for r in scoped:
        # Not narrowed into `scoped` itself: that set is also the
        # "does this project name any domains at all" test below, and
        # a project scoped entirely to cloud zones does name some.
        # Emptying it there would skip the gate filter instead.
        if clouds.is_cloud_domain(r):
            continue
        if r not in counts:
            counts[r] = 0
            origin[r] = "scope"

    # A searched name is NOT offered as a root in its own right.
    #
    # This block used to add one row per searched name, which cost
    # nothing while `searched` was hardcoded empty. Now that it is
    # real, most of what it holds are individual hostnames an
    # operator enumerated directly -- `acat.api.acme.example`, not
    # `acme.example` -- and this endpoint's contract is registrable
    # domains. On one project it would have added 478 rows, none of
    # them a root. `searched` marks the rows that are here for a
    # reason of their own; it does not make rows.

    # Offer only what may actually be enumerated.
    #
    # This list used not to consult the gate at all, while
    # `/enumerate` and the auto_amass standing order both do. So a
    # zone nothing was allowed to touch sat here being offered for
    # ever: picking it queued nothing, the toggle never cleared it,
    # and the dialog reported work outstanding on every visit.
    #
    # Only when the project names domains. A project with no domain
    # scope yet — day one, before anyone has written it down — would
    # otherwise show an empty list, which reads as "nothing to
    # enumerate" when the truth is "nobody has said yet". That is the
    # case this endpoint's own docstring calls out as mattering most.
    #
    # `check_zone`, not `check`: a zone is being enumerated under, not
    # a host scanned, and the two disagree on exactly the apex of a
    # wildcard — which is the entry most likely to be here.
    if scoped:
        idx = await index_for(session, pr.id)
        counts = {d: n for d, n in counts.items() if idx.check_zone(d).allowed}

    return [{"domain": d, "known_hosts": n, "searched": d in searched,
             "source": origin.get(d, "targets")}
            for d, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


#: Most domains one submission will queue tasks for. The same number the
#: typed list is capped at, for the same reason: each is a task, and a
#: queue that long buries everything else the project needs to run.
#:
#: Kitchen Sink is not refused for exceeding it, though. A typed list over
#: the cap is an operator mistake they can fix by splitting it; a generated
#: list over the cap is just a big estate, and there is nothing for them to
#: split. The overflow is reported as deferred and picked up by the next
#: run, which skips everything this one queued — so running it twice drains
#: the backlog rather than repeating it.
MAX_TASKS = 200


class EnumerateRequest(BaseModel):
    """Domains to hand to an agent. One, several, or a pasted list."""
    #: Free text: newlines, commas or spaces. Operators paste from a
    #: spreadsheet, a scope document or a chat message, and making them
    #: reformat it first is the kind of friction that gets a tool
    #: abandoned for a terminal.
    domains: str | list[str] = ""
    mode: str = Field(
        "passive",
        description="passive sends nothing to the client's infrastructure. "
                    "active does, and is a scope decision.")
    kitchen_sink: bool = Field(
        False,
        description="Take every hostname the project knows, drop the "
                    "addresses, and walk each name back to its registrable "
                    "domain. Everything the walk produces is enumerated, "
                    "subject to scope.")
    rescan: bool = Field(
        False,
        description="Queue a Kitchen Sink domain again even though it has "
                    "been enumerated before. Off by default: the point of "
                    "the mode is that running it twice costs nothing.")

    def wanted(self) -> list[str]:
        raw = (self.domains if isinstance(self.domains, str)
               else "\n".join(self.domains))
        out, seen = [], set()
        for piece in re.split(r"[\s,;]+", raw or ""):
            v = piece.strip().rstrip(".").lower().lstrip("*.")
            # A pasted list routinely carries scheme and path from
            # wherever it was copied.
            v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split("?")[0]
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out


@router.post("/enumerate")
async def enumerate_domains(body: EnumerateRequest, project: str = Query(...),
                            pr: Project = Depends(require_project("user")),
                            user: User = Depends(get_current_user),
                            session: AsyncSession = Depends(get_session)):
    """Hand a list of domains to Ghost, and file what comes back.

    This replaced an offline generator that extrapolated from patterns
    the estate already showed and handed back hypotheses for a person
    to triage. Here an agent enumerates the zone for real, so the names
    come back resolved — and they are filed as targets automatically
    when the results arrive, because a name a tool found is a finding
    and not a suggestion.

    One task per domain: amass enumerates a single zone at a time. They
    are queued unassigned so the project's routing policy spreads them,
    which is what makes a list of forty domains finish in parallel
    across every agent rather than serially on one.

    **Kitchen Sink Lookup** (`kitchen_sink`) adds the other way of saying
    what to enumerate: not a list, but "everything this project knows
    about". It takes every hostname on record — targets, the alternate
    and certificate names hung off them, the hosts of web addresses —
    throws away the ones that are addresses and the ones a cloud
    provider named for itself, and walks each remaining name back to its
    registrable domain, so `a.b.c.example` asks about `a.b.c.example`,
    `b.c.example` and `c.example`. Anything typed in the box is walked
    too, so a selection and the estate compose rather than one replacing
    the other.

    The cloud exclusion is Kitchen Sink only, and it is about where the
    walk LANDS. `i-0a1.eu-west-1.compute.amazonaws.com` walks to
    `amazonaws.com`: a zone belonging to AWS, enumerated at AWS, telling
    you nothing about the client. A name chosen inside a cloud
    (`api.acme.example` on an EC2 box) walks to the client and is kept.
    A domain typed into the box is never excluded, because typing one is
    an explicit instruction.

    Two things that walk must not do, and does not:

    * **Run past the registrable domain.** See `gen.walk_to_registrable`.
    * **Assume a parent is approved because a child is.** Every name the
      walk produces goes through the scope gate on its own. Scope does
      not flow upwards — an operator authorised for `uat.acme.example`
      was not thereby authorised for `acme.example`, and amass against a
      zone apex nobody signed off is traffic at an unapproved asset.
      `*.acme.example` deliberately does not cover `acme.example`
      either, which is the usual way a parent gets refused here.

    Domains already handed to amass for this project are skipped and
    reported as skipped, not dropped: the operator sees "queued 12,
    skipped 30". `rescan` turns that off. The skip is Kitchen Sink only
    — a domain somebody typed is an explicit instruction, and silently
    not running it because it ran last month would be the tool deciding
    it knew better.
    """
    mode = (body.mode or "passive").strip().lower()
    if mode not in ("passive", "active"):
        raise HTTPException(422, "mode is passive or active")

    typed = body.wanted()
    if len(typed) > MAX_TASKS:
        raise HTTPException(
            422, f"{len(typed)} domains in one submission. Split it: each "
                 f"becomes a task, and a queue that long buries anything "
                 f"else this project needs to run.")
    if not typed and not body.kitchen_sink:
        raise HTTPException(422, "give at least one domain")

    from ..models import Agent, AgentTask
    live = (await session.execute(
        select(func.count(Agent.id)).where(Agent.project_id == pr.id,
                                           Agent.status == "online"))).scalar_one()
    if not live:
        # Refused rather than queued. Work accepted with nothing to run
        # it sits looking submitted, which reads as a broken scan.
        raise HTTPException(
            409, "no Ghost agent is online for this project, so there is "
                 "nothing to run the enumeration. Bring one up and submit "
                 "again.")

    # Read once and used for two things: the Kitchen Sink source list,
    # and `known_at_last_run` on every row written below. Two indexed
    # selects, so it is cheaper than asking per domain.
    known = await known_hosts(session, pr.id)

    wanted, addresses, cloud = _domains_to_enumerate(body, typed, known)
    if not wanted:
        # Kitchen Sink with nothing to walk. Said plainly rather than
        # returning an empty success, because "it worked and did
        # nothing" and "there was nothing here" read identically on the
        # screen and have different fixes.
        #
        # Which of the two it was decides what to do next -- addresses
        # want a reverse lookup, provider-assigned names want nothing at
        # all -- so they are named separately rather than totalled.
        if addresses and cloud:
            why = (f"{addresses} of the hosts on record are addresses and "
                   f"{cloud} are names their cloud provider assigned, and "
                   f"neither kind has a zone of yours to walk")
        elif cloud:
            why = ("the one host on record is a name its cloud provider "
                   "assigned, and that walks back to the provider's domain, "
                   "not to yours" if cloud == 1 else
                   f"all {cloud} hosts on record are names their cloud "
                   f"providers assigned, and those walk back to the "
                   f"providers' domains, not to yours")
        elif addresses:
            why = ("the one host on record is an address, and an address "
                   "has no zone" if addresses == 1 else
                   f"all {addresses} hosts on record are addresses, and an "
                   f"address has no zone")
        else:
            why = "this project has no hostnames on record yet"
        raise HTTPException(422, f"nothing to enumerate: {why}.")

    # What has already been handed to amass, for the skip. Loaded for
    # every request so the rows are written against current state, and
    # keyed by domain because that is what the unique constraint is on.
    seen: dict[str, DomainSearch] = {
        r.domain: r for r in (await session.execute(
            select(DomainSearch).where(
                DomainSearch.project_id == pr.id,
                DomainSearch.domain.in_(wanted)))).scalars().all()}

    idx = await index_for(session, pr.id)
    queued: list[dict] = []
    refused: dict[str, str] = {}
    skipped: list[dict] = []
    deferred: list[str] = []
    now = datetime.now(UTC)
    for d in wanted:
        if gen.is_ip(d):
            refused[d] = "an address has no zone to enumerate"
            continue
        try:
            validate_host(d)
        except InvalidHost as e:
            refused[d] = str(e)
            continue
        # Independently, for every generated parent as much as for every
        # typed name. This is the check that stops a walk reaching an
        # apex the engagement does not cover.
        #
        # `check_zone`, not `check`: every name queued here is handed to
        # amass as a ZONE to enumerate, and that is the one operation a
        # wildcard authorises on its own apex. `*.acme.example` does not
        # put `acme.example` in scope to be scanned and still does not —
        # but it plainly permits asking who exists under it, and
        # refusing that meant a project scoped the ordinary way could
        # not enumerate itself. Nothing else is widened: a parent above
        # the wildcard is still refused and the out-list still wins,
        # because check_zone defers to check for both.
        ruling = idx.check_zone(d)
        if not ruling.allowed:
            refused[d] = ruling.reason
            continue
        prior = seen.get(d)
        if prior is not None and body.kitchen_sink and not body.rescan:
            skipped.append({"domain": d, "runs": prior.runs,
                            "last_run_at": prior.last_run_at.isoformat()
                            if prior.last_run_at else None})
            continue
        if len(queued) >= MAX_TASKS:
            deferred.append(d)
            continue
        t = AgentTask(agent_id=None, project_id=pr.id, requested_by=user.id,
                      kind="amass",
                      args=json.dumps({"domain": d, "mode": mode}),
                      status="queued")
        session.add(t)
        await session.flush()
        queued.append({"domain": d, "task_id": t.id})
        _record_search(session, pr, user, d, prior, mode, known, now)
    await session.commit()
    await broker.publish("agents", action="task", project=pr.code)
    return {"queued": queued, "refused": refused, "skipped": skipped,
            "deferred": deferred, "agents_online": live, "mode": mode,
            "kitchen_sink": bool(body.kitchen_sink),
            "considered": len(wanted), "cloud_skipped": cloud}


def _domains_to_enumerate(body: EnumerateRequest, typed: list[str],
                          known: list[str]) -> tuple[list[str], int, int]:
    """-> (the domains to put through the gate, how many addresses were
    ignored, how many provider-assigned cloud names were ignored).

    Deduplicated across hosts, and that matters more than it sounds: ten
    names under `f.com` walk to `f.com` ten times, and ten identical
    amass tasks is ten times the traffic for one zone's worth of answer.
    An insertion-ordered dict does it while keeping the order the walk
    produced, which is longest name first — so the output reads from the
    deepest name down to the apex rather than in hash order.
    """
    out: dict[str, None] = {}
    addresses = 0
    if not body.kitchen_sink:
        # Unchanged behaviour: what was typed, as typed. No walking, so
        # a list of names does not quietly become a list of apexes.
        # Typed names are not filtered: somebody who writes a provider
        # name into the box has asked for that zone on purpose.
        return list(dict.fromkeys(typed)), 0, 0
    cloud = 0
    for h in list(known) + typed:
        if gen.is_ip(h):
            # "ignore the ip address hosts". An address has no zone, and
            # `registrable()` on one used to return its last two octets.
            addresses += 1
            continue
        # Where the walk LANDS is what decides this, not where it
        # started. `i-0a1.eu-west-1.compute.amazonaws.com` walks to
        # `amazonaws.com` -- a zone belonging to AWS, enumerated at
        # AWS, with millions of names under it and none of them the
        # client's. `api.acme.example` on the same EC2 box walks to
        # `acme.example` and is kept, because somebody chose that name.
        #
        # So the filter is on the produced names. Every name in a
        # provider-assigned walk is under the provider's zone, so a
        # host of that shape contributes nothing and is counted as
        # skipped; a host that contributes even one name is not.
        #
        # This is the predicate `enumerable_roots` already used for the
        # auto_amass standing order. The two disagreeing is what put a
        # provider's zone in front of the operator here while the
        # automation quietly refused to walk it.
        walk = gen.walk_to_registrable(h)
        kept = False
        for name in walk:
            if clouds.is_cloud_domain(name):
                continue
            out.setdefault(name, None)
            kept = True
        # `walk` and not `kept` alone: a bare label or a malformed name
        # walks to nothing either, and calling that a cloud name would
        # put a wrong reason on the screen for a real data problem.
        if walk and not kept:
            cloud += 1
    return list(out), addresses, cloud


def _record_search(session: AsyncSession, pr: Project, user: User, domain: str,
                   prior: DomainSearch | None, mode: str, known: list[str],
                   now: datetime) -> None:
    """Remember that this domain has been handed to amass.

    Written at queue time rather than when the task reports. The thing
    being prevented is a second task for a zone already being
    enumerated, and a result that has not arrived yet does not make the
    first task un-sent.

    Amends the existing row rather than inserting a second one: the
    table is unique on (project, domain), and `runs` only means anything
    if it accumulates.
    """
    # How much of this zone the project already had. The column's whole
    # purpose is letting a later run say what is genuinely new rather
    # than re-listing an estate that was already there.
    under = sum(1 for h in known if gen.subdomain_of(h, domain) is not None)
    if prior is None:
        session.add(DomainSearch(
            project_id=pr.id, domain=domain, runs=1, last_run_at=now,
            candidates_found=0, known_at_last_run=under,
            requested_by=user.id, note=f"amass {mode}"))
        return
    prior.runs = (prior.runs or 0) + 1
    prior.last_run_at = now
    prior.known_at_last_run = under
    prior.requested_by = user.id
    prior.note = f"amass {mode}"


@router.get("/candidates", response_model=list[DomainCandidateOut])
async def candidates(project: str = Query(...),
                     state: str | None = Query(None),
                     root: str | None = Query(None),
                     pr: Project = Depends(require_project("readonly")),
                     session: AsyncSession = Depends(get_session)):
    stmt = select(DomainCandidate).where(DomainCandidate.project_id == pr.id)
    if state:
        stmt = stmt.where(DomainCandidate.state == state)
    if root:
        stmt = stmt.where(DomainCandidate.root_domain == root.lower())
    rows = (await session.execute(
        stmt.order_by(DomainCandidate.score.desc(),
                      DomainCandidate.name))).scalars().all()
    return [DomainCandidateOut.model_validate(c) for c in rows]


@router.post("/candidates/promote")
async def promote(body: PromoteRequest, project: str = Query(...),
                  pr: Project = Depends(require_project("user")),
                  user: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Turn candidates into targets.

    A candidate is a name something saw alongside a target — currently
    the reverse-IP flow, which records a decision for every name an
    address answers to. Seeing a name is not the same as claiming it is
    part of the estate, so promoting it is a separate, deliberate step.
    The target is created with `alive=None` — not probed — because
    nothing here has checked.
    """
    rows = (await session.execute(
        select(DomainCandidate).where(DomainCandidate.project_id == pr.id,
                                      DomainCandidate.id.in_(body.ids)))).scalars().all()
    created, skipped, refused = await _promote_rows(session, pr, user, rows)
    await session.commit()
    await broker.publish("targets", action="create", project=pr.code)
    return {"created": created, "already_existed": skipped,
            "out_of_scope": refused}


async def _promote_rows(session: AsyncSession, pr: Project, user: User,
                        rows) -> tuple[list[str], list[str], dict[str, str]]:
    """Turn candidate rows into targets. -> (created, already, refused).

    Factored out of the endpoint so a second caller cannot drift from
    the one a person drives — in particular, cannot quietly stop
    checking scope.

    Does not commit; the caller owns the transaction.
    """
    created, skipped = [], []
    refused: dict[str, str] = {}
    # Nothing has been probed at these names: an address answered to
    # them, which is all. On shared hosting most of what answers to an
    # address belongs to somebody else, so the scope check here is the
    # thing standing between a neighbour's hostname and the inventory.
    idx = await index_for(session, pr.id)
    now = datetime.now(UTC)
    for c in rows:
        dup = (await session.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.host == c.name))).scalar_one_or_none()
        if dup is not None:
            c.state, c.decided_by, c.decided_at = "exists", user.id, now
            skipped.append(c.name)
            continue
        ruling = idx.check(c.name)
        if not ruling.allowed:
            # Left in whatever state it was in rather than marked
            # rejected: nobody decided against this candidate, the scope
            # list did, and recording it as a human judgement would be a
            # lie in the audit trail.
            refused[c.name] = ruling.reason
            continue
        t = Target(project_id=pr.id, host=c.name, alive=None)
        session.add(t)
        await session.flush()
        await record(session, t.id, "discovered",
                     f"added from domain discovery ({c.source}, score {c.score})",
                     detail=c.reason, actor=user, source=f"domains:{c.root_domain}")
        c.state, c.decided_by, c.decided_at = "accepted", user.id, now
        created.append(c.name)
    return created, skipped, refused


@router.post("/candidates/reject")
async def reject(body: PromoteRequest, project: str = Query(...),
                 pr: Project = Depends(require_project("user")),
                 user: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_session)):
    """Mark candidates as not worth pursuing, so they are not offered again."""
    rows = (await session.execute(
        select(DomainCandidate).where(DomainCandidate.project_id == pr.id,
                                      DomainCandidate.id.in_(body.ids)))).scalars().all()
    now = datetime.now(UTC)
    for c in rows:
        c.state, c.decided_by, c.decided_at = "rejected", user.id, now
    await session.commit()
    return {"rejected": [c.name for c in rows]}


# ------------------------------------------- certificate transparency
class ArchiveRequest(BaseModel):
    """Which roots to ask the archive about."""
    roots: list[str] = Field(default_factory=list, max_length=50)


@router.post("/candidates/archived-urls")
async def from_archive(body: ArchiveRequest, project: str = Query(...),
                       pr: Project = Depends(require_project("user")),
                       user: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    """Propose paths a site used to serve, from a public web archive.

    **This sends the named domains to a third party**, which is why
    it is off until somebody turns it on and why it is a `user`
    action rather than a readonly one. See `app/archived.py` and the
    `archive.enabled` setting, whose help text says what leaves and
    where it goes. Deliberately the same shape as the CT route next
    door, because it is the same decision.

    URLs are recorded as web addresses with **no status and no
    response**: nothing here has fetched them. That is the honest
    state -- an archive says a path existed once, which is not the
    same as saying it answers now, and marking them as seen would
    put a 2019 404 in a report as a live endpoint.

    They are NOT crawl seeds. `webtargets.crawl_seeds` keys on
    `sources ILIKE '%gobuster%'` precisely so that a crawl cannot
    feed itself -- one project went from 1,109 queued tasks to
    97,959 in under an hour when it could -- and `archive` is
    outside that cycle by construction.

    Hosts the project does not already have are reported, never
    created. An archive records what a crawler saw, not what
    anybody authorised.
    """
    from .. import archived
    from ..weburl import exchange_key, url_key
    from .settings import load_all

    cfg = await load_all(session)
    roots = [r.strip().lower().rstrip(".") for r in body.roots if r.strip()]
    if not roots:
        raise HTTPException(400, "name at least one root domain")

    try:
        found = [await archived.lookup(cfg, r) for r in roots]
    except archived.Disabled as e:
        # 409, not 403: the caller is allowed to do this, the
        # installation has not agreed to it yet, and the fix is a
        # decision in settings rather than a different account.
        raise HTTPException(409, str(e)) from e

    idx = await index_for(session, pr.id)
    targets = {t.host.lower(): t for t in (await session.execute(
        select(Target).where(Target.project_id == pr.id))).scalars().all()}

    added = 0
    already = 0
    refused: dict[str, str] = {}
    unknown_hosts: dict[str, int] = {}
    errors: list[str] = []
    truncated = [f.domain for f in found if f.truncated]

    for f in found:
        if f.error:
            # Carried through rather than swallowed. "the archive
            # could not be asked" and "this domain has no archived
            # URLs" are different answers and only one is about the
            # client.
            errors.append(f.error)
            continue
        for u in f.urls:
            host = archived.host_of(u)
            if not host:
                continue
            ruling = idx.check(host)
            if not ruling.allowed:
                refused.setdefault(host, ruling.reason or "out of scope")
                continue
            t = targets.get(host)
            if t is None:
                # Counted per host, not per URL: "we found 4,000 URLs
                # on a host you do not have" is one decision, not
                # four thousand.
                unknown_hosts[host] = unknown_hosts.get(host, 0) + 1
                continue
            uk = url_key(u)
            # No request and no response, so the exchange identity is
            # the metadata-only one -- the same shape an httpx
            # sighting gets, and distinct from a real capture of the
            # same URL.
            xk = exchange_key("", u, None, None)
            dup = (await session.execute(select(WebAddress).where(
                WebAddress.target_id == t.id,
                WebAddress.exchange_hash == xk))).scalar_one_or_none()
            if dup is not None:
                already += 1
                continue
            parts = u.split("://", 1)[-1].split("/", 1)
            session.add(WebAddress(
                target_id=t.id, url=u, url_hash=uk, exchange_hash=xk,
                scheme="https" if u.lower().startswith("https") else "http",
                path=("/" + (parts[1] if len(parts) > 1 else ""))[:1024],
                method="",
                # Null, and it means "nobody has asked". A path an
                # archive remembers is not a path that answers.
                status_code=None,
                sources=f"archive:{f.source}"[:255],
                notes=f"seen by {f.source}; not fetched by Oddjob"))
            added += 1

    await session.commit()
    if added:
        await record(session, pr.id, "change", user,
                     f"archived-URL lookup proposed {added} path(s) across "
                     f"{len(roots)} root(s)")
    return {
        "roots": roots,
        "source": next((f.source for f in found if f.source), ""),
        "added": added,
        "already_known": already,
        # Reported, never written. The fix for one of these is a
        # scope edit or a target, not a retry.
        "refused": refused,
        "unknown_hosts": unknown_hosts,
        # An empty result must not read as "this domain has nothing
        # archived" when the truth is nobody could ask.
        "errors": errors,
        # A truncated list that does not say so reads as a complete
        # one.
        "truncated_roots": truncated,
        "skipped_entries": sum(f.skipped for f in found),
    }


class CtRequest(BaseModel):
    """Which roots to ask about."""
    roots: list[str] = Field(default_factory=list, max_length=50)


@router.post("/candidates/ct")
async def from_ct(body: CtRequest, project: str = Query(...),
                  pr: Project = Depends(require_project("user")),
                  user: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Propose hostnames from public certificate logs.

    **This sends the named domains to a third party**, which is why
    it is off until somebody turns it on and why it is a `user`
    action rather than a readonly one. See `app/ctlogs.py` and the
    `ct.enabled` setting, whose help text says what leaves and where
    it goes.

    Names come back as CANDIDATES, never as targets. A shared or
    wildcard certificate names hosts belonging to other people, and a
    name in a public log is not evidence that anybody agreed to be
    scanned -- so every name is ruled on by `scopegate` here, the
    refused ones are reported rather than written, and the rest wait
    for a person on the same promote/reject flow every other
    candidate uses.
    """
    from .. import ctlogs
    from .settings import load_all

    cfg = await load_all(session)
    roots = [r.strip().lower().rstrip(".") for r in body.roots if r.strip()]
    if not roots:
        raise HTTPException(400, "name at least one root domain")

    try:
        found = [await ctlogs.lookup(cfg, r) for r in roots]
    except ctlogs.Disabled as e:
        # 409, not 403. The caller is allowed to do this; the
        # installation has not agreed to it yet, and the fix is a
        # decision in settings rather than a different account.
        raise HTTPException(409, str(e)) from e

    idx = await index_for(session, pr.id)
    known = {h.lower() for h in await known_hosts(session, pr.id)}
    existing = {n.lower() for n in (await session.execute(
        select(DomainCandidate.name)
        .where(DomainCandidate.project_id == pr.id))).scalars().all()}

    proposed: list[str] = []
    refused: dict[str, str] = {}
    errors: list[str] = []
    seen_already = 0

    for f in found:
        if f.error:
            # Carried through rather than swallowed. "crt.sh could not
            # be asked" and "this domain has no certificates" are
            # different answers and only one of them is about the
            # client.
            errors.append(f.error)
            continue
        for n in f.names:
            if n in known or n in existing:
                seen_already += 1
                continue
            ruling = idx.check(n)
            if not ruling.allowed:
                # `reason`, not `why`. The first version guessed, and
                # guessed on the ONLY branch no test covered: a CT
                # lookup that proposes nothing out of scope never
                # reaches this line, so three of the engagement's
                # four root domains returned 200 and the fourth
                # returned 500.
                refused[n] = ruling.reason or "out of scope"
                continue
            existing.add(n)
            proposed.append(n)
            session.add(DomainCandidate(
                project_id=pr.id, name=n, root_domain=f.domain,
                source="ct", score=0,
                reason=f"named by a certificate in a public log ({f.source})",
                state="new"))

    await session.commit()
    if proposed:
        await record(session, pr.id, "change", user,
                     f"certificate transparency proposed {len(proposed)} "
                     f"name(s) across {len(roots)} root(s)")
    return {
        "roots": roots,
        "source": next((f.source for f in found if f.source), ""),
        "proposed": sorted(proposed),
        "already_known": seen_already,
        # Reported, never written. The fix for one of these is a scope
        # edit, not a retry.
        "refused": refused,
        # Said plainly, so an empty result cannot read as "this domain
        # has no certificates" when the truth is nobody could ask.
        "errors": errors,
        "unusable_names": sum(f.unusable for f in found),
    }
