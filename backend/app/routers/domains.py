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

from .. import domains as gen
from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..models import (
    DomainCandidate,
    DomainSearch,
    Project,
    ProjectScope,
    Target,
    User,
    WebAddress,
)
from ..schemas import DomainCandidateOut, PromoteRequest
from ..scopegate import index_for
from ..security import get_current_user, require_project
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


async def known_hosts(session: AsyncSession, project_id: int) -> list[str]:
    """Every hostname the project has seen, from every source.

    Not just the target list: alternate names from DNS and TLS, and the
    hosts of web addresses, are exactly the material that makes a
    suggestion good — and they are the names most often absent from the
    inventory, because nobody got round to adding them.
    """
    out: set[str] = set()
    rows = (await session.execute(
        select(Target.host, Target.hostnames, Target.extra)
        .where(Target.project_id == project_id))).all()
    for host, names_json, extra_json in rows:
        if host:
            out.add(host.lower())
        for blob, key in ((names_json, None), (extra_json, "hostscripts")):
            if not blob:
                continue
            try:
                data = json.loads(blob)
            except (TypeError, ValueError):
                continue
            if isinstance(data, list):
                out.update(str(x).lower() for x in data if x)
            elif isinstance(data, dict) and key:
                # TLS SANs captured by nmap's ssl-cert script are a rich
                # source of names nothing else has recorded.
                for script_out in data.get(key, {}).values() if isinstance(
                        data.get(key), dict) else []:
                    out.update(_names_in(str(script_out)))
        if extra_json:
            try:
                ex = json.loads(extra_json)
            except (TypeError, ValueError):
                ex = {}
            if isinstance(ex, dict):
                for v in ex.values():
                    if isinstance(v, dict):
                        for vv in v.values():
                            if isinstance(vv, str):
                                out.update(_names_in(vv))

    urls = (await session.execute(
        select(WebAddress.url).join(Target, Target.id == WebAddress.target_id)
        .where(Target.project_id == project_id))).scalars().all()
    for u in urls:
        from urllib.parse import urlsplit
        h = (urlsplit(u).hostname or "").lower()
        if h:
            out.add(h)
    return sorted(x for x in out if x and "." in x)


_NAME_RE = None


def _names_in(text: str) -> set[str]:
    """Hostnames embedded in free text — certificate SANs, mostly."""
    global _NAME_RE
    if _NAME_RE is None:
        import re
        _NAME_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                              r"[a-z]{2,24}\b", re.I)
    return {m.group(0).lower().rstrip(".") for m in _NAME_RE.finditer(text or "")}


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
    drone now, and whether it has run is a question about tasks, not
    about a table here. `searched` stays in the response and is always
    false, so an older client does not break on its absence.

    `known_hosts` is the count from targets only, so a root that is in
    scope and otherwise untouched still reads as 0 and sorts last
    without being hidden.
    """
    hosts = await known_hosts(session, pr.id)
    # `searched` used to mean "the offline generator has already
    # guessed under this". There is no generator now — enumeration is
    # amass on a drone, and whether that has run is a question about
    # tasks, not about this table.
    searched: set[str] = set()

    counts = dict(gen.roots_in(hosts))
    origin = dict.fromkeys(counts, "targets")

    # Both name kinds. A wildcard is stored as its own kind and is the
    # likeliest way a whole zone gets put in scope — `*.acme.example` is
    # exactly the entry that means "enumerate this" — so reading only
    # `fqdn` missed the entries that matter most here.
    for value, included in (await session.execute(
            select(ProjectScope.value, ProjectScope.included)
            .where(ProjectScope.project_id == pr.id,
                   ProjectScope.kind.in_(("fqdn", "wildcard"))))).all():
        if not included:
            # An excluded domain is the one thing that must not be
            # offered: generating names under it proposes work that is
            # refused the moment anyone promotes it.
            continue
        r = gen.registrable((value or "").strip().lstrip("*."))
        if r and "." in r and r not in counts:
            counts[r] = 0
            origin[r] = "scope"

    for d in searched:
        if d not in counts:
            counts[d] = 0
            origin[d] = "searched"

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
    """Hand a list of domains to Drone, and file what comes back.

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
    throws away the ones that are addresses, and walks each remaining
    name back to its registrable domain, so `a.b.c.example` asks about
    `a.b.c.example`, `b.c.example` and `c.example`. Anything typed in the
    box is walked too, so a selection and the estate compose rather than
    one replacing the other.

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
            409, "no Drone agent is online for this project, so there is "
                 "nothing to run the enumeration. Bring one up and submit "
                 "again.")

    # Read once and used for two things: the Kitchen Sink source list,
    # and `known_at_last_run` on every row written below. Two indexed
    # selects, so it is cheaper than asking per domain.
    known = await known_hosts(session, pr.id)

    wanted, addresses = _domains_to_enumerate(body, typed, known)
    if not wanted:
        # Kitchen Sink with nothing to walk. Said plainly rather than
        # returning an empty success, because "it worked and did
        # nothing" and "there was nothing here" read identically on the
        # screen and have different fixes.
        why = ("this project has no hostnames on record yet" if not addresses
               else "the one host on record is an address, and an address "
                    "has no zone" if addresses == 1
               else f"all {addresses} hosts on record are addresses, and an "
                    f"address has no zone")
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
        ruling = idx.check(d)
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
            "considered": len(wanted)}


def _domains_to_enumerate(body: EnumerateRequest, typed: list[str],
                          known: list[str]) -> tuple[list[str], int]:
    """-> (the domains to put through the gate, how many addresses were
    ignored).

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
        return list(dict.fromkeys(typed)), 0
    for h in list(known) + typed:
        if gen.is_ip(h):
            # "ignore the ip address hosts". An address has no zone, and
            # `registrable()` on one used to return its last two octets.
            addresses += 1
            continue
        for name in gen.walk_to_registrable(h):
            out.setdefault(name, None)
    return list(out), addresses


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
