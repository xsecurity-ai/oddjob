"""Suggesting hostnames worth trying, and remembering what has been tried.

Generation is offline — see `app/domains.py` for why. These routes add the
memory: which domains have been run, what they produced, and what was
accepted or rejected, so a second run returns what is genuinely new rather
than the same list with the same names in it.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import domains as gen
from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..models import (DomainCandidate, DomainSearch, Project, ProjectScope, Target, User,
                      WebAddress)
from ..schemas import (DetectBatch, DetectRequest, DetectResult, DomainCandidateOut,
                       DomainSearchOut, PromoteRequest)
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

    Three sources, because any one alone leaves a real engagement with
    an empty list:

      targets   what the estate already touches, commonest first. The
                best signal, and the only one that exists mid-engagement.
      scope     the FQDNs the engagement was authorised against. These
                matter MOST on day one, which is exactly when there are
                no targets yet — a fresh project used to report "no root
                domains" while its scope named a dozen.
      searched  anything run before. A domain someone typed by hand is
                part of this engagement's working set even if nothing
                under it has resolved yet.

    `known_hosts` is the count from targets only, so a root that is in
    scope and otherwise untouched still reads as 0 and sorts last
    without being hidden.
    """
    hosts = await known_hosts(session, pr.id)
    searched = {d.lower() for d in (await session.execute(
        select(DomainSearch.domain)
        .where(DomainSearch.project_id == pr.id))).scalars().all()}

    counts = dict(gen.roots_in(hosts))
    origin = {d: "targets" for d in counts}

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


@router.post("/detect", response_model=DetectBatch)
async def detect(body: DetectRequest, project: str = Query(...),
                 pr: Project = Depends(require_project("user")),
                 user: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_session)):
    """Run candidate generation across one or more domains.

    Each domain is independent: an unusable one is reported against itself
    and the rest still run, because a typo in the fourth of eight entries
    should not cost you the other seven.
    """
    wanted = body.wanted()
    if not wanted:
        raise HTTPException(422, "give at least one domain")

    results: list[DetectResult] = []
    for d in wanted:
        try:
            results.append(await _detect_one(
                session, pr, user, d, body.limit, body.force,
                auto_promote=body.auto_promote, min_score=body.min_score))
        except HTTPException as e:
            results.append(DetectResult(domain=d, candidates=[], new_candidates=0,
                                        runs=0, error=str(e.detail)))
    await session.commit()
    await broker.publish("domains", action="detect", project=pr.code)
    return DetectBatch(
        results=results,
        new_candidates=sum(r.new_candidates for r in results),
        domains_run=sum(1 for r in results if not r.error),
        domains_skipped=sum(1 for r in results if r.error),
        promoted=sum(len(r.promoted) for r in results),
        promoted_refused=sum(len(r.promoted_refused) for r in results))


async def _detect_one(session: AsyncSession, pr: Project, user: User,
                      domain: str, limit: int, force: bool,
                      *, auto_promote: bool = False,
                      min_score: int = 0) -> DetectResult:
    """Generate candidate hostnames under a domain.

    **No lookups and no packets.** Candidates are extrapolated from what the
    project already holds; each carries the reason it was suggested. They
    are hypotheses until promoted.

    A domain already searched is not re-run unless `force` is set, and even
    then names proposed before are not proposed again — the point of the
    memory is that the second run shows you what changed.
    """
    if gen.is_ip(domain):
        # Subdomains of an address do not exist. Saying so is better than
        # returning an empty list that looks like "nothing found".
        raise HTTPException(
            422, f"{domain} is an IP address — there are no subdomains to "
                 f"enumerate under one. Give a domain name.")
    try:
        validate_host(domain)
    except InvalidHost as e:
        raise HTTPException(422, f"{domain!r} is not a usable domain: {e}")
    if "." not in domain:
        raise HTTPException(422, f"{domain!r} is a single label, not a domain")

    search = (await session.execute(
        select(DomainSearch).where(DomainSearch.project_id == pr.id,
                                   DomainSearch.domain == domain))).scalar_one_or_none()
    if search is not None and not force:
        prior = (await session.execute(
            select(DomainCandidate)
            .where(DomainCandidate.project_id == pr.id,
                   DomainCandidate.root_domain == domain)
            .order_by(DomainCandidate.score.desc(), DomainCandidate.name))).scalars().all()
        return DetectResult(
            domain=domain,
            candidates=[DomainCandidateOut.model_validate(c) for c in prior],
            new_candidates=0, runs=search.runs,
            previously_suggested=len(prior),
            note=(f"{domain} was last searched "
                  f"{search.last_run_at:%Y-%m-%d %H:%M} UTC and produced "
                  f"{search.candidates_found} candidate(s); showing those. "
                  f"Re-run with force to look again."
                  if search.last_run_at else
                  f"{domain} has been searched before; showing what it found."))

    hosts = await known_hosts(session, pr.id)
    existing = {c.name for c in (await session.execute(
        select(DomainCandidate).where(DomainCandidate.project_id == pr.id))).scalars()}

    produced = gen.generate(domain, hosts, limit=limit, already=existing)

    now = datetime.now(timezone.utc)

    # Deduplicated, and inserted so a collision is skipped rather than
    # fatal. Two things made this a 500:
    #
    #   - the generator can propose the same name twice in one batch
    #     (two rules arriving at it from different directions), and the
    #     pair violates the unique index inside a single INSERT;
    #   - `existing` is read once at the top, so two detect runs
    #     overlapping — a double-click is enough — both see the name as
    #     absent and both insert it.
    #
    # Either way the whole run died after generating a few thousand
    # candidates, which is a lot of work to throw away over a name we
    # already had.
    seen: set[str] = set()
    rows: list[dict] = []
    for c in produced:
        if c.name in seen:
            continue
        seen.add(c.name)
        rows.append({"project_id": pr.id, "name": c.name,
                     "root_domain": c.root_domain, "source": c.source,
                     "score": c.score, "reason": c.reason, "state": "new",
                     "times_seen": 1, "created_at": now, "updated_at": now})

    created = 0
    if rows:
        res = await session.execute(
            _conflict_insert(session, DomainCandidate).values(rows)
            .on_conflict_do_nothing(index_elements=["project_id", "name"]))
        # What was actually written, not what was offered: the caller is
        # told how many new names there are, and a skipped duplicate is
        # not a new name.
        created = res.rowcount if res.rowcount is not None and res.rowcount >= 0 \
            else len(rows)

    # A name an earlier run already proposed is bumped rather than re-added:
    # agreement across runs is itself a signal.
    if existing:
        again = [c for c in gen.generate(domain, hosts, limit=limit, already=set())
                 if c.name in existing]
        for c in again:
            row = (await session.execute(
                select(DomainCandidate)
                .where(DomainCandidate.project_id == pr.id,
                       DomainCandidate.name == c.name))).scalar_one_or_none()
            if row is not None and row.state == "new":
                row.times_seen += 1

    if search is None:
        # Claimed the same way candidates are, and for the same reason:
        # two overlapping runs both saw no row above and both tried to
        # create one, which violates uq_domsearch_project_domain. The
        # insert is skipped on conflict and the row is then read back,
        # so whichever request lost the race still ends up with the
        # real row rather than an exception.
        await session.execute(
            _conflict_insert(session, DomainSearch)
            .values(project_id=pr.id, domain=domain, requested_by=user.id,
                    created_at=now, updated_at=now)
            .on_conflict_do_nothing(index_elements=["project_id", "domain"]))
        search = (await session.execute(
            select(DomainSearch).where(
                DomainSearch.project_id == pr.id,
                DomainSearch.domain == domain))).scalar_one()
    # Column defaults are applied on INSERT, so a freshly constructed row
    # still has None here until it is flushed.
    search.runs = (search.runs or 0) + 1
    search.last_run_at = now
    search.candidates_found = (search.candidates_found or 0) + created
    search.known_at_last_run = len(hosts)
    await session.flush()

    rows = (await session.execute(
        select(DomainCandidate)
        .where(DomainCandidate.project_id == pr.id,
               DomainCandidate.root_domain == domain,
               DomainCandidate.state.in_(("new", "accepted")))
        .order_by(DomainCandidate.score.desc(),
                  DomainCandidate.name))).scalars().all()
    known_under = sum(1 for h in hosts
                      if gen.subdomain_of(h, domain) is not None)
    return DetectResult(
        domain=domain,
        candidates=[DomainCandidateOut.model_validate(c) for c in rows],
        new_candidates=created,
        already_known=known_under,
        previously_suggested=len(rows) - created,
        runs=search.runs,
        note=(None if created else
              f"Nothing new under {domain}. Every name this project's "
              f"patterns suggest has already been proposed or already exists."),
    )


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

    The difference from `/detect` is what produces the names. Detection
    extrapolates from patterns the estate already shows and produces
    hypotheses for a person to triage. This asks an agent to actually
    enumerate the zone, so the names come back resolved — and they are
    filed as targets automatically when the results arrive, because a
    name a tool found is a finding and not a suggestion.

    One task per domain: amass enumerates a single zone at a time. They
    are queued unassigned so the project's routing policy spreads them,
    which is what makes a list of forty domains finish in parallel
    across every agent rather than serially on one.
    """
    wanted = body.wanted()
    if not wanted:
        raise HTTPException(422, "give at least one domain")
    if len(wanted) > 200:
        raise HTTPException(
            422, f"{len(wanted)} domains in one submission. Split it: each "
                 f"becomes a task, and a queue that long buries anything "
                 f"else this project needs to run.")
    mode = (body.mode or "passive").strip().lower()
    if mode not in ("passive", "active"):
        raise HTTPException(422, "mode is passive or active")

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

    idx = await index_for(session, pr.id)
    queued, refused = [], {}
    for d in wanted:
        if gen.is_ip(d):
            refused[d] = "an address has no zone to enumerate"
            continue
        try:
            validate_host(d)
        except InvalidHost as e:
            refused[d] = str(e)
            continue
        ruling = idx.check(d)
        if not ruling.allowed:
            refused[d] = ruling.reason
            continue
        t = AgentTask(agent_id=None, project_id=pr.id, requested_by=user.id,
                      kind="amass",
                      args=json.dumps({"domain": d, "mode": mode}),
                      status="queued")
        session.add(t)
        await session.flush()
        queued.append({"domain": d, "task_id": t.id})
    await session.commit()
    await broker.publish("agents", action="task", project=pr.code)
    return {"queued": queued, "refused": refused, "agents_online": live,
            "mode": mode}


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


@router.get("/searches", response_model=list[DomainSearchOut])
async def searches(project: str = Query(...),
                   pr: Project = Depends(require_project("readonly")),
                   session: AsyncSession = Depends(get_session)):
    """What has already been searched, so nothing is ground through twice."""
    rows = (await session.execute(
        select(DomainSearch).where(DomainSearch.project_id == pr.id)
        .order_by(DomainSearch.domain))).scalars().all()
    return [DomainSearchOut.model_validate(r) for r in rows]


@router.post("/candidates/promote")
async def promote(body: PromoteRequest, project: str = Query(...),
                  pr: Project = Depends(require_project("user")),
                  user: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Turn accepted candidates into targets.

    Deliberate, and separate from generation: a guessed name is a
    hypothesis, an inventory row is a claim. The target is created with
    `alive=None` — not probed — because nothing here has checked.
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

    Shared by the explicit promote endpoint and by `auto_promote` on
    detection, so the automatic path cannot drift from the one a person
    drives — in particular it cannot quietly stop checking scope.

    Does not commit; the caller owns the transaction.
    """
    created, skipped = [], []
    refused: dict[str, str] = {}
    # A candidate is a guess, so this is the one creation path where the
    # host was never observed anywhere. All the more reason to check it:
    # the generator extrapolates from names the estate uses, and the
    # neighbouring domain it extrapolates onto is frequently somebody
    # else's.
    idx = await index_for(session, pr.id)
    now = datetime.now(timezone.utc)
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
    now = datetime.now(timezone.utc)
    for c in rows:
        c.state, c.decided_by, c.decided_at = "rejected", user.id, now
    await session.commit()
    return {"rejected": [c.name for c in rows]}
