"""Suggesting hostnames worth trying, and remembering what has been tried.

Generation is offline — see `app/domains.py` for why. These routes add the
memory: which domains have been run, what they produced, and what was
accepted or rejected, so a second run returns what is genuinely new rather
than the same list with the same names in it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import domains as gen
from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..models import (DomainCandidate, DomainSearch, Project, Target, User,
                      WebAddress)
from ..schemas import (DetectBatch, DetectRequest, DetectResult, DomainCandidateOut,
                       DomainSearchOut, PromoteRequest)
from ..scopegate import index_for
from ..security import get_current_user, require_project
from ..timeline import record

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
    """Registrable domains already present, commonest first.

    Drives the dialog's suggestions: the domain most worth running against
    is usually one the estate already touches.
    """
    hosts = await known_hosts(session, pr.id)
    searched = {d.lower() for d in (await session.execute(
        select(DomainSearch.domain)
        .where(DomainSearch.project_id == pr.id))).scalars().all()}
    return [{"domain": d, "known_hosts": n, "searched": d in searched}
            for d, n in gen.roots_in(hosts)]


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
            results.append(await _detect_one(session, pr, user, d,
                                             body.limit, body.force))
        except HTTPException as e:
            results.append(DetectResult(domain=d, candidates=[], new_candidates=0,
                                        runs=0, error=str(e.detail)))
    await session.commit()
    await broker.publish("domains", action="detect", project=pr.code)
    return DetectBatch(
        results=results,
        new_candidates=sum(r.new_candidates for r in results),
        domains_run=sum(1 for r in results if not r.error),
        domains_skipped=sum(1 for r in results if r.error))


async def _detect_one(session: AsyncSession, pr: Project, user: User,
                      domain: str, limit: int, force: bool) -> DetectResult:
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
    created = 0
    for c in produced:
        session.add(DomainCandidate(
            project_id=pr.id, name=c.name, root_domain=c.root_domain,
            source=c.source, score=c.score, reason=c.reason, state="new"))
        created += 1

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
        search = DomainSearch(project_id=pr.id, domain=domain, requested_by=user.id)
        session.add(search)
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
    await session.commit()
    await broker.publish("targets", action="create", project=pr.code)
    return {"created": created, "already_existed": skipped,
            "out_of_scope": refused}


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
