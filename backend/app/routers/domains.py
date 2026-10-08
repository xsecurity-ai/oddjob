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
from ..models import DomainCandidate, Project, ProjectScope, Target, User, WebAddress
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
