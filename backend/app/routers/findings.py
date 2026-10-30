"""Vulns and PoCs.

Supporting tables: they exist because the Targets grid shows live counts of
them. Full CRUD so the API is complete and bulk import has somewhere to land.
"""
from __future__ import annotations

import contextlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import assetfetch, assetwork, audit, lifecycle, manifest, slack
from ..db import get_session
from ..events import broker
from ..hosts import normalise_host
from ..models import (
    ROLE_ORDER,
    TRIAGE_STATES,
    Agent,
    FindingSecret,
    Poc,
    Project,
    RunManifest,
    Target,
    User,
    Vuln,
    WebAddress,
    WebAsset,
    WebAssetFile,
)
from ..query import apply_search, apply_sort, paginate
from ..schemas import Page, PocCreate, PocOut, VulnCreate, VulnOut
from ..security import (
    assert_role_for_target,
    effective_role,
    get_current_user,
    require_project,
    visible_project_ids,
)
from .projects import resolve_project

router = APIRouter(prefix="/api", tags=["findings"])


def _base(model):
    return (select(model, Target.host, Project.code)
            .join(Target, Target.id == model.target_id)
            .join(Project, Project.id == Target.project_id))


def _vuln_out(row, sweeps: dict | None = None) -> VulnOut:
    """One finding, with its lifecycle worked out.

    `sweeps` is the (target, scanner) -> last-looked table for the
    rows being returned, loaded once for the page. Without it every
    finding answers `unconfirmed`, which is the correct answer to
    "has anybody looked since" when nobody has consulted the table —
    not a silent default.
    """
    v = row[0]
    sweeps = sweeps if sweeps is not None else {}
    vd = lifecycle.verdict_for(v, sweeps)
    return VulnOut(
        **{k: getattr(v, k) for k in
           ("id", "target_id", "title", "severity", "status", "triage",
            "port", "protocol", "description", "remediation",
            "external_id", "created_at", "updated_at",
            "scanner", "first_seen_at", "last_seen_at")},
        host=row[1], project_code=row[2],
        lifecycle=vd.state, lifecycle_why=vd.why,
        last_looked_at=vd.last_looked)


async def _with_lifecycle(session, rows) -> list[VulnOut]:
    """A page of finding rows, each with its lifecycle.

    One query for the whole page rather than one per finding: a
    listing of 20,000 findings would otherwise be 20,000 round trips
    to answer a question the sweep table holds in one row per host
    per tool.
    """
    sweeps = await lifecycle.sweeps_for_targets(
        session, [r[0].target_id for r in rows])
    return [_vuln_out(r, sweeps) for r in rows]


def _poc_out(row) -> PocOut:
    p = row[0]
    return PocOut(
        **{k: getattr(p, k) for k in
           ("id", "target_id", "title", "status", "path", "exit_code", "notes",
            "created_at", "updated_at")},
        host=row[1], project_code=row[2])


async def _target_for(session, project: str, host: str) -> Target:
    pr = await resolve_project(session, project)
    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == normalise_host(host)))).scalar_one_or_none()
    if not t:
        raise HTTPException(404, f"no target {host!r} in {pr.code} — create it, or use /api/bulk")
    return t


@router.get("/vulns", response_model=Page[VulnOut])
async def list_vulns(
    project: str | None = Query(None),
    q: str | None = Query(None),
    host: str | None = Query(None),
    title: str | None = Query(
        None, description="Exact title match. Distinct from `q`, which is a "
                          "substring search and would also return findings "
                          "whose title merely contains this one."),
    severity: str | None = Query(None),
    state: str | None = Query(
        None, pattern="^(new|present|resolved|unconfirmed)$",
        description="Lifecycle: what the most recent scan said about "
                    "this finding. Applied to the page after it is "
                    "built, because the value is derived rather than "
                    "stored — `total` still counts the unfiltered query."),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(20000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = _base(Vuln)
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    if host:
        stmt = stmt.where(Target.host == normalise_host(host))
    if title:
        stmt = stmt.where(Vuln.title == title)
    if severity:
        stmt = stmt.where(Vuln.severity == severity.lower())
    stmt = apply_search(stmt, q, [Target.host, Project.code, Vuln.title, Vuln.severity,
                                  Vuln.status, Vuln.description, Vuln.external_id])
    stmt = apply_sort(stmt, sort, order, {
        "host": Target.host, "project_code": Project.code, "title": Vuln.title,
        "severity": Vuln.severity, "status": Vuln.status, "port": Vuln.port,
        "updated_at": Vuln.updated_at,
    }).order_by(Vuln.id)
    rows, total = await paginate(session, stmt, limit, offset)
    items = await _with_lifecycle(session, rows)
    if state:
        # Filtered AFTER the page is built, because the lifecycle is
        # derived and not a column — there is nothing in SQL to put a
        # WHERE on. `total` therefore still describes the unfiltered
        # query, and saying so here is better than reporting a count
        # that does not match what a second page would return.
        items = [i for i in items if i.lifecycle == state]
    return Page[VulnOut](items=items, total=total,
                         limit=limit, offset=offset)


class LifecycleOut(BaseModel):
    """What changed between the last scan and the one before it.

    The answer to the question recurring scanning is bought for.
    """
    project_code: str
    #: state -> how many findings are in it. Every state is present
    #: even at zero: a summary that omitted `resolved` because
    #: nothing was resolved would read as a tool that cannot answer
    #: the question.
    counts: dict[str, int]
    #: What each word means, so a report can carry the definition
    #: next to the number. `resolved` in particular is a claim, and
    #: a reader is entitled to know exactly what is being claimed.
    meaning: dict[str, str]
    #: Per scanner: when it last looked at anything on this project,
    #: and at how many hosts. The thing that makes the rest
    #: interpretable -- "0 resolved" from a tool that has not run in
    #: six weeks is not good news.
    scanners: list[dict]
    #: Hosts carrying findings that no tool has revisited. Named
    #: rather than counted, because the action is to go and scan
    #: them.
    unconfirmed_hosts: list[str]


#: The severities, worst first. Named once so the two rollups below
#: and the UI agree on both the set and the order -- a summary that
#: omitted a severity because nothing was in it would read as a tool
#: that cannot count it.
ROLLUP_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _sev_counts() -> list:
    """One COUNT per severity, as columns.

    Counted in SQL rather than by loading the findings and tallying
    them in Python: FALCON alone has 23,000, and the answer here is
    eight numbers a row.
    """
    # `count(CASE WHEN ... THEN 1 END)` rather than `sum(CASE ... ELSE 0)`:
    # count ignores the NULL the CASE falls through to, so there is no
    # empty-group NULL to coalesce away, and it reads the same on
    # SQLite and Postgres.
    return [
        func.count(case((Vuln.severity == sev, 1))).label(sev)
        for sev in ROLLUP_SEVERITIES
    ]


class Rollup(BaseModel):
    """A rollup, and whether it is all of it.

    A bare list cannot say "there was more". On FALCON the by-title
    rollup is 5,013 rows against a limit that was 5,000, so the first
    version of this would have cut thirteen of them off and looked
    complete -- which is the one thing a summary must not do.

    `truncated` is worked out by asking for one row more than the
    limit and seeing whether it arrives, so it costs nothing.
    """
    items: list
    truncated: bool = False


class VulnsByTargetRow(BaseModel):
    host: str
    project_code: str
    total: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class VulnsByTitleRow(BaseModel):
    """One finding AT one severity.

    Grouped on (title, severity) rather than title alone. The same
    title does arrive at two severities -- different scanners
    disagree about how bad the same thing is -- and rolling those
    together forces a choice between reporting the worst (which
    overstates the other) and listing both in one row (which cannot
    be sorted or counted). Two rows states it plainly and each one
    carries a number that means something.
    """
    title: str
    severity: str
    hosts: int
    total: int


@router.get("/vulns/by-target", response_model=Rollup)
async def vulns_by_target(
    project: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(20000, ge=1, le=100000),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Findings per host, counted by severity.

    The rollup the Vulns page needs to answer "which host is worst",
    which a flat list of 23,000 rows cannot. Aggregated in SQL; the
    findings themselves are fetched per host when a row is expanded,
    so opening one costs one query and opening none costs nothing.
    """
    stmt = (select(Target.host, Project.code,
                   func.count(Vuln.id).label("total"), *_sev_counts())
            .join(Target, Target.id == Vuln.target_id)
            .join(Project, Project.id == Target.project_id))
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    stmt = apply_search(stmt, q, [Target.host, Vuln.title, Vuln.severity])
    stmt = (stmt.group_by(Target.host, Project.code)
            .order_by(func.count(Vuln.id).desc(), Target.host)
            .limit(limit + 1))
    rows = (await session.execute(stmt)).all()
    return Rollup(
        items=[VulnsByTargetRow(
            host=r.host, project_code=r.code, total=r.total,
            **{sev: getattr(r, sev) for sev in ROLLUP_SEVERITIES})
            for r in rows[:limit]],
        truncated=len(rows) > limit)


@router.get("/vulns/by-title", response_model=Rollup)
async def vulns_by_title(
    project: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(20000, ge=1, le=100000),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """The same findings the other way up: one row per finding AT a
    severity, with how many hosts carry it.

    "This one thing is wrong on 400 hosts" and "this host has 400
    things wrong" are different questions and neither answers the
    other.
    """
    stmt = (select(Vuln.title, Vuln.severity,
                   func.count(func.distinct(Target.host)).label("hosts"),
                   func.count(Vuln.id).label("total"))
            .join(Target, Target.id == Vuln.target_id)
            .join(Project, Project.id == Target.project_id))
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    stmt = apply_search(stmt, q, [Vuln.title, Target.host, Vuln.severity])
    stmt = (stmt.group_by(Vuln.title, Vuln.severity)
            .order_by(func.count(func.distinct(Target.host)).desc(),
                      Vuln.title)
            .limit(limit + 1))
    rows = (await session.execute(stmt)).all()
    return Rollup(
        items=[VulnsByTitleRow(title=r.title, severity=r.severity,
                               hosts=r.hosts, total=r.total)
               for r in rows[:limit]],
        truncated=len(rows) > limit)


@router.get("/vulns/lifecycle", response_model=LifecycleOut)
async def vuln_lifecycle(
    project: str = Query(..., description="Engagement code."),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """New since the last scan, still present, resolved — and unknown.

    Four numbers rather than three. The fourth is the one that keeps
    the other three honest: a finding nothing has looked for since it
    was last seen is not resolved and not confirmed present, and
    rolling it into either would be the tool making up an answer.

    Nothing here is stored. The states are derived from the sweep
    table on every request, so a scan that finds something again
    revives it with no column to clear first.
    """
    pr = await resolve_project(session, project)
    vis = await visible_project_ids(session, user)
    if vis is not None and pr.id not in vis:
        raise HTTPException(404, f"no project {project!r}")

    rows = (await session.execute(
        select(Vuln, Target.host)
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == pr.id))).all()
    sweeps = await lifecycle.sweeps_for(session, pr.id)

    counts = dict.fromkeys(lifecycle.STATES, 0)
    unconfirmed: set[str] = set()
    for v, host in rows:
        vd = lifecycle.verdict_for(v, sweeps)
        counts[vd.state] = counts.get(vd.state, 0) + 1
        if vd.state == lifecycle.UNCONFIRMED:
            unconfirmed.add(host)

    # Per scanner, so "0 resolved" can be read correctly. A tool that
    # has not run since March has not resolved anything and has not
    # failed to -- it has not looked.
    by_scanner: dict[str, dict] = {}
    for (_tid, name), at in sweeps.items():
        cur = by_scanner.setdefault(name, {"scanner": name, "hosts": 0,
                                           "last_looked_at": None})
        cur["hosts"] += 1
        if cur["last_looked_at"] is None or at > cur["last_looked_at"]:
            cur["last_looked_at"] = at

    return LifecycleOut(
        project_code=pr.code,
        counts=counts,
        meaning=dict(lifecycle.MEANING),
        scanners=sorted(by_scanner.values(),
                        key=lambda r: r["scanner"]),
        # Capped: this is a prompt to go and scan, and a list of
        # four thousand hostnames is not one.
        unconfirmed_hosts=sorted(unconfirmed)[:200],
    )


class VulnOccurrence(BaseModel):
    """One host this finding was recorded on."""
    id: int
    target_id: int
    host: str
    project_code: str
    port: int | None = None
    protocol: str | None = None
    status: str = "open"
    severity: str = "info"


class VulnDetail(VulnOut):
    """One finding, with every host carrying the same issue.

    The table has a row per (finding, host), because that is what the
    scanners report and what gets fixed. But the question a reader
    actually has in front of a finding is "where else is this?", and
    answering it by eye across 7,076 rows is not reasonable.

    Matched on `external_id` when there is one -- a CVE is the same
    issue wherever it appears -- and on the exact title otherwise.
    Scoped to the finding's own project: two engagements sharing a
    scanner's wording are not one finding.
    """
    occurrences: list[VulnOccurrence] = []
    #: Whether the match was by identifier or by title, so a reader can
    #: judge how much to trust the grouping.
    grouped_by: str = "title"
    #: When a sweep could not clear this finding because it was
    #: configured differently, WHICH part of the configuration
    #: changed -- `-severity: 'critical,high' -> 'critical'`.
    #:
    #: Empty whenever there is nothing to say, which is most of the
    #: time. "The configuration changed" on its own is a dead end for
    #: whoever reads it; the whole reason the manifest detail is
    #: stored is so this list can exist.
    configuration_changed: list[str] = []
    #: Whether there is a credential stored against this finding.
    #:
    #: Asked of the database rather than guessed from the detector's
    #: name. The UI used to offer Reveal whenever the id started
    #: `detect-secrets:`, which is true of 3,457 findings and wrong
    #: for the 92 that predate secrets being kept -- so the button
    #: appeared, was pressed, and returned an error. A control that
    #: cannot do the thing it offers is worse than no control.
    has_secret: bool = False


@router.get("/vulns/{vuln_id}", response_model=VulnDetail)
async def get_vuln(vuln_id: int,
                   user: User = Depends(get_current_user),
                   session: AsyncSession = Depends(get_session)):
    """One finding in full, plus every other host it was found on."""
    row = (await session.execute(_base(Vuln).where(Vuln.id == vuln_id))).first()
    if row is None:
        raise HTTPException(404, "no such vulnerability")
    vuln = row[0]
    target = await session.get(Target, vuln.target_id)
    vis = await visible_project_ids(session, user)
    if target is None or (vis is not None and target.project_id not in vis):
        raise HTTPException(404, "no such vulnerability")

    same = _base(Vuln).where(Target.project_id == target.project_id)
    if vuln.external_id:
        same = same.where(Vuln.external_id == vuln.external_id)
        grouped = f"external_id {vuln.external_id}"
    else:
        same = same.where(Vuln.title == vuln.title)
        grouped = "title"
    rows = (await session.execute(same.order_by(Target.host, Vuln.port))).all()
    # Existence only. The value itself goes nowhere near this
    # response -- it is readable from exactly one endpoint, which
    # checks a role and writes an audit entry first.
    has_secret = (await session.execute(
        select(FindingSecret.id).where(
            FindingSecret.vuln_id == vuln.id))).scalar_one_or_none() is not None

    out = _vuln_out(row, await lifecycle.sweeps_for_targets(
        session, [vuln.target_id]))
    # Only looked up when the verdict actually turned on it. Two
    # extra rows per finding detail for a case that does not arise on
    # most of them.
    changed: list[str] = []
    vd = lifecycle.verdict_for(vuln, await lifecycle.sweeps_for_targets(
        session, [vuln.target_id]))
    if vd.found_by and vd.looked_with and vd.found_by != vd.looked_with:
        a = await session.get(RunManifest, vd.found_by)
        b = await session.get(RunManifest, vd.looked_with)
        if a is not None and b is not None:
            with contextlib.suppress(ValueError):
                changed = manifest.differences(json.loads(a.detail),
                                               json.loads(b.detail))

    return VulnDetail(
        **out.model_dump(),
        configuration_changed=changed,
        grouped_by=grouped,
        has_secret=has_secret,
        # `_base` selects (Vuln, Target.host, Project.code) — the second
        # and third are strings, not ORM objects.
        occurrences=[
            VulnOccurrence(id=v.id, target_id=v.target_id, host=host,
                           project_code=code, port=v.port, protocol=v.protocol,
                           status=v.status, severity=v.severity)
            for (v, host, code) in rows],
    )


class TriageIn(BaseModel):
    """A verdict, for one finding or for many."""
    triage: str
    #: Bulk form. Empty means "just the one in the path".
    ids: list[int] = []


class TriageOut(BaseModel):
    changed: int
    #: Named back, because a bulk action that silently skipped rows
    #: the caller cannot write to would look like it worked.
    refused: list[int] = []


async def _set_triage(session: AsyncSession, user: User, ids: list[int],
                      triage: str) -> TriageOut:
    """Apply one verdict to many findings, checking each.

    Permission is checked PER FINDING, not once for the batch. A
    selection in the UI can span projects -- the vulns table is
    cross-project when no project is chosen -- so one check against
    the first row would let a caller write to an engagement they
    cannot see by selecting it alongside one they can.
    """
    if triage not in TRIAGE_STATES:
        raise HTTPException(
            422, f"triage is one of {', '.join(TRIAGE_STATES)}")
    vis = await visible_project_ids(session, user)
    changed, refused = 0, []
    for vid in ids[:2000]:
        v = (await session.execute(
            select(Vuln).where(Vuln.id == vid))).scalar_one_or_none()
        if v is None:
            refused.append(vid)
            continue
        t = await session.get(Target, v.target_id)
        if t is None or (vis is not None and t.project_id not in vis):
            refused.append(vid)
            continue
        try:
            await assert_role_for_target(session, user, t.id, "user")
        except HTTPException:
            refused.append(vid)
            continue
        if v.triage != triage:
            v.triage = triage
            changed += 1
    await session.commit()
    return TriageOut(changed=changed, refused=refused)


@router.patch("/vulns/{vuln_id}/triage", response_model=TriageOut)
async def set_one_triage(vuln_id: int, body: TriageIn,
                         user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """Record what somebody concluded about one finding."""
    return await _set_triage(session, user, [vuln_id], body.triage)


@router.post("/vulns/triage", response_model=TriageOut)
async def set_bulk_triage(body: TriageIn,
                          user: User = Depends(get_current_user),
                          session: AsyncSession = Depends(get_session)):
    """The same verdict across a selection.

    Triage is the bulk job: a scanner produces four thousand
    findings and most of a review is marking families of them at
    once. Doing that one request at a time is what makes people
    not do it.
    """
    if not body.ids:
        raise HTTPException(422, "no findings given")
    return await _set_triage(session, user, body.ids, body.triage)


class SecretOut(BaseModel):
    """The credential behind a finding, when someone asks for it."""
    secret: str
    detector: str | None = None


@router.get("/vulns/{vuln_id}/secret", response_model=SecretOut)
async def reveal_secret(vuln_id: int,
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """The actual credential behind a secret finding.

    Separate from the finding itself, and from `GET /vulns/{id}`,
    for one reason: a value returned by the detail endpoint is a
    value in every list, export and Slack message that endpoint
    feeds. Here it is returned only when somebody asks for this
    specific credential.

    **Three guards, and each is doing a different job.**

    `user` role, not `readonly` — reading a finding is reporting
    work and belongs to everyone on the engagement; reading the
    credential inside it is not, and a readonly account exists
    precisely so it can be handed out more freely.

    An audit entry BEFORE the value is returned, naming who and
    which finding. Rotating a leaked key, or explaining to a client
    who could have seen it, both need that record, and an audit
    written afterwards is one a failure can skip.

    The entry records the finding and the detector and **never the
    value** — an audit log every site admin can read is the last
    place a credential should end up, which is the whole reason it
    is not in the description either.
    """
    row = (await session.execute(
        select(Vuln).where(Vuln.id == vuln_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "no such vulnerability")
    target = await session.get(Target, row.target_id)
    if target is None:
        raise HTTPException(404, "no such vulnerability")
    # Same visibility rule as the finding, then a stricter role on
    # top of it.
    vis = await visible_project_ids(session, user)
    if vis is not None and target.project_id not in vis:
        raise HTTPException(404, "no such vulnerability")
    await assert_role_for_target(session, user, target.id, "user")

    sec = (await session.execute(select(FindingSecret).where(
        FindingSecret.vuln_id == vuln_id))).scalar_one_or_none()
    if sec is None:
        raise HTTPException(
            404, "this finding has no stored credential: it either predates "
                 "them being kept, or the detector reported a location "
                 "rather than a value")

    await audit.record(
        session, "ui", "finding.secret.reveal", user=user, commit=True,
        project_code=None,
        detail=(f"revealed the credential on finding {vuln_id} "
                f"({sec.detector or 'unknown detector'}) on "
                f"{target.host or target.id}"))
    return SecretOut(secret=sec.secret, detector=sec.detector)


#: How much of a file the modal is given at once.
#:
#: A recovered original is a few hundred lines; a `raw` bundle is
#: routinely megabytes on ONE line. Sending the whole of the second
#: to a browser to highlight forty characters in the middle of it is
#: the case this cap exists for, and a window around the match is
#: strictly more useful than the first 120 kB of a minified file.
SOURCE_WINDOW = 120_000

#: Views of one asset, most readable first.
#:
#: `source` is what the developer wrote, `beautified` is our
#: reformatting of a bundle, `raw` is what the server sent. That is
#: also the order anybody wants to read them in, so it doubles as
#: the default choice.
VIEW_ORDER = ("source", "beautified", "raw")


class SourceView(BaseModel):
    """One readable rendering of the asset this credential is in."""
    origin: str
    path: str
    bytes: int
    #: Produced for this request rather than read from storage, which
    #: is a different claim about the line numbers: nothing else has
    #: ever seen them, so they cannot be quoted anywhere.
    generated: bool = False
    #: The file the finding was actually recorded against. Only this
    #: one has a meaningful `line`.
    recorded: bool = False


class SecretSourceOut(BaseModel):
    """The file a credential was found in, and where in it.

    `body` may be a WINDOW rather than the whole file -- see
    `SOURCE_WINDOW`. `offset` is where that window starts in the
    file, so the caller can number lines and resolve the match
    without having been sent the rest.
    """
    path: str
    #: raw | beautified | source. Not decoration: a line number from
    #: `beautified` names a line in a file WE produced, and saying so
    #: is the difference between sending somebody to their own source
    #: and sending them to our reformatting of it.
    origin: str
    #: True when this rendering was produced for this request.
    generated: bool = False
    #: The origin of the file the finding was RECORDED against, which
    #: is not always the one being shown. `line` belongs to that file
    #: and to no other.
    recorded_origin: str
    #: Every rendering that can be asked for, so the caller can offer
    #: the choice without guessing which exist.
    views: list[SourceView] = []
    asset_url: str | None = None
    line: int | None = None
    body: str
    #: Characters of the whole file, before any windowing.
    total: int
    #: Where `body` starts within the file, in characters, and which
    #: line that is. Both zero/one for an unwindowed file.
    offset: int = 0
    first_line: int = 1
    truncated: bool = False
    #: Where the credential sits INSIDE `body`, in characters, so the
    #: UI can highlight the value itself rather than a whole line.
    #: A minified bundle is one line of two megabytes; "line 1" names
    #: the entire file and is no help at all.
    match_start: int | None = None
    match_end: int | None = None
    #: Four answers, not two.
    #:
    #:   confirmed  the recorded file, value at the recorded line
    #:   moved      the recorded file, value at a DIFFERENT line --
    #:              re-fetched and shifted since the scan
    #:   found      a different rendering of the same asset. The
    #:              recorded line belongs to another file and is not
    #:              claimed here; the value was located by searching
    #:   absent     not in this body at all
    #:
    #: Collapsing `moved` into `confirmed` would scroll somebody
    #: confidently to the wrong place, and collapsing `found` into
    #: `confirmed` would quote a line number from a file the scanner
    #: never read.
    located: str


def _locate(body: str, sec, is_recorded: bool):
    """Where the credential sits in this text, and a window round it.

    Shared by the asset path and the page path. They differ in how
    the text was obtained and in nothing else, and two copies of
    this would be two chances for `located` to come to mean
    different things in the two places a reader compares.

    -> (body, total, start, end, located, offset, truncated, first_line)
    """
    total = len(body)
    lines = body.split("\n")
    start = end_ = None
    located = "absent"
    if is_recorded and sec.line and 1 <= sec.line <= len(lines):
        at = lines[sec.line - 1].find(sec.secret)
        if at >= 0:
            start = sum(len(x) + 1 for x in lines[:sec.line - 1]) + at
            end_ = start + len(sec.secret)
            located = "confirmed"
    if start is None:
        at = body.find(sec.secret)
        if at >= 0:
            start, end_ = at, at + len(sec.secret)
            located = "moved" if is_recorded else "found"

    # Window around the match when the file is too big to send. An
    # unlocated secret in a huge file windows from the top: there is
    # nothing better to centre on, and `located` already says so.
    offset, truncated, first_line = 0, False, 1
    if total > SOURCE_WINDOW:
        truncated = True
        centre = start if start is not None else 0
        offset = max(0, centre - SOURCE_WINDOW // 2)
        whole = body
        body = whole[offset:offset + SOURCE_WINDOW]
        if start is not None:
            start, end_ = start - offset, (end_ or 0) - offset
        # Which line the window opens on, so the gutter counts from
        # the file's numbering and not from the window's.
        first_line = whole[:offset].count("\n") + 1
    return body, total, start, end_, located, offset, truncated, first_line


async def _page_source(session, user, vuln_id: int, target, sec,
                       body: str) -> SecretSourceOut:
    """The captured page a credential was found in.

    One view and no choice of renderings: a page body is the bytes
    the client's server sent, there is no source map behind it and
    no minified sibling to offer. Saying so with a single `page`
    view is better than presenting an empty switcher.

    The line number IS meaningful here -- `scan_pages` hands the
    scanner the stripped response body, which is exactly this -- so
    the recorded line is trusted the same way a recorded file's is.
    """
    body, total, start, end_, located, offset, truncated, first_line = \
        _locate(body, sec, True)
    await audit.record(
        session, "ui", "finding.secret.source", user=user, commit=True,
        project_code=None,
        detail=(f"read the source around the credential on finding {vuln_id} "
                f"(captured page) on {target.host or target.id}"))
    view = SourceView(origin="page", path=sec.path or sec.asset_url,
                      bytes=total, generated=False, recorded=True)
    return SecretSourceOut(
        path=view.path, origin="page", generated=False,
        recorded_origin="page", views=[view], asset_url=sec.asset_url,
        line=sec.line, body=body, total=total, offset=offset,
        first_line=first_line, truncated=truncated,
        match_start=start, match_end=end_, located=located)


@router.get("/vulns/{vuln_id}/secret/source", response_model=SecretSourceOut)
async def secret_source(vuln_id: int,
                        view: str | None = Query(
                            None, description="raw | beautified | source"),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """The source this credential was found in, positioned on it.

    Same guards as `reveal_secret`, and for the same reason rather
    than for symmetry: this returns a file that CONTAINS the
    credential, so it discloses everything that endpoint does and
    some of the surrounding code besides. A weaker check here would
    make the stricter one next door decorative.

    The file is located the way it was scanned. `assetwork` hands
    the scanners `(file.id, file.path, file.body)` one
    `WebAssetFile` at a time, so the `path` and `line` stored on the
    finding name that row exactly -- the asset by URL, then the file
    by path within it.

    **Views.** A secret found in a minified bundle is a secret on one
    line two megabytes long, which is not something anybody can read.
    The same bytes usually exist in a second form already -- the
    source map's originals, or the `.pretty` copy `assetfetch` writes
    when a bundle is minified and has no map -- so the readable one
    is offered by default and the others are offered beside it.

    Nothing is reformatted that does not need to be. `assetfetch`
    stores a `beautified` copy only when a file is minified AND no
    map gave us the originals, which means a readable rendering
    already exists for every case it recognised. The on-the-fly
    beautify below is for the files it did not -- rows written before
    that logic, or a bundle whose map has since gone -- and it is
    flagged as `generated` because its line numbers have never been
    stored and must not be quoted as though they had.
    """
    row = (await session.execute(
        select(Vuln).where(Vuln.id == vuln_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "no such vulnerability")
    target = await session.get(Target, row.target_id)
    if target is None:
        raise HTTPException(404, "no such vulnerability")
    vis = await visible_project_ids(session, user)
    if vis is not None and target.project_id not in vis:
        raise HTTPException(404, "no such vulnerability")
    await assert_role_for_target(session, user, target.id, "user")

    sec = (await session.execute(select(FindingSecret).where(
        FindingSecret.vuln_id == vuln_id))).scalar_one_or_none()
    if sec is None:
        raise HTTPException(404, "this finding has no stored credential")
    if not sec.asset_url or not sec.path:
        raise HTTPException(
            404, "this finding predates the origin being stored as columns, "
                 "so the file it came from cannot be identified")

    asset = (await session.execute(select(WebAsset).where(
        WebAsset.project_id == target.project_id,
        WebAsset.url == sec.asset_url))).scalar_one_or_none()

    # A finding from a PAGE, not from an asset file.
    #
    # `scan_pages` runs the same scanners over the body of every
    # captured 2xx exchange and files what they find through the same
    # `_file_vuln`, which stores the PAGE's url in `asset_url`. That
    # url is a `web_addresses` row and will never be in `web_assets`,
    # so this lookup could not possibly succeed for one of them --
    # and the 404 below told the operator the asset "was removed, or
    # the project was re-imported", which is a confident explanation
    # of something that never happened.
    #
    # On the live estate that was 87 of 1,588 stored credentials:
    # every one of them findable, none of them viewable, and all of
    # them blamed on a deletion. The evidence was in the captured
    # response the whole time.
    if asset is None:
        page = (await session.execute(select(WebAddress).where(
            WebAddress.target_id == row.target_id,
            WebAddress.url == sec.asset_url,
            WebAddress.response.is_not(None))
            # The scanner read `assetwork.response_body` of whichever
            # capture it was handed; newest wins here because that is
            # the one a re-scan would read now.
            .order_by(WebAddress.id.desc()).limit(1))).scalar_one_or_none()
        if page is None:
            raise HTTPException(
                404, "this credential's origin is not recorded any more: "
                     "neither an asset nor a captured page at that URL is "
                     "in the project now. It was removed, or the project "
                     "was re-imported since the scan")
        return await _page_source(
            session, user, vuln_id, target, sec,
            assetwork.response_body(page.response or ""))

    # Every stored file of this asset that has contents. Ordered so a
    # scanned row comes first, which is the one a line number came
    # from if two ever shared a path.
    files = (await session.execute(
        select(WebAssetFile)
        .where(WebAssetFile.asset_id == asset.id,
               WebAssetFile.body.is_not(None))
        .order_by(WebAssetFile.scanned_at.is_(None),
                  WebAssetFile.id))).scalars().all()

    recorded = next((f for f in files if f.path == sec.path), None)
    if recorded is None:
        raise HTTPException(
            404, "the file is recorded but its contents are not: the asset "
                 "was known by reference and never pulled back, or the "
                 "fetch failed")

    # The choice offered. The recorded file always, plus this asset's
    # raw and beautified renderings -- at most three. NOT every source
    # a map produced: those are a hundred different files and only one
    # of them holds this value, so offering them all would be offering
    # ninety-nine wrong answers.
    chosen: dict[str, WebAssetFile] = {}
    for f in files:
        if f is recorded or f.origin in ("raw", "beautified"):
            chosen.setdefault(f.origin, f)
    # The recorded file wins its own slot even if another row of the
    # same origin sorted first.
    chosen[recorded.origin] = recorded

    generated_body: str | None = None
    if "beautified" not in chosen:
        raw = chosen.get("raw")
        if raw and raw.body and assetfetch.looks_minified(raw.body):
            pretty = assetfetch.beautify(raw.body)
            if pretty and pretty != raw.body:
                generated_body = pretty

    def _describe(origin: str) -> SourceView:
        if origin == "beautified" and generated_body is not None:
            return SourceView(origin=origin, path=f"{chosen['raw'].path}.pretty",
                              bytes=len(generated_body), generated=True,
                              recorded=False)
        f = chosen[origin]
        return SourceView(origin=origin, path=f.path, bytes=len(f.body or ""),
                          generated=False, recorded=f is recorded)

    available = [o for o in VIEW_ORDER
                 if o in chosen or (o == "beautified" and generated_body)]
    views = [_describe(o) for o in available]

    # What to show. An explicit `view` wins; otherwise the most
    # readable available, which is what VIEW_ORDER is sorted by. The
    # recorded file is NOT the default when a more readable rendering
    # of the same bytes exists -- reading the credential in context is
    # the whole point, and one line of two megabytes is not context.
    want = view if view in available else available[0]

    if want == "beautified" and generated_body is not None:
        body, shown_path, shown_generated = (
            generated_body, f"{chosen['raw'].path}.pretty", True)
    else:
        f = chosen[want]
        body, shown_path, shown_generated = (f.body or ""), f.path, False
    is_recorded = (not shown_generated) and chosen.get(want) is recorded

    # Where the value actually is, rather than where it was recorded.
    # The recorded line is checked FIRST, and only on the recorded
    # file: on any other rendering it names a line in a different
    # file, so the only honest way to find the value there is to look
    # for it. Checking the line first also means an unchanged file
    # reports `confirmed` when the same value appears more than once,
    # instead of resolving to whichever copy came first.
    body, total, start, end_, located, offset, truncated, first_line = \
        _locate(body, sec, is_recorded)

    await audit.record(
        session, "ui", "finding.secret.source", user=user, commit=True,
        project_code=None,
        detail=(f"read the source around the credential on finding {vuln_id} "
                f"({shown_path}) on {target.host or target.id}"))

    return SecretSourceOut(
        path=shown_path, origin=want, generated=shown_generated,
        recorded_origin=recorded.origin, views=views,
        asset_url=sec.asset_url,
        line=sec.line if is_recorded else None,
        body=body, total=total, offset=offset, first_line=first_line,
        truncated=truncated, match_start=start, match_end=end_,
        located=located)


class SecretRow(BaseModel):
    """One stored credential, with where it came from."""
    vuln_id: int
    secret: str
    detector: str | None = None
    #: NULL means the origin was never recorded in columns -- a row
    #: written before they existed whose description did not parse.
    #: Distinct from "no URL", and rendered as such.
    asset_url: str | None = None
    path: str | None = None
    line: int | None = None
    host: str | None = None
    project_code: str
    severity: str
    triage: str
    title: str


@router.get("/secrets", response_model=list[SecretRow])
async def list_secrets(project: str | None = Query(None),
                       limit: int = Query(5000, ge=1, le=50000),
                       offset: int = Query(0, ge=0),
                       user: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    """Every stored credential the caller may see, with its origin.

    **This returns credentials in bulk and in clear, and that is a
    real widening of what `GET /vulns/{id}/secret` deliberately kept
    narrow.** It is here because the opposite is worse in practice:
    the job this serves is "we have several hundred of these, which
    are real and which belong to the same system", and doing it one
    audited click at a time means it does not get done, which is how
    a live key stays in a report for a week. The same argument
    already decided bulk triage.

    What is kept from the narrow version, because it still works at
    this size:

    `user` on the project, never `readonly` -- and enforced per
    project rather than once, so a caller with mixed roles gets the
    credentials from the engagements they work on and nothing from
    the ones they were only shown. A readonly account exists to be
    handed out freely and must not become a way to read every key on
    the estate.

    An audit entry BEFORE the values are returned, recording the
    count and the projects. One line per bulk read rather than one
    per credential: the question it has to answer later is "who
    could have seen this key", and a row naming the project and the
    time answers that.

    It is NOT in the vulns list, and the value is still absent from
    `description`. A credential here is a credential in one response
    to one deliberate request; a credential there is one in every
    export, report and Slack message.
    """
    vis = await visible_project_ids(session, user)
    stmt = (select(FindingSecret, Vuln, Target.host, Project.code)
            .join(Vuln, Vuln.id == FindingSecret.vuln_id)
            .join(Target, Target.id == Vuln.target_id)
            .join(Project, Project.id == Target.project_id))
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    # Newest first: the reason to open this list is almost always a
    # sweep that just finished.
    stmt = stmt.order_by(FindingSecret.id.desc()).limit(limit).offset(offset)
    rows = (await session.execute(stmt)).all()

    # The role check is per project and the result is cached, because
    # the alternative is one ACL lookup per credential and these
    # arrive in the hundreds.
    allowed: dict[int, bool] = {}
    out: list[SecretRow] = []
    for sec, vuln, host, code in rows:
        pid = (await session.get(Target, vuln.target_id)).project_id
        if pid not in allowed:
            role = await effective_role(session, user, pid)
            allowed[pid] = ROLE_ORDER.get(role or "", -1) >= ROLE_ORDER["user"]
        if not allowed[pid]:
            continue
        out.append(SecretRow(
            vuln_id=vuln.id, secret=sec.secret, detector=sec.detector,
            asset_url=sec.asset_url, path=sec.path, line=sec.line,
            host=host, project_code=code, severity=vuln.severity,
            triage=vuln.triage, title=vuln.title))

    if out:
        codes = sorted({r.project_code for r in out})
        await audit.record(
            session, "ui", "finding.secret.list", user=user, commit=True,
            project_code=codes[0] if len(codes) == 1 else None,
            detail=(f"listed {len(out)} credential(s) in clear across "
                    f"{', '.join(codes)}"))
    return out


@router.post("/vulns", response_model=VulnOut, status_code=201)
async def create_vuln(body: VulnCreate, project: str = Query(...),
                      pr: Project = Depends(require_project("user")),
                      session: AsyncSession = Depends(get_session)):
    t = await _target_for(session, project, body.host)
    v = Vuln(target_id=t.id, **body.model_dump(exclude={"host"}))
    session.add(v)
    await session.commit()
    await broker.publish("vulns", action="create", host=t.host, project=project)

    # Announced here as well as on import. Wiring only the import path
    # meant a finding an operator recorded by hand — which is how you
    # log something you found yourself, and usually the most important
    # kind — went to Slack silently. Caught by posting a real critical
    # into a real channel and watching nothing arrive.
    #
    # No severity floor, unlike an import: a person filing one finding
    # has already decided it is worth recording, where a scanner
    # filing six thousand has not.
    await slack.announce_finding(
        session, pr, severity=v.severity, host=t.host, title=v.title,
        port=v.port, protocol=v.protocol, detail=v.description)

    # A finding somebody typed in. No scanner is responsible for
    # looking for it again, so its lifecycle reads `unconfirmed` and
    # no sweep will ever close it -- which is the point: a person's
    # finding is not something a tool gets to resolve.
    return _vuln_out(
        (await session.execute(_base(Vuln).where(Vuln.id == v.id))).first())


@router.delete("/vulns/{vuln_id}", status_code=204)
async def delete_vuln(vuln_id: int, user: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    v = await session.get(Vuln, vuln_id)
    if not v:
        raise HTTPException(404, f"no vuln {vuln_id}")
    code = await assert_role_for_target(session, user, v.target_id, "user")
    await session.delete(v)
    await session.commit()
    await broker.publish("vulns", action="delete", project=code)


@router.get("/pocs", response_model=Page[PocOut])
async def list_pocs(
    project: str | None = Query(None),
    q: str | None = Query(None),
    host: str | None = Query(None),
    status: str | None = Query(None),
    sort: str | None = Query("host"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(20000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = _base(Poc)
    vis = await visible_project_ids(session, user)
    if vis is not None:
        stmt = stmt.where(Target.project_id.in_(vis))
    if project:
        pr = await resolve_project(session, project)
        if vis is not None and pr.id not in vis:
            raise HTTPException(404, f"no project {project!r}")
        stmt = stmt.where(Target.project_id == pr.id)
    if host:
        stmt = stmt.where(Target.host == normalise_host(host))
    if status:
        stmt = stmt.where(Poc.status == status.lower())
    stmt = apply_search(stmt, q, [Target.host, Project.code, Poc.title, Poc.status,
                                  Poc.path, Poc.notes])
    stmt = apply_sort(stmt, sort, order, {
        "host": Target.host, "project_code": Project.code, "title": Poc.title,
        "status": Poc.status, "exit_code": Poc.exit_code, "updated_at": Poc.updated_at,
    }).order_by(Poc.id)
    rows, total = await paginate(session, stmt, limit, offset)
    return Page[PocOut](items=[_poc_out(r) for r in rows], total=total,
                        limit=limit, offset=offset)


@router.post("/pocs", response_model=PocOut, status_code=201)
async def create_poc(body: PocCreate, project: str = Query(...),
                     _: Project = Depends(require_project("user")),
                     session: AsyncSession = Depends(get_session)):
    t = await _target_for(session, project, body.host)
    p = Poc(target_id=t.id, **body.model_dump(exclude={"host"}))
    session.add(p)
    await session.commit()
    await broker.publish("pocs", action="create", host=t.host, project=project)
    return _poc_out((await session.execute(_base(Poc).where(Poc.id == p.id))).first())


class PocRequest(BaseModel):
    """Prove one finding, now."""
    #: Where to point it. Omitted, the host and port on the finding
    #: decide — which is right for a web finding and guessable for
    #: anything else, so an operator who knows better may say.
    url: str | None = None


@router.post("/vulns/{vuln_id}/poc", response_model=dict, status_code=201)
async def build_poc(vuln_id: int, body: PocRequest | None = None,
                    project: str = Query(...),
                    pr: Project = Depends(require_project("user")),
                    user: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    """Write a proof for this finding and queue it for validation.

    The per-finding half of `auto_poc`. Same code, same checks, same
    high-priority task; what differs is that somebody asked for this
    one rather than a floor covering it.

    **Both halves of the agent are required and the refusal says
    which is missing.** Without a model there is nothing to write the
    template; without a Ghost online there is nothing to run it, and
    the proof would sit reading "not validated" with no way to tell
    that from a failure. A 409 naming the missing half is actionable;
    a proof that silently never validates is not.

    `user`, not `readonly`. This writes a template and queues traffic
    at the client — see `roe.IMPACT["poc"]`, which classes it
    `state_changing` for the same reason.
    """
    from ..agent.pocbuild import Rejected
    from ..agent.pocworker import _configured, build_one

    vuln = (await session.execute(
        select(Vuln).join(Target, Target.id == Vuln.target_id)
        .where(Vuln.id == vuln_id, Target.project_id == pr.id))
    ).scalar_one_or_none()
    if vuln is None:
        raise HTTPException(404, f"no finding {vuln_id} in {pr.code}")

    if not await _configured():
        raise HTTPException(
            409, "no model is configured, so there is nothing to write the "
                 "proof. Set one in Site Config → Agent.")
    live = (await session.execute(
        select(Agent.id).where(Agent.project_id == pr.id,
                               Agent.status == "online").limit(1))).first()
    if live is None:
        raise HTTPException(
            409, f"no Ghost is online for {pr.code}, so a proof could be "
                 f"written but never run. It would read 'not validated' "
                 f"for ever, which is indistinguishable from one that "
                 f"failed. Bring an agent up and ask again.")

    target = await session.get(Target, vuln.target_id)
    host = (body.url if body and body.url else None) or target.host
    try:
        poc = await build_one(session, vuln, pr, host)
    except Rejected as e:
        # Not a server error: the model answered and the answer may
        # not be run. Said plainly so the operator knows whether to
        # write one by hand.
        raise HTTPException(
            422, f"no proof was written: {e}") from e
    await session.commit()
    await broker.publish("pocs", action="create", project=pr.code, id=poc.id)
    await broker.publish("agents", action="task", project=pr.code)
    await audit.record(session, "ui", "poc.build", user=user, commit=True,
                       project_code=pr.code,
                       detail=f"queued a proof for finding {vuln_id} "
                              f"against {poc.target_url}")
    return {"id": poc.id, "target_url": poc.target_url,
            "status": "queued for validation"}


@router.delete("/pocs/{poc_id}", status_code=204)
async def delete_poc(poc_id: int, user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    p = await session.get(Poc, poc_id)
    if not p:
        raise HTTPException(404, f"no poc {poc_id}")
    code = await assert_role_for_target(session, user, p.target_id, "user")
    await session.delete(p)
    await session.commit()
    await broker.publish("pocs", action="delete", project=code)
