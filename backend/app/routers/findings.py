"""Vulns and PoCs.

Supporting tables: they exist because the Targets grid shows live counts of
them. Full CRUD so the API is complete and bulk import has somewhere to land.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, slack
from ..db import get_session
from ..events import broker
from ..hosts import normalise_host
from ..models import (
    ROLE_ORDER,
    TRIAGE_STATES,
    FindingSecret,
    Poc,
    Project,
    Target,
    User,
    Vuln,
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


def _vuln_out(row) -> VulnOut:
    v = row[0]
    return VulnOut(
        **{k: getattr(v, k) for k in
           ("id", "target_id", "title", "severity", "status", "triage",
            "port", "protocol", "description", "remediation",
            "external_id", "created_at", "updated_at")},
        host=row[1], project_code=row[2])


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
    severity: str | None = Query(None),
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
    return Page[VulnOut](items=[_vuln_out(r) for r in rows], total=total,
                         limit=limit, offset=offset)


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

    return VulnDetail(
        **_vuln_out(row).model_dump(),
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
    #: Three answers, not two. `confirmed` -- the value is at the
    #: recorded line. `moved` -- it is in this file at a different
    #: line, so the file was re-fetched and shifted since the scan.
    #: `absent` -- it is not in this file at all, which means the
    #: stored body is not the one that was scanned. Collapsing the
    #: last two into "here it is" would scroll somebody confidently
    #: to the wrong place.
    located: str


@router.get("/vulns/{vuln_id}/secret/source", response_model=SecretSourceOut)
async def secret_source(vuln_id: int,
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
    if asset is None:
        raise HTTPException(
            404, "the asset this came from is no longer recorded: it was "
                 "removed, or the project was re-imported since the scan")

    # Path identifies the file within the asset. The three origins do
    # not collide in practice -- `raw` is the URL's basename,
    # `beautified` is that plus `.pretty`, and `source` paths come out
    # of a source map -- so this is a lookup and not a guess. Ordered
    # so that, if one ever did collide, the scanned row wins: that is
    # the one the line number came from.
    files = (await session.execute(
        select(WebAssetFile)
        .where(WebAssetFile.asset_id == asset.id,
               WebAssetFile.path == sec.path)
        .order_by(WebAssetFile.scanned_at.is_(None),
                  WebAssetFile.id))).scalars().all()
    f = next((x for x in files if x.body), None)
    if f is None:
        raise HTTPException(
            404, "the file is recorded but its contents are not: the asset "
                 "was known by reference and never pulled back, or the "
                 "fetch failed")

    body: str = f.body or ""
    total = len(body)

    # Where the value actually is, rather than where it was recorded.
    # The recorded line is checked FIRST so an unchanged file reports
    # `confirmed` even when the same value appears more than once --
    # a key repeated in a bundle would otherwise resolve to whichever
    # copy came first and call a correct record "moved".
    lines = body.split("\n")
    start = end = None
    located = "absent"
    if sec.line and 1 <= sec.line <= len(lines):
        at = lines[sec.line - 1].find(sec.secret)
        if at >= 0:
            start = sum(len(x) + 1 for x in lines[:sec.line - 1]) + at
            end = start + len(sec.secret)
            located = "confirmed"
    if start is None:
        at = body.find(sec.secret)
        if at >= 0:
            start, end, located = at, at + len(sec.secret), "moved"

    # Window around the match when the file is too big to send. An
    # unlocated secret in a huge file windows from the top: there is
    # nothing better to centre on, and `located` already says so.
    offset, truncated, first_line = 0, False, 1
    if total > SOURCE_WINDOW:
        truncated = True
        centre = start if start is not None else 0
        offset = max(0, centre - SOURCE_WINDOW // 2)
        body = body[offset:offset + SOURCE_WINDOW]
        if start is not None:
            start, end = start - offset, (end or 0) - offset
        # Which line the window opens on, so the gutter counts from
        # the file's numbering and not from the window's.
        first_line = (f.body or "")[:offset].count("\n") + 1

    await audit.record(
        session, "ui", "finding.secret.source", user=user, commit=True,
        project_code=None,
        detail=(f"read the source around the credential on finding {vuln_id} "
                f"({sec.path}) on {target.host or target.id}"))

    return SecretSourceOut(
        path=sec.path, origin=f.origin, asset_url=sec.asset_url,
        line=sec.line, body=body, total=total, offset=offset,
        first_line=first_line, truncated=truncated,
        match_start=start, match_end=end, located=located)


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

    return _vuln_out((await session.execute(_base(Vuln).where(Vuln.id == v.id))).first())


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
