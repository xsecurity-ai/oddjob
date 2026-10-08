"""Bulk import.

Design points that matter when loading thousands of rows:

ONE PROJECT, ONE TRANSACTION. Everything lands in the project named in the
payload and commits together, or not at all. A half-applied import is worse
than a failed one because you cannot tell which half landed.

IDEMPOTENT. Upsert keys, all scoped to the project:
    targets   host
    services  (host, port, protocol)
    vulns     external_id when supplied, else (host, title)
    pocs      (host, title)
Re-running an unchanged payload creates nothing.

BAD ROWS ARE SKIPPED, NOT FATAL. Host is validated per row here rather than by
the request model, so one wildcard like `*.acme.example` in a 6,000-row scanner
export is reported in `errors` instead of 422-ing the batch. Real exports
always contain some junk; an importer that refuses all-or-nothing just gets
worked around.

KEY LOOKUPS ARE BATCHED. Existing keys are read once per table, not per row.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..models import (
    ROLE_ORDER,
    Credential,
    Poc,
    Project,
    ProjectACL,
    Service,
    Target,
    User,
    Vuln,
    implies_alive,
)
from ..schemas import (
    BulkIds,
    BulkOpResult,
    BulkPatch,
    BulkPayload,
    BulkResult,
    PocIn,
    ServiceIn,
    TargetIn,
    VulnIn,
)
from ..scope import BARRED
from ..scopegate import index_for
from ..security import effective_role, get_current_user

router = APIRouter(prefix="/api/bulk", tags=["bulk"])

def _fields(model, *join_keys: str) -> tuple[str, ...]:
    """Everything the input schema accepts, minus the keys we upsert on.

    Derived rather than written out: these were literal tuples, and when
    `remediation` was added to the vuln model it was absent here, so every
    bulk import silently discarded it while reporting success. A list of
    column names maintained by hand is a list that goes stale.
    """
    return tuple(k for k in model.model_fields if k not in join_keys)


TARGET_FIELDS = _fields(TargetIn, "host")
SERVICE_FIELDS = _fields(ServiceIn, "host", "port", "protocol")
VULN_FIELDS = _fields(VulnIn, "host")
POC_FIELDS = _fields(PocIn, "host", "title")
MAX_ERRORS = 50          # enough to diagnose, not enough to bury the response


def _set_if_given(obj, data: dict, fields) -> bool:
    """Copy only keys the caller actually sent. A partial payload must not
    blank out columns it said nothing about."""
    changed = False
    for f in fields:
        if f in data and data[f] is not None and getattr(obj, f) != data[f]:
            setattr(obj, f, data[f])
            changed = True
    return changed


@router.post("", response_model=BulkResult)
async def bulk_import(payload: BulkPayload,
                      user: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    t0 = time.perf_counter()
    created = {"targets": 0, "services": 0, "vulns": 0, "pocs": 0}
    updated = {"targets": 0, "services": 0, "vulns": 0, "pocs": 0}
    skipped = {"targets": 0, "services": 0, "vulns": 0, "pocs": 0}
    errors: list[str] = []

    def note(msg: str) -> None:
        if len(errors) < MAX_ERRORS:
            errors.append(msg)
        elif len(errors) == MAX_ERRORS:
            errors.append("... further errors suppressed")

    # ------------------------------------------------------- the project
    pr = (await session.execute(
        select(Project).where(Project.code == payload.project))).scalar_one_or_none()
    if pr is None:
        if not payload.create_project:
            raise HTTPException(404, f"no project {payload.project!r}")
        if not user.is_site_admin:
            # Creating a project is a site-level act; otherwise any user with
            # an import token could spawn projects outside the ACL model.
            raise HTTPException(
                403, f"no project {payload.project!r}, and creating one requires site admin")
        pr = Project(code=payload.project, name=payload.project_name or payload.project)
        session.add(pr)
        await session.flush()
        # The creator keeps admin on it, or they would immediately lose access.
        session.add(ProjectACL(project_id=pr.id, user_id=user.id, role="admin"))
        await session.flush()
    else:
        role = await effective_role(session, user, pr.id)
        if role is None:
            raise HTTPException(404, f"no project {payload.project!r}")
        if ROLE_ORDER[role] < ROLE_ORDER["user"]:
            raise HTTPException(403, f"writing to {pr.code} needs user or admin; you have {role}")

    # ------------------------------------------------------------ hosts
    def ok_host(raw: str, kind: str) -> str | None:
        try:
            return validate_host(raw)
        except InvalidHost as e:
            skipped[kind] += 1
            note(f"{kind}: {e}")
            return None

    want: set[str] = set()
    clean_targets: list[tuple[str, dict]] = []
    for body in payload.targets:
        h = ok_host(body.host, "targets")
        if h:
            clean_targets.append((h, body.model_dump(exclude={"host"})))
            want.add(h)

    child_clean: dict[str, list[tuple[str, dict]]] = {}
    for kind, coll in (("services", payload.services), ("vulns", payload.vulns),
                       ("pocs", payload.pocs)):
        rows = []
        for body in coll:
            h = ok_host(body.host, kind)
            if h:
                rows.append((h, body.model_dump(exclude={"host"})))
                want.add(h)
        child_clean[kind] = rows

    existing = {
        t.host: t for t in (await session.execute(
            select(Target).where(Target.project_id == pr.id, Target.host.in_(want)))).scalars()
    } if want else {}

    # -------------------------------------------------------- the scope
    # One index for the whole payload: the alternative is a query per
    # row, and this route exists to load thousands of them.
    #
    # Every host is filtered here, before any loop below can create one.
    # The children matter as much as the targets: `autocreate_targets`
    # turns a vuln row naming a host nobody declared into a new target,
    # which is a target creation path however it is spelled.
    idx = await index_for(session, pr.id)
    barred: dict[str, str] = {}
    for h in sorted(want):
        ip = next((d.get("ip_address") for hh, d in clean_targets if hh == h), None)
        ruling = idx.check(h, ip)
        # An existing target outside the in-scope list keeps working:
        # the lists govern what is new. One on the out list does not.
        if ruling.verdict == BARRED or (not ruling.allowed and h not in existing):
            barred[h] = ruling.reason
    if barred:
        want -= set(barred)
        kept_targets = [(h, d) for h, d in clean_targets if h not in barred]
        skipped["targets"] += len(clean_targets) - len(kept_targets)
        clean_targets = kept_targets
        for kind in child_clean:
            kept = [(h, d) for h, d in child_clean[kind] if h not in barred]
            skipped[kind] += len(child_clean[kind]) - len(kept)
            child_clean[kind] = kept
        # Dropped from `existing` too, so a child row cannot reach a
        # barred target that happens to already be in the project.
        existing = {h: t for h, t in existing.items() if h not in barred}
        for _host, why in sorted(barred.items()):
            note(f"scope: {why}")

    # Iterate the LIST, not a dict keyed by host: collapsing to a dict first
    # makes duplicate hosts vanish before they are counted, and the totals
    # then silently fail to add up.
    seen: set[str] = set()
    dupes = 0
    for host, data in clean_targets:
        if host in seen:
            dupes += 1
        seen.add(host)
        cur = existing.get(host)
        if cur is None:
            cur = Target(project_id=pr.id, host=host, **data)
            session.add(cur)
            existing[host] = cur
            created["targets"] += 1
        else:
            # Call once: _set_if_given mutates, so a second call would always
            # report "no change" and the row would count as both.
            if _set_if_given(cur, data, TARGET_FIELDS):
                updated["targets"] += 1
            else:
                skipped["targets"] += 1
    if dupes:
        note(f"{dupes} target row(s) repeated a host already in this payload and were "
             f"merged; host is unique per project.")

    orphans = want - set(existing)
    if orphans:
        if payload.autocreate_targets:
            for host in sorted(orphans):
                t = Target(project_id=pr.id, host=host)
                session.add(t)
                existing[host] = t
                created["targets"] += 1
        else:
            note(f"{len(orphans)} host(s) referenced but not declared, and "
                 f"autocreate_targets=false: {', '.join(sorted(orphans)[:10])}")

    await session.flush()                 # children need target ids
    tid = {h: t.id for h, t in existing.items()}

    # --------------------------------------------------------- services
    rows = child_clean["services"]
    if rows:
        ids = [tid[h] for h, _ in rows if h in tid]
        cur_map = {(s.target_id, s.port, s.protocol): s for s in (await session.execute(
            select(Service).where(Service.target_id.in_(ids)))).scalars()}
        # Targets this payload proves are up, resolved in one query after
        # the loop rather than one per service row.
        answered: set[int] = set()
        for host, data in rows:
            if host not in tid:
                skipped["services"] += 1
                continue
            key = (tid[host], data["port"], data["protocol"])
            cur = cur_map.get(key)
            if cur is None:
                cur = Service(target_id=tid[host], **data)
                session.add(cur)
                cur_map[key] = cur
                created["services"] += 1
            else:
                if _set_if_given(cur, data, SERVICE_FIELDS):
                    updated["services"] += 1
                else:
                    skipped["services"] += 1
            if implies_alive(data.get("state")):
                answered.add(tid[host])

        # A service that answered is proof the host is up. Only ever
        # upwards: this never marks a host down, because a payload that
        # mentions no open ports is not evidence of anything.
        if answered:
            for t in (await session.execute(
                    select(Target).where(Target.id.in_(answered),
                                         Target.alive.isnot(True)))).scalars():
                t.alive = True

    # ------------------------------------------------------------ vulns
    rows = child_clean["vulns"]
    if rows:
        ids = [tid[h] for h, _ in rows if h in tid]
        have = (await session.execute(select(Vuln).where(Vuln.target_id.in_(ids)))).scalars().all()
        by_ext = {v.external_id: v for v in have if v.external_id}
        by_title = {(v.target_id, v.title): v for v in have}
        for host, data in rows:
            if host not in tid:
                skipped["vulns"] += 1
                continue
            t_id = tid[host]
            # When external_id is supplied it is AUTHORITATIVE. Falling back to
            # (host, title) on an external_id miss merges two genuinely
            # distinct source records that happen to share a title -- and
            # "Coverage record — ..." style titles repeat constantly. That
            # silently destroyed 443 findings on the first real import.
            if data.get("external_id"):
                cur = by_ext.get(data["external_id"])
            else:
                cur = by_title.get((t_id, data["title"]))
            if cur is None:
                cur = Vuln(target_id=t_id, **data)
                session.add(cur)
                if data.get("external_id"):
                    by_ext[data["external_id"]] = cur
                by_title[(t_id, data["title"])] = cur
                created["vulns"] += 1
            else:
                if _set_if_given(cur, data, VULN_FIELDS):
                    updated["vulns"] += 1
                else:
                    skipped["vulns"] += 1

    # ------------------------------------------------------------- pocs
    rows = child_clean["pocs"]
    if rows:
        ids = [tid[h] for h, _ in rows if h in tid]
        cur_map = {(p.target_id, p.title): p for p in (await session.execute(
            select(Poc).where(Poc.target_id.in_(ids)))).scalars()}
        for host, data in rows:
            if host not in tid:
                skipped["pocs"] += 1
                continue
            key = (tid[host], data["title"])
            cur = cur_map.get(key)
            if cur is None:
                cur = Poc(target_id=tid[host], **data)
                session.add(cur)
                cur_map[key] = cur
                created["pocs"] += 1
            else:
                if _set_if_given(cur, data, POC_FIELDS):
                    updated["pocs"] += 1
                else:
                    skipped["pocs"] += 1

    await session.commit()
    if any(created.values()) or any(updated.values()):
        await broker.publish("bulk", project=pr.code, created=created, updated=updated)
    return BulkResult(project=pr.code, created=created, updated=updated,
                      skipped=skipped, errors=errors,
                      elapsed_ms=int((time.perf_counter() - t0) * 1000))


# ===================================================== bulk edit / delete
# Addressed by row id, so there is no project in the path. Every row's own
# project is therefore resolved and role-checked individually: a selection
# can legitimately span projects the caller holds different roles on, and the
# permitted subset must be applied rather than the whole thing allowed or
# refused on the first row.

_MODELS = {"targets": Target, "services": Service, "vulns": Vuln,
           "pocs": Poc, "credentials": Credential}

# Only these may be set in bulk. An allow list, not a deny list: without it a
# caller could bulk-write project_id and move rows between engagements, or
# host and break the join key.
_PATCHABLE = {
    "targets": {"alive", "hacked", "os", "notes", "tags", "ip_address"},
    "services": {"state", "name", "product", "version", "banner"},
    "vulns": {"severity", "status", "description", "remediation"},
    "pocs": {"status", "exit_code", "notes"},
    "credentials": {"kind", "validated", "source", "notes", "service", "port"},
}


async def _project_of(session: AsyncSession, kind: str, row) -> int:
    if kind == "targets":
        return row.project_id
    if kind == "credentials":
        return row.project_id
    t = await session.get(Target, row.target_id)
    return t.project_id if t else -1


async def _authorised(session: AsyncSession, user: User, kind: str, rows: list):
    """Split rows into (allowed, refused-with-reason)."""
    ok, bad = [], []
    cache: dict[int, str | None] = {}
    for r in rows:
        pid = await _project_of(session, kind, r)
        if pid not in cache:
            cache[pid] = await effective_role(session, user, pid)
        role = cache[pid]
        if role is None or ROLE_ORDER[role] < ROLE_ORDER["user"]:
            bad.append((r.id, role or "no access"))
        else:
            ok.append(r)
    return ok, bad


@router.post("/delete", response_model=BulkOpResult)
async def bulk_delete(body: BulkIds, user: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """Delete many rows by id. Deleting a target cascades to its children."""
    Model = _MODELS[body.kind]
    rows = (await session.execute(select(Model).where(Model.id.in_(body.ids)))).scalars().all()
    ok, bad = await _authorised(session, user, body.kind, rows)
    for r in ok:
        await session.delete(r)
    await session.commit()
    missing = len(body.ids) - len(rows)
    errors = [f"id {i}: {why}" for i, why in bad[:20]]
    if missing:
        errors.append(f"{missing} id(s) did not exist")
    if ok:
        await broker.publish(body.kind, action="bulk_delete", count=len(ok))
    return BulkOpResult(kind=body.kind, requested=len(body.ids), changed=len(ok),
                        skipped=len(body.ids) - len(ok), errors=errors)


@router.post("/patch", response_model=BulkOpResult)
async def bulk_patch(body: BulkPatch, user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """Set the same fields on many rows."""
    Model = _MODELS[body.kind]
    allowed = _PATCHABLE[body.kind]
    unknown = set(body.fields) - allowed
    if unknown:
        raise HTTPException(
            422, f"cannot bulk-set {sorted(unknown)} on {body.kind}; "
                 f"allowed: {sorted(allowed)}")

    rows = (await session.execute(select(Model).where(Model.id.in_(body.ids)))).scalars().all()
    ok, bad = await _authorised(session, user, body.kind, rows)
    changed = 0
    for r in ok:
        touched = False
        for k, v in body.fields.items():
            if getattr(r, k) != v:
                setattr(r, k, v)
                touched = True
        changed += 1 if touched else 0
    await session.commit()
    missing = len(body.ids) - len(rows)
    errors = [f"id {i}: {why}" for i, why in bad[:20]]
    if missing:
        errors.append(f"{missing} id(s) did not exist")
    if changed:
        await broker.publish(body.kind, action="bulk_patch", count=changed)
    return BulkOpResult(kind=body.kind, requested=len(body.ids), changed=changed,
                        skipped=len(body.ids) - changed, errors=errors)
