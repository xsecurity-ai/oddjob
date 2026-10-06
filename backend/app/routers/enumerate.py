"""Turning Jaws lookups back into inventory, and naming what has not been scanned.

Two questions the Targets page asks that nothing could answer.

**What did the lookup actually find?** A `reverse_ip` or `nslookup`
result comes home as the raw JSON the agent produced and lands on
`agent_tasks.output`. That column is deliberately not on `TaskOut` —
the agent list would then carry every scan's output — so the answer
existed and the UI could not see it. These routes read the output of
the *completed* task and hand back only the choice it implies.

**Which scope ranges has nothing been scanned in?** Derived by asking
which included ranges contain no target we hold an address for. That
is a claim about our coverage, not about the client: a range with no
targets in it has not been looked at, which is not the same as a range
that is empty.

Nothing here is stored. A pending choice is recomputed from completed
tasks and the current inventory every time it is asked for, so acting
on one makes it disappear and there is no second table to keep in
step. The cost is that a lookup which found nothing keeps being
reported — correctly, because "we looked and nothing came back" stays
true until something changes it.
"""
from __future__ import annotations

import ipaddress
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..models import AgentTask, Project, ProjectScope, Target, User
from ..security import get_current_user, require_project
from ..timeline import record

router = APIRouter(prefix="/api/enumerate", tags=["enumerate"])

#: How far back through a project's finished lookups to read. A project
#: accumulates these for the life of the engagement and only the newest
#: answer per subject is of any use, so this is a cap on work, not on
#: completeness.
LOOKUP_SCAN_LIMIT = 300

#: Kinds whose output this module knows how to read.
LOOKUP_KINDS = ("reverse_ip", "nslookup")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").split("%", 1)[0])
        return True
    except ValueError:
        return False


class PendingChoice(BaseModel):
    """One finished lookup whose answer has not been applied yet."""
    task_id: int
    kind: str = Field(description="reverse_ip | nslookup")
    #: What was looked up — an address for reverse_ip, a name for nslookup.
    subject: str
    #: The target this lands on, named as the inventory names it now.
    target_host: str
    #: Which column applying it would write.
    field: str = Field(description="host | ip_address")
    options: list[str] = []
    #: At least one source did not answer, so `options` is a floor and
    #: not a total. Saying "two names" when a source timed out would
    #: present our coverage gap as a fact about the address.
    partial: bool = False
    note: str | None = None
    finished_at: str | None = None


class ResolveIn(BaseModel):
    #: The target as the inventory names it right now.
    host: str
    field: str = Field(description="host | ip_address")
    value: str


class RangeCoverage(BaseModel):
    value: str
    kind: str
    #: How many addresses the range holds. A /16 and a /29 are both one
    #: row in the scope table and are not the same amount of scanning.
    addresses: int
    #: Targets we hold an address for inside this range. Zero means
    #: nothing here has been looked at — not that the range is empty.
    targets: int


def _parse(blob: str | None) -> list[dict]:
    try:
        data = json.loads(blob or "")
    except (TypeError, ValueError):
        return []
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _reverse_choice(rec: dict) -> tuple[str, list[str], bool, str | None]:
    ip = str(rec.get("ip") or "").strip()
    seen: list[str] = []
    for d in rec.get("domains") or []:
        d = str(d).strip().lower().rstrip(".")
        if d and d not in seen:
            seen.append(d)
    return ip, seen, bool(rec.get("partial")), rec.get("note") or None


def _forward_choice(rec: dict) -> tuple[str, list[str], bool, str | None]:
    name = str(rec.get("query") or "").strip().lower().rstrip(".")
    addrs: list[str] = []
    for key in ("a", "aaaa"):
        for v in rec.get(key) or []:
            v = str(v).strip()
            if v and v not in addrs:
                addrs.append(v)
    # An error is not an empty result. The agent already keeps them
    # apart; carrying that through is the whole point of the field.
    err = rec.get("error") or None
    return name, addrs, bool(err), err


@router.get("/pending", response_model=list[PendingChoice])
async def pending(project: str = Query(...),
                  pr: Project = Depends(require_project("readonly")),
                  _: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Finished lookups whose answer the inventory does not yet carry.

    Only the newest task per subject is offered. An address looked up
    three times produces one choice, not three, and it is the most
    recent answer — re-running a lookup is how you correct a stale one,
    so an older result must not be able to win.

    A choice is dropped once the target it would change no longer needs
    it. That is what makes this safe to derive: answering removes it,
    and nothing has to be marked done.
    """
    rows = (await session.execute(
        select(AgentTask)
        .where(AgentTask.project_id == pr.id,
               AgentTask.kind.in_(LOOKUP_KINDS),
               AgentTask.status == "done")
        .order_by(AgentTask.id.desc()).limit(LOOKUP_SCAN_LIMIT))).scalars().all()

    targets = (await session.execute(
        select(Target).where(Target.project_id == pr.id))).scalars().all()
    # Two indexes because the two lookups are addressed differently: a
    # reverse result names an address, a forward one names a host.
    by_ip: dict[str, Target] = {}
    by_host: dict[str, Target] = {}
    for t in targets:
        by_host[t.host.lower()] = t
        for addr in ((t.ip_address or "").strip(), t.host.strip()):
            if addr and _is_ip(addr) and addr not in by_ip:
                by_ip[addr] = t

    out: list[PendingChoice] = []
    seen_subjects: set[tuple[str, str]] = set()
    for task in rows:
        for rec in _parse(task.output):
            if task.kind == "reverse_ip":
                subject, options, partial, note = _reverse_choice(rec)
                field = "host"
                t = by_ip.get(subject)
                # Only offered while the target is still named by its
                # address. A target that already carries a name does not
                # need one, and overwriting it from a reverse lookup on
                # shared hosting would replace a known name with a
                # neighbour's.
                if t is None or not _is_ip(t.host):
                    continue
            else:
                subject, options, partial, note = _forward_choice(rec)
                field = "ip_address"
                t = by_host.get(subject)
                if t is None or (t.ip_address or "").strip():
                    continue
                # A mobile app has no address, so a forward lookup on
                # one is not a gap to fill.
                if t.kind == "mobile":
                    continue

            if not subject:
                continue
            key = (task.kind, subject)
            if key in seen_subjects:
                continue
            seen_subjects.add(key)
            out.append(PendingChoice(
                task_id=task.id, kind=task.kind, subject=subject,
                target_host=t.host, field=field, options=options,
                partial=partial, note=note,
                finished_at=task.finished_at.isoformat() if task.finished_at else None))
    return out


@router.post("/resolve")
async def resolve(body: ResolveIn, project: str = Query(...),
                  pr: Project = Depends(require_project("user")),
                  user: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Write a chosen lookup answer onto the target.

    Renaming is a rename, not a merge. If the project already holds a
    target under the chosen name this refuses and says which one:
    folding two targets together moves services, findings and PoCs
    between them, and that is a decision somebody makes deliberately,
    not a side effect of picking a name off a list.
    """
    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == body.host))).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, f"{pr.code} has no target {body.host!r}")

    value = (body.value or "").strip()
    if not value:
        raise HTTPException(422, "nothing to apply")

    if body.field == "host":
        try:
            name = validate_host(value)
        except InvalidHost as e:
            raise HTTPException(422, str(e))
        if _is_ip(name):
            raise HTTPException(
                422, f"{name} is an address, not a name — a reverse lookup "
                     f"that returns the address back is not a result")
        clash = (await session.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.host == name))).scalar_one_or_none()
        if clash is not None:
            raise HTTPException(
                409, f"{pr.code} already has a target named {name}. Renaming "
                     f"{t.host} to it would merge two targets, which moves "
                     f"their services and findings — do that deliberately.")
        was = t.host
        # The old name was the address, and the address is worth keeping.
        if not (t.ip_address or "").strip() and _is_ip(was):
            t.ip_address = was
        t.host = name
        await record(session, t.id, "change",
                     f"named {name} from a reverse lookup on {was}",
                     actor=user, source="jaws:reverse_ip")
    elif body.field == "ip_address":
        if not _is_ip(value):
            raise HTTPException(422, f"{value!r} is not an IP address")
        was = t.ip_address or "none"
        t.ip_address = value
        await record(session, t.id, "change",
                     f"ip_address: {was} → {value} (forward lookup)",
                     actor=user, source="jaws:nslookup")
    else:
        raise HTTPException(422, "field is host or ip_address")

    await session.commit()
    await broker.publish("targets", action="update", host=t.host, project=pr.code)
    return {"host": t.host, "ip_address": t.ip_address}


@router.get("/ranges", response_model=list[RangeCoverage])
async def ranges(project: str = Query(...),
                 pr: Project = Depends(require_project("readonly")),
                 _: User = Depends(get_current_user),
                 session: AsyncSession = Depends(get_session)):
    """The project's included ranges, with how many targets sit in each.

    Excluded entries are left out entirely rather than returned with a
    flag: a scope document says "this /16 except these eight hosts",
    and offering the exclusions as scannable is how the eight get
    scanned.
    """
    rows = (await session.execute(
        select(ProjectScope).where(ProjectScope.project_id == pr.id,
                                   ProjectScope.included.is_(True),
                                   ProjectScope.kind == "cidr"))).scalars().all()
    addrs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for (ip,) in (await session.execute(
            select(Target.ip_address).where(Target.project_id == pr.id,
                                            Target.ip_address.is_not(None)))).all():
        try:
            addrs.append(ipaddress.ip_address((ip or "").split("%", 1)[0]))
        except ValueError:
            continue

    out: list[RangeCoverage] = []
    for row in rows:
        try:
            net = ipaddress.ip_network(row.value, strict=False)
        except ValueError:
            # A malformed entry is reported as uncountable rather than
            # dropped; a range nobody can parse is still a range in the
            # scope document and the operator should see it.
            out.append(RangeCoverage(value=row.value, kind=row.kind,
                                     addresses=0, targets=0))
            continue
        inside = sum(1 for a in addrs if a.version == net.version and a in net)
        out.append(RangeCoverage(value=str(net), kind=row.kind,
                                 addresses=net.num_addresses, targets=inside))
    out.sort(key=lambda r: (r.targets, -r.addresses))
    return out
