"""Turning Ghost lookups back into inventory, and naming what has not been scanned.

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

**Most results are no longer a choice at all.** They were, when
`Target.ip_address` was one column: four addresses for one slot is four
candidates, and a human had to pick. Addresses are many-to-many now, so
four addresses is just four addresses. `app/lookups.py` holds the rule
for which results are deterministic and which are not, and argues the
boundary at length; this module applies it. `POST /auto` writes every
deterministic outcome and reports what it did, and `GET /pending`
labels each row `auto`, `choice` or `blocked` so the queue can show the
three apart. A `blocked` row is not a question — the scope list refused
the name, or somebody already did — so it is reported and never
offered as something to pick.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import addresses as addr_mod
from .. import audit, lookups
from .. import merge as merge_mod
from ..db import get_session
from ..domains import registrable
from ..events import broker
from ..hosts import InvalidHost, validate_host
from ..lookups import BLOCKED, CHOICE, LOOKUP_KINDS
from ..models import (
    AgentTask,
    DomainCandidate,
    Project,
    ProjectScope,
    Target,
    TargetAddress,
    User,
)
from ..scope import ScopeIndex
from ..scopegate import index_for
from ..security import get_current_user, require_project
from ..timeline import record

router = APIRouter(prefix="/api/enumerate", tags=["enumerate"])

#: How far back through a project's finished lookups to read. A project
#: accumulates these for the life of the engagement and only the newest
#: answer per subject is of any use, so this is a cap on work, not on
#: completeness.
LOOKUP_SCAN_LIMIT = 300


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").split("%", 1)[0])
        return True
    except ValueError:
        return False


class PendingChoice(BaseModel):
    """One finished lookup whose answer the inventory does not carry yet.

    Not all of these are choices any more, which is why `decision` is
    here. The name is kept because the route is `/pending` and the UI
    type is generated from it; what changed is that two thirds of the
    rows now say `auto`, carry a `plan`, and want a human to read them
    rather than answer them.
    """
    task_id: int
    kind: str = Field(description="reverse_ip | nslookup")
    #: What was looked up — an address for reverse_ip, a name for nslookup.
    subject: str
    #: The target this lands on, named as the inventory names it now.
    target_host: str
    #: What applying it would write. `host` renames or merges the
    #: address-named row; `ip_address` adds addresses to it.
    field: str = Field(description="host | ip_address")
    options: list[str] = []
    #: At least one source did not answer, so `options` is a floor and
    #: not a total. Saying "two names" when a source timed out would
    #: present our coverage gap as a fact about the address.
    partial: bool = False
    note: str | None = None
    finished_at: str | None = None
    #: auto | choice | blocked. See `app/lookups.py` for where the line
    #: falls and why.
    decision: str = CHOICE
    #: One sentence saying what will happen, or why nothing will.
    plan: str = ""
    #: The subset of `options` that would actually be written. For a
    #: reverse result that is the names the scope gate allows, which is
    #: usually fewer than came back.
    applicable: list[str] = []
    #: Each entry that will not be written, and why. Always reported:
    #: a name the gate refused is the operator's cue to edit the scope
    #: list, and a count they cannot act on is not a report.
    refused: dict[str, str] = {}


class ResolveIn(BaseModel):
    #: The target as the inventory names it right now.
    host: str
    field: str = Field(description="host | ip_address")
    value: str
    #: Every name the lookup returned, not only the one chosen.
    #:
    #: Picking one name does not make the others untrue. An address
    #: answering to six names is usually shared hosting or a load
    #: balancer, and those other names are leads — frequently the most
    #: useful thing a reverse lookup produces. Throwing them away
    #: because a dropdown only has room for one answer loses them
    #: silently, so they are recorded against the target.
    also_resolved: list[str] = []
    #: Of those others, the ones to create as targets in their own
    #: right. Recording a name on a timeline makes it findable; adding
    #: it makes it testable, and an operator looking at six names
    #: usually wants some of them in the inventory and the rest gone.
    #: Scope decides, exactly as it does everywhere else.
    add: list[str] = []
    #: And the ones to refuse. Remembered rather than merely skipped,
    #: so a later lookup on the same shared address does not ask for
    #: the same judgement a second time.
    deny: list[str] = []


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


async def _outstanding(session: AsyncSession, pr: Project
                       ) -> list[tuple[AgentTask, Target, str, str,
                                       list[str], bool, str | None]]:
    """Every finished lookup the inventory has not acted on yet.

    -> (task, target, subject, field, options, partial, note).

    One derivation shared by `/pending` and `/auto`, because the moment
    they were two the queue showed one thing and the apply did another.

    Only the newest task per subject is offered. An address looked up
    three times produces one row, not three, and it is the most recent
    answer — re-running a lookup is how you correct a stale one, so an
    older result must not be able to win.

    A row disappears once the target it would change no longer needs
    it. That is what makes this safe to derive: acting removes it, and
    nothing has to be marked done.
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
    #
    # `by_ip` now indexes EVERY address a target carries, not one
    # column. That is the many-to-many showing through: a reverse
    # lookup on the second address of a multi-homed host used to find
    # nothing and be silently dropped.
    by_ip: dict[str, Target] = {}
    by_host: dict[str, Target] = {}
    for t in targets:
        by_host[t.host.lower()] = t
        for a in [*t.ip_addresses, t.host.strip()]:
            if a and _is_ip(a) and a not in by_ip:
                by_ip[a] = t

    out = []
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
                if t is None:
                    continue
                # Not "has no address" any more — a host may have four,
                # and a later lookup finding a fifth is still news. The
                # row drops out when every address it names is already
                # held, which is checked against the decision below.
                if not [a for a in options if a not in t.ip_addresses]:
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
            out.append((task, t, subject, field, options, partial, note))
    return out


async def _rejected_names(session: AsyncSession, project_id: int) -> set[str]:
    """Names a human has already refused for this project.

    A rejected `DomainCandidate` row exists precisely so the same name
    coming back from a later lookup does not ask for the judgement a
    second time. Auto-adding one would reverse a decision somebody
    made, silently, which is the one thing automation here must not do.
    """
    return {n for (n,) in (await session.execute(
        select(DomainCandidate.name)
        .where(DomainCandidate.project_id == project_id,
               DomainCandidate.state == "rejected"))).all()}


def _gate(idx: ScopeIndex, rejected: set[str], known: set[str]):
    """-> a `allowed(name)` callable for `app/lookups.py`.

    Returns None to permit and a sentence to refuse. Every name is
    asked about separately and on its own merits: nothing is admitted
    because a name beside it in the same answer was.
    """
    def allowed(name: str, ip=None) -> str | None:
        n = name.strip().lower().rstrip(".")
        if n in rejected:
            return ("already refused for this project; promote the "
                    "candidate if that has changed")
        if not _is_ip(n):
            try:
                validate_host(n)
            except InvalidHost as e:
                return str(e)
        if n in known:
            # Already a target. The gate governs what is NEW, and
            # refusing a host the project already holds would freeze an
            # engagement the day its scope list was typed in — the same
            # reasoning as `bulk.py`. A merge into it is still gated by
            # the merge's own rules.
            return None
        ruling = idx.check(n, ip)
        return None if ruling.allowed else ruling.reason
    return allowed


async def _decisions(session: AsyncSession, pr: Project):
    """Pair every outstanding lookup with what should be done about it."""
    rows = await _outstanding(session, pr)
    if not rows:
        return []
    idx = await index_for(session, pr.id)
    rejected = await _rejected_names(session, pr.id)
    known = {h for (h,) in (await session.execute(
        select(Target.host).where(Target.project_id == pr.id))).all()}
    allowed = _gate(idx, rejected, known)

    out = []
    for task, t, subject, field, options, partial, note in rows:
        if field == "ip_address":
            # The addresses the target does not have yet. One it
            # already carries is not news and must not be reported as
            # something that would be added.
            fresh = [a for a in options if a not in t.ip_addresses]

            def at_name(a, _idx=idx, _n=t.host):
                # The forward direction is the SAFE half of the pair,
                # and the only one where the lookup's subject may vouch.
                # `_n` is a host this project holds and the resolver
                # says it lives at `a`; a scope document written as
                # names would otherwise be unable to record any address
                # at all, which is the failure `ScopeIndex`'s link rule
                # exists to prevent — "the thing being refused is the
                # same machine under a different label".
                #
                # Recording the pair on the index before asking is not a
                # shortcut round the gate. `check` walks the link ONE
                # step and requires the partner to match the document
                # DIRECTLY, so this only works because `_n` itself is on
                # the scope list; a third name sharing the address still
                # has to stand on its own. And the out-of-scope list is
                # consulted before any of it, so a barred address stays
                # barred however in-scope the name is.
                _idx.link(_n, a)
                return allowed(a)

            # Each address asked about separately. Nothing is admitted
            # because a sibling in the same answer was.
            d = lookups.decide_forward(fresh, at_name, partial)
        else:
            # NAME ONLY when the address answers to more than one — see
            # `app/lookups.py`. With a single name the address and the
            # name are the same asset we already hold, and
            # `check(name, ip)` is what that parameter is for.
            names = [n for n in options if n]
            def one(n, _s=subject, _n=names):
                return allowed(n, _s if len(_n) == 1 else None)
            d = lookups.decide_reverse(names, one, partial,
                                       lambda n: n in known)
        out.append((task, t, subject, field, options, partial, note, d))
    return out


#: The decisions, for callers outside this module. The agent tools read
#: it and the auto-apply writes from it, and they share this function
#: rather than each deriving the rule: if the agent's idea of what scope
#: allows could drift from the API's, that difference is the bug, and
#: having one function is the only way to be sure there is none to find.
lookup_decisions = _decisions


@router.get("/pending", response_model=list[PendingChoice])
async def pending(project: str = Query(...),
                  pr: Project = Depends(require_project("readonly")),
                  _: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Finished lookups, each labelled with what should happen to it.

    Writes nothing, including for the rows marked `auto` — a GET that
    changed the inventory would make refreshing the page an action.
    `POST /auto` is what applies them.
    """
    return [
        PendingChoice(
            task_id=task.id, kind=task.kind, subject=subject,
            target_host=t.host, field=field, options=options,
            partial=partial, note=note,
            finished_at=task.finished_at.isoformat() if task.finished_at else None,
            decision=d.verdict, plan=d.plan, applicable=d.apply,
            refused=d.refused)
        for task, t, subject, field, options, partial, note, d
        in await _decisions(session, pr)
    ]


async def _decide_others(session: AsyncSession, pr: Project, user: User,
                         body: ResolveIn, others: list[str]
                         ) -> tuple[list[str], dict[str, str], list[str]]:
    """Act on the names the operator did not choose.

    Picking one name does not make the others untrue, and until now
    they went on the timeline and nowhere else — findable, but not
    testable, and offered again by the next lookup on that address.

    Two explicit decisions, both remembered:

      add   becomes a target in its own right, scope permitting. This
            is the one creation path where nothing has been observed
            at the name itself, only that an address answers to it, so
            `alive` stays None — a reverse lookup is not a probe.
      deny  is written as a rejected candidate. Not merely skipped:
            the row is what carries the decision forward, so the same
            name coming back from a later lookup on the same shared
            address does not ask for the judgement twice.

    Anything in neither list is left exactly as before, on the
    timeline. Silence is not a decision.
    """
    want_add = {n.strip().lower().rstrip(".") for n in body.add if n.strip()}
    want_deny = {n.strip().lower().rstrip(".") for n in body.deny if n.strip()}
    # Only names the lookup actually returned. A client that posts an
    # arbitrary host here would otherwise be creating targets through a
    # door meant for choosing between answers.
    allowed = set(others)
    want_add &= allowed
    want_deny &= allowed - want_add

    added: list[str] = []
    refused: dict[str, str] = {}
    denied: list[str] = []
    if not (want_add or want_deny):
        return added, refused, denied

    idx = await index_for(session, pr.id)
    now = datetime.now(UTC)
    for n in sorted(want_add):
        try:
            validate_host(n)
        except InvalidHost as e:
            refused[n] = str(e)
            continue
        dup = (await session.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.host == n))).scalar_one_or_none()
        if dup is not None:
            continue                      # already here; nothing to do
        ruling = idx.check(n)
        if not ruling.allowed:
            refused[n] = ruling.reason
            continue
        t = Target(project_id=pr.id, host=n, alive=None)
        session.add(t)
        await session.flush()
        # The address it was seen at goes on it. That is the whole
        # content of a reverse lookup about this name, and without it
        # the new target is a bare string with no record of why it is
        # here — and the scope index has no pair to read back out.
        if _is_ip(body.host):
            await addr_mod.attach(session, t, [body.host])
        await record(session, t.id, "discovered",
                     f"added from a reverse lookup on {body.value}",
                     detail=(f"{body.value} answers to this name as well as "
                             f"to the one chosen. Nothing has been probed at "
                             f"it — it is a lead, added deliberately."),
                     actor=user, source="ghost:reverse_ip")
        added.append(n)

    for n in sorted(want_add | want_deny):
        # A row either way. The row is the decision: without one for
        # an accepted name, nothing distinguishes "chosen" from "never
        # looked at" once the target exists.
        row = (await session.execute(
            select(DomainCandidate)
            .where(DomainCandidate.project_id == pr.id,
                   DomainCandidate.name == n))).scalar_one_or_none()
        state = "accepted" if n in want_add else "rejected"
        if row is None:
            session.add(DomainCandidate(
                project_id=pr.id, name=n, root_domain=registrable(n) or n,
                source="reverse_ip", score=0,
                reason=f"seen on {body.value} alongside {body.value}",
                state=state, decided_by=user.id, decided_at=now))
        else:
            row.state, row.decided_by, row.decided_at = state, user.id, now
        if state == "rejected":
            denied.append(n)
    return added, refused, denied


async def _take_name(session: AsyncSession, pr: Project, user: User | None,
                     t: Target, name: str, who: str | None = None) -> str:
    """Give the address-named target `t` the name `name`. -> what happened.

    Two outcomes, and which one it is depends only on whether the
    project already holds that name.

    **Rename** when it does not. The address the row was named for moves
    into `ip_addresses`, where before it had to fit a single column and
    sometimes could not.

    **Merge** when it does — and this reverses a refusal that stood here
    deliberately. Folding two targets together moves services, findings,
    PoCs, web exchanges, implants and a timeline between them, and that
    was a decision somebody should make rather than a side effect of a
    name appearing in a dropdown. The operator has ruled it automatic in
    ONE narrow direction: an address-named row merging into an
    established FQDN. That direction is low-risk because an address-named
    target is nearly always sparse — it exists because a sweep found an
    open port before anything knew what the machine was called — and
    because the FQDN target survives, keeps its name, and loses nothing.
    The reverse, and FQDN-to-FQDN, still refuse: see `resolve`.

    Sparse is not the same as empty, so the surviving target gets a
    timeline entry naming exactly what came across, with findings called
    out on the first line. An address-named row that HAD accumulated
    findings must be visible in the record, not silently absorbed.
    """
    clash = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == name))).scalar_one_or_none()
    was = t.host
    if clash is None:
        await addr_mod.attach(session, t, [was])
        t.host = name
        await record(session, t.id, "change",
                     f"named {name} from a reverse lookup on {was}",
                     actor=user or who, source="ghost:reverse_ip")
        return "renamed"

    done = await merge_mod.merge(
        session, t, clash, actor=who or (user.username if user else "system"))
    summary = merge_mod.describe(done)
    await record(
        session, clash.id, "change", summary.split("\n")[0],
        detail=(f"A reverse lookup on {was} returned {name}, which this "
                f"project already held, so the two were one host all "
                f"along and the address-named row was folded in "
                f"automatically.\n\n{summary}"),
        actor=user or who, source="ghost:reverse_ip")
    # Also in the installation audit trail. A merge deletes a row, and
    # the timeline that would have explained it goes with it; this is
    # the only place that still names what was absorbed.
    await audit.record(session, "ui" if user else "ghost", "target.merge",
                       user=user, username=None if user else who,
                       project_code=pr.code,
                       detail=summary.replace("\n", "; ")[:4000])
    return "merged"


async def _note_others(session: AsyncSession, target_id: int, subject: str,
                       chosen: str, others: list[str],
                       refused: dict[str, str] | None = None) -> None:
    """The names that were not the one this row took. Timeline only.

    Its own entry rather than folded into the rename line, because this
    is a finding about the ADDRESS — what else lives there — and not a
    note about the rename.

    **The refused ones are in here too, and this is the only place they
    survive.** Once the row has been renamed it stops being an
    outstanding lookup, so `GET /pending` can no longer report it; a
    name the scope gate turned down would then exist nowhere at all. It
    was found, and the record has to say so even though nothing was
    done with it — that is the difference between "we did not look" and
    "we looked and were not allowed to follow it up".
    """
    refused = refused or {}
    if not others and not refused:
        return
    shown = others[:40]
    more = f" (+{len(others) - len(shown)} more)" if len(others) > len(shown) else ""
    body = ""
    if others:
        body += "\n".join(shown) + more
    if refused:
        body += ("\n\nNot added, and why:\n"
                 + "\n".join(f"{k} — {v}" for k, v in sorted(refused.items())))
    await record(
        session, target_id, "discovered",
        f"{subject} also resolves to {len(others) + len(refused)} other name(s)",
        detail=("A reverse lookup on " + subject + " returned these as "
                "well as " + chosen + ". They are not necessarily the "
                "same host — an address answering to several names "
                "is usually shared hosting or a load balancer — but "
                "each is a lead and none is in scope merely because "
                "it appeared here:\n\n" + body),
        source="ghost:reverse_ip")


@router.post("/resolve")
async def resolve(body: ResolveIn, project: str = Query(...),
                  pr: Project = Depends(require_project("user")),
                  user: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    """Write a chosen lookup answer onto the target.

    The one case that merges is an ADDRESS-named target taking a name
    the project already holds — see `_take_name`. Everything else that
    would fold two targets together still refuses and says which one it
    would have collided with: moving findings between two established
    FQDNs is a decision somebody makes at `/api/enumerate/merge`, with a
    plan in front of them, and not a side effect of picking a name off a
    list.
    """
    t = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host == body.host))).scalar_one_or_none()
    if t is None:
        raise HTTPException(404, f"{pr.code} has no target {body.host!r}")

    value = (body.value or "").strip()
    if not value:
        raise HTTPException(422, "nothing to apply")

    # Same shape whichever branch runs below: a caller should not have
    # to know which field it asked about to read the reply.
    added: list[str] = []
    refused: dict[str, str] = {}
    denied: list[str] = []
    surviving = t

    if body.field == "host":
        try:
            name = validate_host(value)
        except InvalidHost as e:
            raise HTTPException(422, str(e)) from e
        if _is_ip(name):
            raise HTTPException(
                422, f"{name} is an address, not a name — a reverse lookup "
                     f"that returns the address back is not a result")
        was = t.host
        if not _is_ip(was):
            # The narrow direction, enforced. `_take_name` would merge
            # happily; what makes the automatic merge acceptable is that
            # the row being absorbed is an address, and this is where
            # that is checked rather than assumed.
            clash = (await session.execute(
                select(Target).where(Target.project_id == pr.id,
                                     Target.host == name))).scalar_one_or_none()
            if clash is not None:
                raise HTTPException(
                    409, f"{pr.code} already has a target named {name}. "
                         f"Renaming {was} to it would merge two named "
                         f"targets, which moves their services and findings "
                         f"— do that at /api/enumerate/merge, with the plan "
                         f"in front of you.")

        others = [n for n in
                  dict.fromkeys(x.strip().lower().rstrip(".")
                                for x in body.also_resolved)
                  if n and n != name]
        # Explicit decisions first, so the timeline note can say what was
        # done with them rather than only that they existed.
        added, refused, denied = await _decide_others(
            session, pr, user, body, others)

        outcome = await _take_name(session, pr, user, t, name)
        if outcome == "merged":
            surviving = (await session.execute(
                select(Target).where(Target.project_id == pr.id,
                                     Target.host == name))).scalar_one()
        await _note_others(session, surviving.id, was, name, others)
    elif body.field == "ip_address":
        # Plural now. One address was all a column could hold; a host
        # with an A record, a AAAA record and two more behind a load
        # balancer has four, and dropping three of them was never a fact
        # about the host.
        values = [value, *(x for x in body.also_resolved if x)]
        got, bad = await addr_mod.attach(session, t, values)
        if bad and not got:
            raise HTTPException(422, f"{bad[0]!r} is not an IP address")
        for b in bad:
            refused[b] = "not an IP address"
        if got:
            added = got
            await record(session, t.id, "change",
                         "addresses added: " + ", ".join(got)
                         + " (forward lookup)",
                         actor=user, source="ghost:nslookup")
    else:
        raise HTTPException(422, "field is host or ip_address")

    t = surviving

    await session.commit()
    await broker.publish("targets", action="update", host=t.host, project=pr.code)
    if added:
        await broker.publish("targets", action="create", project=pr.code)
    # Named, not counted: "3 added" with no list is not something an
    # operator can check, and `refused` is the half they most need.
    return {"host": t.host, "ip_address": t.ip_address,
            "ip_addresses": t.ip_addresses,
            "added": added, "denied": denied, "out_of_scope": refused}


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
    # Every address in the project, not one per target. A target counts
    # in every range it has an address in, because it genuinely is in
    # every one of them, and a /24 whose only resident is the second
    # address of a multi-homed host used to report as never looked at.
    # Distinct rows already, by the unique constraint on the table.
    for (ip,) in (await session.execute(
            select(TargetAddress.address)
            .where(TargetAddress.project_id == pr.id))).all():
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


# ------------------------------------------------- automatic resolution
class AutoReport(BaseModel):
    """What applying the deterministic results did. Named, never counted.

    Every list here holds the things themselves. A reply saying "4
    applied, 2 refused" is not something an operator can check, and the
    refusals are the half they most need — a name the scope gate turned
    down is the cue to edit the scope list, and it is invisible if all
    they get is a number.
    """
    #: "host -> 198.51.100.4, 198.51.100.5" and the like.
    addresses_added: dict[str, list[str]] = {}
    #: Address-named rows that learned their name. "198.51.100.10 -> web01…"
    renamed: dict[str, str] = {}
    #: Address-named rows folded into a target the project already held.
    merged: dict[str, str] = {}
    #: New targets created from the other names on a shared address.
    created: list[str] = []
    #: Each thing not written, and why.
    refused: dict[str, str] = {}
    #: Results that are still a human's decision, with the question.
    deferred: dict[str, str] = {}


@router.post("/auto", response_model=AutoReport)
async def auto(project: str = Query(...),
               pr: Project = Depends(require_project("user")),
               user: User = Depends(get_current_user),
               session: AsyncSession = Depends(get_session)):
    """Apply every lookup result whose answer is not in doubt."""
    report = await apply_auto(session, pr, user=user)
    if report.renamed or report.merged or report.created or report.addresses_added:
        await session.commit()
        await broker.publish("targets", action="update", project=pr.code)
        for ch in ("services", "vulns", "web"):
            await broker.publish(ch, action="merge", project=pr.code)
    return report


async def apply_auto(session: AsyncSession, pr: Project, *,
                     user: User | None = None,
                     actor: str | None = None) -> AutoReport:
    """Apply every lookup result whose answer is not in doubt.

    Called from the route above AND from the agent result handler, so
    that a lookup finishing resolves itself whether or not anybody has
    a browser open. "Automatic" that needs somebody to go and look at a
    page is not automatic; it is a button with a long name.

    The CALLER commits. The agent handler is mid-transaction with its
    own writes when it gets here and committing underneath it would
    split one result into two.

    Idempotent and safe to call on every refresh: the work list is
    derived from what the inventory is still missing, so a second call
    with nothing new to do writes nothing and reports nothing.

    What counts as "not in doubt" is argued in `app/lookups.py` and is
    the substance of this change. The short version: adding an address
    to a host we already hold is never a question, naming an
    address-named row from a single reverse answer never is either, and
    everything that turns on an address being SHARED stays with a human.

    One pass, one transaction. A reverse result that renames a target
    changes what the next result can see — the name it just created is
    now "already a target", which is what turns the following merge
    from a guess into a fact — so the decisions are re-derived rather
    than computed once and replayed.
    """
    # The agent path has no person behind it. `actor` is then the
    # ghost's own name, which is the honest answer to "who did this"
    # and the one worth having when a rename looks wrong.
    who = actor or (user.username if user else "system")
    report = AutoReport()
    # Bounded rather than `while True`. Each pass must make the next one
    # strictly smaller, and if a bug ever made that untrue this would
    # spin inside a request holding a transaction open. Five is far more
    # than any real queue needs: one pass settles the forward results,
    # and a chain of reverse results long enough to need five is not
    # something that happens to an engagement.
    for _ in range(5):
        progress = False
        for task, t, subject, field, options, partial, _note, d in \
                await _decisions(session, pr):
            key = f"{task.kind}:{subject}"
            for k, why in d.refused.items():
                report.refused.setdefault(k, why)
            if d.verdict == CHOICE:
                report.deferred.setdefault(key, d.plan)
                continue
            if d.verdict == BLOCKED or not d.apply:
                continue

            if field == "ip_address":
                got, _bad = await addr_mod.attach(session, t, d.apply)
                if not got:
                    continue
                report.addresses_added.setdefault(t.host, []).extend(got)
                floor = (" The resolver did not answer in full, so this is "
                         "a floor and not necessarily every address."
                         if partial else "")
                await record(
                    session, t.id, "change",
                    "addresses added: " + ", ".join(got),
                    detail=(f"A forward lookup on {subject} returned "
                            f"{', '.join(options)}. A host having several "
                            f"addresses is not a question, so these were "
                            f"recorded without asking.{floor}"),
                    actor=user or who, source="ghost:nslookup")
                progress = True
                continue

            # Reverse. The takeover first: it may delete `t`, and the
            # leads below have to be created against whatever survives.
            was = t.host
            name = d.takeover
            outcome = await _take_name(session, pr, user, t, name, who)
            (report.merged if outcome == "merged" else report.renamed)[was] = name
            surviving = (await session.execute(
                select(Target).where(Target.project_id == pr.id,
                                     Target.host == name))).scalar_one()
            leads = [n for n in d.apply if n != name]
            report.created.extend(
                await _add_leads(session, pr, user, leads, was, who))
            await _note_others(session, surviving.id, was, name, leads,
                               d.refused)
            progress = True

        await session.flush()
        if not progress:
            break
    return report


async def _add_leads(session: AsyncSession, pr: Project, user: User | None,
                     names: list[str], subject: str,
                     who: str | None = None) -> list[str]:
    """Create targets for names a shared address answers to. -> created.

    Already gated by the caller — these are the names that matched this
    project's scope document on their own merits, which under the
    several-names branch of `app/lookups.py` is the only way in. The
    address they were seen at vouches for none of them.

    `alive` stays None. A reverse lookup is not a probe, and recording
    "responding" because a resolver answered would be a claim about the
    host that nothing has tested.
    """
    now = datetime.now(UTC)
    made: list[str] = []
    for n in names:
        dup = (await session.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.host == n))).scalar_one_or_none()
        if dup is not None:
            continue
        t = Target(project_id=pr.id, host=n, alive=None)
        session.add(t)
        await session.flush()
        await addr_mod.attach(session, t, [subject])
        await record(session, t.id, "discovered",
                     f"added from a reverse lookup on {subject}",
                     detail=(f"{subject} answers to this name as well as to "
                             f"the one that took over the address-named row. "
                             f"Nothing has been probed at it — it is a lead, "
                             f"and it is here because it matches this "
                             f"project's scope list in its own right."),
                     actor=user or who, source="ghost:reverse_ip")
        row = (await session.execute(
            select(DomainCandidate)
            .where(DomainCandidate.project_id == pr.id,
                   DomainCandidate.name == n))).scalar_one_or_none()
        if row is None:
            session.add(DomainCandidate(
                project_id=pr.id, name=n, root_domain=registrable(n) or n,
                source="reverse_ip", score=0,
                reason=f"seen on {subject}", state="accepted",
                decided_by=user.id if user else None, decided_at=now))
        else:
            row.state, row.decided_by, row.decided_at = \
                "accepted", user.id if user else None, now
        made.append(n)
    return made


# ------------------------------------------------------------- merging
class MergeIn(BaseModel):
    #: The target that will survive, named as the inventory names it.
    into: str
    #: Refuse unless the caller has seen a plan. Merging moves findings
    #: and deletes a row; approving a verb is not the same as approving
    #: a list of consequences.
    confirm: bool = False


@router.get("/merge-plan")
async def merge_plan(host: str = Query(...), into: str = Query(...),
                     project: str = Query(...),
                     pr: Project = Depends(require_project("readonly")),
                     _: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """What merging one target into another would do. Writes nothing."""
    src, dst = await _two(session, pr, host, into)
    return asdict(await merge_mod.plan(session, src, dst))


@router.post("/merge")
async def merge_targets(body: MergeIn, host: str = Query(...),
                        project: str = Query(...),
                        pr: Project = Depends(require_project("user")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Fold one target into another.

    The destination survives and keeps its name. Everything the source
    holds moves to it, and the source row goes.

    Both sides get a timeline entry — the destination because it has
    absorbed another host's findings and that is material to anyone
    reading it later, and the entry names what moved rather than
    saying "merged", because "where did these services come from" is
    the question someone will have in three weeks.
    """
    src, dst = await _two(session, pr, host, body.into)
    p = await merge_mod.plan(session, src, dst)
    blocking = [w for w in p.warnings
                if w.startswith(("a target cannot", "these targets are"))]
    if blocking:
        raise HTTPException(409, "; ".join(blocking))
    if not body.confirm:
        raise HTTPException(
            428, "merging moves findings and deletes a target. Fetch "
                 "/api/enumerate/merge-plan, show it, and repeat with "
                 "confirm=true.")

    done = await merge_mod.merge(session, src, dst, actor=user.username)
    summary = merge_mod.describe(done)
    await record(session, dst.id, "change", summary.split("\n")[0],
                 detail=summary, actor=user, source="merge")
    # Also in the audit trail, not only on the surviving target's
    # timeline: a merge deletes a row, and the timeline that would have
    # explained it went with it. The installation-level log is the only
    # place that still names what was absorbed.
    await audit.record(session, "ui", "target.merge", user=user,
                       project_code=pr.code,
                       detail=summary.replace("\n", "; ")[:4000])
    await session.commit()
    await broker.publish("targets", action="merge", host=dst.host,
                         project=pr.code)
    for ch in ("services", "vulns", "web"):
        await broker.publish(ch, action="merge", project=pr.code)
    return {"ok": True, "surviving": dst.host, "removed": p.source,
            "summary": summary, **asdict(done)}


async def _two(session: AsyncSession, pr: Project, host: str,
               into: str) -> tuple[Target, Target]:
    async def one(name: str) -> Target:
        t = (await session.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.host == name.strip().lower()))
             ).scalar_one_or_none()
        if t is None:
            raise HTTPException(404, f"{pr.code} has no target {name!r}")
        return t
    return await one(host), await one(into)
