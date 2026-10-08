"""Recording what happened to a target.

One helper, used everywhere something changes, so the timeline cannot drift
from the data: if a code path writes to a target and does not call `record`,
that is the bug, and it is visible as a gap in the narrative rather than as
a silently wrong report.

`record` never raises. A timeline entry is a side effect of the real work,
and losing the engagement narrative is bad, but failing somebody's import
because the narrative could not be written is worse.
"""
from __future__ import annotations

import json
import re
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Event, Target, User


def _clip(s: str, n: int = 400) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


async def record(session: AsyncSession, target_id: int, kind: str, summary: str,
                 *, detail: str | None = None, actor: str | User | None = None,
                 source: str | None = None) -> Event | None:
    """Append one entry. Caller commits."""
    user_id = None
    if isinstance(actor, User):
        user_id, actor = actor.id, actor.username
    try:
        ev = Event(target_id=target_id, kind=kind, summary=_clip(summary),
                   detail=detail, actor=actor, source=source, user_id=user_id)
        session.add(ev)
        return ev
    except Exception:
        return None


def describe_changes(before: dict, after: dict, fields: tuple[str, ...]) -> str | None:
    """"os: none → Ubuntu 24.04; alive: none → yes" for the fields that moved.

    Only changed fields appear. An edit that saved the form without altering
    anything should not produce a timeline entry at all, which is why this
    returns None rather than an empty string.
    """
    parts = []
    for f in fields:
        old, new = before.get(f), after.get(f)
        if old == new:
            continue
        parts.append(f"{f}: {_show(old)} → {_show(new)}")
    return "; ".join(parts) if parts else None


def _show(v) -> str:
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (dict, list)):
        return json.dumps(v)[:60]
    s = str(v).strip()
    return f'"{_clip(s, 60)}"' if s else "empty"


# ------------------------------------------------- what is worth a notice
# Everything below exists to answer one question for the Slack digest in
# `slack.py`: in a given five minutes, how many targets were ADDED to a
# project and how many were MODIFIED in a way a person would want to know
# about. The answer is derived HERE rather than there because this module
# already owns the definition of "something happened to a target" — if the
# two ever disagree, the timeline is right and the digest is wrong.
#
# Derived, not counted. Nothing increments a tally as it writes; the digest
# asks the database what the window contains. That is deliberate:
#
#   * a counter in memory is lost by a restart, and the live deployment now
#     updates itself, so restarts are routine rather than rare;
#   * a counter incremented before `session.commit()` counts work that was
#     then rolled back, and `record()` explicitly leaves the commit to its
#     caller — there is no moment in this module where the write is known
#     to have landed;
#   * a row that was committed and then deleted simply is not there to be
#     counted, which is the behaviour we want and which no counter gives.

#: Timeline kinds that can describe a change to the TARGET itself.
#:
#: IN:
#:   change   a field moved. Filtered again by field name below — most
#:            field moves are sweep noise and only some are news.
#:   status   the `hacked` flag was set or cleared. The single most
#:            important thing that can change about a target, and the one
#:            everybody wants to hear about the moment it happens.
#:   note     somebody wrote on the target by hand. Low volume, always
#:            deliberate, and the entry people most often go looking for.
#:
#: OUT, and each for its own reason:
#:   discovered  the target appearing is the ADDED number, counted from the
#:               row's own `created_at`. Counting it here too would put a
#:               new target in both halves of the message.
#:   scan        OS fingerprints and NSE output. One sweep writes one of
#:               these per host; this is exactly the flood the digest
#:               exists to suppress.
#:   service     ports opening and closing. Same argument, higher volume.
#:   vuln        findings already have their own Slack path, with severity
#:               and a thread — see `announce_finding`. A second, weaker
#:               notice for the same event helps nobody.
#:   web         web addresses observed; a crawl produces hundreds.
#:   credential
#:   implant     both are about things found ON the host, not about the
#:               host record changing. They belong to the finding story.
NOTIFIABLE_KINDS = frozenset({"change", "status", "note"})

#: Which FIELDS, inside a `change` entry, are worth a notice.
#:
#: An allowlist and not a denylist, because the default for a feature whose
#: whole purpose is noise control has to be silence. A column added to
#: Target next month then stays out of the digest until somebody decides it
#: belongs, rather than joining it by accident and being noticed only as a
#: number that crept up.
#:
#: IN:
#:   host        a rename. The name is the identity of the asset, and a
#:               target changing its name silently is how two people end up
#:               arguing about different hosts.
#:   ip_address  scope is frequently written as ranges, so an asset moving
#:               address can move it in or out of what is authorised. That
#:               makes it a scope question and not a detail.
#:   hacked      compromise. Also reaches us as kind `status` from the UI
#:               path; covered here too because the importers write it as a
#:               field diff instead.
#:   kind        host / mobile / cloud. Changes what testing even means for
#:               the asset.
#:   provider    which cloud. Same argument, and it is how a cloud asset is
#:               attributed to an owner.
#:   tags        how people slice the estate. Someone retagging an asset out
#:               of a workstream is a decision, not an observation.
#:
#: OUT:
#:   alive       flips on every sweep, in both directions, for reasons that
#:               are usually about the network and not the host. This is the
#:               single noisiest field in the table and the operator named
#:               it specifically.
#:   os
#:   os_accuracy a second scanner with a better fingerprint rewrites these
#:               constantly. Interesting on the target page, not in a channel.
#:   mac_address
#:   mac_vendor  only ever seen from the local segment, and never news.
#:   hostnames
#:   extra       bulk scanner output. `extra` in particular is a JSON blob
#:               that differs between two runs of the same tool.
#:   notes       the prose itself arrives as kind `note`, which IS counted.
#:               Counting the field diff as well would count one edit twice.
NOTEWORTHY_FIELDS = frozenset({
    "host", "ip_address", "hacked", "kind", "provider", "tags"})

#: `describe_changes` writes "field: old → new", joined with "; ". So does
#: the hand-rolled equivalent in `routers/scans.py`. A clause that does NOT
#: start with a bare identifier and a colon is therefore not a field diff at
#: all — it is prose written by a deliberate operation, and the two that
#: produce it are a rename ("named corp.com from a reverse lookup on …")
#: and a merge ("merged acme.example into corp.com: 2 findings moved").
#: Both are exactly the kind of thing the digest should count, so an
#: unrecognised clause is treated as noteworthy rather than ignored. The
#: failure mode of that choice is an occasional extra count; the failure
#: mode of the opposite is silence about a merge, which is worse.
_FIELD_CLAUSE = re.compile(r"^([a-z_][a-z0-9_]*):")


def is_notable(kind: str, summary: str) -> bool:
    """Would a person want this entry counted as "a target was modified"?"""
    if kind not in NOTIFIABLE_KINDS:
        return False
    if kind != "change":
        return True
    # Any one noteworthy clause carries the whole entry: an edit that moved
    # `ip_address` and `alive` together is news about the address, and the
    # `alive` half does not cancel it out.
    for clause in str(summary or "").split("; "):
        m = _FIELD_CLAUSE.match(clause.strip())
        if m is None:
            return True
        if m.group(1) in NOTEWORTHY_FIELDS:
            return True
    return False


#: A ceiling on the rows one window may inspect. The kind filter already
#: throws away the scan/service/vuln bulk, so reaching this takes something
#: extraordinary — a multi-gigabyte import landing inside five minutes. If
#: it is ever reached the count is an undercount, which is why it is logged
#: by the caller rather than passed over: a number quietly capped is a
#: number that lies.
ACTIVITY_ROW_CAP = 50_000


async def target_activity(session: AsyncSession, project_id: int,
                          start: datetime, end: datetime) -> tuple[int, int, bool]:
    """-> (added, modified, capped) for one project over [start, end).

    ADDED is the target row's own `created_at`, not a `discovered` timeline
    entry. Those are not the same question: `routers/enumerate.py` writes a
    `discovered` entry against an EXISTING target when a reverse lookup
    turns up other names at the same address, and an importer re-seeing a
    host can write one too. The row's creation stamp is the only
    unambiguous answer to "is this target new", and it needs no filtering.

    MODIFIED excludes anything created inside the same window — done in SQL
    with `created_at < start` rather than by subtracting a set afterwards,
    so a 50,000-target import never materialises 50,000 ids in memory just
    to throw them away. A target added and then edited in the same five
    minutes counts once, as added, which is what somebody reading the line
    would assume.

    Never raises on its own account; the caller is a background loop and a
    failed count must not take it down.
    """
    added = int((await session.execute(
        select(func.count()).select_from(Target)
        .where(Target.project_id == project_id,
               Target.created_at >= start, Target.created_at < end))).scalar_one())

    rows = (await session.execute(
        select(Event.target_id, Event.kind, Event.summary)
        .join(Target, Target.id == Event.target_id)
        .where(Target.project_id == project_id,
               Event.at >= start, Event.at < end,
               Event.kind.in_(NOTIFIABLE_KINDS),
               Target.created_at < start)
        .limit(ACTIVITY_ROW_CAP))).all()

    modified = {tid for tid, kind, summary in rows if is_notable(kind, summary)}
    return added, len(modified), len(rows) >= ACTIVITY_ROW_CAP
