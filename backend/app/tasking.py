"""Has this already been asked of this project?

One implementation, because two would disagree and the disagreement
would be invisible: one half quietly re-scanning what the other
considered finished, at a client, for a question already answered.

Lives on its own rather than in `automation.py` so that the modules
deciding WHAT to queue can use it without `automation` having to
import them back. That cycle is what kept `auto_web` reading a
narrower list of URLs than the dialog did.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AgentTask

log = logging.getLogger("oddjob.tasking")

#: Statuses that mean no agent ever took the task, so nothing was sent.
#:
#: `cancelled` only. A task is cancelled while queued and never after:
#: the UI's delete refuses anything past `queued` and says why, and
#: killing an agent marks its work `failed`, not this. So this is the
#: one status that proves the client saw no traffic.
#:
#: `failed` is deliberately NOT here. It covers a scan that ran and
#: errored as well as one refused at dispatch, and re-running the
#: first against a client because the second shares its status is the
#: worse mistake of the two.
NEVER_SENT = ("cancelled",)


async def tasked_subjects(
        session: AsyncSession, project_id: int,
        kinds: tuple[str, ...]) -> set[tuple[str, str]]:
    """Every (kind, subject) this project has ever really tasked.

    "Ever", including FAILED: the question both callers ask is whether
    the work was ATTEMPTED, not whether it succeeded. A scan that ran
    and found nothing has still been run, and the packets still went
    to the client.

    Cancelled is the other answer, and it used to be counted here as
    though it were the same thing. It is not: a task is only ever
    cancelled while it is still queued -- nothing in this codebase
    moves a claimed task to `cancelled`, and the UI refuses to delete
    one -- so no agent ever took it and nothing was sent anywhere. By
    this docstring's own test it was not attempted, and marking its
    subject done retires it permanently: a standing order will never
    propose it again, because the only record of it is the proof that
    it must not be repeated.

    That is not theoretical. One engagement had 54,147 subjects whose
    every task had been cancelled, 4,982 of them in scope and never
    scanned, left behind by a queue cleanup. The operator with the
    toggle on found them by hand, which is the thing these two
    callers exist to make unnecessary.

    `args` is JSON, so it is parsed here rather than matched in SQL --
    a LIKE against a serialised blob would match `a.example` inside
    `xa.example` and silently skip a host.

    Shared by the standing orders and by the "never scanned" selection
    in the scan dialog, because two implementations of "has this been
    done" would disagree and the disagreement would be invisible: one
    would quietly re-scan what the other considered finished.
    """
    out: set[tuple[str, str]] = set()
    for kind, raw in (await session.execute(
            select(AgentTask.kind, AgentTask.args).where(
                AgentTask.project_id == project_id,
                AgentTask.kind.in_(kinds),
                AgentTask.status.notin_(NEVER_SENT)))).all():
        try:
            a = json.loads(raw or "{}")
        except ValueError:
            continue
        if kind == "amass":
            if d := a.get("domain"):
                out.add(("amass", str(d).lower()))
            continue
        for sub in (a.get("targets") or []):
            out.add((kind, str(sub).lower()))
    return out


#: A task that has not finished. Work is "in flight" in all three:
#: waiting for an agent, handed to one, or executing on it.
OUTSTANDING = ("queued", "claimed", "running")


async def outstanding_subjects(
        session: AsyncSession, project_id: int,
        kinds: tuple[str, ...]) -> set[tuple[str, str]]:
    """Every (kind, subject) this project already has work in flight for.

    Distinct from `tasked_subjects`, which answers "has this ever been
    attempted". This answers "is it happening right now", and the two
    are wanted in different places: the standing orders must not
    repeat finished work, and the queueing path must not stack a
    second copy of work that has not finished.

    Subjects are lowercased, matching `tasked_subjects`. The two
    disagreeing on case is exactly how one project came to hold five
    queued copies of the same URL.
    """
    out: set[tuple[str, str]] = set()
    for kind, raw in (await session.execute(
            select(AgentTask.kind, AgentTask.args).where(
                AgentTask.project_id == project_id,
                AgentTask.kind.in_(kinds),
                AgentTask.status.in_(OUTSTANDING)))).all():
        try:
            a = json.loads(raw or "{}")
        except ValueError:
            continue
        if kind == "amass":
            if d := a.get("domain"):
                out.add(("amass", str(d).lower()))
            continue
        for sub in (a.get("targets") or []):
            out.add((kind, str(sub).lower()))
    return out

# ----------------------------------------------------- output retention
#
# A finished task keeps the scanner's raw stdout. That is the right
# default while the task is recent -- it is what an operator reads
# when an import looks wrong, and what a re-import runs against -- and
# it is the wrong default for ever.
#
# Measured on the production mirror: 13 GB of `output` across 74,023
# done tasks, one row holding 94 MB, the oldest four weeks old. It is
# the largest thing in the database by a wide margin, and it is the
# reason a query that selected whole `AgentTask` rows OOM-killed the
# application container.
#
# The TASK is not deleted. What a Ghost was asked to do and what it
# reported is engagement history; the megabytes of XML behind it stop
# being evidence once they have been imported, which happens the
# moment the result arrives.

#: How long a finished task keeps its raw output.
#:
#: Fourteen days rather than the audit table's seven: the question
#: this answers is "why did that scan import badly", which is asked
#: days later, against a scan somebody has just noticed.
DEFAULT_OUTPUT_RETAIN_DAYS = 14


async def prune_task_output(session, days: int | None = None) -> tuple[int, int]:
    """Drop the raw output of long-finished tasks. -> (rows, bytes).

    Only `done` and `cancelled` tasks, and only past the window.

    **`failed` is deliberately exempt.** A failed task's output is the
    only account of HOW it failed, there is no imported result standing
    in for it, and the whole set is 21 kB -- the rounding error on a
    13 GB table. Sweeping it would save nothing and lose the one thing
    worth keeping.
    """
    try:
        d = DEFAULT_OUTPUT_RETAIN_DAYS if days is None else int(days)
    except (TypeError, ValueError):
        d = DEFAULT_OUTPUT_RETAIN_DAYS
    # As in `audit.prune`: "keep nothing" is a configuration mistake
    # rather than an instruction, and it would throw away the output
    # of a scan that finished this morning.
    if d <= 0:
        d = DEFAULT_OUTPUT_RETAIN_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=d)
    stale = (AgentTask.status.in_(("done", "cancelled")),
             AgentTask.created_at < cutoff,
             AgentTask.output.is_not(None))
    try:
        freed = int((await session.execute(
            select(func.coalesce(func.sum(func.length(AgentTask.output)), 0))
            .where(*stale))).scalar() or 0)
        res = await session.execute(
            update(AgentTask).where(*stale)
            .values(output=None,
                    # Said in the row itself. An operator opening a
                    # task to read its output needs to know the
                    # difference between "it produced none" and "it
                    # produced plenty and we no longer keep it".
                    summary=func.coalesce(AgentTask.summary, "")
                    + " [raw output dropped by retention]"))
        await session.commit()
        return int(res.rowcount or 0), freed
    except Exception:                            # noqa: BLE001
        log.exception("task output retention sweep failed")
        await session.rollback()
        return 0, 0
