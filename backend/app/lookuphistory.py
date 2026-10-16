"""Which subjects have already been asked, and answered with nothing.

Re-running a lookup that has already come back empty costs an outbound
request about a client's estate and returns the same nothing. Over a
sweep of a thousand names that is a thousand pointless questions, and
on a reverse sweep they leave the agent's host and reach a third party.
So the queueing path skips them by default and says that it did.

**This is not a cache, and the distinction matters.** A cache would
also suppress a subject whose lookup failed, and a failure is not an
answer. `lookups.answered_nothing` is deliberately narrow for that
reason -- an error, a timeout or a partial source never lands here, so
the only thing skipped is a subject a resolver positively said has no
records. Anything else is asked again, because asking again is how a
"could not determine" ever becomes a determination.

The operator can override it per run. That is the escape hatch for the
case the rule cannot see: records that did not exist last week and do
now. Nothing here expires on its own, because a clock would be
guessing at that.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .lookups import (
    LOOKUP_KINDS,
    answered_nothing,
    forward_choice,
    parse_records,
    reverse_choice,
)
from .models import AgentTask

#: How far back to read. The same bound `enumerate._outstanding` uses,
#: and for the same reason: this is a sweep aid, not an audit, and
#: walking every task a long engagement ever ran to answer it would
#: cost more than the requests it saves.
SCAN_LIMIT = 2000


async def answered_empty(session: AsyncSession, project_id: int, kind: str,
                         subjects: list[str]) -> dict[str, int]:
    """Of `subjects`, those already answered with a definite nothing.

    -> {subject: id of the task that answered it}. The task id is
    returned rather than a bare set so the caller can point an operator
    at the run it is declining to repeat; "skipped 94" with no way to
    check them is not something anyone can act on.

    Only `status == "done"` is read. A task that failed never produced
    an answer, and a task still queued or running has not produced one
    yet -- neither is evidence the subject is empty, and treating them
    as such would suppress a name on the strength of a crashed agent.
    """
    if kind not in LOOKUP_KINDS or not subjects:
        return {}
    wanted = {s.strip() for s in subjects if s and s.strip()}
    if not wanted:
        return {}

    rows = (await session.execute(
        select(AgentTask.id, AgentTask.output)
        .where(AgentTask.project_id == project_id,
               AgentTask.kind == kind,
               AgentTask.status == "done")
        # Oldest first, so a later run overwrites an earlier verdict for
        # the same subject rather than losing to it. A name that was
        # empty in March and resolved in April must not read as empty.
        .order_by(AgentTask.id.asc()).limit(SCAN_LIMIT))).all()

    # Every finished run is folded in, in order, and the newest wins.
    # A subject that answered with addresses after once answering with
    # nothing is REMOVED again -- the question has been settled since,
    # and skipping it now would be acting on the stale half of the
    # record.
    verdict: dict[str, int] = {}
    for task_id, output in rows:
        empty = answered_nothing(kind, output)
        for subject in _subjects_in(kind, output):
            if subject in empty:
                verdict[subject] = task_id
            else:
                verdict.pop(subject, None)
    return {s: tid for s, tid in verdict.items() if s in wanted}


def _subjects_in(kind: str, blob: str | None) -> set[str]:
    """Every subject this output speaks about, empty or not.

    Needed alongside `answered_nothing` so a later non-empty answer can
    clear an earlier empty one. Without it the fold could only ever add
    subjects, and a name would stay skipped forever once it had been
    quiet once.
    """
    out: set[str] = set()
    for rec in parse_records(blob):
        if kind == "reverse_ip":
            subject, _, _, _ = reverse_choice(rec)
        else:
            subject, _, _, _ = forward_choice(rec)
        if subject:
            out.add(subject)
    return out
