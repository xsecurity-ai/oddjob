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

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AgentTask

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
