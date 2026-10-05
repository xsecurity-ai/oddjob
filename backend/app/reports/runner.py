"""Running a report job in the background.

The row exists in `queued` from the moment the request returns, so the
table can honestly show work in progress rather than nothing. Generation
then happens on its own task with its own session — reusing the request's
session would tie the job's lifetime to a connection that is about to
close.

Every exit path writes a terminal status. A job that dies without doing so
leaves a row stuck on `running` forever, and the user is left looking at a
spinner with no way to tell whether it failed.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ..db import SessionLocal
from ..events import broker
from ..models import Project, Report, User
from .agentic import AgentPassError, revise
from .render import render
from .template import build, summary_json

log = logging.getLogger("oddjob.reports")


async def run(report_id: int, agentic: bool, min_severity: str = "low") -> None:
    """Build a queued report. Never raises; failure is recorded on the row."""
    async with SessionLocal() as session:
        row = await session.get(Report, report_id)
        if row is None:
            return
        row.status = "running"
        row.started_at = datetime.now(timezone.utc)
        await session.commit()
        await broker.publish("reports", action="running", id=report_id)

        try:
            project = await session.get(Project, row.project_id)
            if project is None:
                raise RuntimeError("the project was deleted while the report ran")
            who = "someone"
            if row.requested_by:
                u = await session.get(User, row.requested_by)
                who = (u.full_name or u.username) if u else who

            doc = await build(session, project, row.kind, who, min_severity)

            if agentic:
                try:
                    doc = await revise(session, project, doc)
                except AgentPassError as e:
                    # The report is still good. Say what was skipped rather
                    # than failing the job over an optional embellishment.
                    doc.agent_note = f"agentic pass skipped: {e}"
                    log.info("report %s: agentic pass skipped: %s", report_id, e)

            row.content = json.dumps(doc.to_json())
            row.summary = summary_json(doc)
            # Size the reader will actually download, not the JSON's.
            row.size_bytes = len(render(doc, "pdf")[0])
            row.status = "ready"
            row.finished_at = datetime.now(timezone.utc)
            row.error = None
        except Exception as e:
            log.exception("report %s failed", report_id)
            row.status = "failed"
            row.error = f"{type(e).__name__}: {e}"[:2000]
            row.finished_at = datetime.now(timezone.utc)

        await session.commit()
        await broker.publish("reports", action=row.status, id=report_id)

        if row.status == "ready":
            await _notify(session, row)
            await _announce(session, row)


async def _announce(session, row: Report) -> None:
    """Tell the engagement channel, with download links.

    The links are absolute and come from `site.base_url`, because a
    relative path in Slack is not clickable. Without a base URL the
    message still goes out, just without them — saying a report is
    ready is useful even when we cannot say where from.
    """
    from .. import slack
    from ..routers.reports import KIND_LABEL   # local: reports.py imports us
    from ..routers.settings import load_all
    try:
        pr = await session.get(Project, row.project_id)
        if pr is None:
            return
        base = str((await load_all(session)).get("site.base_url") or "").rstrip("/")
        pdf = f"{base}/api/reports/{row.id}/download?format=pdf" if base else None
        docx = f"{base}/api/reports/{row.id}/download?format=docx" if base else None
        label = KIND_LABEL.get(row.kind, row.kind)
        await slack.announce(session, pr, slack.report_generated(label, pdf, docx))
    except Exception:                            # noqa: BLE001
        # A report that generated but did not get announced is a
        # notification problem, not a reason to mark it failed.
        log.warning("could not announce report %s to slack", row.id, exc_info=True)


async def _notify(session, row: Report) -> None:
    """Email the requester, if they have an address and SMTP is configured.

    Both conditions are recorded on the row rather than logged and
    forgotten: "why didn't I get an email" is otherwise unanswerable.
    """
    from ..mailer import send_mail
    from ..routers.settings import load_all

    if not row.requested_by:
        row.email_error = "no requester recorded"
        await session.commit()
        return
    user = await session.get(User, row.requested_by)
    if user is None or not user.email:
        row.email_error = "the requester has no email address on their profile"
        await session.commit()
        return

    cfg = await load_all(session)
    if not cfg.get("smtp.host"):
        row.email_error = "SMTP is not configured"
        await session.commit()
        return

    project = await session.get(Project, row.project_id)
    base = str(cfg.get("site.base_url") or "").rstrip("/")
    link = f"{base}/api/reports/{row.id}/download?format=pdf" if base else ""
    body = (
        f"Your {row.kind} report for {project.code if project else 'the project'} "
        f"is ready to download.\n\n"
        f"  {row.title}\n"
        f"  generated {row.finished_at:%Y-%m-%d %H:%M} UTC\n\n"
        + (f"Download: {link}\n\n" if link else
           "Open Oddjob and find it under Reports.\n\n")
        + "PDF and DOCX are both available from the Reports table.\n")
    try:
        await send_mail(cfg, user.email,
                        f"{cfg.get('site.name') or 'Oddjob'} — "
                        f"{row.kind} report ready", body)
        row.emailed_to = user.email
        row.email_error = None
    except Exception as e:
        row.email_error = f"{type(e).__name__}: {e}"[:500]
    await session.commit()


def schedule(report_id: int, agentic: bool, min_severity: str = "low") -> None:
    """Fire and forget, keeping a reference so the task is not collected.

    asyncio only holds a weak reference to a bare task; without this the
    garbage collector can cancel a long report mid-run.
    """
    task = asyncio.create_task(run(report_id, agentic, min_severity))
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


_RUNNING: set[asyncio.Task] = set()


async def reap_stale() -> int:
    """Fail any report left mid-flight by a restart.

    A process that dies during generation leaves a `running` row that
    nothing will ever finish. On the next start those become `failed` with
    the reason, instead of spinning forever in the UI.
    """
    async with SessionLocal() as session:
        rows = (await session.execute(
            select(Report).where(Report.status.in_(("queued", "running"))))).scalars().all()
        for r in rows:
            r.status = "failed"
            r.error = "the server restarted while this report was being generated"
            r.finished_at = datetime.now(timezone.utc)
        if rows:
            await session.commit()
        return len(rows)
