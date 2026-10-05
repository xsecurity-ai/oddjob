"""Running an import in the background.

A 2.5 GB proxy history takes tens of minutes to ingest. Held open as one
HTTP request that is hostage to the browser tab: navigating away aborts
the upload, a laptop sleeping kills it, and when it does fail there is
nowhere to look to find out how far it got. The import itself was
already restartable — chunks commit as they go and re-running upserts
rather than duplicates — but nothing recorded that it had been asked
for.

This is the same shape as `app/reports/runner.py`: a row exists from the
moment the work is queued, a detached task does the work and updates the
row, and a restart marks anything left mid-flight as failed rather than
leaving it spinning forever.

The uploaded file is not copied anywhere. The job runs against the
spooled upload the server is already holding, and releases it at the
end whichever way the job went.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from ..db import SessionLocal
from ..models import ImportJob

log = logging.getLogger("oddjob.import")

#: Live tasks. asyncio keeps only a weak reference to a bare task, so
#: without this the collector can cancel a long import mid-run.
_RUNNING: set[asyncio.Task] = set()


async def run(job_id: int) -> None:
    """Execute one queued job. Never raises; failures land on the row."""
    # Imported here: the router imports this module, so a module-level
    # import the other way would be circular.
    from ..routers.scans import run_job_body  # noqa: PLC0415

    async with SessionLocal() as session:
        job = await session.get(ImportJob, job_id)
        if job is None or job.status != "queued":
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await session.commit()

    try:
        result = await run_job_body(job_id)
    except Exception as e:                      # noqa: BLE001 - recorded, not raised
        log.exception("import job %s failed", job_id)
        async with SessionLocal() as session:
            job = await session.get(ImportJob, job_id)
            if job is not None:
                job.status = "failed"
                job.error = f"{type(e).__name__}: {e}"[:2000]
                job.finished_at = datetime.now(timezone.utc)
                await session.commit()
        return

    async with SessionLocal() as session:
        job = await session.get(ImportJob, job_id)
        if job is not None:
            job.status = "done"
            job.finished_at = datetime.now(timezone.utc)
            job.result = json.dumps(result)
            job.rows_done = int(result.get("urls_created", 0)
                                + result.get("urls_updated", 0))
            job.hosts_seen = int(result.get("hosts_seen", 0))
            await session.commit()


def schedule(job_id: int) -> None:
    """Fire and forget, holding a reference so the task survives."""
    task = asyncio.create_task(run(job_id))
    _RUNNING.add(task)
    task.add_done_callback(_RUNNING.discard)


async def progress(job_id: int, rows: int, hosts: int) -> None:
    """Record how far a running job has got.

    Its own session and its own commit: the import's session is inside a
    chunk transaction, and writing progress through that would either
    be rolled back with a retried chunk or hold the row's lock for the
    whole import.
    """
    try:
        async with SessionLocal() as session:
            job = await session.get(ImportJob, job_id)
            if job is not None and job.status == "running":
                job.rows_done = rows
                job.hosts_seen = hosts
                await session.commit()
    except Exception:                           # noqa: BLE001
        # Progress is a convenience. Losing a tick to a locked database
        # must never take the import down with it.
        log.debug("could not record progress for job %s", job_id, exc_info=True)


async def reap_stale() -> int:
    """Fail any import left mid-flight by a restart.

    The rows it already wrote are committed and keep their value — an
    import is an upsert, so re-running resumes rather than duplicating.
    The message says so, because otherwise the honest question "do I
    have to start over?" has no answer on screen.
    """
    async with SessionLocal() as session:
        rows = (await session.execute(
            select(ImportJob).where(
                ImportJob.status.in_(("queued", "running"))))).scalars().all()
        for r in rows:
            r.status = "failed"
            r.error = ("the server restarted while this import was running. "
                       "Rows written before that are kept; importing the same "
                       "file again resumes rather than duplicating.")
            r.finished_at = datetime.now(timezone.utc)
        if rows:
            await session.commit()
        return len(rows)
