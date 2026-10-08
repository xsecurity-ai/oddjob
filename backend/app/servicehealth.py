"""What each subsystem last actually did, and whether it worked.

Configuration does not answer "is Slack working". A token can be present
and valid while the workspace refuses every message, and the first
anybody hears of it is a finding that quietly never arrived. SMTP is
worse: a magic link that is never delivered looks, from this side,
exactly like one nobody clicked.

So nothing here is a synthetic probe. Probes test the probe, and a probe
that passes while real traffic fails is an alibi rather than a check.
Every record below is the outcome of a real send that something actually
wanted to make.

`note()` is called from INSIDE `slack.post` and `mailer.send_mail`, not
from their call sites. There are fourteen call sites between the two,
and a health page that silently misses one is worse than no health page
at all — it reports green for a path nobody is watching.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from .models import ServiceHealth

log = logging.getLogger("oddjob.health")

#: Past this, "it worked once" stops being reassuring. Used only to
#: label a row, never to hide one.
STALE_AFTER = timedelta(days=7)


async def note(service: str, ok: bool, detail: str = "",
               error: str = "") -> None:
    """Record one real attempt. Never raises, and never blocks the caller.

    Opens its own session deliberately. The callers are `slack.post` and
    `send_mail`, which are reached from request handlers, background
    workers and the Slack socket loop alike — some hold a session, some
    hold one mid-transaction, and joining whichever happens to be open
    would make a health write able to roll back a user's actual work.
    """
    try:
        from .db import SessionLocal
        async with SessionLocal() as s:
            row = await s.get(ServiceHealth, service)
            if row is None:
                row = ServiceHealth(service=service)
                s.add(row)
            now = datetime.now(timezone.utc)
            if ok:
                row.last_ok_at = now
                row.ok_count = (row.ok_count or 0) + 1
            else:
                row.last_error_at = now
                row.error_count = (row.error_count or 0) + 1
                # Kept after a later success on purpose. "Working now,
                # but it broke an hour ago" is usually the more useful
                # of the two facts, and clearing it on the next success
                # is how an intermittent fault stays invisible.
                row.last_error = (error or detail or "failed")[:500]
            if detail:
                row.last_detail = detail[:300]
            await s.commit()
    except Exception as e:                       # noqa: BLE001
        # A failure to record a failure must not become a third failure.
        # The caller is usually something that has promised not to raise.
        log.warning("could not record %s health: %s", service, e)


def _aware(dt: datetime | None) -> datetime | None:
    """UTC-stamp a timestamp the driver handed back naive.

    Postgres returns these aware and SQLite returns them naive, from the
    same column and the same model. Comparing a naive one to `now()`
    raises, so the health page worked against Postgres and crashed
    against the default deployment — which is the wrong way round for a
    page whose whole job is to be available when things are broken.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def describe(row: ServiceHealth | None, *,
             never_used: str = "has never been used") -> dict:
    """One subsystem's row as the health page reads it.

    Three states, never two. "Working", "broken", and "nothing has ever
    tried" are different answers, and collapsing the third into either
    of the others is how a page comes to report green for something that
    has never run at all.
    """
    if row is None or (row.last_ok_at is None and row.last_error_at is None):
        return {"state": "unused", "note": never_used,
                "last_ok": None, "last_error_at": None, "last_error": None,
                "ok_count": 0, "error_count": 0}

    now = datetime.now(timezone.utc)
    ok_at, err_at = _aware(row.last_ok_at), _aware(row.last_error_at)
    if ok_at is not None and (err_at is None or ok_at >= err_at):
        state = "ok"
        if now - ok_at > STALE_AFTER:
            state = "idle"          # worked, but not lately
    else:
        state = "failing"
    return {
        "state": state,
        "last_ok": ok_at.isoformat() if ok_at else None,
        "last_error_at": err_at.isoformat() if err_at else None,
        # Shown even when the state is ok: an error an hour ago that has
        # since recovered is exactly what somebody debugging wants.
        "last_error": row.last_error,
        "last_detail": row.last_detail,
        "ok_count": row.ok_count or 0,
        "error_count": row.error_count or 0,
    }
