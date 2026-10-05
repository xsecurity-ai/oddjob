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

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Event, User


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
