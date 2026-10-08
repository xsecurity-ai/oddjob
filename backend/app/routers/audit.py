"""The audit trail, for site admins.

Two views of one query, at the paths an operator will reach for:

  /audit/log    fixed-width text, meant to be read in a browser tab or
                piped through grep. One line per entry.
  /audit/json   the same rows as JSON, for anything that parses.

Each origin is also addressable on its own, so the common narrowing is
a URL rather than a query someone has to remember the spelling of:

  /audit/ghost/log        /audit/ghost/json
  /audit/ui/log          /audit/ui/json
  /audit/middleware/log  /audit/middleware/json
  /audit/backend/log     /audit/backend/json

Same handlers, same filters; the path simply pins `source`. An unknown
origin is a 404 that NAMES the valid ones, rather than an empty page --
`/audit/ghost-agent/log` returning nothing looks exactly like a quiet
day, which is the wrong thing for an audit tool to imply.

Site admin only, and not negotiable: the trail names who was where, so
read access to it is read access to everybody's movements. It is also
the one table where a weak filter would be noticed late.

These live OUTSIDE `/api` because they are a destination a person types,
not an endpoint the SPA calls. They are registered before the SPA's
catch-all, so they win over it.
"""
from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import retain_days
from ..db import get_session
from ..models import AUDIT_SOURCES, AuditEvent, User
from ..security import require_site_admin

router = APIRouter(prefix="/audit", tags=["audit"])

#: A page, not the table. Someone reading this in a browser does not want
#: 400k lines, and someone scripting it can page with `before`.
MAX_LIMIT = 5000


async def _rows(session: AsyncSession, limit: int, source: str | None,
                username: str | None, project: str | None,
                action: str | None, hours: int | None,
                before: int | None, q: str | None = None,
                ) -> list[AuditEvent]:
    stmt = select(AuditEvent)
    if source:
        stmt = stmt.where(AuditEvent.source == source)
    if username:
        stmt = stmt.where(AuditEvent.username == username)
    if project:
        stmt = stmt.where(AuditEvent.project_code == project)
    if action:
        # Prefix match, so `project` finds `project.create` and
        # `project.delete` without needing to know the whole verb.
        stmt = stmt.where(AuditEvent.action.startswith(action))
    if q:
        # One box over the columns a person would actually type into.
        # Deliberately not `detail` alone: the thing half-remembered is
        # as often the username, the path or the address as the message.
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            AuditEvent.action.ilike(like),
            AuditEvent.username.ilike(like),
            AuditEvent.detail.ilike(like),
            AuditEvent.path.ilike(like),
            AuditEvent.project_code.ilike(like),
            AuditEvent.ip.ilike(like)))
    if hours:
        stmt = stmt.where(AuditEvent.at
                    >= datetime.now(UTC) - timedelta(hours=hours))
    if before:
        stmt = stmt.where(AuditEvent.id < before)
    # Newest first, with id as the tiebreak so entries written in the same
    # tick keep a stable order across pages.
    stmt = stmt.order_by(AuditEvent.at.desc(),
                         AuditEvent.id.desc()).limit(limit)
    return list((await session.execute(stmt)).scalars())


def _common(
    limit: int = Query(500, ge=1, le=MAX_LIMIT),
    source: str | None = Query(None, description="|".join(AUDIT_SOURCES)),
    username: str | None = None,
    project: str | None = None,
    action: str | None = Query(None, description="prefix match"),
    hours: int | None = Query(None, ge=1,
                              description="only the last N hours"),
    before: int | None = Query(None, description="id to page back from"),
    q: str | None = Query(None, description="free text over action, user, "
                                            "detail, path, project and ip"),
) -> dict:
    return {"limit": limit, "source": source, "username": username,
            "project": project, "action": action, "hours": hours,
            "before": before, "q": q}


def _narrow(f: dict, origin: str) -> dict:
    """Pin `source` from the PATH, which beats any `?source=`.

    The segment is `origin` rather than `source` because `_common`
    already declares a `source` query parameter, and FastAPI will not
    let one name be both a path and a query param.

    A path segment is the more specific statement of intent: nobody
    types /audit/ghost/log meaning "and also show me the UI entries".
    """
    if origin not in AUDIT_SOURCES:
        raise HTTPException(
            404, f"no such audit source {origin!r} — "
                 f"try one of: {', '.join(AUDIT_SOURCES)}")
    return {**f, "source": origin}


async def _as_json(session: AsyncSession, f: dict) -> dict:
    rows = await _rows(session, **f)
    return {
        "retain_days": await retain_days(session),
        "source": f.get("source"),
        "count": len(rows),
        #: What to pass as `before` for the next page. None when this
        #: page is the end, so a script can stop without a second call.
        "next_before": rows[-1].id if len(rows) == f["limit"] else None,
        "entries": [{
            "id": r.id,
            "at": r.at.isoformat() if r.at else None,
            "source": r.source,
            "action": r.action,
            "username": r.username,
            "ip": r.ip,
            "method": r.method,
            "path": r.path,
            "status": r.status,
            "ms": r.ms,
            "project": r.project_code,
            "detail": r.detail,
        } for r in rows],
    }


@router.get("/json")
async def audit_json(f: dict = Depends(_common),
                     _: User = Depends(require_site_admin),
                     session: AsyncSession = Depends(get_session)):
    return await _as_json(session, f)


@router.get("/{origin}/json")
async def audit_source_json(origin: str, f: dict = Depends(_common),
                            _: User = Depends(require_site_admin),
                            session: AsyncSession = Depends(get_session)):
    return await _as_json(session, _narrow(f, origin))


def _line(r: AuditEvent) -> str:
    when = r.at.strftime("%Y-%m-%d %H:%M:%S") if r.at else "-" * 19
    who = r.username or "-"
    where = r.ip or "-"
    what = f"{r.method or '':<6} {r.path or ''}".rstrip() if r.path else ""
    bits = [f"{when}  {r.source:<10} {r.action:<22} {who:<16} {where:<15}"]
    if what:
        bits.append(what)
    if r.status is not None:
        bits.append(f"-> {r.status}")
    if r.ms is not None:
        bits.append(f"{r.ms}ms")
    if r.project_code:
        bits.append(f"[{r.project_code}]")
    if r.detail:
        bits.append(f"| {r.detail}")
    return " ".join(bits)


async def _as_text(session: AsyncSession, f: dict) -> str:
    rows = await _rows(session, **f)
    days = await retain_days(session)
    who = f" [{f['source']} only]" if f.get("source") else ""
    head = (f"# oddjob audit trail{who} — {len(rows)} entr"
            f"{'y' if len(rows) == 1 else 'ies'}, newest first, "
            f"retained {days} day{'' if days == 1 else 's'}\n"
            f"# bodies, headers and query strings are never recorded; "
            f"credential-bearing path segments read <redacted>\n")
    if not rows:
        return head + "# nothing recorded in this window\n"
    return head + "\n".join(_line(r) for r in rows) + "\n"


@router.get("/log", response_class=PlainTextResponse)
async def audit_log(f: dict = Depends(_common),
                    _: User = Depends(require_site_admin),
                    session: AsyncSession = Depends(get_session)):
    return await _as_text(session, f)


@router.get("/{origin}/log", response_class=PlainTextResponse)
async def audit_source_log(origin: str, f: dict = Depends(_common),
                           _: User = Depends(require_site_admin),
                           session: AsyncSession = Depends(get_session)):
    return await _as_text(session, _narrow(f, origin))


#: Column order for the export. Fixed and explicit: a spreadsheet whose
#: columns move between downloads cannot be compared against an older
#: one, which is most of what an exported audit trail is for.
CSV_COLUMNS = ("at", "id", "source", "action", "username", "ip",
               "method", "path", "status", "ms", "project", "detail")


async def _as_csv(session: AsyncSession, f: dict) -> StreamingResponse:
    """The same rows the table shows, as a file.

    Exports what the FILTERS select, not the whole table. Someone who
    has narrowed to one user and one afternoon and then clicks export
    means that afternoon; handing them 5,000 unrelated rows is a
    different document and they would have to redo the work in Excel.
    """
    rows = await _rows(session, **f)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([
            r.at.isoformat() if r.at else "", r.id, r.source, r.action,
            r.username or "", r.ip or "", r.method or "", r.path or "",
            "" if r.status is None else r.status,
            "" if r.ms is None else r.ms,
            r.project_code or "", r.detail or "",
        ])
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    who = f"-{f['source']}" if f.get("source") else ""
    name = f"oddjob-audit{who}-{stamp}.csv"
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/csv")
async def audit_csv(f: dict = Depends(_common),
                    _: User = Depends(require_site_admin),
                    session: AsyncSession = Depends(get_session)):
    return await _as_csv(session, f)


@router.get("/{origin}/csv")
async def audit_source_csv(origin: str, f: dict = Depends(_common),
                           _: User = Depends(require_site_admin),
                           session: AsyncSession = Depends(get_session)):
    return await _as_csv(session, _narrow(f, origin))
