"""Everything a site admin needs to answer "why is it not working".

One request, because the question is never about one subsystem. "Nobody
got the report" is a question about SMTP, the report runner and the
scheduler at once, and three screens to check is how the one that
matters gets skipped.

**Three states, never two.** Working, broken, and never-used are
different answers. A Slack integration that has never sent a message is
not healthy and is not failing, and reporting it as either is how a page
earns the habit of being ignored.

Site-admin only: it names the database, the mail host and the error text
from every subsystem, which together describe the deployment closely
enough to be worth withholding.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .. import servicehealth
from ..db import get_session
from ..models import (
    Agent,
    AgentTask,
    AuditEvent,
    CveRecord,
    Exploit,
    FeedState,
    Project,
    ServiceHealth,
    Target,
    User,
    Vuln,
)
from ..security import require_site_admin
from ..version import IS_DEV, VERSION

router = APIRouter(prefix="/api/health", tags=["health"])

#: When the process came up. A surprising amount of "it started doing
#: this an hour ago" resolves to "it restarted an hour ago".
STARTED_AT = datetime.now(UTC)

#: Matches OFFLINE_AFTER in routers/agents.py. Imported there rather
#: than redefined, so the two cannot drift into disagreeing about what
#: "online" means on two different screens.


def _age(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return round((datetime.now(UTC) - dt).total_seconds(), 1)


async def _database(session: AsyncSession) -> dict:
    """Reachable, how fast, and how big."""
    out: dict = {"state": "failing"}
    try:
        t0 = time.perf_counter()
        await session.execute(select(1))
        out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        out["state"] = "ok"
    except Exception as e:                       # noqa: BLE001
        out["last_error"] = f"{type(e).__name__}: {e}"[:300]
        return out

    from ..db import display_url, engine
    out["url"] = display_url()                   # already masked
    out["dialect"] = engine.dialect.name
    try:
        pool = engine.pool
        out["pool"] = {"checked_out": pool.checkedout(),
                       "in_pool": pool.checkedin()}
    except Exception:                            # noqa: BLE001
        pass

    # Row counts an admin actually asks for, and the ones that explain a
    # slow page. Cheap on every supported backend.
    try:
        counts = {}
        for label, model in (("projects", Project), ("targets", Target),
                             ("findings", Vuln), ("users", User),
                             ("audit_events", AuditEvent)):
            counts[label] = int((await session.execute(
                select(func.count()).select_from(model))).scalar_one())
        out["rows"] = counts
    except Exception as e:                       # noqa: BLE001
        out["rows_error"] = str(e)[:200]

    if engine.dialect.name == "postgresql":
        try:
            out["size"] = (await session.execute(text(
                "SELECT pg_size_pretty(pg_database_size(current_database()))"
            ))).scalar_one()
        except Exception:                        # noqa: BLE001
            pass
    return out


async def _feed(session: AsyncSession, source: str, label: str) -> dict:
    """One vulnerability feed, as freshness rather than as a boolean.

    `records` comes from the table, not from the feed's own counter: the
    counter is what the last sync believed, and the whole point of this
    page is the case where those two have come apart.
    """
    st = await session.get(FeedState, source)
    model = CveRecord if source == "nvd" else Exploit
    held = int((await session.execute(
        select(func.count()).select_from(model))).scalar_one())

    if st is None or st.last_success_at is None:
        return {"state": "unused", "label": label, "records": held,
                "note": f"{label} has never synced — an empty result from it "
                        f"means 'nothing is recorded here', not 'nothing "
                        f"exists'",
                "last_error": st.error if st else None,
                "running": bool(st.running) if st else False}

    age = _age(st.last_success_at)
    # A day is the promise; two days is late; a week is not current data
    # any more, whatever the row count says.
    state = "ok"
    if age and age > 7 * 86400:
        state = "failing"
    elif age and age > 2 * 86400:
        state = "idle"
    if st.error:
        state = "failing" if state == "ok" else state
    return {"state": state, "label": label,
            "synced": st.last_success_at.isoformat(),
            "age_seconds": age, "records": held,
            "counter_says": st.records,
            "last_error": st.error, "running": bool(st.running),
            "resume_from": st.cursor}


async def _ghosts(session: AsyncSession) -> dict:
    """The fleet, and the work it is or is not getting through."""
    from .agents import OFFLINE_AFTER, _stale

    agents = list((await session.execute(select(Agent))).scalars())
    busy: dict[int, int] = {}
    for aid, n in (await session.execute(
            select(AgentTask.agent_id, func.count())
            .where(AgentTask.status.in_(("claimed", "running")))
            .group_by(AgentTask.agent_id))).all():
        if aid is not None:
            busy[aid] = int(n)

    states: dict[str, int] = {}
    rows = []
    for a in agents:
        st = _stale(a, busy.get(a.id, 0))
        states[st] = states.get(st, 0) + 1
        rows.append({"id": a.id, "name": a.name, "state": st,
                     # Null, not a placeholder string. An agent old
                     # enough to predate version reporting, or one that
                     # has been created but has never registered, has
                     # not told us anything — and "unknown" rendered as
                     # though it were a version is how a fleet summary
                     # grows a bucket that is not a version.
                     "version": a.version or None,
                     "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                     "age_seconds": _age(a.last_seen),
                     "missing_tools": (a.missing_tools or "") or None})

    queue: dict[str, int] = {}
    for status, n in (await session.execute(
            select(AgentTask.status, func.count())
            .group_by(AgentTask.status))).all():
        queue[str(status)] = int(n)

    # Work that has stopped moving. Queued-and-unassigned is normal for
    # a moment and a problem after an hour, and it is invisible from any
    # single ghost's row.
    stuck = int((await session.execute(
        select(func.count()).select_from(AgentTask)
        .where(AgentTask.status == "queued",
               AgentTask.created_at
               < datetime.now(UTC) - timedelta(hours=1)))).scalar_one())

    online = states.get("online", 0) + states.get("busy", 0)
    if not agents:
        state = "unused"
    elif online == 0:
        state = "failing"
    elif stuck:
        state = "idle"
    else:
        state = "ok"
    return {"state": state, "ghosts": rows, "by_state": states,
            # The fleet's versions, summarised from the same list of
            # agents the rows came from rather than from a second
            # query. One read, so the card and the rows under it
            # cannot disagree about which ghosts exist.
            "versions": servicehealth.fleet_versions(
                (a.version for a in agents), server_version=VERSION),
            "queue": queue, "queued_over_an_hour": stuck,
            "offline_after_seconds": int(OFFLINE_AFTER.total_seconds()),
            "note": ("no ghosts are enrolled" if not agents
                     else "no ghost has checked in" if online == 0
                     else f"{stuck} task(s) queued over an hour" if stuck
                     else None)}


@router.get("/site", response_model=dict)
async def site_health(_: User = Depends(require_site_admin),
                      session: AsyncSession = Depends(get_session)):
    """Every subsystem, in one request."""
    rows = {r.service: r for r in
            (await session.execute(select(ServiceHealth))).scalars()}

    from ..events import broker
    from .settings import load_all
    cfg = await load_all(session)

    slack = servicehealth.describe(
        rows.get("slack"),
        never_used="no message has ever been sent from this install")
    slack["configured"] = bool(str(cfg.get("slack.bot_token") or "").strip())
    # Being unconfigured explains an unused row, and saying so here is
    # the difference between "broken" and "you have not set it up".
    if not slack["configured"] and slack["state"] == "unused":
        slack["note"] = "no bot token is set"

    smtp = servicehealth.describe(
        rows.get("smtp"), never_used="no mail has ever been sent")
    smtp["configured"] = bool(str(cfg.get("smtp.host") or "").strip())
    smtp["host"] = str(cfg.get("smtp.host") or "") or None
    if not smtp["configured"] and smtp["state"] == "unused":
        smtp["note"] = "no SMTP host is set"

    try:
        from ..slack_socket import worker as slack_worker
        socket = {"connected": bool(slack_worker.connected),
                  "last": slack_worker.last}
    except Exception:                            # noqa: BLE001
        socket = {"connected": False, "last": "not running"}

    # The background loops, and what each last did.
    #
    # Both of these fail silently when they fail at all: a crashed
    # asyncio task leaves the app healthy, every endpoint answering,
    # and nothing happening. For standing orders that means an
    # operator believing their estate is being enumerated and scanned
    # when it is not, which is worse than the feature being off,
    # because "off" is visible on the Targets screen and this is not.
    #
    # `last` rather than only `running`: a loop can be alive and doing
    # nothing for a reason worth reading -- no project has a standing
    # order, no agent is online -- and "running: true" alone does not
    # distinguish that from work actually being queued.
    workers = {}
    for name, mod, attr in (("standing_orders", "..automation", "worker"),
                            ("remediation", "..agent.remediate", "worker")):
        try:
            import importlib
            w = getattr(importlib.import_module(mod, __package__), attr)
            task = getattr(w, "task", None)
            workers[name] = {
                "running": bool(getattr(w, "running", False))
                and task is not None and not task.done(),
                "last": getattr(w, "last", None),
            }
            # A task that finished is a loop that will never run again.
            # Said plainly rather than left as `running: false`, which
            # reads the same as "not started yet".
            if task is not None and task.done():
                exc = task.exception() if not task.cancelled() else None
                workers[name]["stopped"] = (
                    f"{type(exc).__name__}: {exc}" if exc else "exited")
        except Exception as e:                   # noqa: BLE001
            workers[name] = {"running": False, "last": f"unavailable: {e}"}

    audit_newest = (await session.execute(
        select(func.max(AuditEvent.at)))).scalar_one_or_none()

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "server": {
            "state": "ok",
            # Which Oddjob this is. Read from the VERSION file at
            # import (see app/version.py), never a literal here — a
            # second literal is a second answer, and it is always the
            # stale one.
            "version": VERSION,
            # Stated rather than left for the reader to spot the
            # suffix. "0.0.1-dev-1759900000" in a bug report is only
            # useful if whoever reads it knows that means an
            # unreleased build of 0.0.1.
            "dev": IS_DEV,
            "started_at": STARTED_AT.isoformat(),
            "uptime_seconds": _age(STARTED_AT),
            "sse_subscribers": broker.subscriber_count,
        },
        "database": await _database(session),
        "cve_feed": await _feed(session, "nvd", "NVD"),
        "exploit_feed": await _feed(session, "exploitdb", "Exploit-DB"),
        "slack": slack,
        "slack_socket": socket,
        "workers": workers,
        "smtp": smtp,
        "ghosts": await _ghosts(session),
        "audit": {
            "state": "ok" if audit_newest else "unused",
            "newest": audit_newest.isoformat() if audit_newest else None,
            "age_seconds": _age(audit_newest),
            "retain_days": cfg.get("audit.retain_days"),
        },
    }
