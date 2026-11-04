"""The audit trail: who did what to this installation, and from where.

Three ways in, all landing in one table so one page can answer the
question:

  middleware  every HTTP request, recorded by `AuditTrail` below. Method,
              scrubbed path, status, duration, client address and -- when
              the request authenticated -- the username.
  deliberate  `record()`, called from the handful of places where
              something happened that a request line alone does not
              explain: a project created, a scanner enrolled, somebody
              granted a role.
  backend     the server acting on its own, e.g. retention pruning and
              startup, with no request and no person behind it.

**What is deliberately NOT recorded.** Request bodies, headers, cookies
and query strings never reach this table. Every site admin can read it,
so anything written here is disclosed to all of them, and a request body
is the one place a password reliably appears. The rule is that an entry
says what happened and to what, never what was sent.

`scrub_path` exists for a specific hole rather than on principle:
magic-link sign-in tokens travel in the URL PATH (`/api/auth/magic/<tok>`),
and they are bearer credentials. Logging a path verbatim would put live
account-takeover tokens in a table and call it an audit feature. The same
treatment covers the agent enrolment and API-key paths.

**Failure is never fatal.** A request that could not be audited is still
a request that has to be served; an exception here must not become a 500
for the person who made it. Every write swallows its errors, loudly in
the log and silently to the caller.

That promise needs one qualification, because it was quietly false for
years. With `commit=False` -- the default -- `record` only queues a row
on the caller's session, so a value the database rejects fails during
the CALLER's commit, far from the try/except here, and takes the
caller's transaction with it. Nothing is logged, and the action being
audited is what gets rolled back. Everything bound for a bounded column
is therefore clipped on the way in (see `_fit`); what remains outside
the promise is a row the database refuses for some reason other than
length, which has not happened and would be a bug worth seeing.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, insert
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .models import AuditEvent, utcnow

log = logging.getLogger("oddjob.audit")

#: Default retention. Short on purpose: this table grows with traffic,
#: not with the engagement, and a week is long enough to answer "what
#: happened on Tuesday" without becoming a second copy of the database.
DEFAULT_RETAIN_DAYS = 7

#: Paths whose NEXT segment is a credential rather than an identifier.
#: Matched by prefix, so `/api/auth/magic/abc123` is stored as
#: `/api/auth/magic/<redacted>` and keeps its shape for reading.
_SECRET_PREFIXES = (
    "/api/auth/magic/",
    "/api/ghosts/enroll/",
)

#: Anything that LOOKS like a credential wherever it appears. The prefix
#: list above is exact and therefore cannot cover a path added later, so
#: this is the backstop: long opaque segments, and the two key formats
#: this application issues.
_SECRETISH = re.compile(
    r"^(?:ghost_[A-Za-z0-9_\-]+"          # agent keys
    r"|ojk_[A-Za-z0-9_\-]+"              # api keys
    r"|[A-Za-z0-9_\-]{24,})$"            # any long opaque blob
)


def for_log(raw) -> str:
    """One line, safe to concatenate into a log.

    A newline in a logged value lets a caller forge log entries: put
    `\\n2026-01-01 INFO authorised` in a field and the log grows a line
    nobody wrote. This is the audit log, so a forged entry is not a
    cosmetic problem — it is evidence.

    Applied at the logging site rather than at each caller, because the
    callers are the part that keeps changing.
    """
    # The two line terminators go first and explicitly. A comprehension
    # over str.isprintable() removes them just as thoroughly, but static
    # analysis cannot see that it does — and a sanitiser a scanner
    # cannot recognise means a real alert on every future caller, which
    # is how a scanner gets ignored.
    s = str(raw).replace("\r", "\\r").replace("\n", "\\n")
    # Everything else unprintable — escapes, nulls, the terminal control
    # characters that rewrite a line already on screen.
    s = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in s)
    return s[:200]


def scrub_path(raw: str) -> str:
    """A path safe to store. Never includes the query string.

    The query is dropped wholesale rather than filtered: an allowlist of
    safe parameters is a list somebody has to remember to update, and
    forgetting once writes a token into the log permanently.
    """
    path = (raw or "").split("?", 1)[0][:512]
    for pre in _SECRET_PREFIXES:
        if path.startswith(pre):
            return pre + "<redacted>"
    if "/" not in path:
        return path
    out = []
    for seg in path.split("/"):
        out.append("<redacted>" if seg and _SECRETISH.match(seg) else seg)
    return "/".join(out)


#: Column widths, read off the model rather than repeated here, so that
#: widening a column in a migration cannot leave a stale number behind
#: that silently keeps clipping.
_WIDTH = {c.name: c.type.length
          for c in AuditEvent.__table__.columns
          if getattr(c.type, "length", None)}


def _fit(field: str, value) -> str | None:
    """Clip a value to what its column can hold.

    This is not tidiness. A value too long does not fail where it is
    written -- `session.add` only queues the row -- so with `commit`
    False, which is the default and the common case, the error surfaces
    in the CALLER's commit and takes the caller's whole transaction with
    it. `record` is wrapped in a try/except that cannot see it happen.

    The result is the worst shape a failure can have here: the project
    did not get created, the role was not granted, and the reason is a
    length limit on the log entry about it. **The audit of an action
    must never be the thing that destroys the action.**

    `source` was the live case -- `String(16)`, and the only field
    `record` did not clip. Every bounded column is clipped now, because
    the next one added will not be remembered either.
    """
    if value is None:
        return None
    s = str(value)
    n = _WIDTH.get(field)
    return s[:n] if n else s


def _client_ip(request: Request) -> str | None:
    """The caller's address.

    `X-Forwarded-For` is honoured only as the LEFTMOST entry and only
    because this commonly runs behind nginx. It is attacker-controlled
    when there is no proxy, which is worth knowing when reading a row:
    this field says what the caller claimed, not what is provable.
    """
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return request.client.host[:64] if request.client else None


def _row(source: str, action: str, *,
         user=None, username: str | None = None,
         ip: str | None = None, method: str | None = None,
         path: str | None = None, status: int | None = None,
         ms: int | None = None, project_code: str | None = None,
         detail: str | None = None) -> dict:
    """The column values for one entry, clipped to what the table holds.

    One place, because there are now two ways a row reaches the table --
    `record` queues an ORM object on a caller's session, the spool below
    inserts dicts in batches -- and a field clipped on one path and not
    the other is the `source` bug in `_fit` all over again.
    """
    return {
        "source": _fit("source", source), "action": _fit("action", action),
        "username": _fit("username",
                         username or getattr(user, "username", None)) or None,
        "user_id": getattr(user, "id", None),
        "ip": _fit("ip", ip), "method": _fit("method", method) or None,
        "status": status, "ms": ms,
        "path": (_fit("path", scrub_path(path)) if path else None),
        "project_code": _fit("project_code", project_code) or None,
        # `detail` is Text, so this is a policy cap rather than a
        # column limit: one line for a person to read, not a place
        # to put a payload.
        "detail": (detail[:4000] if detail else None),
    }


async def record(session, source: str, action: str, *,
                 user=None, username: str | None = None,
                 ip: str | None = None, method: str | None = None,
                 path: str | None = None, status: int | None = None,
                 ms: int | None = None, project_code: str | None = None,
                 detail: str | None = None, commit: bool = False) -> None:
    """Write one entry. Never raises.

    `commit` is False by default so an entry joins the caller's
    transaction and cannot claim something happened that was then rolled
    back. Callers that have already committed pass True.

    **This path is never batched**, and that is the point of it. A
    deliberate entry -- a project created, a role granted -- shares the
    fate of the thing it describes, so if the action rolls back the
    claim that it happened rolls back with it. Only the middleware's
    per-request line goes through the spool, because that one records a
    request that has already been served either way.
    """
    try:
        session.add(AuditEvent(**_row(
            source, action, user=user, username=username, ip=ip,
            method=method, path=path, status=status, ms=ms,
            project_code=project_code, detail=detail)))
        if commit:
            await session.commit()
    except Exception:                            # noqa: BLE001
        log.exception("could not write audit entry %s/%s",
                      for_log(source), for_log(action))


async def prune(session, days: int | None = None) -> int:
    """Drop entries past the retention window. -> rows removed."""
    try:
        d = DEFAULT_RETAIN_DAYS if days is None else int(days)
    except (TypeError, ValueError):
        d = DEFAULT_RETAIN_DAYS
    # 0 or less would mean "keep nothing", which is a configuration
    # mistake rather than an instruction -- it would delete the entry
    # recording the change that caused it. Treated as the default.
    if d <= 0:
        d = DEFAULT_RETAIN_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=d)
    try:
        res = await session.execute(
            delete(AuditEvent).where(AuditEvent.at < cutoff))
        await session.commit()
        return int(res.rowcount or 0)
    except Exception:                            # noqa: BLE001
        log.exception("audit retention sweep failed")
        return 0


async def retain_days(session) -> int:
    """The configured window, falling back to the default."""
    from .routers.settings import load_all
    try:
        raw = (await load_all(session)).get("audit.retain_days")
        d = int(raw)                             # type: ignore[arg-type]
        return d if d > 0 else DEFAULT_RETAIN_DAYS
    except Exception:                            # noqa: BLE001
        return DEFAULT_RETAIN_DAYS


#: How deep the spool goes before it stops being a spool. A burst
#: should be absorbed; a stall should NOT be hidden. At the rate one
#: process serves requests this is on the order of a second of traffic,
#: and a writer that cannot keep up for a whole second is not about to
#: catch up quietly -- past this point entries are written the slow way,
#: on the request, which is visible rather than silent.
SPOOL_MAX = 2048

#: The most rows one INSERT carries. The win is per-statement and
#: per-commit, so it is already most of the way there by a few dozen;
#: past this the batch is just a bigger thing to lose and a longer
#: statement to parse.
SPOOL_BATCH = 256

#: How long a shutdown waits for the writer to finish. Long enough for
#: a batch against a database under load, short enough that a database
#: which has stopped answering does not hold the process open.
STOP_GRACE = 5.0

#: Put on the queue to close it. Identity, not a value, so it can never
#: be confused with an entry.
_CLOSE: dict = {}


class _Spool:
    """The middleware's per-request entries, off the request's path.

    Auditing a request cost 1.75 ms on the request itself: a session
    opened, one INSERT, one commit, all of it between the response being
    ready and the response being sent. The work is the same work; the
    person waiting for it is the difference.

    Entries are handed to a queue and written by one background task,
    which takes whatever has arrived and inserts it in a single
    statement. Batching is not on a timer -- it falls out of the queue
    depth. Idle, an entry is written immediately and the batch is one
    row; under load the queue has a backlog by the time the writer comes
    round, and the backlog IS the batch. A timer would add latency when
    there is nothing to gain by waiting.

    **The trade, stated plainly.** An entry in the queue is in memory. A
    clean shutdown drains it (`stop`), and a crash loses it -- up to one
    batch of per-request lines, for a process that was killed. That is a
    real loss on a security tool's audit trail and it is why only the
    middleware's line goes this way: `record`, which is what writes
    "somebody granted themselves admin", stays synchronous and
    transactional. This path records that a request was served, by a
    process that then died, which is the fact an operator is least
    likely to be relying on this table for.

    **Nothing is ever dropped.** A full queue means the writer is not
    keeping up, and the answer to that is back-pressure, not amnesia:
    `offer` returns False and the caller writes the entry the old slow
    way. The audit trail stays complete and the latency comes back,
    which is the right way round for this table.
    """

    def __init__(self) -> None:
        self._q: asyncio.Queue | None = None
        self._task: asyncio.Task | None = None
        #: Entries that had to take the slow path because the queue was
        #: full. Not a drop count -- those entries were written -- but
        #: the number worth knowing about, because a non-zero one says
        #: the writer is behind.
        self.overflowed = 0

    def start(self) -> None:
        """Begin draining. Safe to call twice."""
        if self._task is not None and not self._task.done():
            return
        self._q = asyncio.Queue(maxsize=SPOOL_MAX)
        self._task = asyncio.create_task(self._drain())

    async def stop(self) -> None:
        """Write what is queued, then stop. Safe to call without start."""
        task, q = self._task, self._q
        # From here `offer` refuses, so anything still arriving during
        # the shutdown is written by its own caller rather than put on
        # a queue that is closing.
        self._task = self._q = None
        if task is None or q is None:
            return
        # A sentinel, NOT a cancel. A cancel lands wherever the writer
        # happens to be, and if that is inside `_flush` then the batch
        # it had already taken off the queue is gone -- entries lost to
        # a clean shutdown, which is the one case that has no excuse.
        # The sentinel lets it finish what it is holding and then stop.
        with contextlib.suppress(asyncio.QueueFull):
            q.put_nowait(_CLOSE)
        try:
            await asyncio.wait_for(task, STOP_GRACE)
        except (TimeoutError, asyncio.CancelledError):
            # A writer wedged on a database that is not answering. The
            # shutdown cannot wait for ever; say so rather than hang.
            task.cancel()
            log.warning("audit spool did not drain within %ss", STOP_GRACE)
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        except Exception:                        # noqa: BLE001
            log.exception("audit spool stopped badly")
        # Whatever the sentinel did not reach: a queue that was already
        # full when `stop` was called (so the sentinel never went on),
        # or a writer that had to be cancelled after all.
        rows = []
        while not q.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                item = q.get_nowait()
                if item is not _CLOSE:
                    rows.append(item)
        if rows:
            with contextlib.suppress(Exception):
                await self._flush(rows)

    def offer(self, row: dict) -> bool:
        """Queue one entry. -> False if the caller must write it itself.

        Never raises and never blocks: this runs on the request.
        """
        q = self._q
        if q is None or self._task is None or self._task.done():
            return False                 # not running; caller writes it
        try:
            q.put_nowait(row)
        except asyncio.QueueFull:
            self.overflowed += 1
            return False
        return True

    async def _drain(self) -> None:
        # Captured once: `stop` clears the attribute to close the door
        # on new entries, and this loop still has what it was draining.
        q = self._q
        assert q is not None
        while True:
            # Blocks until there is something, so an idle process does
            # no work at all rather than waking on a timer.
            first = await q.get()
            closing = first is _CLOSE
            rows = [] if closing else [first]
            while len(rows) < SPOOL_BATCH:
                try:
                    item = q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if item is _CLOSE:
                    closing = True
                    break
                rows.append(item)
            if rows:
                try:
                    await self._flush(rows)
                except asyncio.CancelledError:
                    raise
                except Exception:                # noqa: BLE001
                    log.exception("audit spool could not write %d entries",
                                  len(rows))
            if closing:
                return

    async def _flush(self, rows: list[dict]) -> None:
        """One statement for the batch; one row at a time if it fails.

        A batch is all-or-nothing, so without the retry a single row the
        database refuses would take every good entry beside it down. The
        audit trail is the wrong table to lose 255 rows from because of
        the one in front of them.
        """
        from .db import SessionLocal
        try:
            async with SessionLocal() as s:
                await s.execute(insert(AuditEvent), rows)
                await s.commit()
            return
        except Exception:                        # noqa: BLE001
            if len(rows) == 1:
                log.exception("audit spool: entry refused by the database")
                return
            log.exception("audit spool: batch of %d refused, retrying singly",
                          len(rows))
        for row in rows:
            with contextlib.suppress(Exception):
                async with SessionLocal() as s:
                    await s.execute(insert(AuditEvent), [row])
                    await s.commit()


#: The one spool. Started from the application lifespan; inert until
#: then, which is what makes `offer` safe to call from a test that never
#: ran one.
spool = _Spool()


#: Not worth a row each. The SPA's own assets and the liveness probe are
#: traffic, not actions, and at one entry per asset per page load they
#: would bury the entries somebody is actually looking for.
_SKIP_EXACT = {"/healthz", "/favicon.ico", "/robots.txt"}
_SKIP_PREFIX = ("/assets/", "/static/")


def _skip(path: str) -> bool:
    if path in _SKIP_EXACT or path.startswith(_SKIP_PREFIX):
        return True
    # The SPA itself is served from a catch-all, so every deep link looks
    # like a page request. Those are recorded; asset extensions are not.
    return path.rsplit(".", 1)[-1] in (
        "js", "css", "map", "png", "jpg", "jpeg", "svg", "ico", "woff", "woff2")


class AuditTrail(BaseHTTPMiddleware):
    """Record every request that is not static noise.

    Sits OUTSIDE authentication, so a refused request is recorded too --
    a 401 from an unknown address is precisely the entry worth having,
    and a middleware inside the gate would never see it.

    The username is not resolved here. `get_current_user` stamps
    `request.state.auth_user` when it authenticates one, which this reads
    afterwards; doing it that way costs nothing, and covers API keys,
    which would otherwise need an argon2 verify per request just to put
    a name in a log.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if _skip(path):
            return await call_next(request)

        started = time.perf_counter()
        response = await call_next(request)
        elapsed = int((time.perf_counter() - started) * 1000)

        try:
            user = getattr(request.state, "auth_user", None)
            row = _row("middleware", "request",
                       user=user, ip=_client_ip(request),
                       method=request.method, path=path,
                       status=response.status_code, ms=elapsed)
            # The time the request happened, not the time its row is
            # written. The spool holds entries for as long as the writer
            # takes to come round, and a batch stamped on arrival at the
            # database would quietly compress a burst into one instant
            # and reorder it against everything written synchronously.
            row["at"] = utcnow()
            if not spool.offer(row):
                # Not running, or not keeping up. Either way the entry
                # is written here and now -- slower, on the request, and
                # complete.
                from .db import SessionLocal
                # Its own session. The request's session is finished by
                # now, and committing on it from out here would reach
                # into a transaction this layer knows nothing about.
                async with SessionLocal() as s:
                    s.add(AuditEvent(**row))
                    await s.commit()
        except Exception:                        # noqa: BLE001
            log.exception("audit middleware could not record %s", for_log(path))
        return response
