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
"""
from __future__ import annotations

import logging
import re
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .models import AuditEvent

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
    """
    try:
        session.add(AuditEvent(
            source=source, action=action[:64],
            username=(username or (getattr(user, "username", None)))or None,
            user_id=getattr(user, "id", None),
            ip=ip, method=(method or None), status=status, ms=ms,
            path=(scrub_path(path) if path else None),
            project_code=(project_code[:64] if project_code else None),
            detail=(detail[:4000] if detail else None)))
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
            from .db import SessionLocal
            # Its own session. The request's session is finished by now,
            # and committing on it from out here would reach into a
            # transaction this layer knows nothing about.
            async with SessionLocal() as s:
                await record(
                    s, "middleware", "request",
                    user=user, ip=_client_ip(request),
                    method=request.method, path=path,
                    status=response.status_code, ms=elapsed, commit=True)
        except Exception:                        # noqa: BLE001
            log.exception("audit middleware could not record %s", for_log(path))
        return response
