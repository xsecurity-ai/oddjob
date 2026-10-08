"""Oddjob API."""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (FileResponse, HTMLResponse,
                               RedirectResponse)
from fastapi.staticfiles import StaticFiles

from .db import DB_PATH, init_db
from .agentseal import AgentSeal
from .gatekeeper import (FORBIDDEN_HTML, Gatekeeper, NOT_FOUND_HTML,
                         wants_html)
from .routers import (agents, actions, agent, audit, auth, bulk, credentials, domains,
                      vulnfeeds,
                      enumerate as enumerate_routes, explore,
                      index as api_index, rest,
                      findings, google, magic, meta, projects, reports, scans,
                      services, settings, targets, web)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # A report left mid-flight by a restart would otherwise spin forever.
    from .reports.runner import reap_stale
    if (n := await reap_stale()):
        print(f"marked {n} interrupted report(s) as failed")
    # Same for an import: a `running` row nothing will ever finish is
    # worse than an honest failure, because the UI cannot tell them
    # apart and the operator waits forever.
    from .importers.jobs import reap_stale as reap_imports
    if (n := await reap_imports()):
        print(f"marked {n} interrupted import(s) as failed")
    # Security headers depend on site.base_url, which lives in the
    # database, so they cannot be computed until it is open.
    from .db import SessionLocal
    async with SessionLocal() as s:
        await _headers.refresh(s)

    # A killed process never runs the `finally` that removes a spooled
    # upload, and a held one outlives its request on purpose. Nothing is
    # held yet at startup, so anything on disk is an orphan.
    from .routers.scans import sweep_orphan_uploads
    if (n := sweep_orphan_uploads()):
        print(f"removed {n} orphaned upload file(s)")

    # One worker, started once. It is inert until an agent is configured.
    from .agent.remediate import worker
    worker.start()

    # The inbound half of Slack. Socket Mode, so it needs no public
    # endpoint: inert until an app-level token exists and answering is
    # switched on.
    from .slack_socket import worker as slack_worker
    slack_worker.start()

    # The audit table grows with TRAFFIC, not with the engagement, so it
    # is the one table that needs sweeping rather than keeping. Once at
    # startup, then daily -- a long-lived process would otherwise never
    # sweep at all, and the window would quietly mean nothing.
    from . import audit as _audit
    from .db import SessionLocal as _Sess
    from .db import display_url as _display_url

    async def _audit_retention():
        while True:
            try:
                async with _Sess() as s:
                    days = await _audit.retain_days(s)
                    n = await _audit.prune(s, days)
                    if n:
                        print(f"audit: removed {n} expired entr"
                              f"{'y' if n == 1 else 'ies'}")
                        # Recorded, because a gap in an audit trail that
                        # nothing explains is indistinguishable from one
                        # somebody made. The entry naming the sweep is
                        # written after it, so it survives its own run.
                        await _audit.record(
                            s, "backend", "audit.prune",
                            detail=f"removed {n} entries older than "
                                   f"{days} days", commit=True)
            except asyncio.CancelledError:
                raise
            except Exception as e:               # noqa: BLE001
                # Never fatal: losing the sweep costs disk, losing the
                # process costs the engagement.
                print(f"audit: retention sweep failed: {e}")
            await asyncio.sleep(24 * 60 * 60)

    audit_task = asyncio.create_task(_audit_retention())

    # Exploit and CVE data, kept current so "is anything known about
    # this version" can be answered without asking anybody. Off unless
    # switched on: the first NVD sync is ~290,000 records, and plenty of
    # deployments have no outbound internet at all.
    async def _vulnfeeds():
        from . import vulnfeed
        from .routers.settings import load_all
        # A little after start, so a restart during an engagement does
        # not spend its first minute fetching.
        await asyncio.sleep(90)
        while True:
            try:
                async with _Sess() as s:
                    cfg = await load_all(s)
                    if bool(cfg.get("vulnfeed.enabled", False)):
                        key = str(cfg.get("vulnfeed.nvd_api_key") or "").strip()
                        r1 = await vulnfeed.sync_exploitdb(s)
                        r2 = await vulnfeed.sync_nvd(s, key)
                        for r in (r1, r2):
                            if not r.get("ok"):
                                print(f"vulnfeed: {r['source']} failed: "
                                      f"{r.get('error')}")
            except asyncio.CancelledError:
                raise
            except Exception as e:                   # noqa: BLE001
                # Never fatal. Losing a feed costs freshness, which is
                # reported; losing the process costs the engagement.
                print(f"vulnfeed: sync loop failed: {e}")
            await asyncio.sleep(24 * 60 * 60)

    vulnfeed_task = asyncio.create_task(_vulnfeeds())

    # A restart is the explanation for a lot of things an operator will
    # otherwise spend an hour on — a gap in the log, an agent that went
    # quiet, a setting that reverted. One line costs nothing.
    try:
        async with _Sess() as s:
            await _audit.record(s, "backend", "server.start",
                                detail=f"db {_display_url()}",
                                commit=True)
    except Exception as e:                       # noqa: BLE001
        print(f"audit: could not record startup: {e}")
    # display_url(), not DB_PATH: DB_PATH is the SQLite file path and is
    # computed whether or not SQLite is in use, so this line claimed the
    # app was on SQLite while it was actually talking to Postgres. The
    # masked DSN is the honest answer and never shows the password.
    from .db import display_url
    print(f"Oddjob API ready — db: {display_url()}")
    yield
    audit_task.cancel()
    vulnfeed_task.cancel()
    await worker.stop()
    await slack_worker.stop()


app = FastAPI(
    title="Oddjob API",
    version="0.1.0",
    description=(
        "Engagement data store: targets, ports/services, vulns, PoCs.\n\n"
        "Every list endpoint takes `q` (full search), `sort`, `order`, `limit`, "
        "`offset` and returns `{items, total, limit, offset}`.\n\n"
        "`POST /api/bulk` upserts any mix of entities in one transaction. "
        "`GET /api/events` is an SSE stream that fires whenever data changes."
    ),
    lifespan=lifespan,
)

from . import headers as _headers      # noqa: E402
from .audit import AuditTrail         # noqa: E402

# ORDER. `add_middleware` prepends, so the LAST one added is the
# outermost and therefore the last to touch a response on the way out.
# Desired, outside in:
#
#   SecurityHeaders   stamps everything, including responses the layers
#                     below short-circuit — a gate refusal needs the same
#                     headers as a 200, and an earlier arrangement had it
#                     innermost, so the 401 went out bare.
#   CORS              a refusal still needs CORS headers, or the browser
#                     reports an opaque network error instead of the 401
#                     the SPA is waiting for.
#   Gatekeeper        authentication.
#   AgentSeal         decrypts an agent's request body and encrypts the
#                     reply. Innermost on purpose: the route should see
#                     plaintext and know nothing about sealing, because
#                     a route that has to remember is a route that one
#                     day forgets and sends a scan result in the clear.
#
# So they are added in the reverse of that.
app.add_middleware(Gatekeeper)
app.add_middleware(AgentSeal)

# The Vite dev server runs on another origin; in production the built SPA is
# served from this same app and CORS is irrelevant.
# Same-origin in production — the SPA is served from this app, so CORS is
# not involved at all. The list exists for the Vite dev server on another
# port, plus whatever `site.extra_origins` names. allow_credentials means
# every entry here can make authenticated requests, so it stays short.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.environ.get(
        "ODDJOB_CORS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ApiSlash:
    """Route `/api/foo/` as `/api/foo`. A rewrite, NOT a redirect.

    `/api/agents/?project=X` used to answer "no such endpoint" while
    `/api/agents` worked, because the SPA catch-all matched first and
    swallowed the redirect FastAPI would otherwise have issued.

    Redirecting was the obvious fix and it was wrong. What produced the
    slashed URL in the first place was a reverse proxy emitting a 301 —
    and a 301 is PERMANENT, so browsers cache it and keep replaying it
    long after the proxy is corrected. Answering it with a redirect
    back to the unslashed form gives the browser two redirects pointing
    at each other: ERR_TOO_MANY_REDIRECTS, which surfaces to a fetch()
    as the uniquely unhelpful "Failed to fetch".

    Rewriting the path leaves nothing to loop against. The slashed URL
    is simply served, whatever any client has cached.

    Outermost, so Gatekeeper sees the normalised path as well — its
    allowlist matches exact strings, and a slashed public path would
    otherwise be refused before routing.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            path = scope.get("path", "")
            if path.startswith("/api/") and path.endswith("/") and len(path) > 5:
                trimmed = path.rstrip("/")
                scope = dict(scope)
                scope["path"] = trimmed
                if scope.get("raw_path"):
                    # Kept in step, or anything reading raw_path (and
                    # Starlette does, for routing) sees the old one.
                    q = scope["raw_path"].split(b"?", 1)
                    scope["raw_path"] = trimmed.encode() + (
                        b"?" + q[1] if len(q) > 1 else b"")
        await self.app(scope, receive, send)


# Added last, so it is outermost and nothing escapes without it.
app.add_middleware(_headers.SecurityHeaders)
app.add_middleware(ApiSlash)

# Outside Gatekeeper on purpose, so a REFUSED request is recorded as
# well: a run of 401s from an address nobody recognises is the entry
# most worth having, and a middleware inside the gate never sees one.
# It is inside SecurityHeaders only because it must not be the thing
# that stops a response being stamped.
app.add_middleware(AuditTrail)

for r in (auth.router, google.router, magic.router, projects.router, targets.router,
          services.router, findings.router, credentials.router,
          explore.router, actions.router, settings.router, bulk.router,
          scans.router, web.router, domains.router, agent.router,
          rest.router, api_index.router, agents.router, enumerate_routes.router,
          reports.router,
          audit.router,
          vulnfeeds.router,
          meta.router):
    app.include_router(r)

# Serve the built SPA when it exists, so one process runs the whole app.
_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    #: `_DIST` with every symlink resolved, so containment can be tested
    #: against a canonical path rather than the string that was typed.
    _DIST_REAL = _DIST.resolve()

    def dist_file(full_path: str) -> Path | None:
        """A real file inside the built SPA, or None.

        `_DIST / full_path` is NOT safe by itself, which is how this was
        written first. Two ways out of the directory:

          "/etc/passwd"        an absolute right-hand side replaces the
                               base entirely — pathlib documents this
          "../../backend/..."  climbs out a segment at a time

        Browsers collapse `..` before sending, so this never shows up in
        normal use; `curl --path-as-is` and anything speaking raw HTTP do
        not. Verified reachable as a signed-in user: it returned
        app/main.py and the whole 91 MB SQLite database, which holds the
        password hashes, stored credentials and API keys. Resolve first,
        then require the result to still be under the dist directory.
        """
        if not full_path:
            return None
        candidate = (_DIST / full_path).resolve()
        if candidate != _DIST_REAL and _DIST_REAL not in candidate.parents:
            return None
        return candidate if candidate.is_file() else None

    #: Paths the single-page app owns. A browser asking for one gets the
    #: app; anything else gets redirected to the JSON underneath it, so the
    #: same URL works whether you paste it into a tab or into curl.
    #:
    #: This MUST match GLOBAL ∪ SCOPED in frontend/src/lib/route.ts. It is
    #: a second copy of a list that lives there, and it drifted: `drone`
    #: and `settings` were added to the app and not here, so every deep
    #: link and every refresh on those pages answered 404 while the page
    #: worked perfectly if you navigated to it. `webtest.py` reads the
    #: TypeScript and fails when the two disagree, because the next view
    #: added will be added in one place again.
    SPA_ROUTES = ("projects", "targets", "services", "web", "vulns",
                  "credentials", "reports", "import", "config", "users",
                  "profile", "drones", "settings")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(request: Request, full_path: str):
        # An unknown /api/... path must answer as JSON, not fall through to
        # index.html — a client getting HTML back from a typo'd endpoint is a
        # genuinely confusing way to debug.
        if full_path.startswith("api/"):
            # Slashed paths never arrive here: ApiSlash (below) has
            # already rewritten them. Anything left really is unknown.
            raise HTTPException(404, f"no such endpoint: /{full_path}")
        if (asset := dist_file(full_path)) is not None:
            return FileResponse(asset)
        head = full_path.strip("/").split("/", 1)[0]
        if head in SPA_ROUTES:
            # One URL, two readers. A browser gets the app, which routes
            # on the same path; a program gets the resource it named.
            if wants_html(request):
                return FileResponse(_DIST / "index.html")
            target = "/api/" + full_path.strip("/")
            if request.url.query:
                target += f"?{request.url.query}"
            return RedirectResponse(target, status_code=307)

        # Reaching here means the gate let it through, so the caller is
        # authenticated and an honest 404 costs nothing — there is no
        # longer anything to withhold by pretending every path is
        # forbidden. An unauthenticated caller never gets this far; the
        # gate redirects them to sign in.
        if full_path:
            if wants_html(request):
                return HTMLResponse(NOT_FOUND_HTML, status_code=404)
            raise HTTPException(404, f"no such path: /{full_path}")

        # The root. A browser gets the app, which routes "/" to the
        # project list; a program gets the API index, for the same reason
        # the nested paths redirect — one URL, two readers.
        if not wants_html(request):
            return RedirectResponse("/api", status_code=307)
        return FileResponse(_DIST / "index.html")
