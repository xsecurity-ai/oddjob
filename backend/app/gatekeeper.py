"""One gate in front of everything, plus the page an unauthenticated visitor sees.

Why middleware rather than a dependency on each route: a route dependency can
only protect routes that exist. The requirement is that *anything* a stranger
asks for is refused the same way -- `/api/targets`, `/openapi.json`, `/wp-admin`
and `/.env` alike. Only a layer that runs before routing can do that, because
by the time FastAPI has decided there is no route, the 404 has already told the
caller that this path is not one of ours.

So this is deliberately a second, coarser layer rather than a replacement: every
route keeps its own `get_current_user` / `require_project` checks, which are the
authoritative ones (is the account still active, does it hold a role on this
project). The gate's only job is "did you present a credential at all". If the
gate were ever bypassed or misconfigured, the routes would still be closed.

What stays public is the smallest set that makes signing in possible:
the SPA shell and its bundle, and the sign-in endpoints themselves. Everything
else, known or unknown, is refused.
"""
from __future__ import annotations

import re

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                                 Response)

from urllib.parse import quote

from .security import API_KEY_PREFIX, COOKIE, decode_token

# Paths served to anyone, because the login screen cannot render without them.
PUBLIC_EXACT = {
    "/", "/index.html", "/favicon.ico", "/favicon-32.png",
    "/icon-192.png", "/icon-512.png",
    "/apple-touch-icon.png", "/vite.svg", "/robots.txt",
    "/manifest.webmanifest",
    # Sign-in. /setup is the bootstrap the user explicitly excepted: it is the
    # only way the first account can exist, and it refuses once one does.
    "/api/auth/setup",
    "/api/auth/setup-required",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/methods",
    "/api/auth/magic-link",
    "/api/auth/google/start",
    "/api/auth/google/callback",
    "/api/auth/google/status",
    # See PUBLIC_PREFIX: these carry an agent key, not a session.
    "/api/agents/register",
    "/api/agents/heartbeat",
    # The one-time token is the credential here; there is no identity yet.
    "/api/agents/enroll",
    "/api/agents/enrol",      # the old spelling, still answered
}

PUBLIC_PREFIX = (
    "/assets/",            # the built bundle; the shell is useless without it
    "/api/auth/magic/",    # redeeming a link arrives with no session yet
)

# Drone agents. NOT unauthenticated — they authenticate with an agent key,
# which this middleware knows nothing about, so the route's own dependency
# has to be the thing that checks. Matched exactly rather than by a
# "/api/agents/tasks/" prefix: under a prefix, every route later added
# below it is public by default, and the one that gets added is an
# operator-facing one. The two routes an agent actually calls are both
# of the form /api/agents/tasks/{int}/{verb}, so say that.
PUBLIC_AGENT_ROUTE = re.compile(r"^/api/agents/tasks/\d+/(start|result)$")


def is_public(path: str) -> bool:
    return (path in PUBLIC_EXACT
            or path.startswith(PUBLIC_PREFIX)
            or PUBLIC_AGENT_ROUTE.match(path) is not None)


def has_credential(request: Request) -> bool:
    """Coarse check: did the caller present something that could be a session?

    A JWT is verified properly here, so a forged one does not even reach the
    router. An API key can only be checked against the database, and doing an
    argon2 verification twice per request to save a 404 is not a trade worth
    making -- the route's own `get_current_user` is what actually accepts it.
    """
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not token:
        token = request.cookies.get(COOKIE, "")
    if not token:
        return False
    if token.startswith(API_KEY_PREFIX):
        return True
    return decode_token(token) is not None


def wants_html(request: Request) -> bool:
    """Is this a person browsing, or a program calling?

    Sec-Fetch-Mode is the reliable signal in a current browser; Accept is the
    fallback for everything else. curl sends `Accept: */*`, which must not be
    treated as a browser or scripts get a page of HTML where they expected an
    error object.
    """
    if request.headers.get("Sec-Fetch-Mode") == "navigate":
        return True
    return "text/html" in request.headers.get("Accept", "")


class Gatekeeper(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # A CORS preflight carries no credentials by design; blocking it turns
        # every cross-origin call into an opaque network error instead of a 401.
        if request.method == "OPTIONS" or is_public(path):
            return await call_next(request)

        if not has_credential(request):
            return refusal(request)
        return await call_next(request)


#: Everything a path, query or fragment may legitimately contain:
#: RFC 3986 unreserved + sub-delims + the delimiters a URL path uses.
#: An ALLOWLIST, because the first version of this was a denylist
#: (`startswith("//")`, `"://" in p`, …) and five bypasses walked through
#: it. You cannot enumerate what a browser will normalise; you can
#: enumerate what a path is allowed to look like.
_PATH_OK = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "-._~"            # unreserved
    "!$&'()*+,;="     # sub-delims
    ":@"              # allowed within a path segment
    "/?#%[]"          # structure, percent-encoding, IPv6 literals
)


def safe_next(raw: str) -> str:
    r"""A return path that cannot be turned into an off-site redirect.

    The attack this stops: `next=//evil.com` is a protocol-relative URL
    and a browser follows it off-site, so a link to *our* sign-in page
    lands the victim on the attacker's, still trusting the domain they
    clicked. Variants are endless — `/\evil.com` because browsers read a
    backslash as a slash in the authority, and `/<TAB>/evil.com` because
    Chrome *strips* tabs, newlines and returns before parsing and is then
    left with `//evil.com`.

    So this does not try to spot bad input. It accepts only what a local
    path can contain, after removing the characters a browser would
    remove, and then confirms the result parses with no scheme and no
    host. Anything else becomes "/".
    """
    p = raw or ""
    # Exactly what a browser discards before it parses. Doing it first
    # means we validate the string the browser will actually act on, not
    # the one that was sent.
    p = p.translate({0x09: None, 0x0a: None, 0x0d: None})
    if not p or any(ord(c) < 0x20 or ord(c) == 0x7f for c in p):
        return "/"
    if any(c not in _PATH_OK for c in p):
        return "/"          # includes space, backslash and every control
    if not p.startswith("/") or p.startswith("//"):
        return "/"

    # Belt and braces: whatever survived must still parse as a bare path.
    from urllib.parse import urlsplit
    try:
        bits = urlsplit(p)
    except ValueError:
        return "/"
    if bits.scheme or bits.netloc:
        return "/"
    return p[:2048]


def refusal(request: Request) -> Response:
    """Sign-in for a browser, 401 for a program.

    The distinction is not cosmetic. The SPA's fetch layer treats 401 as "your
    session ended, show the sign-in screen", so answering an XHR with a
    redirect would have it parse the login page as JSON. A navigation has no
    such handler and wants the door.

    Every unauthenticated path redirects the same way, so this still tells a
    stranger nothing about which paths exist.
    """
    if wants_html(request):
        wanted = request.url.path
        if request.url.query:
            wanted += f"?{request.url.query}"
        # 302, not 307: the browser should GET the sign-in page, whatever
        # method it tried.
        target = "/" if wanted in ("/", "") else f"/?next={quote(safe_next(wanted), safe='')}"
        return RedirectResponse(target, status_code=302)
    return JSONResponse({"detail": "not authenticated"}, status_code=401,
                        headers={"WWW-Authenticate": "Bearer"})


# The page is standalone on purpose: no bundle, no font fetch, no asset that
# could itself be gated. It has to render correctly as the very first thing a
# stranger ever receives from this host.
def page(code: str, heading: str, body: str, hint: str,
         button: str, href: str) -> str:
    """Fill the template.

    Token replacement rather than str.format: the template is mostly CSS,
    and every `{` in a rule would have to be doubled.
    """
    out = _PAGE
    for token, value in (("@CODE@", code), ("@HEADING@", heading),
                         ("@BODY@", body), ("@HINT@", hint),
                         ("@BUTTON@", button), ("@HREF@", href)):
        out = out.replace(token, value)
    return out


_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>@CODE@ — @HEADING@</title>
<style>
  :root{--bg:#241b2f;--deep:#1a1526;--pink:#ff7edb;--cyan:#36f9f6;--yellow:#fede5d;
        --purple:#b893ce;--muted:#848bbd}
  *{box-sizing:border-box}
  html,body{height:100%;margin:0}
  body{background:var(--deep);color:var(--purple);
       font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
       display:flex;align-items:center;justify-content:center;
       padding:16px;overflow:hidden;position:relative}
  /* horizon grid */
  body::before{content:"";position:fixed;left:-50%;right:-50%;bottom:-60%;height:120%;
    background-image:linear-gradient(var(--pink) 1px,transparent 1px),
                     linear-gradient(90deg,var(--pink) 1px,transparent 1px);
    background-size:44px 44px;opacity:.14;
    transform:perspective(320px) rotateX(68deg);
    animation:roll 7s linear infinite;pointer-events:none}
  @keyframes roll{to{background-position:0 44px,0 0}}
  /* scanlines */
  body::after{content:"";position:fixed;inset:0;pointer-events:none;
    background:repeating-linear-gradient(180deg,rgba(0,0,0,.22) 0 1px,transparent 1px 3px);
    opacity:.5}
  .card{position:relative;z-index:1;max-width:620px;width:100%;text-align:center;
    padding:40px 28px;border:1px solid rgba(255,126,219,.34);border-radius:14px;
    background:linear-gradient(180deg,rgba(36,27,47,.92),rgba(26,21,38,.92));
    box-shadow:0 0 64px rgba(255,126,219,.14),inset 0 0 44px rgba(54,249,246,.05)}
  .code{font-size:clamp(68px,19vw,132px);line-height:.92;font-weight:800;
    letter-spacing:.06em;color:var(--pink);
    text-shadow:0 0 6px currentColor,0 0 18px currentColor,0 0 42px rgba(255,126,219,.55);
    animation:flicker 4.2s infinite}
  @keyframes flicker{0%,96%,100%{opacity:1}97%{opacity:.62}98.5%{opacity:.9}}
  h1{margin:6px 0 0;font-size:clamp(14px,3.6vw,19px);letter-spacing:.42em;
     text-transform:uppercase;color:var(--cyan);
     text-shadow:0 0 6px currentColor,0 0 20px rgba(54,249,246,.45)}
  .rule{height:1px;margin:24px auto;max-width:300px;
    background:linear-gradient(90deg,transparent,var(--pink),transparent);opacity:.65}
  p{margin:0 auto;max-width:44ch;font-size:13.5px;line-height:1.75;color:var(--muted)}
  .hint{margin-top:10px;color:var(--yellow);opacity:.82;font-size:12.5px}
  a.btn{display:inline-block;margin-top:28px;padding:11px 30px;border-radius:8px;
    text-decoration:none;font-size:12.5px;letter-spacing:.22em;text-transform:uppercase;
    color:var(--cyan);border:1px solid rgba(54,249,246,.5);
    background:rgba(54,249,246,.07);
    text-shadow:0 0 8px rgba(54,249,246,.6);transition:all .18s ease}
  a.btn:hover{background:rgba(54,249,246,.16);box-shadow:0 0 26px rgba(54,249,246,.3)}
  .tag{margin-top:26px;font-size:10.5px;letter-spacing:.34em;color:var(--muted);opacity:.42}
  @media (prefers-reduced-motion:reduce){
    body::before{animation:none}.code{animation:none}}
</style></head><body>
<div class="card">
  <div class="code">@CODE@</div>
  <h1>@HEADING@</h1>
  <div class="rule"></div>
  <p>@BODY@</p>
  <p class="hint">@HINT@</p>
  <a class="btn" href="@HREF@">@BUTTON@</a>
  <div class="tag">ODDJOB</div>
</div>
</body></html>"""


#: Kept for anything that still refuses outright rather than redirecting.
FORBIDDEN_HTML = page(
    "403", "Access Denied",
    "You are signed in, but this is not yours to see.",
    "If you think it should be, ask whoever administers the engagement.",
    "Back to Oddjob", "/")

#: What an authenticated user gets for a path that does not exist. Honest,
#: because they have already proved who they are — there is nothing left to
#: withhold by pretending everything is forbidden.
NOT_FOUND_HTML = page(
    "404", "No Such Page",
    "That address does not correspond to anything in Oddjob.",
    "Check the link, or start from the project list.",
    "Project list", "/projects")
