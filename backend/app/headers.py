"""Security headers, derived from the configured base URL.

They are computed from `site.base_url` rather than hard-coded because the
right answer differs between a laptop on http://127.0.0.1:8000 and a
deployment behind TLS. Sending HSTS from a plain-http dev server teaches
the browser to refuse the thing you are developing; omitting it in
production leaves the first request downgradeable. One setting decides.

The content-security policy is the part worth reading. It is tight on
purpose:

  default-src 'self'        nothing loads from anywhere else
  script-src  'self'        no inline script, no CDN — the SPA is one
                            bundle served from here
  style-src   'self' 'unsafe-inline'
                            MUI injects styles at runtime through
                            Emotion; there is no nonce to give it and
                            removing it would mean abandoning the UI
                            framework. This is the one concession, and it
                            is a real one: with inline styles permitted,
                            a CSS-injection bug stays exploitable.
  img-src     'self' data: https:
                            avatars from Google sign-in, and data: for
                            inline SVG icons
  connect-src 'self' + the configured origins
  frame-ancestors           nothing, unless configured — clickjacking
  form-action 'self'        a form cannot be made to post off-site
  base-uri    'none'        a <base> tag cannot re-point relative URLs

`upgrade-insecure-requests` is added only on https, for the same reason
as HSTS.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

#: Cached per (base_url, extra, hsts, frame) so the policy string is not
#: rebuilt on every single request.
_cache: dict[tuple, dict[str, str]] = {}


def origins(raw: str) -> list[str]:
    out = []
    for piece in (raw or "").replace(";", ",").split(","):
        p = piece.strip().rstrip("/")
        if p and "://" in p:
            out.append(p)
    return out


def build(base_url: str, extra: str = "", hsts_days: int = 365,
          frame_ancestors: str = "") -> dict[str, str]:
    key = (base_url, extra, hsts_days, frame_ancestors)
    if key in _cache:
        return _cache[key]

    bits = urlsplit(base_url or "")
    secure = bits.scheme == "https"
    allowed = origins(extra)
    connect = " ".join(["'self'", *allowed])
    frames = " ".join(origins(frame_ancestors)) or "'none'"

    csp = [
        "default-src 'self'",
        "script-src 'self'",
        # See the module docstring: Emotion injects styles at runtime.
        "style-src 'self' 'unsafe-inline'",
        "style-src-elem 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        f"connect-src {connect}",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        f"frame-ancestors {frames}",
        "frame-src 'none'",
        "worker-src 'self' blob:",
        "manifest-src 'self'",
    ]
    if secure:
        csp.append("upgrade-insecure-requests")

    headers = {
        "Content-Security-Policy": "; ".join(csp),
        # Belt and braces for browsers that predate frame-ancestors.
        "X-Frame-Options": "DENY" if frames == "'none'" else "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        # An engagement URL must not leak this host to the target in a
        # Referer when someone clicks through to a finding.
        "Referrer-Policy": "no-referrer",
        # This app needs none of them. Saying so stops an injected iframe
        # or script asking on our behalf.
        "Permissions-Policy": (
            "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
            "encrypted-media=(), fullscreen=(self), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), midi=(), "
            "payment=(), usb=(), xr-spatial-tracking=()"),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Permitted-Cross-Domain-Policies": "none",
    }
    if secure and hsts_days > 0:
        headers["Strict-Transport-Security"] = (
            f"max-age={int(hsts_days) * 86400}; includeSubDomains")

    _cache.clear()          # one deployment, one config; no need to grow
    _cache[key] = headers
    return headers


#: The headers currently in force. Module-level rather than an attribute
#: on the middleware: Starlette stores middleware as a spec and builds the
#: instance itself, so there is no object to reach in order to update one.
CURRENT: dict[str, str] = build("http://127.0.0.1:8000")


def _is_shell(path: str) -> bool:
    """Whether this path serves the SPA's HTML shell.

    Every SPA route returns index.html, so "has no file extension" is
    the test rather than a list of route names that would drift.
    """
    if path in ("/", "/index.html"):
        return True
    last = path.rsplit("/", 1)[-1]
    return "." not in last


class SecurityHeaders(BaseHTTPMiddleware):
    """Applies the headers to every response, including errors.

    Reading the settings per request would be a database round trip on
    every asset, so they are computed at startup and recomputed when Site
    Config is saved.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for k, v in CURRENT.items():
            # Never clobber something a route set deliberately.
            if k not in response.headers:
                response.headers[k] = v
        # The API is not a web page; stopping it being cached matters
        # more than the few bytes saved.
        path = request.url.path
        if path.startswith("/api/"):
            response.headers.setdefault("Cache-Control",
                                        "no-store, no-cache, must-revalidate")
        elif path.startswith("/assets/"):
            # Vite puts a content hash in these filenames, so a changed
            # file is a changed URL and this can be cached hard.
            response.headers.setdefault(
                "Cache-Control", "public, max-age=31536000, immutable")
        elif _is_shell(path):
            # The shell must NOT be cached. It is the only thing that
            # names the hashed bundle, so a stale copy pins the browser
            # to old JavaScript for as long as the heuristic lasts --
            # with no Cache-Control at all, Chrome invents one from
            # Last-Modified. That is not theoretical: it served a build
            # with a known-broken file import hours after the fix
            # shipped, and looked exactly like the bug still being there.
            response.headers.setdefault(
                "Cache-Control", "no-cache, must-revalidate")
        return response


async def refresh(session) -> dict[str, str]:
    """Recompute from the current settings. Called at startup and on save."""
    global CURRENT, _https
    from .routers.settings import load_all
    cfg = await load_all(session)
    base = str(cfg.get("site.base_url") or "")
    _https = urlsplit(base).scheme == "https"
    CURRENT = build(
        base,
        str(cfg.get("site.extra_origins") or ""),
        int(cfg.get("site.hsts_days") or 0),
        str(cfg.get("site.frame_ancestors") or ""))
    return CURRENT


def cookies_secure() -> bool:
    """Whether session cookies should carry the Secure flag.

    Derived from the same base URL as everything else. Hard-coding
    `secure=True` breaks sign-in on a plain-http dev server — the browser
    accepts the Set-Cookie and then never sends it back, which looks
    exactly like a broken password. Hard-coding False, which is what this
    did before, ships a session cookie that travels in clear over any
    downgrade.
    """
    return CURRENT.get("Strict-Transport-Security") is not None or _https


#: Set alongside CURRENT so the two cannot disagree.
_https = False
