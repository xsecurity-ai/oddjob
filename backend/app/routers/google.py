"""Sign in / register with Google.

Standard authorization-code flow. Disabled unless a client id and secret are
configured, in which case /status reports why and the UI hides the button.

    ODDJOB_GOOGLE_CLIENT_ID=...
    ODDJOB_GOOGLE_CLIENT_SECRET=...
    ODDJOB_GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/auth/google/callback

Credentials come from Site Config, falling back to those variables when a
site has never set them, so an existing deployment keeps working. The
settings are authoritative because they are the ones the Test button can
actually exercise before they are relied on.

A GOOGLE-REGISTERED ACCOUNT JOINS NO GROUPS. It can sign in and sees an empty
application until a site admin grants it something. That is the point: the
set of people who hold a Google account is not the set of people who should
see an engagement, so registration must not be authorisation. In particular
Google can never produce the first site admin — that only comes from
first-run setup.
"""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..headers import cookies_secure
from ..db import get_session
from ..events import broker
from ..models import User
from ..routers.settings import load_all
from ..schemas import GoogleStatus
from ..security import ALGO, COOKIE, SECRET, TOKEN_TTL_HOURS, create_access_token

router = APIRouter(prefix="/api/auth/google", tags=["auth"])

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")

ENV_CLIENT_ID = os.environ.get("ODDJOB_GOOGLE_CLIENT_ID", "").strip()
ENV_CLIENT_SECRET = os.environ.get("ODDJOB_GOOGLE_CLIENT_SECRET", "").strip()
ENV_REDIRECT_URI = os.environ.get(
    "ODDJOB_GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/auth/google/callback").strip()
STATE_COOKIE = "oddjob_oauth_state"
STATE_TTL = 600

_jwks: jwt.PyJWKClient | None = None


async def creds(session: AsyncSession) -> tuple[str, str, str]:
    """-> (client_id, client_secret, redirect_uri). Settings win over env."""
    cfg = await load_all(session)
    return (str(cfg.get("auth.google_client_id") or "").strip() or ENV_CLIENT_ID,
            str(cfg.get("auth.google_client_secret") or "").strip() or ENV_CLIENT_SECRET,
            str(cfg.get("auth.google_redirect_uri") or "").strip() or ENV_REDIRECT_URI)


async def _why_disabled(session: AsyncSession) -> str | None:
    cfg = await load_all(session)
    cid, csec, _ = await creds(session)
    if not cid:
        return "no Google client ID is configured"
    if not csec:
        return "no Google client secret is configured"
    # The switch is separate from the credentials on purpose: an admin can
    # stage the client details and turn sign-in on only once Test passes.
    if not cfg.get("auth.google_enabled"):
        return "Google sign-in is switched off in Site Config"
    return None


@router.get("/status", response_model=GoogleStatus)
async def status(session: AsyncSession = Depends(get_session)):
    """Unauthenticated: the sign-in page must know whether to show the button."""
    why = await _why_disabled(session)
    return GoogleStatus(enabled=why is None, reason=why)


def safe_next(raw: str) -> str:
    r"""A path on this site to return to after sign-in, or "/".

    `startswith("/")` is not enough, which is what this used to do.
    `//evil.com` starts with a slash and a browser resolves it as
    `https://evil.com` — a protocol-relative URL. That made the
    sign-in flow an open redirect: send someone
    `/api/auth/google/start?next=//evil.com`, they authenticate
    against the real site, and land on the attacker's, having just
    been shown a genuine Google consent screen. The cookie is not
    leaked, but the credibility is.

    Backslashes are rejected too: some browsers normalise `\` to `/`
    before resolving, so `/\evil.com` is the same attack with a
    different spelling. So is a control character, which can be used
    to break the Location header.
    """
    v = (raw or "/").strip()
    if (not v.startswith("/")          # must be site-relative
            or v.startswith("//")      # protocol-relative
            or v.startswith("/\\")     # ...and its backslash spelling
            or "\\" in v
            or any(c < " " or c == "\x7f" for c in v)):
        return "/"
    return v


@router.get("/start")
async def start(response: Response, next: str = Query("/", description="path to return to"),
                session: AsyncSession = Depends(get_session)):
    why = await _why_disabled(session)
    if why:
        raise HTTPException(503, f"Google sign-in is not configured: {why}")

    # State is a short-lived signed token echoed back by Google and compared
    # against a cookie. Without it, an attacker can feed a victim a callback
    # URL carrying their own code and silently bind the victim's session to
    # the attacker's identity.
    client_id, _secret, redirect_uri = await creds(session)
    nonce = secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    state = jwt.encode({"n": nonce, "next": safe_next(next),
                        "exp": now + timedelta(seconds=STATE_TTL)},
                       SECRET, algorithm=ALGO)
    params = {
        "client_id": client_id, "redirect_uri": redirect_uri,
        "response_type": "code", "scope": "openid email profile",
        "state": state, "prompt": "select_account",
    }
    url = AUTH_URL + "?" + "&".join(f"{k}={httpx.QueryParams({k: v})[k]}" for k, v in params.items())
    r = RedirectResponse(url, status_code=307)
    r.set_cookie(STATE_COOKIE, state, httponly=True, samesite="lax",
                 max_age=STATE_TTL, secure=cookies_secure())
    return r


def _verify_id_token(raw: str, client_id: str) -> dict:
    global _jwks
    if _jwks is None:
        _jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True)
    key = _jwks.get_signing_key_from_jwt(raw).key
    claims = jwt.decode(raw, key, algorithms=["RS256"], audience=client_id,
                        options={"require": ["exp", "iat", "sub", "aud", "iss"]})
    if claims.get("iss") not in ISSUERS:
        raise HTTPException(401, "id_token issuer is not Google")
    return claims


@router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None,
                   error: str | None = None, session: AsyncSession = Depends(get_session)):
    if error:
        raise HTTPException(400, f"Google returned: {error}")
    if await _why_disabled(session):
        raise HTTPException(503, "Google sign-in is not configured")
    client_id, client_secret, redirect_uri = await creds(session)
    if not code or not state:
        raise HTTPException(400, "missing code or state")

    cookie_state = request.cookies.get(STATE_COOKIE)
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        raise HTTPException(400, "state mismatch — start the sign-in again")
    try:
        st = jwt.decode(state, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        raise HTTPException(400, "state expired — start the sign-in again")

    async with httpx.AsyncClient(timeout=20) as c:
        tok = await c.post(TOKEN_URL, data={
            "code": code, "client_id": client_id, "client_secret": client_secret,
            "redirect_uri": redirect_uri, "grant_type": "authorization_code"})
    if tok.status_code != 200:
        raise HTTPException(401, f"token exchange failed: {tok.text[:200]}")
    id_token = tok.json().get("id_token")
    if not id_token:
        raise HTTPException(401, "Google did not return an id_token")

    claims = _verify_id_token(id_token, client_id)
    sub = claims.get("sub")
    email = (claims.get("email") or "").strip().lower()
    if not sub:
        raise HTTPException(401, "id_token has no subject")
    # An unverified address can be anything the user typed, so it must not be
    # used to match an existing local account.
    verified = bool(claims.get("email_verified"))

    u = (await session.execute(select(User).where(User.google_sub == sub))).scalar_one_or_none()
    if u is None and email and verified:
        u = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if u is not None:
            u.google_sub = sub          # link Google to the existing account

    created = False
    if u is None:
        # Domain restriction applies to REGISTRATION only. An existing account
        # whose domain was later removed from the list keeps working; locking
        # people out of accounts they already have is a different decision
        # from deciding who may create one.
        cfg = await load_all(session)
        allowed = [d.strip().lower().lstrip("@")
                   for d in str(cfg.get("auth.google_domains") or "").split(",") if d.strip()]
        if allowed:
            domain = email.split("@")[-1] if "@" in email else ""
            if not verified or domain not in allowed:
                raise HTTPException(
                    403,
                    f"registration is limited to {', '.join(allowed)}; "
                    f"{email or 'this account'} is not eligible")
        base = (email.split("@")[0] if email else f"google-{sub[:8]}")
        base = "".join(ch for ch in base.lower() if ch.isalnum() or ch in "._-") or "user"
        username = base
        n = 1
        while (await session.execute(
                select(User).where(User.username == username))).scalar_one_or_none():
            n += 1
            username = f"{base}{n}"
        # No groups. Registration is identity, not authorisation.
        u = User(username=username, email=email or None,
                 full_name=claims.get("name"), google_sub=sub,
                 avatar_url=claims.get("picture"), password_hash=None)
        session.add(u)
        created = True
    else:
        if claims.get("picture") and not u.avatar_url:
            u.avatar_url = claims["picture"]
        if claims.get("name") and not u.full_name:
            u.full_name = claims["name"]

    if not u.is_active:
        raise HTTPException(403, "this account is disabled")
    await session.commit()
    if created:
        await broker.publish("users", action="register", via="google")

    # Checked again on the way out. The state is signed, so this should
    # already be safe — but a redirect is the last thing that happens
    # before the user leaves, and validating it in one place only means
    # a second way into this dict becomes a second open redirect.
    r = RedirectResponse(safe_next(st.get("next", "/")), status_code=303)
    r.set_cookie(COOKIE, create_access_token(u), httponly=True, samesite="lax",
                 max_age=TOKEN_TTL_HOURS * 3600, secure=cookies_secure())
    r.delete_cookie(STATE_COOKIE)
    return r
