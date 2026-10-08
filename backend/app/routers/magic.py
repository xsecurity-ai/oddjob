"""Magic-link sign-in, and invitations built on the same machinery.

A magic link is a bearer credential that skips the password entirely, so the
handling is deliberately strict:

  single use    `used_at` is stamped inside the same transaction that signs
                you in, so a link forwarded to a mailing list, or sitting in
                a mailbox someone else can read, works exactly once.
  short lived   15 minutes by default.
  hashed        only a hash is stored; the plaintext lives in the email.
  constant answer
                requesting a link ALWAYS returns 202, whether or not the
                account exists. The endpoint is unauthenticated, so any
                difference in response or timing turns it into a free
                "does this person have an account here" oracle.
  throttled     per identifier and per client, because an unauthenticated
                endpoint that sends email is otherwise a mail cannon aimed
                at whoever you name.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..headers import cookies_secure
from ..mailer import send_mail
from ..models import MagicLink, User
from ..security import COOKIE, TOKEN_TTL_HOURS, create_access_token, require_site_admin
from .settings import load_all

log = logging.getLogger("oddjob.magic")
router = APIRouter(prefix="/api/auth", tags=["auth"])

TTL_MINUTES = 15
WINDOW_SECONDS = 900

# Two different limits, because they defend against two different things.
#
#   identifier  don't repeatedly mail ONE person: a 60s cooldown and 3 per
#               15 minutes.
#   client      don't let one source blast many addresses: a higher cap and
#               NO cooldown.
#
# A single shared limit gets this wrong in a way that is invisible: a user
# who mistypes their address and corrects it immediately would have burned
# the budget, and the corrected request is silently dropped — the endpoint
# answers 202 either way, so nobody finds out until the email never arrives.
IDENT_COOLDOWN = 60
IDENT_MAX = 3
CLIENT_MAX = 10

# In-process. Single-worker deployment, so a dict is honest and sufficient;
# it resets on restart, which is the documented trade.
_recent: dict[str, list[float]] = {}


def _throttled(key: str, cooldown: int, cap: int) -> bool:
    now = time.time()
    hits = [t for t in _recent.get(key, []) if now - t < WINDOW_SECONDS]
    _recent[key] = hits
    if cooldown and hits and now - hits[-1] < cooldown:
        return True
    if len(hits) >= cap:
        return True
    hits.append(now)
    return False


def _hash(token: str) -> str:
    # SHA-256, not argon2: these are 256-bit random tokens with a 15-minute
    # life, so there is nothing to brute force, and a login path should not
    # spend 100ms of CPU per lookup.
    return hashlib.sha256(token.encode()).hexdigest()


async def _issue(session: AsyncSession, user: User, purpose: str) -> str:
    token = secrets.token_urlsafe(32)
    session.add(MagicLink(
        user_id=user.id, token_hash=_hash(token), purpose=purpose,
        expires_at=datetime.now(UTC) + timedelta(minutes=TTL_MINUTES)))
    await session.commit()
    return token


def _email_body(cfg: dict, token: str, purpose: str) -> tuple[str, str]:
    site = cfg.get("site.name") or "Oddjob"
    base = str(cfg.get("site.base_url") or "http://127.0.0.1:8000").rstrip("/")
    link = f"{base}/api/auth/magic/{token}"
    if purpose == "invite":
        subject = f"You have been invited to {site}"
        body = (f"An account has been created for you on {site}.\n\n"
                f"Open this link to sign in and set a password:\n\n  {link}\n\n"
                f"It works once and expires in {TTL_MINUTES} minutes.\n")
    else:
        subject = f"Your {site} sign-in link"
        body = (f"Open this link to sign in to {site}:\n\n  {link}\n\n"
                f"It works once and expires in {TTL_MINUTES} minutes.\n"
                f"If you did not ask for it, you can ignore this email.\n")
    return subject, body


class MagicRequest(BaseModel):
    identifier: str


class AuthMethods(BaseModel):
    password: bool = True
    google: bool
    magic_link: bool
    self_registration: bool


@router.get("/methods", response_model=AuthMethods)
async def methods(session: AsyncSession = Depends(get_session)):
    """Unauthenticated: the sign-in page needs to know what to offer."""
    import os
    cfg = await load_all(session)
    google = bool(cfg.get("auth.google_enabled")) and bool(
        os.environ.get("ODDJOB_GOOGLE_CLIENT_ID", "").strip())
    return AuthMethods(
        google=google,
        magic_link=bool(cfg.get("smtp.host")),
        self_registration=bool(cfg.get("auth.allow_self_registration")),
    )


@router.post("/magic-link", status_code=202)
async def request_magic_link(body: MagicRequest, request: Request,
                             session: AsyncSession = Depends(get_session)):
    """Always 202. Never reveals whether the account exists."""
    ident = body.identifier.strip().lower()
    client = request.client.host if request.client else "?"
    answer = {"status": "accepted",
              "detail": "If that account exists and email is configured, a link is on its way."}

    # Client budget first and unconditionally, so a flood of made-up
    # addresses still counts against the source.
    if not ident or _throttled(f"ip:{client}", 0, CLIENT_MAX):
        return answer
    if _throttled(f"id:{ident}", IDENT_COOLDOWN, IDENT_MAX):
        return answer

    u = (await session.execute(select(User).where(
        or_(User.username == ident, User.email == ident)))).scalar_one_or_none()
    if not u or not u.is_active or not u.email:
        return answer

    cfg = await load_all(session)
    if not cfg.get("smtp.host"):
        return answer

    token = await _issue(session, u, "login")
    subject, text = _email_body(cfg, token, "login")
    try:
        await send_mail(cfg, u.email, subject, text)
    except Exception as e:
        # Still 202 to the caller: a delivery failure must not become the
        # signal that distinguishes a real account from a made-up one. But
        # log it, or an SMTP misconfiguration is undiagnosable from either
        # side — the user sees nothing and the operator sees nothing.
        log.warning("magic-link send failed for user %s: %s: %s",
                    u.id, type(e).__name__, e)
    return answer


@router.get("/magic/{token}")
async def redeem(token: str, session: AsyncSession = Depends(get_session)):
    now = datetime.now(UTC)
    link = (await session.execute(
        select(MagicLink).where(MagicLink.token_hash == _hash(token)))).scalar_one_or_none()
    if link is None:
        raise HTTPException(400, "this link is not valid")
    if link.used_at is not None:
        raise HTTPException(400, "this link has already been used")
    # SQLite can hand back a naive datetime; compare like with like.
    exp = link.expires_at if link.expires_at.tzinfo else link.expires_at.replace(tzinfo=UTC)
    if exp < now:
        raise HTTPException(400, "this link has expired — request a new one")

    u = await session.get(User, link.user_id)
    if not u or not u.is_active:
        raise HTTPException(403, "this account is not active")

    link.used_at = now
    await session.commit()

    base = str((await load_all(session)).get("site.base_url") or "").rstrip("/")
    r = RedirectResponse(f"{base}/" if base else "/", status_code=303)
    r.set_cookie(COOKIE, create_access_token(u), httponly=True, samesite="lax",
                 max_age=TOKEN_TTL_HOURS * 3600, secure=cookies_secure())
    return r


class InviteResult(BaseModel):
    ok: bool
    detail: str


async def deliver_invite(session: AsyncSession, user: User, cfg: dict) -> InviteResult:
    """Issue a single-use link for `user` and mail it to them.

    Shared by the invite endpoint and by invitation-driven account creation
    in `auth.py`, so both produce the same email, the same TTL and the same
    honest report. Never raises: every caller here is already authenticated
    and privileged, so a delivery failure is theirs to see and retry rather
    than a 500.
    """
    if not user.email:
        return InviteResult(ok=False, detail=f"{user.username} has no email address set")
    if not cfg.get("smtp.host"):
        return InviteResult(ok=False, detail="SMTP is not configured — see Site Config")

    token = await _issue(session, user, "invite")
    subject, text = _email_body(cfg, token, "invite")
    try:
        await send_mail(cfg, user.email, subject, text)
    except Exception as e:
        return InviteResult(ok=False, detail=f"{type(e).__name__}: {e}")
    await broker.publish("users", action="invited")
    return InviteResult(ok=True, detail=f"invitation sent to {user.email}")


@router.post("/invite/{username}", response_model=InviteResult)
async def invite(username: str, _: User = Depends(require_site_admin),
                 session: AsyncSession = Depends(get_session)):
    """Email an existing account a link to sign in and set a password.

    Authenticated and site-admin only, so unlike /magic-link it CAN report
    failure honestly — there is no account-existence to protect from someone
    who can already list every account.
    """
    u = (await session.execute(
        select(User).where(User.username == username.lower()))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, f"no user {username!r}")
    return await deliver_invite(session, u, await load_all(session))
