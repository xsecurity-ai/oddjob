"""Authentication and per-project authorisation.

AUTHENTICATION accepts three credentials, checked in this order:
  1. Authorization: Bearer <jwt>      browser SPA after login, and scripts
  2. Authorization: Bearer <api key>  long-lived, for the MCP server and CI
  3. the `oddjob_token` cookie       httpOnly, set by /api/auth/login

AUTHORISATION is per project. A user's effective role on a project is the
HIGHEST of:
  - their direct ProjectACL grant
  - the grant on any group they belong to
  - admin, if they are in the site-admins group
No grant at all means no access -- deny by default, including for listing.

Roles are ordered readonly < user < admin, so a route declares the minimum it
needs (`Depends(require_project("user"))`) and the comparison is ordinal.
"""
from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db import get_session
from .models import ROLE_ORDER, SITE_ADMIN_GROUP, ApiKey, Project, ProjectACL, User

ALGO = "HS256"
TOKEN_TTL_HOURS = int(os.environ.get("ODDJOB_TOKEN_TTL_HOURS", "12"))
COOKIE = "oddjob_token"
_ph = PasswordHasher()


def _secret() -> str:
    """Persist a generated secret so tokens survive a restart.

    An ephemeral key would log every user out on each reload, which in
    practice trains people to keep a long-lived token lying around instead.
    """
    env = os.environ.get("ODDJOB_SECRET")
    if env:
        return env
    path = Path(os.environ.get("ODDJOB_SECRET_FILE",
                               Path(__file__).resolve().parents[1] / ".secret"))
    if path.exists():
        return path.read_text().strip()
    val = secrets.token_urlsafe(48)
    path.write_text(val)
    path.chmod(0o600)
    return val


SECRET = _secret()


# ------------------------------------------------------------- passwords
def hash_password(p: str) -> str:
    return _ph.hash(p)


def verify_password(p: str, hashed: str) -> bool:
    try:
        _ph.verify(hashed, p)
        return True
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _ph.check_needs_rehash(hashed)
    except Exception:
        return False


# ---------------------------------------------------------------- tokens
def create_access_token(user: User) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {"sub": str(user.id), "username": user.username,
         "iat": now, "exp": now + timedelta(hours=TOKEN_TTL_HOURS)},
        SECRET, algorithm=ALGO)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        return None


# --------------------------------------------------------------- api keys
API_KEY_PREFIX = "msk_"


def new_api_key() -> tuple[str, str, str]:
    """-> (plaintext, prefix, hash). Plaintext is shown once and never stored."""
    raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:12], _ph.hash(raw)


# ------------------------------------------------------------ current user
async def get_current_user(request: Request,
                           session: AsyncSession = Depends(get_session)) -> User:
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    if not token:
        token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})

    if token.startswith(API_KEY_PREFIX):
        rows = (await session.execute(
            select(ApiKey).where(ApiKey.prefix == token[:12],
                                 ApiKey.revoked.is_(False)))).scalars().all()
        for k in rows:
            try:
                _ph.verify(k.key_hash, token)
            except Exception:
                continue
            k.last_used_at = datetime.now(UTC)
            await session.commit()
            u = await session.get(User, k.user_id)
            if u and u.is_active:
                request.state.auth_user = u      # see the note below
                return u
            break
        raise HTTPException(401, "invalid or revoked api key")

    payload = decode_token(token)
    if not payload:
        raise HTTPException(401, "invalid or expired token")
    u = await session.get(User, int(payload.get("sub", 0)))
    if not u or not u.is_active:
        raise HTTPException(401, "user not found or disabled")
    # The audit middleware runs outside the gate and so has no way to
    # name who acted. Stamping it here costs nothing and is the only way
    # an API-key caller gets a name in the log without an argon2 verify
    # on every single request purely to write it down.
    request.state.auth_user = u
    return u


async def require_site_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_site_admin:
        raise HTTPException(403, f"membership of {SITE_ADMIN_GROUP!r} is required")
    return user


# ---------------------------------------------------------- project roles
async def effective_role(session: AsyncSession, user: User, project_id: int) -> str | None:
    """Highest role the user holds on the project, or None for no access."""
    if user.is_site_admin:
        return "admin"
    gids = [g.id for g in user.groups]
    conds = [ProjectACL.user_id == user.id]
    if gids:
        conds.append(ProjectACL.group_id.in_(gids))
    roles = (await session.execute(
        select(ProjectACL.role).where(ProjectACL.project_id == project_id,
                                      or_(*conds)))).scalars().all()
    if not roles:
        return None
    return max(roles, key=lambda r: ROLE_ORDER.get(r, -1))


async def visible_project_ids(session: AsyncSession, user: User) -> list[int] | None:
    """Projects the user can see at all. None means "every project"."""
    if user.is_site_admin:
        return None
    gids = [g.id for g in user.groups]
    conds = [ProjectACL.user_id == user.id]
    if gids:
        conds.append(ProjectACL.group_id.in_(gids))
    return list((await session.execute(
        select(ProjectACL.project_id).where(or_(*conds)).distinct())).scalars().all())


def require_project(minimum: str = "readonly"):
    """Dependency factory. Resolves the `project` path/query param, checks the
    caller holds at least `minimum` on it, and returns the Project."""
    async def _dep(request: Request,
                   user: User = Depends(get_current_user),
                   session: AsyncSession = Depends(get_session)) -> Project:
        ref = request.path_params.get("project") or request.query_params.get("project")
        if not ref:
            raise HTTPException(422, "a project is required for this operation")
        ref = str(ref).strip()
        pr = (await session.execute(
            select(Project).where(
                Project.code == ref.upper().replace(" ", "-")))).scalar_one_or_none()
        if pr is None and ref.isdigit():
            pr = await session.get(Project, int(ref))
        if pr is None:
            raise HTTPException(404, f"no project {ref!r}")
        role = await effective_role(session, user, pr.id)
        if role is None:
            # 404 rather than 403: telling an unauthorised caller that a
            # project exists is itself a disclosure.
            raise HTTPException(404, f"no project {ref!r}")
        if ROLE_ORDER[role] < ROLE_ORDER[minimum]:
            raise HTTPException(403, f"{minimum} required on {pr.code}; you have {role}")
        request.state.project = pr
        request.state.role = role
        return pr
    return _dep


async def assert_role_for_target(session: AsyncSession, user: User,
                                 target_id: int, minimum: str = "user") -> str:
    """Role check for routes addressed by child-object id rather than project.

    Without this a caller with readonly on a project could still DELETE a
    service by guessing its integer id -- the ACL would never be consulted
    because no project appears in the path.

    Returns the project's code. These routes are reached by child id and so
    never had the engagement to hand, which is exactly why their change
    events used to go out unlabelled and therefore to everybody; it is
    already loaded here to do the ACL check, so handing it back costs
    nothing and gives the call site no excuse.
    """
    from .models import Target
    t = await session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    role = await effective_role(session, user, t.project_id)
    if role is None:
        raise HTTPException(404, "not found")
    if ROLE_ORDER[role] < ROLE_ORDER[minimum]:
        raise HTTPException(403, f"{minimum} required; you have {role}")
    pr = await session.get(Project, t.project_id)
    return pr.code if pr else ""


# ------------------------------------------------------------ agent keys
#: Drone keys are 256 bits of randomness that we generate, not passwords
#: a person chose, and they are checked on every heartbeat.
#:
#: So SHA-256 and not argon2. Argon2 is deliberately slow to make
#: guessing a low-entropy secret expensive; against a key with 256 bits
#: of entropy there is nothing to guess, and the slowness would instead
#: be paid on every poll by every agent. The comparison is still
#: constant-time, because the hash is the thing an attacker would try
#: to match.
AGENT_KEY_PREFIX = "drone_"


def new_agent_key() -> tuple[str, str]:
    """-> (plaintext, hash). The plaintext is shown once and never stored."""
    raw = AGENT_KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, _hash_key(raw)


def _hash_key(raw: str) -> str:
    import hashlib
    return hashlib.sha256((raw or "").encode()).hexdigest()


def verify_key(raw: str | None, hashed: str | None) -> bool:
    """Constant-time check of a key against its stored hash."""
    if not raw or not hashed:
        return False
    return secrets.compare_digest(_hash_key(raw), hashed)
