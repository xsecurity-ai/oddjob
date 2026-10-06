"""Login, users, groups, per-project ACLs and API keys."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..headers import cookies_secure
from ..db import get_session
from ..events import broker
from .. import slack
from ..models import (ApiKey, Group, Project, ProjectACL,
                      SITE_ADMIN_GROUP, User)
from pydantic import BaseModel

from ..schemas import (AclGrant, AclOut, ApiKeyCreated, ApiKeyOut, GroupCreate,
                       GroupOut, LoginRequest, LoginResponse, MeResponse,
                       ProfileUpdate, UserCreate, UserOut, UserUpdate)
from ..security import (COOKIE, TOKEN_TTL_HOURS, create_access_token,
                        effective_role, get_current_user, hash_password,
                        new_api_key, require_project, require_site_admin,
                        verify_password)

router = APIRouter(prefix="/api", tags=["auth"])


# ------------------------------------------------------------ first run
# There is deliberately NO seeded admin account. A shipped default credential
# is a permanent hole: it survives in deployments nobody re-secured, and it is
# the first thing anyone tries. Instead the app refuses to be useful until a
# human creates the first account, and the endpoint that does so stops
# working the moment one exists.

async def _user_count(session: AsyncSession) -> int:
    return int((await session.execute(
        select(func.count()).select_from(User))).scalar_one())


@router.get("/auth/setup-required")
async def setup_required(session: AsyncSession = Depends(get_session)):
    """Unauthenticated on purpose: the SPA has to ask this before it can know
    whether to show a login form or the first-run form."""
    return {"setup_required": await _user_count(session) == 0}


@router.post("/auth/setup", response_model=LoginResponse, status_code=201)
async def first_run_setup(body: UserCreate, response: Response,
                          session: AsyncSession = Depends(get_session)):
    """Create the first account, as site admin. Works only while there are
    zero users; afterwards it is permanently 409."""
    if await _user_count(session) > 0:
        raise HTTPException(409, "setup already completed; sign in instead")
    admins = Group(name=SITE_ADMIN_GROUP,
                   description="Site administrators. Bypasses every project ACL.")
    u = User(username=body.username, email=body.email, full_name=body.full_name,
             password_hash=hash_password(body.password))
    u.groups.append(admins)                  # the first user runs the site
    session.add_all([admins, u])
    try:
        await session.commit()
    except IntegrityError:
        # Two setup requests raced; the unique index on username is the real
        # guard, the count check above is just the friendly path.
        await session.rollback()
        raise HTTPException(409, "setup already completed; sign in instead")
    token = create_access_token(u)
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax",
                        max_age=TOKEN_TTL_HOURS * 3600, secure=cookies_secure())
    return LoginResponse(access_token=token, expires_in=TOKEN_TTL_HOURS * 3600,
                         user=UserOut.model_validate(u))


@router.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, response: Response,
                session: AsyncSession = Depends(get_session)):
    u = (await session.execute(
        select(User).where(User.username == body.username.strip().lower()))).scalar_one_or_none()
    # Same message and same work either way: a different error or a faster
    # reply for an unknown username tells an attacker which names are real.
    if not u or not u.password_hash or not u.is_active \
            or not verify_password(body.password, u.password_hash):
        # Same message and comparable work in every branch: a distinct error
        # for "this is a Google-only account" tells an attacker which names
        # are real and how they authenticate.
        if not u or not u.password_hash:
            hash_password(body.password)
        raise HTTPException(401, "invalid username or password")
    token = create_access_token(u)
    response.set_cookie(
        COOKIE, token, httponly=True, samesite="lax",
        max_age=TOKEN_TTL_HOURS * 3600,
        # Secure would break plain-http localhost use; set ODDJOB_SECURE_COOKIE
        # when this is served over TLS.
        secure=cookies_secure(),
    )
    return LoginResponse(access_token=token, expires_in=TOKEN_TTL_HOURS * 3600,
                         user=UserOut.model_validate(u))


@router.post("/auth/logout", status_code=204)
async def logout(response: Response):
    response.delete_cookie(COOKIE)


@router.get("/auth/me", response_model=MeResponse)
async def me(user: User = Depends(get_current_user),
             session: AsyncSession = Depends(get_session)):
    projects: dict[str, str] = {}
    for pr in (await session.execute(select(Project))).scalars():
        role = await effective_role(session, user, pr.id)
        if role:
            projects[pr.code] = role
    return MeResponse(user=UserOut.model_validate(user), projects=projects)


@router.patch("/auth/me", response_model=UserOut)
async def update_profile(body: ProfileUpdate, user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """Self-service profile edits.

    Changing an existing password requires the current one. Without that,
    anyone who walks up to an unlocked session — or steals a token — can lock
    the real owner out by rotating the password.

    A Google-only account has no current password, so it may SET one without
    proving a previous; there is nothing to prove.
    """
    data = body.model_dump(exclude_unset=True)
    new = data.pop("new_password", None)
    current = data.pop("current_password", None)

    if new:
        if user.password_hash:
            if not current:
                raise HTTPException(422, "current_password is required to change a password")
            if not verify_password(current, user.password_hash):
                raise HTTPException(403, "current password is incorrect")
        user.password_hash = hash_password(new)

    if "slack_handle" in data:
        # Stored bare. "@alice" and "alice" are one person, and keeping
        # both spellings would make the workspace lookup miss half the
        # time depending on how someone typed it.
        h = (data["slack_handle"] or "").strip().lstrip("@")
        data["slack_handle"] = h or None

    for k, v in data.items():
        setattr(user, k, v)
    await session.commit()
    u = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
    return UserOut.model_validate(u)


class SelectableUser(BaseModel):
    id: int
    username: str
    full_name: str | None = None


@router.get("/users/selectable", response_model=list[SelectableUser])
async def selectable_users(user: User = Depends(get_current_user),
                           session: AsyncSession = Depends(get_session)):
    """The people a project admin may grant access to.

    Deliberately narrower than /api/users: id, username and name only — no
    email, no flags, no group membership. A project admin needs to pick a
    person from a list; they do not need the staff directory. Site admins use
    the full endpoint.
    """
    if not user.is_site_admin:
        admin_somewhere = (await session.execute(
            select(ProjectACL.id).where(ProjectACL.user_id == user.id,
                                        ProjectACL.role == "admin").limit(1))).first()
        if not admin_somewhere:
            # Group-granted admin counts too.
            gids = [g.id for g in user.groups]
            if gids:
                admin_somewhere = (await session.execute(
                    select(ProjectACL.id).where(ProjectACL.group_id.in_(gids),
                                                ProjectACL.role == "admin").limit(1))).first()
        if not admin_somewhere:
            raise HTTPException(403, "you administer no projects")
    rows = (await session.execute(
        select(User).where(User.is_active.is_(True)).order_by(User.username))).scalars()
    return [SelectableUser(id=u.id, username=u.username, full_name=u.full_name) for u in rows]


# ----------------------------------------------------------------- users
@router.get("/users", response_model=list[UserOut])
async def list_users(_: User = Depends(require_site_admin),
                     session: AsyncSession = Depends(get_session)):
    return [UserOut.model_validate(u) for u in
            (await session.execute(select(User).order_by(User.username))).scalars()]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(body: UserCreate, _: User = Depends(require_site_admin),
                      session: AsyncSession = Depends(get_session)):
    if (await session.execute(
            select(User).where(User.username == body.username))).scalar_one_or_none():
        raise HTTPException(409, f"user {body.username!r} already exists")
    u = User(username=body.username, email=body.email, full_name=body.full_name,
             password_hash=hash_password(body.password))
    session.add(u)
    await session.commit()
    # Re-select so the `groups` relationship is loaded. UserOut exposes
    # is_site_admin, which reads groups; on a freshly added instance that
    # attribute has never been loaded and touching it emits IO from inside
    # Pydantic, where there is no greenlet to await on.
    u = (await session.execute(select(User).where(User.id == u.id))).scalar_one()
    await broker.publish("users", action="create")
    return UserOut.model_validate(u)


@router.patch("/users/{username}", response_model=UserOut)
async def update_user(username: str, body: UserUpdate,
                      _: User = Depends(require_site_admin),
                      session: AsyncSession = Depends(get_session)):
    u = (await session.execute(
        select(User).where(User.username == username.lower()))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, f"no user {username!r}")
    data = body.model_dump(exclude_unset=True)
    if "password" in data and data["password"]:
        u.password_hash = hash_password(data.pop("password"))
    data.pop("password", None)
    for k, v in data.items():
        setattr(u, k, v)
    await session.commit()
    return UserOut.model_validate(u)


@router.delete("/users/{username}", status_code=204)
async def delete_user(username: str, actor: User = Depends(require_site_admin),
                      session: AsyncSession = Depends(get_session)):
    u = (await session.execute(
        select(User).where(User.username == username.lower()))).scalar_one_or_none()
    if not u:
        raise HTTPException(404, f"no user {username!r}")
    if u.id == actor.id:
        raise HTTPException(409, "refusing to delete the account you are signed in as")
    if u.is_site_admin:
        admins = (await session.execute(
            select(Group).where(Group.name == SITE_ADMIN_GROUP))).scalar_one_or_none()
        if admins and len(admins.users) <= 1:
            raise HTTPException(409, f"{username!r} is the only {SITE_ADMIN_GROUP} member")
    await session.delete(u)
    await session.commit()


# ---------------------------------------------------------------- groups
@router.get("/groups", response_model=list[GroupOut])
async def list_groups(_: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    return [GroupOut.model_validate(g) for g in
            (await session.execute(select(Group).order_by(Group.name))).scalars()]


@router.post("/groups", response_model=GroupOut, status_code=201)
async def create_group(body: GroupCreate, _: User = Depends(require_site_admin),
                       session: AsyncSession = Depends(get_session)):
    if (await session.execute(
            select(Group).where(Group.name == body.name))).scalar_one_or_none():
        raise HTTPException(409, f"group {body.name!r} already exists")
    g = Group(**body.model_dump())
    session.add(g)
    await session.commit()
    return GroupOut.model_validate(g)


@router.post("/groups/{name}/members/{username}", response_model=GroupOut)
async def add_member(name: str, username: str, _: User = Depends(require_site_admin),
                     session: AsyncSession = Depends(get_session)):
    g = (await session.execute(select(Group).where(Group.name == name))).scalar_one_or_none()
    u = (await session.execute(
        select(User).where(User.username == username.lower()))).scalar_one_or_none()
    if not g or not u:
        raise HTTPException(404, "no such group or user")
    if u not in g.users:
        g.users.append(u)
        await session.commit()
    return GroupOut.model_validate(g)


@router.delete("/groups/{name}/members/{username}", status_code=204)
async def remove_member(name: str, username: str, _: User = Depends(require_site_admin),
                        session: AsyncSession = Depends(get_session)):
    g = (await session.execute(select(Group).where(Group.name == name))).scalar_one_or_none()
    u = (await session.execute(
        select(User).where(User.username == username.lower()))).scalar_one_or_none()
    if not g or not u:
        raise HTTPException(404, "no such group or user")
    if g.name == SITE_ADMIN_GROUP and len(g.users) <= 1:
        # Emptying site-admins leaves nobody able to administer users or
        # grant project access — unrecoverable without editing the database.
        raise HTTPException(
            409, f"{SITE_ADMIN_GROUP} must keep at least one member; "
                 f"add another before removing {username!r}")
    if u in g.users:
        g.users.remove(u)
        await session.commit()


@router.delete("/groups/{name}", status_code=204)
async def delete_group(name: str, _: User = Depends(require_site_admin),
                       session: AsyncSession = Depends(get_session)):
    if name == SITE_ADMIN_GROUP:
        raise HTTPException(409, f"{SITE_ADMIN_GROUP} is reserved and cannot be deleted")
    g = (await session.execute(select(Group).where(Group.name == name))).scalar_one_or_none()
    if not g:
        raise HTTPException(404, f"no group {name!r}")
    await session.delete(g)
    await session.commit()


# ------------------------------------------------------------------ acls
@router.get("/projects/{project}/acl", response_model=list[AclOut])
async def list_acl(project: str, pr: Project = Depends(require_project("admin")),
                   session: AsyncSession = Depends(get_session)):
    out = []
    for a in (await session.execute(
            select(ProjectACL).where(ProjectACL.project_id == pr.id))).scalars():
        u = await session.get(User, a.user_id) if a.user_id else None
        g = await session.get(Group, a.group_id) if a.group_id else None
        out.append(AclOut(id=a.id, project_code=pr.code, role=a.role,
                          username=u.username if u else None,
                          group=g.name if g else None))
    return out


@router.post("/projects/{project}/acl", response_model=AclOut, status_code=201)
async def grant(project: str, body: AclGrant,
                pr: Project = Depends(require_project("admin")),
                session: AsyncSession = Depends(get_session)):
    if bool(body.username) == bool(body.group):
        raise HTTPException(422, "give exactly one of username or group")
    u = g = None
    if body.username:
        u = (await session.execute(select(User).where(
            User.username == body.username.lower()))).scalar_one_or_none()
        if not u:
            raise HTTPException(404, f"no user {body.username!r}")
    else:
        g = (await session.execute(select(Group).where(
            Group.name == body.group))).scalar_one_or_none()
        if not g:
            raise HTTPException(404, f"no group {body.group!r}")
    existing = (await session.execute(select(ProjectACL).where(
        ProjectACL.project_id == pr.id,
        ProjectACL.user_id == (u.id if u else None),
        ProjectACL.group_id == (g.id if g else None)))).scalar_one_or_none()
    if existing:
        existing.role = body.role          # re-granting changes the role
        acl = existing
    else:
        acl = ProjectACL(project_id=pr.id, user_id=u.id if u else None,
                         group_id=g.id if g else None, role=body.role)
        session.add(acl)
    await session.commit()
    await broker.publish("acl", action="grant", project=pr.code)
    await slack.announce(session, pr, slack.user_joined(
        u.username if u else f"group:{g.name}", acl.role))
    return AclOut(id=acl.id, project_code=pr.code, role=acl.role,
                  username=u.username if u else None, group=g.name if g else None)


@router.delete("/projects/{project}/acl/{acl_id}", status_code=204)
async def revoke(project: str, acl_id: int,
                 pr: Project = Depends(require_project("admin")),
                 session: AsyncSession = Depends(get_session)):
    a = await session.get(ProjectACL, acl_id)
    if not a or a.project_id != pr.id:
        raise HTTPException(404, f"no acl {acl_id} on {pr.code}")
    # Read the name before the row goes: afterwards there is nothing to
    # name in the message.
    who = None
    if a.user_id:
        _u = await session.get(User, a.user_id)
        who = _u.username if _u else None
    elif a.group_id:
        _g = await session.get(Group, a.group_id)
        who = f"group:{_g.name}" if _g else None
    await session.delete(a)
    await session.commit()
    await broker.publish("acl", action="revoke", project=pr.code)
    if who:
        await slack.announce(session, pr, slack.user_removed(who))


# -------------------------------------------------------------- api keys
@router.get("/auth/keys", response_model=list[ApiKeyOut])
async def list_keys(user: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    return [ApiKeyOut.model_validate(k) for k in (await session.execute(
        select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.id))).scalars()]


@router.post("/auth/keys", response_model=ApiKeyCreated, status_code=201)
async def create_key(name: str, user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """The plaintext key is in this response and nowhere else, ever again."""
    raw, prefix, hashed = new_api_key()
    k = ApiKey(user_id=user.id, name=name, prefix=prefix, key_hash=hashed)
    session.add(k)
    await session.commit()
    return ApiKeyCreated(**ApiKeyOut.model_validate(k).model_dump(), key=raw)


@router.delete("/auth/keys/{key_id}", status_code=204)
async def revoke_key(key_id: int, user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    k = await session.get(ApiKey, key_id)
    if not k or (k.user_id != user.id and not user.is_site_admin):
        raise HTTPException(404, f"no api key {key_id}")
    k.revoked = True
    await session.commit()
