"""Login, users, groups, per-project ACLs and API keys."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, slack
from ..db import get_session
from ..events import broker
from ..headers import cookies_secure
from ..models import ROLE_ORDER, ROLES, SITE_ADMIN_GROUP, ApiKey, Group, Project, ProjectACL, User
from ..schemas import (
    AclGrant,
    AclOut,
    ApiKeyCreated,
    ApiKeyOut,
    GroupCreate,
    GroupOut,
    LoginRequest,
    LoginResponse,
    MeResponse,
    ProfileUpdate,
    UserCreate,
    UserOut,
    UserUpdate,
)
from ..security import (
    COOKIE,
    TOKEN_TTL_HOURS,
    create_access_token,
    effective_role,
    get_current_user,
    hash_password,
    new_api_key,
    require_project,
    require_site_admin,
    verify_password,
)
from .magic import deliver_invite
from .settings import load_all

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
    except IntegrityError as e:
        # Two setup requests raced; the unique index on username is the real
        # guard, the count check above is just the friendly path.
        await session.rollback()
        raise HTTPException(409, "setup already completed; sign in instead") from e
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
        # The username as TYPED, which is the whole value of the entry:
        # a run of failures against one real account reads differently
        # from a spray across names that do not exist. Never the
        # password, and never a hint about which of the two was wrong —
        # the reply does not distinguish them and neither does this.
        await audit.record(
            session, "ui", "auth.login.fail",
            username=body.username.strip().lower()[:128],
            detail="rejected", commit=True)
        raise HTTPException(401, "invalid username or password")
    await audit.record(session, "ui", "auth.login", user=u, commit=True)
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
    # No project: the user list is a site-admin view, and an unlabelled
    # event is delivered to site admins only. See events.py.
    await broker.publish("users", action="create")
    return UserOut.model_validate(u)


# ------------------------------------------- invitation-driven creation
#
# The password flow above asks an administrator to invent a credential for
# somebody else and then send it to them somehow. With mail configured there
# is a better answer: create the account with NO password at all and email a
# single-use link, so the first secret the account has is one its owner chose
# and nobody else ever saw. `password_hash` stays NULL until then, and
# /auth/login refuses an account with no hash, so the window between creation
# and redemption is not a window anyone can sign in through.

#: Everything a username may not contain. UserCreate allows letters, digits
#: and . _ - ; anything else is FOLDED to a hyphen rather than deleted, so
#: "a b@acme.example" and "ab@acme.example" do not derive the same name.
_UNSAFE_IN_USERNAME = re.compile(r"[^a-z0-9._-]+")
#: Deliberately crude. This is not an RFC 5321 parser — it rejects the
#: typos (no @, no dot, stray spaces) and leaves the real verdict to
#: whether the invitation arrives.
_EMAIL = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")


def username_from_email(email: str) -> str:
    """Derive an account name from an address.

    The local part, lowercased, with any +tag dropped and anything outside
    [a-z0-9._-] folded to a hyphen:

        someone@acme.example              -> someone
        Someone.Else+oddjob@acme.example  -> someone.else
        "odd name"@acme.example           -> odd-name

    The +tag goes because two addresses differing only by tag are one
    mailbox, and carrying the tag into the name people see is noise.

    This is a SUGGESTION. It is never applied over an existing account —
    see the collision handling in `invite_user`.
    """
    local = email.split("@", 1)[0].lower().split("+", 1)[0]
    name = _UNSAFE_IN_USERNAME.sub("-", local).strip("-._")[:64].strip("-._")
    # An address whose whole local part is punctuation leaves nothing to
    # name the account after. Better a dull name the admin can change than
    # a 422 they cannot act on.
    return name or "user"


def _clean_username(v: str) -> str:
    """Same rule as UserCreate, as an HTTP error rather than a 422 body."""
    v = (v or "").strip().lower()
    if not v or len(v) > 64:
        raise HTTPException(422, "username must be 1-64 characters")
    if not v.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise HTTPException(422, "username may contain only letters, digits, . _ -")
    return v


async def _free_username(session: AsyncSession, base: str) -> str:
    """A nearby unused name, for the error message only.

    Suggested, never applied. Silently minting `alice2` for a second Alice
    produces two accounts one keystroke apart, and whoever grants project
    access later has no way to tell which one they are looking at.
    """
    for n in range(2, 100):
        cand = f"{base[:64 - len(str(n))]}{n}"
        if not (await session.execute(
                select(User.id).where(User.username == cand))).first():
            return cand
    return ""


class InviteGrant(BaseModel):
    """One project the new account should get, and at what level."""
    project: str
    role: str

    @field_validator("role")
    @classmethod
    def _r(cls, v: str) -> str:
        # ROLE_ORDER is the real list; inventing names here is how a role
        # that authorises nothing gets stored and silently denies everything.
        v = (v or "").strip().lower()
        if v not in ROLE_ORDER:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        return v


class UserInvite(BaseModel):
    email: str
    full_name: str | None = None
    #: Only needed to settle a collision. Normally the server derives it.
    username: str | None = None
    #: The fallback for a deployment with no mail: an invitation cannot be
    #: sent, so somebody has to set a first password out of band. Supplying
    #: one also suppresses the email when SMTP *is* configured — the caller
    #: has chosen to hand the credential over themselves.
    password: str | None = Field(default=None, min_length=8)
    grants: list[InviteGrant] = []


class UserInvited(BaseModel):
    user: UserOut
    #: Whether the email actually went out. False is not a failure of the
    #: creation — the account and its grants exist either way — so `detail`
    #: says what happened and the Invite button on the row retries it.
    invited: bool
    detail: str
    grants: list[AclOut] = []


async def _resolve_grants(session: AsyncSession, actor: User,
                          grants: list[InviteGrant]) -> list[tuple[Project, str]]:
    """Resolve requested grants, refusing any the caller does not administer.

    THIS is the control. The picker in the dialog only offers projects the
    caller administers, but that is a convenience: a caller who posts a
    project code straight at this endpoint gets the same answer. A site
    admin passes because effective_role returns "admin" everywhere.

    Every grant is checked BEFORE the account exists, so one bad entry
    creates nothing. A half-applied invitation would leave an account
    nobody asked for, named after a real person, with no record of why.
    """
    out: list[tuple[Project, str]] = []
    seen: set[int] = set()
    for g in grants:
        code = g.project.strip().upper().replace(" ", "-")
        pr = (await session.execute(
            select(Project).where(Project.code == code))).scalar_one_or_none()
        role = await effective_role(session, actor, pr.id) if pr else None
        if pr is None or role is None:
            # 404 and not 403, matching require_project: confirming that a
            # project exists to someone with no access is itself disclosure.
            raise HTTPException(404, f"no project {g.project!r}")
        if ROLE_ORDER[role] < ROLE_ORDER["admin"]:
            raise HTTPException(
                403, f"admin required on {pr.code} to grant access; you have {role}")
        if pr.id in seen:
            raise HTTPException(422, f"{pr.code} is listed twice")
        seen.add(pr.id)
        out.append((pr, g.role))
    return out


@router.post("/users/invite", response_model=UserInvited, status_code=201)
async def invite_user(body: UserInvite, actor: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """Create an account from an email address and invite its owner to it.

    Who may call this:

      site admin      anyone, with or without project grants.
      project admin   only together with at least one grant on a project
                      they administer. They can already grant any existing
                      account access to their own projects, so the power
                      added is "bring someone new in", not "reach a project
                      I could not reach" — and an account with no grant at
                      all is a site-wide object, which stays site-admin work.

    Collisions are refused, never merged. Attaching an invitation to an
    account that already exists would mail a working sign-in link for
    somebody else's access to whoever was named on this form.
    """
    email = (body.email or "").strip().lower()
    if not _EMAIL.match(email):
        raise HTTPException(422, "a valid email address is required")
    if not actor.is_site_admin and not body.grants:
        raise HTTPException(
            403, "only a site administrator may create an account with no project grant")

    grants = await _resolve_grants(session, actor, body.grants)

    cfg = await load_all(session)
    if not cfg.get("smtp.host") and not body.password:
        raise HTTPException(
            409, "no invitation can be sent because SMTP is not configured — "
                 "set a password for this account, or configure email in Site Config")

    # Address collision. Almost always an admin re-inviting somebody who is
    # already here; point them at the button that does that rather than
    # creating a second account for one mailbox.
    taken = (await session.execute(select(User).where(
        func.lower(User.email) == email))).scalar_one_or_none()
    if taken:
        raise HTTPException(
            409, f"{email} already belongs to {taken.username!r} — use Invite on "
                 f"that account to send them a fresh sign-in link")

    derived = username_from_email(email)
    username = _clean_username(body.username) if body.username else derived
    clash = (await session.execute(
        select(User).where(User.username == username))).scalar_one_or_none()
    if clash:
        hint = await _free_username(session, username)
        raise HTTPException(
            409, f"the username {username!r} is already taken by another account"
                 + (f"; choose a different one, for example {hint!r}" if hint else ""))

    u = User(username=username, email=email, full_name=body.full_name or None,
             password_hash=hash_password(body.password) if body.password else None)
    session.add(u)
    try:
        await session.commit()
    except IntegrityError as e:
        # Two invitations raced onto the same name. The unique index is the
        # real guard; the lookup above is only the friendly path.
        await session.rollback()
        raise HTTPException(409, f"user {username!r} already exists") from e

    acls = [ProjectACL(project_id=pr.id, user_id=u.id, role=role)
            for pr, role in grants]
    if acls:
        # No upsert dance: the account was created a moment ago, so it
        # cannot already hold a grant on anything.
        session.add_all(acls)
        await session.commit()
        for pr, role in grants:
            await broker.publish("acl", action="grant", project=pr.code)
            # `was=None` is a fact here and not an assumption: the account
            # was created three lines up, so it cannot already hold a grant.
            await slack.announce_membership(session, pr, u.username,
                                            was=None, now=role)

    if body.password:
        result_ok, detail = False, "account created with a password; no invitation sent"
    else:
        r = await deliver_invite(session, u, cfg)
        result_ok, detail = r.ok, r.detail

    # Re-select so `groups` is loaded; see create_user for why touching it
    # from inside Pydantic on a fresh instance blows up.
    u = (await session.execute(select(User).where(User.id == u.id))).scalar_one()
    # No project: the user list is a site-admin view, and an unlabelled
    # event is delivered to site admins only. See events.py.
    await broker.publish("users", action="create")
    return UserInvited(
        user=UserOut.model_validate(u), invited=result_ok, detail=detail,
        grants=[AclOut(id=a.id, project_code=pr.code, role=a.role,
                       username=u.username)
                for (pr, _role), a in zip(grants, acls, strict=True)])


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
                # Named only so the audit entry can say WHO granted it.
                user: User = Depends(get_current_user),
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
    # Read before the write, because afterwards there is nothing left to
    # compare against and the announce below cannot tell a new member from
    # a promotion. It used to not try: every grant said "joined the
    # engagement", including the ones that were actually somebody being
    # made an admin of a project they had been readonly on for a month.
    # That is the single access-control event most worth seeing, and it
    # was indistinguishable in the channel from a routine addition.
    was = existing.role if existing else None
    if existing:
        existing.role = body.role          # re-granting changes the role
        acl = existing
    else:
        acl = ProjectACL(project_id=pr.id, user_id=u.id if u else None,
                         group_id=g.id if g else None, role=body.role)
        session.add(acl)
    await audit.record(
        session, "ui", "project.member", user=user, project_code=pr.code,
        detail=f"{u.username if u else 'group:' + g.name} -> {acl.role}")
    await session.commit()
    await broker.publish("acl", action="grant", project=pr.code)
    # After the commit, so nothing is announced that did not land, and
    # through the one helper that knows all three transitions. A re-grant
    # of the role somebody already held posts nothing at all.
    await slack.announce_membership(
        session, pr, u.username if u else f"group:{g.name}",
        was=was, now=acl.role)
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
    a_role = a.role
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
        await slack.announce_membership(session, pr, who, was=a_role, now=None)


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
