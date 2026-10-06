"""Projects. Every target belongs to exactly one."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from .. import slack
from ..models import (Poc, Project, ProjectACL, ProjectContact, ProjectScope,
                      ProjectSlackMember,
                      Service, Target, User, Vuln)
from ..query import apply_search, apply_sort, paginate
from ..scope import classify_many
from ..slack import channel_for, normalise_channel
from .settings import load_all
from ..schemas import (AgentOverride, AclOut, ContactIn, ContactOut, Page, ProjectCreate,
                       ProjectCreated, ProjectCreateFull, ProjectOut,
                       ProjectUpdate, ScopeEntryOut)
from ..security import (get_current_user, require_project,
                        visible_project_ids)

log = logging.getLogger("oddjob.projects")

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _counts_query():
    """Per-project rollups. Grouped subqueries + LEFT JOIN, not correlated
    scalars, so the cost does not scale with target count."""
    t = (select(Target.project_id.label("pid"), func.count().label("n_targets"))
         .group_by(Target.project_id).subquery())
    s = (select(Target.project_id.label("pid"), func.count(Service.id).label("n_services"))
         .join(Service, Service.target_id == Target.id)
         .group_by(Target.project_id).subquery())
    v = (select(Target.project_id.label("pid"), func.count(Vuln.id).label("n_vulns"))
         .join(Vuln, Vuln.target_id == Target.id)
         .group_by(Target.project_id).subquery())
    p = (select(Target.project_id.label("pid"), func.count(Poc.id).label("n_pocs"))
         .join(Poc, Poc.target_id == Target.id)
         .group_by(Target.project_id).subquery())
    return (
        select(Project,
               func.coalesce(t.c.n_targets, 0).label("total_targets"),
               func.coalesce(s.c.n_services, 0).label("total_services"),
               func.coalesce(v.c.n_vulns, 0).label("total_vulns"),
               func.coalesce(p.c.n_pocs, 0).label("total_pocs"))
        .outerjoin(t, t.c.pid == Project.id)
        .outerjoin(s, s.c.pid == Project.id)
        .outerjoin(v, v.c.pid == Project.id)
        .outerjoin(p, p.c.pid == Project.id)
    )


#: Fields `_out` supplies itself; everything else in ProjectOut that is
#: also a column gets copied straight off the row.
#:
#: Derived rather than listed, because the list was hand-written and a
#: new column therefore defaulted to being dropped in silence —
#: `codename` was added, stored correctly, and never appeared in a
#: single response. The same mistake cost `remediation` in bulk.py.
_EXPLICIT = {"slack_token_set", "slack_delivery", "slack_private",
             "slack_private_effective", "total_targets", "total_services",
             "total_vulns", "total_pocs"}
_COPY = tuple(k for k in ProjectOut.model_fields
              if k not in _EXPLICIT and hasattr(Project, k))


def _out(row, site_private: bool = True) -> ProjectOut:
    p = row[0]
    return ProjectOut(
        **{k: getattr(p, k) for k in _COPY},
        slack_token_set=bool(p.slack_token),
        slack_delivery=p.slack_delivery or "site",
        slack_private=p.slack_private,
        slack_private_effective=(site_private if p.slack_private is None
                                 else bool(p.slack_private)),
        total_targets=row[1], total_services=row[2], total_vulns=row[3], total_pocs=row[4],
    )


async def resolve_project(session: AsyncSession, ref: str) -> Project:
    """Accept a project code or a numeric id, so callers can use either."""
    ref = (ref or "").strip()
    stmt = select(Project).where(Project.code == ref.upper().replace(" ", "-"))
    pr = (await session.execute(stmt)).scalar_one_or_none()
    if pr is None and ref.isdigit():
        pr = await session.get(Project, int(ref))
    if pr is None:
        raise HTTPException(404, f"no project {ref!r}")
    return pr


@router.get("", response_model=Page[ProjectOut])
async def list_projects(
    q: str | None = Query(None),
    status: str | None = Query(None),
    sort: str | None = Query("code"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(1000, ge=0),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    stmt = _counts_query()
    vis = await visible_project_ids(session, user)
    if vis is not None:                      # None means site admin: see all
        stmt = stmt.where(Project.id.in_(vis))
    if status:
        stmt = stmt.where(Project.status == status.lower())
    stmt = apply_search(stmt, q, [Project.code, Project.name, Project.client,
                                  Project.description, Project.status])
    stmt = apply_sort(stmt, sort, order, {
        "code": Project.code, "name": Project.name, "client": Project.client,
        "status": Project.status, "updated_at": Project.updated_at,
    })
    rows, total = await paginate(session, stmt, limit, offset)
    sp = bool((await load_all(session)).get("slack.default_private", True))
    return Page[ProjectOut](items=[_out(r, sp) for r in rows], total=total,
                            limit=limit, offset=offset)


@router.get("/{project}", response_model=ProjectOut)
async def get_project(project: str, pr: Project = Depends(require_project("readonly")),
                      session: AsyncSession = Depends(get_session)):
    row = (await session.execute(_counts_query().where(Project.id == pr.id))).first()
    return _out(row, bool((await load_all(session)).get("slack.default_private", True)))


@router.post("", response_model=ProjectCreated, status_code=201)
async def create_project(body: ProjectCreateFull,
                         user: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """Create an engagement. ANY authenticated user may do this; the creator
    becomes its admin.

    Site admin is not required: starting a piece of work is not a privileged
    act, and funnelling every new engagement through one person is how people
    end up sharing a single account. Authority stays scoped — the creator is
    admin of THIS project and nothing else."""
    dup = (await session.execute(
        select(Project).where(Project.code == body.code))).scalar_one_or_none()
    if dup:
        raise HTTPException(409, f"project {body.code!r} already exists")

    cfg = await load_all(session)
    sp = bool(cfg.get("slack.default_private", True))
    # Selecting override/both without a token would silently post nowhere.
    delivery = body.slack_delivery
    if delivery != "site" and not body.slack_token:
        raise HTTPException(
            422, f"slack_delivery={delivery!r} needs a slack_token; "
                 f"without one only 'site' is possible")
    base = body.model_dump(exclude={"scope", "contacts", "members", "slack_token",
                                    "slack_channel", "slack_delivery", "slack_private"})
    pr = Project(
        **base,
        slack_token=body.slack_token or None,
        # Named after the operation when there is one: the existing
        # channels are called after the codename, not the client code.
        slack_channel=channel_for(body.codename or body.code,
                                  str(cfg.get("slack.channel_prefix") or ""),
                                  body.slack_channel),
        slack_delivery=delivery,
        slack_private=body.slack_private)
    session.add(pr)
    await session.flush()

    # Creator keeps admin, or they would immediately lose access to the thing
    # they just made.
    session.add(ProjectACL(project_id=pr.id, user_id=user.id, role="admin"))

    # ---- scope: kinds are derived, bad lines are named not fatal -------
    entries, scope_errors = classify_many(body.scope)
    for e in entries:
        session.add(ProjectScope(project_id=pr.id, kind=e.kind,
                                 value=e.value, included=e.included))

    for c in body.contacts:
        session.add(ProjectContact(project_id=pr.id, **c.model_dump()))

    # ---- members -------------------------------------------------------
    member_errors: list[str] = []
    wanted = {m.username.strip().lower(): m.role for m in body.members
              if m.username.strip()}
    wanted.pop(user.username, None)      # creator is already admin
    if wanted:
        found = {u.username: u for u in (await session.execute(
            select(User).where(User.username.in_(wanted)))).scalars()}
        for uname, role in wanted.items():
            u = found.get(uname)
            if u is None:
                member_errors.append(f"no user {uname!r} — not added")
                continue
            session.add(ProjectACL(project_id=pr.id, user_id=u.id, role=role))

    await session.commit()
    await broker.publish("projects", action="create", project=pr.code)

    # The setting says "Create a channel per new project". Until now it
    # said only that: `ensure_channel` existed and nothing called it, so
    # the switch was a control that did nothing. A toggle that lies is
    # worse than no toggle, because you stop checking.
    #
    # After the commit, and never fatal: a project that exists without
    # its channel is recoverable; a project refused because Slack was
    # down is not.
    if bool(cfg.get("slack.auto_create_channel", False)) and pr.slack_channel:
        token = str(cfg.get("slack.bot_token") or "").strip()
        if (pr.slack_delivery or "site") != "site" and pr.slack_token:
            token = pr.slack_token
        if token:
            made = await slack.ensure_channel(token, pr.slack_channel, bool(sp))
            if made.ok:
                await slack.announce(
                    session, pr,
                    slack.engagement_started(pr.codename or pr.code))
            else:
                log.warning("could not create #%s: %s", pr.slack_channel, made.error)

    row = (await session.execute(_counts_query().where(Project.id == pr.id))).first()
    scope_rows = (await session.execute(
        select(ProjectScope).where(ProjectScope.project_id == pr.id)
        .order_by(ProjectScope.kind, ProjectScope.value))).scalars().all()
    contact_rows = (await session.execute(
        select(ProjectContact).where(ProjectContact.project_id == pr.id))).scalars().all()
    acl_rows = []
    for a in (await session.execute(
            select(ProjectACL).where(ProjectACL.project_id == pr.id))).scalars():
        au = await session.get(User, a.user_id) if a.user_id else None
        acl_rows.append(AclOut(id=a.id, project_code=pr.code, role=a.role,
                               username=au.username if au else None, group=None))
    return ProjectCreated(
        project=_out(row, sp),
        scope=[ScopeEntryOut.model_validate(x) for x in scope_rows],
        contacts=[ContactOut.model_validate(x) for x in contact_rows],
        members=acl_rows, scope_errors=scope_errors, member_errors=member_errors)


# ------------------------------------------------------- scope & contacts
@router.get("/{project}/scope", response_model=list[ScopeEntryOut])
async def list_scope(project: str, pr: Project = Depends(require_project("readonly")),
                     session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(ProjectScope).where(ProjectScope.project_id == pr.id)
        .order_by(ProjectScope.kind, ProjectScope.value))).scalars().all()
    return [ScopeEntryOut.model_validate(x) for x in rows]


class ScopeAdd(BaseModel):
    lines: list[str]


@router.post("/{project}/scope", response_model=ProjectCreated)
async def add_scope(project: str, body: ScopeAdd,
                    pr: Project = Depends(require_project("admin")),
                    session: AsyncSession = Depends(get_session)):
    """Append entries. Existing values are left alone rather than duplicated."""
    entries, errors = classify_many(body.lines)
    have = {v for (v,) in await session.execute(
        select(ProjectScope.value).where(ProjectScope.project_id == pr.id))}
    for e in entries:
        if e.value not in have:
            session.add(ProjectScope(project_id=pr.id, kind=e.kind,
                                     value=e.value, included=e.included))
    await session.commit()
    await broker.publish("projects", action="scope", project=pr.code)
    rows = (await session.execute(
        select(ProjectScope).where(ProjectScope.project_id == pr.id)
        .order_by(ProjectScope.kind, ProjectScope.value))).scalars().all()
    row = (await session.execute(_counts_query().where(Project.id == pr.id))).first()
    sp = bool((await load_all(session)).get("slack.default_private", True))
    return ProjectCreated(project=_out(row, sp),
                          scope=[ScopeEntryOut.model_validate(x) for x in rows],
                          contacts=[], members=[], scope_errors=errors, member_errors=[])


@router.delete("/{project}/scope/{entry_id}", status_code=204)
async def delete_scope(project: str, entry_id: int,
                       pr: Project = Depends(require_project("admin")),
                       session: AsyncSession = Depends(get_session)):
    e = await session.get(ProjectScope, entry_id)
    if not e or e.project_id != pr.id:
        raise HTTPException(404, f"no scope entry {entry_id} on {pr.code}")
    await session.delete(e)
    await session.commit()


@router.get("/{project}/contacts", response_model=list[ContactOut])
async def list_contacts(project: str, pr: Project = Depends(require_project("readonly")),
                        session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(ProjectContact).where(ProjectContact.project_id == pr.id))).scalars().all()
    return [ContactOut.model_validate(x) for x in rows]


@router.post("/{project}/contacts", response_model=ContactOut, status_code=201)
async def add_contact(project: str, body: ContactIn,
                      pr: Project = Depends(require_project("admin")),
                      session: AsyncSession = Depends(get_session)):
    c = ProjectContact(project_id=pr.id, **body.model_dump())
    session.add(c)
    await session.commit()
    return ContactOut.model_validate(c)


@router.delete("/{project}/contacts/{contact_id}", status_code=204)
async def delete_contact(project: str, contact_id: int,
                         pr: Project = Depends(require_project("admin")),
                         session: AsyncSession = Depends(get_session)):
    c = await session.get(ProjectContact, contact_id)
    if not c or c.project_id != pr.id:
        raise HTTPException(404, f"no contact {contact_id} on {pr.code}")
    await session.delete(c)
    await session.commit()


@router.patch("/{project}", response_model=ProjectOut)
async def update_project(project: str, body: ProjectUpdate,
                         pr: Project = Depends(require_project("admin")),
                         session: AsyncSession = Depends(get_session)):
    data = body.model_dump(exclude_unset=True)
    if data.get("slack_delivery") and data["slack_delivery"] != "site":
        if not (data.get("slack_token") or pr.slack_token):
            raise HTTPException(
                422, f"slack_delivery={data['slack_delivery']!r} needs a slack_token")
    if "slack_channel" in data:
        data["slack_channel"] = normalise_channel(data["slack_channel"])
    was = pr.status
    for k, v in data.items():
        # A blank Slack token means unchanged, not cleared — the UI cannot
        # show the stored value, so saving any other field would wipe it.
        if k == "slack_token" and not v:
            continue
        setattr(pr, k, v)
    await session.commit()
    # Only on a real transition: saving the form with the status
    # unchanged must not announce the engagement starting again.
    if "status" in data and data["status"] != was:
        label = pr.codename or pr.code
        if data["status"] == "active":
            await slack.announce(session, pr, slack.engagement_started(label))
        elif was == "active":
            await slack.announce(session, pr, slack.engagement_stopped(label))
    await broker.publish("projects", action="update", project=pr.code)
    row = (await session.execute(_counts_query().where(Project.id == pr.id))).first()
    return _out(row, bool((await load_all(session)).get("slack.default_private", True)))


@router.delete("/{project}/slack-token", status_code=204)
async def clear_slack_token(project: str, pr: Project = Depends(require_project("admin")),
                            session: AsyncSession = Depends(get_session)):
    """The only way to remove a stored override, since an empty PATCH is
    treated as 'unchanged'."""
    pr.slack_token = None
    # Delivery must not keep pointing at a token that no longer exists.
    if pr.slack_delivery != "site":
        pr.slack_delivery = "site"
    await session.commit()
    await broker.publish("projects", action="update", project=pr.code)


@router.delete("/{project}", status_code=204)
async def delete_project(project: str, pr: Project = Depends(require_project("admin")),
                         session: AsyncSession = Depends(get_session)):
    """Deletes the project AND every target, service, vuln and PoC in it."""
    code = pr.code
    await session.delete(pr)
    await session.commit()
    await broker.publish("projects", action="delete", project=code)


# ------------------------------------------------------- agent overrides
@router.get("/{project}/agent")
async def get_agent_override(project: str,
                             pr: Project = Depends(require_project("admin")),
                             session: AsyncSession = Depends(get_session)):
    """What this project overrides. Tokens are never returned, only whether
    one is stored and which kind it is."""
    from ..agent import token_kind
    return {
        "agent_provider": pr.agent_provider,
        "agent_model": pr.agent_model,
        "anthropic_token_set": bool(pr.agent_anthropic_token),
        "anthropic_token_kind": token_kind("anthropic", pr.agent_anthropic_token or ""),
        "openai_token_set": bool(pr.agent_openai_token),
    }


@router.patch("/{project}/agent")
async def set_agent_override(project: str, body: AgentOverride,
                             pr: Project = Depends(require_project("admin")),
                             session: AsyncSession = Depends(get_session)):
    patch = body.model_dump(exclude_unset=True)
    for key in ("agent_anthropic_token", "agent_openai_token"):
        if key in patch:
            # Empty means unchanged, matching every other secret field here.
            if patch[key]:
                setattr(pr, key, patch[key].strip())
            patch.pop(key)
    for key in ("agent_provider", "agent_model"):
        if key in patch:
            setattr(pr, key, (patch[key] or None) or None)
    await session.commit()
    return await get_agent_override(project, pr, session)


@router.delete("/{project}/agent/{which}", status_code=204)
async def clear_agent_token(project: str, which: str,
                            pr: Project = Depends(require_project("admin")),
                            session: AsyncSession = Depends(get_session)):
    """Clear one stored token, so the project falls back to the site's."""
    if which not in ("anthropic", "openai"):
        raise HTTPException(404, f"no agent token named {which!r}")
    setattr(pr, f"agent_{which}_token", None)
    await session.commit()


# ------------------------------------------------- slack membership
class SlackMeOut(BaseModel):
    """Whether to ask this person for their Slack handle, and with what."""
    slack_enabled: bool
    #: Ask now. True only when Slack is on for the project and we have
    #: neither a confirmed handle nor a recorded refusal.
    prompt: bool
    #: Their profile default, offered as the one-click answer.
    default_handle: str | None = None
    #: What they already gave for this project, if anything.
    handle: str | None = None
    confirmed: bool = False
    declined: bool = False
    channels: list[str] = []
    invite_result: str | None = None


class SlackMeIn(BaseModel):
    handle: str = Field(min_length=1, max_length=128)
    #: Also store it on the profile, so the next project can offer it.
    save_as_default: bool = False


async def _slack_member(session: AsyncSession, project_id: int,
                        user_id: int) -> ProjectSlackMember | None:
    return (await session.execute(
        select(ProjectSlackMember).where(
            ProjectSlackMember.project_id == project_id,
            ProjectSlackMember.user_id == user_id))).scalar_one_or_none()


async def _slack_channels(session: AsyncSession,
                          pr: Project) -> list[tuple[str, str]]:
    """(token, channel) for everywhere this project posts. Empty means
    Slack is not configured for it, which is how "enabled" is decided —
    a project with no destination has nothing to add anyone to."""
    try:
        return await slack.targets_for(session, pr)
    except Exception:                            # noqa: BLE001
        return []


@router.get("/{project}/slack/me", response_model=SlackMeOut)
async def slack_me(pr: Project = Depends(require_project("readonly")),
                   user: User = Depends(get_current_user),
                   session: AsyncSession = Depends(get_session)):
    """Should this person be asked for their Slack handle?

    Asked on opening a project rather than only at the moment of
    joining, because Slack is often turned on for an engagement after
    people are already on it. The condition is a state, not an event:
    Slack is on, and we do not have an answer from them yet.
    """
    dests = await _slack_channels(session, pr)
    m = await _slack_member(session, pr.id, user.id)
    return SlackMeOut(
        slack_enabled=bool(dests),
        prompt=bool(dests) and (m is None or
                                (m.confirmed_at is None and m.declined_at is None)),
        default_handle=user.slack_handle,
        handle=m.handle if m else None,
        confirmed=bool(m and m.confirmed_at),
        declined=bool(m and m.declined_at),
        channels=[ch for _tok, ch in dests],
        invite_result=m.invite_result if m else None)


@router.post("/{project}/slack/me", response_model=SlackMeOut)
async def slack_me_confirm(body: SlackMeIn,
                           pr: Project = Depends(require_project("readonly")),
                           user: User = Depends(get_current_user),
                           session: AsyncSession = Depends(get_session)):
    """Record the handle and add them to the project's channels.

    The handle is stored whatever the invite does. Failing to add
    someone to a channel is a Slack problem — they may not be in the
    workspace yet — and losing their answer because of it would mean
    asking again on every visit.
    """
    handle = body.handle.strip().lstrip("@")
    dests = await _slack_channels(session, pr)

    m = await _slack_member(session, pr.id, user.id)
    if m is None:
        m = ProjectSlackMember(project_id=pr.id, user_id=user.id)
        session.add(m)
    m.handle = handle
    m.declined_at = None
    m.confirmed_at = datetime.now(timezone.utc)
    if body.save_as_default:
        user.slack_handle = handle

    results: list[str] = []
    if not dests:
        results.append("slack is not configured for this project")
    for token, channel in dests:
        uid = m.slack_user_id
        if not uid:
            uid, why = await slack.find_user(token, handle, user.email)
            if not uid:
                results.append(f"{channel}: {why}")
                continue
            m.slack_user_id = uid
        r = await slack.invite_to_channel(token, channel, uid)
        results.append(f"{channel}: {'added' if r.ok else r.error}")

    m.invite_result = "; ".join(results)[:2000]
    await session.commit()
    return await slack_me(pr=pr, user=user, session=session)


@router.post("/{project}/slack/me/decline", response_model=SlackMeOut)
async def slack_me_decline(pr: Project = Depends(require_project("readonly")),
                           user: User = Depends(get_current_user),
                           session: AsyncSession = Depends(get_session)):
    """Stop asking, for this engagement.

    Recorded rather than simply dismissed in the browser: a prompt
    that reappears on every page load is one people learn to click
    past without reading.
    """
    m = await _slack_member(session, pr.id, user.id)
    if m is None:
        m = ProjectSlackMember(project_id=pr.id, user_id=user.id)
        session.add(m)
    m.declined_at = datetime.now(timezone.utc)
    m.confirmed_at = None
    await session.commit()
    return await slack_me(pr=pr, user=user, session=session)
