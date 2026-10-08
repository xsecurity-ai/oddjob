"""Posting engagement events to Slack.

The configuration for this already existed — a bot token, a channel
prefix, a per-project override — but nothing ever sent a message. This
is the part that does.

**What gets posted is deliberately narrow.** An engagement channel that
carries every event becomes a channel nobody reads, and the one message
that mattered scrolls past. Only two kinds of thing go to Slack:

  findings      `HIGH on web01.example.com: SQL injection`, with the
                port, protocol and detail in the thread rather than the
                channel — the one-liner is what gets scanned, the
                thread is what gets read.
  engagement    started, stopped, imports beginning and ending, people
                joining and leaving, reports requested and delivered.

Everything else — a service discovered, a note added, a target marked
alive — stays in the timeline, which is where that level of detail
belongs.

**Failure is never fatal.** A finding that exists in the database but
did not reach Slack is a notification problem; refusing to record the
finding because Slack is down would be a data problem. Every call here
swallows its errors and reports them through the return value.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger("oddjob.slack")

#: Overridable so a test can point the whole app at a fake Slack. The
#: alternative is asserting on the strings this module formats, which
#: passes just as happily when nothing ever calls it.
API = os.environ.get("ODDJOB_SLACK_API") or "https://slack.com/api"
TIMEOUT = 15.0


# ------------------------------------------------------- channel names
#: Slack accepts lowercase letters, digits, hyphen and underscore, up to
#: 80 characters. Anything else is rejected at creation time, so the
#: name is cleaned here rather than discovered to be invalid later.
#: `frontend/src/components/NewProjectDialog.tsx` mirrors this so the
#: preview shown while typing is the name that will actually be used.
_CHANNEL_OK = re.compile(r"[^a-z0-9_-]+")


def normalise_channel(raw: str | None) -> str | None:
    """A Slack-legal channel name, or None for empty input."""
    if raw is None:
        return None
    v = raw.strip().lstrip("#").lower()
    v = _CHANNEL_OK.sub("-", v)
    v = re.sub(r"-{2,}", "-", v).strip("-")
    return v[:80] or None


def channel_for(code: str, prefix: str, explicit: str | None = None) -> str | None:
    """The channel a project should use.

    An explicit name wins; otherwise the site prefix plus the project
    code. Normalised either way, because a name the user typed and one
    we derived are equally capable of being illegal.
    """
    if explicit and explicit.strip():
        return normalise_channel(explicit)
    return normalise_channel(f"{prefix}{code}")



@dataclass
class Posted:
    """What happened. `ts` is Slack's message id, needed for threading."""
    ok: bool
    ts: str | None = None
    channel: str | None = None
    error: str | None = None
    #: `ensure_channel` only. True when THIS call made the channel, as
    #: opposed to finding one that was already there. Both are `ok` --
    #: the channel existing is the outcome either way -- but only one of
    #: them is a new room with nobody in it, and a welcome posted into a
    #: channel with months of history reads as a bot that lost its place.
    created: bool = False


async def _call(token: str, method: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        r = await c.post(f"{API}/{method}",
                         headers={"Authorization": f"Bearer {token}",
                                  "Content-Type": "application/json; charset=utf-8"},
                         json=payload)
        # Slack answers 200 with {"ok": false, "error": "..."} for most
        # failures, so the status code alone proves nothing.
        try:
            return r.json()
        except ValueError:
            return {"ok": False, "error": f"non-JSON reply ({r.status_code})"}


async def post(token: str | None, channel: str | None, text: str,
               thread_ts: str | None = None,
               blocks: list[dict[str, Any]] | None = None) -> Posted:
    """Send one message. Never raises."""
    if not token or not channel:
        # Not recorded: nothing was attempted, and writing a failure
        # here would make an unconfigured install look broken rather
        # than unconfigured.
        return Posted(ok=False, error="slack is not configured")
    payload: dict[str, Any] = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    if blocks:
        payload["blocks"] = blocks
    # Recorded here rather than at the call sites. There are ten of
    # them, and the one that gets forgotten is the one whose silence
    # nobody notices.
    from . import servicehealth
    where = f"#{channel}" if not str(channel).startswith("#") else str(channel)
    try:
        d = await _call(token, "chat.postMessage", payload)
    except Exception as e:                       # noqa: BLE001
        log.warning("slack post failed: %s", e)
        err = f"{type(e).__name__}: {e}"[:300]
        await servicehealth.note("slack", False, f"post to {where}", err)
        return Posted(ok=False, error=err)
    if not d.get("ok"):
        err = str(d.get("error"))[:300]
        await servicehealth.note("slack", False, f"post to {where}", err)
        return Posted(ok=False, error=err)
    # The text itself is never recorded: a finding's title can name a
    # client's host, and every site admin can read the health page.
    await servicehealth.note("slack", True, f"post to {where}")
    return Posted(ok=True, ts=d.get("ts"), channel=d.get("channel"))


#: One page is 1000 channels and a busy workspace has more. Bounded so
#: a paging bug cannot turn a status check into an unbounded crawl of
#: someone's workspace; 20 pages is 20,000 channels.
_LIST_PAGES = 20


async def list_channels(token: str) -> tuple[dict[str, str] | None, str]:
    """Every channel the token can see, as {name: id}. -> (map, error).

    `None` for the map means the question could not be put — a bad
    token, a rate limit, Slack being down. That is categorically
    different from an empty map, which means the workspace answered and
    has no channels we can see, and callers must not collapse the two:
    one says a channel is absent, the other says we do not know.

    Private channels are only listed where the bot is a member, so a
    name missing from this map is "not visible to this bot" rather than
    "does not exist in the workspace". For the purpose it is put to —
    will a post to this name arrive — those amount to the same thing.
    """
    out: dict[str, str] = {}
    try:
        cursor = ""
        for _ in range(_LIST_PAGES):
            args: dict[str, Any] = {
                "types": "public_channel,private_channel",
                "limit": 1000, "exclude_archived": True}
            if cursor:
                args["cursor"] = cursor
            d = await _call(token, "conversations.list", args)
            if not d.get("ok"):
                return None, str(d.get("error") or "slack refused the listing")[:300]
            for ch in d.get("channels") or []:
                if ch.get("name"):
                    out[str(ch["name"])] = str(ch.get("id") or "")
            cursor = ((d.get("response_metadata") or {}).get("next_cursor") or "")
            if not cursor:
                break
        return out, ""
    except Exception as e:                       # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"[:300]


async def ensure_channel(token: str, name: str, private: bool) -> Posted:
    """Create the channel if it is not there, and return its id.

    `name_taken` is a success: the channel existing is the outcome we
    wanted, and the id comes back from a lookup.
    """
    try:
        d = await _call(token, "conversations.create",
                        {"name": name, "is_private": bool(private)})
        if d.get("ok"):
            return Posted(ok=True, created=True,
                          channel=(d.get("channel") or {}).get("id"))
        if d.get("error") != "name_taken":
            return Posted(ok=False, error=str(d.get("error"))[:300])
        # Already exists: find it. Paginated, because the name we want
        # is as likely to be on page two as page one and reporting
        # "could not be found" for a channel that is plainly there is
        # the kind of answer that gets the tool distrusted.
        found, err = await list_channels(token)
        if found is None:
            return Posted(ok=False, error=err)
        if name in found:
            return Posted(ok=True, channel=found[name])
        return Posted(ok=False, error="channel exists but could not be found")
    except Exception as e:                       # noqa: BLE001
        return Posted(ok=False, error=f"{type(e).__name__}: {e}"[:300])


# ----------------------------------------------------------- messages
#: Rendered with Slack's own severity colouring convention. Kept as
#: emoji rather than attachment colours because a one-line message in a
#: busy channel is scanned, not read, and the shape of the line is what
#: carries the severity.
SEVERITY_MARK = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":large_blue_circle:",
    "info": ":white_circle:",
}


async def find_user(token: str, handle: str,
                    email: str | None = None) -> tuple[str | None, str]:
    """Resolve a Slack handle to a user id. -> (id, detail).

    Email first when we have one: `users.lookupByEmail` is an exact
    match and cheap. A handle has to be matched against the member
    list, because Slack has no lookup-by-handle, and the thing people
    type is sometimes the display name and sometimes the username.

    Returns a reason rather than raising. Not finding someone is an
    ordinary outcome -- they may simply not be in the workspace yet --
    and it is the operator's problem to see, not an exception.
    """
    want = (handle or "").strip().lstrip("@").lower()
    if email:
        try:
            d = await _call(token, "users.lookupByEmail", {"email": email})
            if d.get("ok") and d.get("user", {}).get("id"):
                return d["user"]["id"], f"matched on email {email}"
        except Exception as e:                   # noqa: BLE001
            log.warning("slack lookupByEmail failed: %s", e)
    if not want:
        return None, "no handle given"

    cursor, scanned = "", 0
    while True:
        payload = {"limit": 200}
        if cursor:
            payload["cursor"] = cursor
        try:
            d = await _call(token, "users.list", payload)
        except Exception as e:                   # noqa: BLE001
            return None, f"could not read the member list: {e}"
        if not d.get("ok"):
            return None, f"could not read the member list: {d.get('error')}"
        for m in d.get("members", []):
            if m.get("deleted") or m.get("is_bot"):
                continue
            prof = m.get("profile") or {}
            names = {str(m.get("name") or "").lower(),
                     str(prof.get("display_name") or "").lower(),
                     str(prof.get("display_name_normalized") or "").lower(),
                     str(prof.get("real_name") or "").lower()}
            if want in {n for n in names if n}:
                return m.get("id"), f"matched @{want} in the workspace"
            scanned += 1
        cursor = (d.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            break
    return None, (f"no member matching @{want} in this workspace "
                  f"(checked {scanned}) — they may need to be invited to "
                  f"the workspace first")


#: C public, G legacy private, D a DM. The `conversations.*` family resolves
#: ids ONLY: handed a name it answers `channel_not_found`, which reads as "your
#: channel is missing" and sends you looking for the wrong thing entirely.
#: `targets_for` deals in NAMES, because a name is what a human configures and
#: what `chat.postMessage` happens to accept, so the translation belongs here --
#: at the one call that cannot work without an id.
CHANNEL_ID_RE = re.compile(r"^[CGD][A-Z0-9]{6,}$")


async def resolve_channel(token: str, channel: str) -> tuple[str | None, str]:
    """An id for `channel`, which may already be one. -> (id, error)."""
    name = (channel or "").strip().lstrip("#")
    if not name:
        return None, "no channel configured"
    if CHANNEL_ID_RE.match(name):
        return name, ""
    found, err = await list_channels(token)
    if found is None:
        return None, err
    cid = found.get(name)
    if not cid:
        # Deliberately Slack's own word: it is what the caller would have
        # seen anyway, and it is accurate -- no channel by that name here.
        return None, "channel_not_found"
    return cid, ""


async def invite_to_channel(token: str, channel: str,
                            user_id: str) -> Posted:
    """Add one person to one channel.

    `channel` may be a name or an id; `conversations.invite` accepts an
    id only, so a name is resolved first.

    `already_in_channel` is a success: the state we wanted is the
    state we have, and reporting it as an error would make a repeat
    confirmation look broken.
    """
    cid, rerr = await resolve_channel(token, channel)
    if not cid:
        return Posted(ok=False, error=rerr[:300])
    try:
        d = await _call(token, "conversations.invite",
                        {"channel": cid, "users": user_id})
    except Exception as e:                       # noqa: BLE001
        return Posted(ok=False, error=f"{type(e).__name__}: {e}"[:300])
    if d.get("ok"):
        return Posted(ok=True, channel=cid)
    err = str(d.get("error") or "")
    if err in ("already_in_channel", "cant_invite_self"):
        return Posted(ok=True, channel=cid)
    return Posted(ok=False, error=err[:300])


def finding_line(severity: str, host: str, title: str) -> str:
    """`$severity on $host: $title` — the channel message."""
    sev = (severity or "info").lower()
    return (f"{SEVERITY_MARK.get(sev, '')} *{sev.upper()}* on `{host}`: {title}"
            .strip())


def finding_thread(port: int | None, protocol: str | None,
                   detail: str | None, url: str | None = None) -> str:
    """The reply under it: where it is and what it says.

    Truncated, because a scanner's detail paragraph can be thousands of
    characters and Slack silently drops a message over 40,000 — a
    finding that fails to post because it was too long is the one you
    most wanted to see.
    """
    bits = []
    where = "/".join(x for x in (str(port) if port else None, protocol) if x)
    if where:
        bits.append(f"*Port:* `{where}`")
    if url:
        bits.append(f"*URL:* {url}")
    if detail:
        d = detail.strip()
        bits.append(d[:2800] + ("\n…(truncated — see Oddjob for the rest)"
                                if len(d) > 2800 else ""))
    return "\n".join(bits) or "_No further detail was recorded._"


def engagement_started(name: str) -> str:
    return f":green_circle: Engagement started. *{name}*"


#: How many scope lines go in the welcome before it is summarised. A
#: channel opener that is four screens of CIDRs is one nobody reads,
#: and the full list is one click away in Oddjob.
WELCOME_SCOPE_LIMIT = 12

#: The same rule for agents. A deployment with twenty scanners does not
#: need all twenty named in a channel opener; the count is the fact and
#: the list is the colour.
WELCOME_AGENT_LIMIT = 6


async def welcome(session, project, token: str) -> str:
    """The first message in a channel that was just created.

    Answers the three things somebody added to a new engagement channel
    asks immediately: what is this, who do I ask, and where do I go.

    Admins are @-mentioned when we know their Slack id IN THIS
    WORKSPACE -- identities are per workspace, so the id that works in
    the site workspace is meaningless in a client's. Anyone we cannot
    resolve is named in plain text rather than silently dropped: "who
    is the admin" must still be answerable, and a half-list that looks
    complete is worse than one that is visibly plain.
    """
    from sqlalchemy import func, select

    from .models import Agent, ProjectACL, ProjectScope, Target, User, UserSlackIdentity, Vuln
    from .routers.settings import load_all

    lines = [f":wave: *{project.codename or project.name}* "
             f"(`{project.code}`) — engagement channel"]
    if project.client:
        lines.append(f"*Client:* {project.client}")
    # Only when it says something the header did not. The header
    # already carries the codename and the code, and an engagement
    # whose name is one of those printed itself twice.
    if project.name and project.name not in (project.codename, project.code):
        lines.append(f"*Engagement:* {project.name}")

    # ---- who to ask -------------------------------------------------
    key = workspace_key(token)
    admin_ids = [a.user_id for a in (await session.execute(
        select(ProjectACL).where(ProjectACL.project_id == project.id,
                                 ProjectACL.role == "admin",
                                 ProjectACL.user_id.is_not(None)))).scalars()]
    who: list[str] = []
    if admin_ids:
        users = {u.id: u for u in (await session.execute(
            select(User).where(User.id.in_(admin_ids)))).scalars()}
        idents = {i.user_id: i for i in (await session.execute(
            select(UserSlackIdentity).where(
                UserSlackIdentity.user_id.in_(admin_ids),
                UserSlackIdentity.workspace_key == key))).scalars()}
        for uid in admin_ids:
            u = users.get(uid)
            if not u:
                continue
            sid = (idents.get(uid) or None) and idents[uid].slack_user_id
            who.append(f"<@{sid}>" if sid else u.username)
    lines.append("*Admins:* " + (", ".join(who) if who
                                 else "none assigned yet"))

    # ---- what is in play --------------------------------------------
    rows = list((await session.execute(
        select(ProjectScope).where(ProjectScope.project_id == project.id)
        .order_by(ProjectScope.included.desc(), ProjectScope.kind,
                  ProjectScope.value))).scalars())
    inc = [r for r in rows if r.included]
    exc = [r for r in rows if not r.included]
    if not rows:
        # Said out loud rather than omitted. An absent scope section
        # reads as "not shown here"; this has to read as "nothing is
        # authorised yet", which is a different and more urgent fact.
        lines.append("*Scope:* none defined yet — nothing is in scope "
                     "until it is added in Oddjob.")
    else:
        head = f"*Scope:* {len(inc)} included"
        if exc:
            head += f", {len(exc)} excluded"
        lines.append(head)
        for r in inc[:WELCOME_SCOPE_LIMIT]:
            lines.append(f"• `{r.value}`")
        if len(inc) > WELCOME_SCOPE_LIMIT:
            lines.append(f"• …and {len(inc) - WELCOME_SCOPE_LIMIT} more")
        if exc:
            lines.append("• _excluded:_ " + ", ".join(
                f"`{r.value}`" for r in exc[:3])
                + (f" and {len(exc) - 3} more" if len(exc) > 3 else ""))

    # ---- what is already on record -----------------------------------
    # A channel opened for an engagement that has been running for weeks
    # is the normal case, not the exception, and "4,319 targets already"
    # is the difference between somebody starting work and somebody
    # starting it again from the beginning.
    n_targets = int((await session.execute(
        select(func.count()).select_from(Target)
        .where(Target.project_id == project.id))).scalar_one())
    if not n_targets:
        lines.append("*Targets:* none yet.")
    else:
        alive = int((await session.execute(
            select(func.count()).select_from(Target)
            .where(Target.project_id == project.id,
                   Target.alive.is_(True)))).scalar_one())
        n_vulns = int((await session.execute(
            select(func.count()).select_from(Vuln)
            .join(Target, Vuln.target_id == Target.id)
            .where(Target.project_id == project.id))).scalar_one())
        bits = [f"{n_targets:,} on record"]
        if alive:
            bits.append(f"{alive:,} confirmed up")
        if n_vulns:
            bits.append(f"{n_vulns:,} finding{'' if n_vulns == 1 else 's'}")
        lines.append("*Targets:* " + ", ".join(bits) + ".")

    # ---- what will do the scanning ------------------------------------
    agents = list((await session.execute(
        select(Agent).where(Agent.project_id == project.id)
        .order_by(Agent.priority, Agent.id))).scalars())
    live = [a for a in agents if a.status == "online"]
    if not agents:
        # Stated, not omitted. Somebody reading this needs to know that
        # nothing can be scanned yet, which is not the same as nothing
        # having been scanned.
        lines.append("*Drone:* no agents enrolled — nothing can run until "
                     "one is.")
    else:
        mode = (project.drone_mode or "mesh").lower()
        how = {"mesh": "load-balanced across all of them",
               "primary": "one at a time, next in line takes over",
               "geo": "routed by region"}.get(mode, mode)
        lines.append(f"*Drone:* {len(live)} of {len(agents)} online · "
                     f"`{mode}` — {how}")
        for a in agents[:WELCOME_AGENT_LIMIT]:
            mark = {"online": ":large_green_circle:",
                    "disabled": ":no_entry:"}.get(a.status, ":white_circle:")
            extra = []
            if a.connection_mode == "call_in":
                extra.append("call-in")
            if mode == "geo":
                # The one mode where a missing region is a misconfiguration
                # rather than a detail: an agent serving no region is one
                # that will never be given work.
                extra.append(f"regions {a.regions}" if a.regions
                             else "_no regions set_")
            lines.append(f"• {mark} `{a.name}`"
                         + (f" — {', '.join(extra)}" if extra else ""))
        if len(agents) > WELCOME_AGENT_LIMIT:
            lines.append(f"• …and {len(agents) - WELCOME_AGENT_LIMIT} more")

    # ---- where to go -------------------------------------------------
    cfg = await load_all(session)
    base = str(cfg.get("site.base_url") or "").strip().rstrip("/")
    if base:
        lines.append(f"*Oddjob:* {base}/projects/{project.code}")
    else:
        # Without a base URL there is no link to give. Say so, rather
        # than emitting a relative path that resolves to nothing.
        lines.append("*Oddjob:* set `site.base_url` in site config to "
                     "get a link here.")
    return "\n".join(lines)


async def opened(session, project, token: str, channel: str | None,
                 *, created: bool) -> list[Posted]:
    """Say the right thing in the right workspace after ensure_channel.

    Not `announce`, which fans the SAME text out to every destination.
    A Slack user id is meaningful only in the workspace it came from, so
    a welcome full of `<@U…>` mentions posted into a SECOND workspace
    renders as dead text naming strangers. The opener therefore goes to
    the one workspace whose channel was just made, and every other
    destination gets the one-liner it has always had.
    """
    results: list[Posted] = []
    line = engagement_started(project.codename or project.code)
    if created and channel:
        results.append(await post(token, channel,
                                  await welcome(session, project, token)))
    else:
        results.append(await post(token, channel, line))
    for tok, ch in await targets_for(session, project):
        if tok != token:
            results.append(await post(tok, ch, line))
    return results


def engagement_stopped(name: str) -> str:
    return f":black_circle: Engagement stopped. *{name}*"


def import_started(kind: str, filename: str) -> str:
    return f":inbox_tray: Importing `{kind}` from file `{filename}` started."


def import_completed(kind: str, filename: str, summary: str = "") -> str:
    s = f":inbox_tray: Import `{kind}` from file `{filename}` completed."
    return f"{s} {summary}".strip()


def user_joined(username: str, role: str) -> str:
    return f":bust_in_silhouette: User `{username}` joined the engagement as `{role}`."


def user_removed(username: str) -> str:
    return f":bust_in_silhouette: User `{username}` was removed from engagement."


def report_requested(report_type: str) -> str:
    return f":page_facing_up: Report requested for `{report_type}`."


def report_generated(report_type: str, pdf: str | None, docx: str | None) -> str:
    links = []
    if pdf:
        links.append(f"<{pdf}|PDF>")
    if docx:
        links.append(f"<{docx}|DOCX>")
    tail = (" Download " + " or ".join(links)) if links else ""
    return f":page_facing_up: Report generated for `{report_type}`.{tail}"


# --------------------------------------------------------- dispatch
async def targets_for(session, project) -> list[tuple[str, str]]:
    """Where a project's notifications go: a list of (token, channel).

    `slack_delivery` decides. "site" uses the site-wide bot, "override"
    uses the engagement's own token — engagements frequently run in the
    customer's workspace — and "both" sends to each, because an
    engagement can need to be visible to the customer AND stay on the
    internal record.

    Returns an empty list when nothing is configured, which is the
    normal state for a deployment that does not use Slack and must not
    produce errors because of it.
    """
    from .routers.settings import load_all
    cfg = await load_all(session)
    site_token = str(cfg.get("slack.bot_token") or "").strip()
    prefix = str(cfg.get("slack.channel_prefix") or "eng-")

    channel = (project.slack_channel or "").strip()
    if not channel:
        # Named after the operation when there is one — that is what the
        # channels are actually called — and the code otherwise.
        base = (project.codename or project.code or "").lower()
        channel = (prefix + base).strip("-")

    delivery = (project.slack_delivery or "site").lower()
    own = (project.slack_token or "").strip()
    out: list[tuple[str, str]] = []
    if delivery in ("site", "both") and site_token:
        out.append((site_token, channel))
    if delivery in ("override", "both") and own:
        out.append((own, channel))
    return out


def workspace_key(token: str) -> str:
    """A stable identifier for "the same Slack", from its bot token.

    A digest, never the token: this is used as a lookup key and lands
    in a table, and a second copy of a live credential sitting in a
    column people join on would be indefensible. Two engagements
    sharing a token are the same workspace, which is the question being
    asked; the same workspace reached by two different tokens reads as
    two, which costs one extra prompt and never leaks an identity
    across a boundary it should not cross.
    """
    return hashlib.sha256((token or "").strip().encode()).hexdigest()[:32]


# ------------------------------------------- does the channel exist?
#: What `refresh_channels` writes, and what the API reports.
CHANNEL_PRESENT = "present"
CHANNEL_MISSING = "missing"
CHANNEL_UNKNOWN = "unknown"
#: No token resolves, so there is nothing to look in.
CHANNEL_NO_TOKEN = "no_token"


async def refresh_channels(session, projects) -> dict[int, str]:
    """Ask each workspace which of our channels exist. -> {project_id: state}.

    Grouped by token, so a deployment with fifty engagements on one
    bot makes one listing call and not fifty. Commits.

    A project set to deliver to two workspaces has to have the channel
    in both: a post that reaches half its destinations is not a working
    notification, and showing it as working is how someone comes to
    believe the client was told something they were not.

    Nothing here raises. Slack being unreachable leaves the previous
    answer in place with the reason recorded, which is why the stored
    state has an "unknown" and not just a boolean.
    """
    from .models import utcnow

    # token -> the projects posting through it, and where.
    by_token: dict[str, list[tuple[Any, str]]] = {}
    no_token: list[Any] = []
    for pr in projects:
        dests = await targets_for(session, pr)
        if not dests:
            no_token.append(pr)
            continue
        for tok, ch in dests:
            by_token.setdefault(tok, []).append((pr, ch))

    listings: dict[str, tuple[dict[str, str] | None, str]] = {}
    for tok in by_token:
        listings[tok] = await list_channels(tok)

    #: project id -> (state, id, error). Worst outcome across the
    #: project's destinations wins, missing being worse than unknown
    #: because it is actionable and unknown is not.
    verdict: dict[int, tuple[str, str | None, str]] = {}
    for tok, rows in by_token.items():
        found, err = listings[tok]
        for pr, ch in rows:
            if found is None:
                cur = (CHANNEL_UNKNOWN, None, err)
            elif ch in found:
                cur = (CHANNEL_PRESENT, found[ch] or None, "")
            else:
                cur = (CHANNEL_MISSING, None,
                       f"#{ch} is not in the workspace, or the bot is not in it")
            prev = verdict.get(pr.id)
            if prev is None or _worse(cur[0], prev[0]):
                verdict[pr.id] = cur
            elif cur[0] == CHANNEL_PRESENT and prev[0] == CHANNEL_PRESENT:
                verdict[pr.id] = prev

    out: dict[int, str] = {}
    for pr in projects:
        if pr in no_token:
            # Not recorded as a check: there was no workspace to ask, so
            # stamping checked_at would claim a lookup that never
            # happened. The absent token is the finding.
            out[pr.id] = CHANNEL_NO_TOKEN
            continue
        state, cid, err = verdict.get(
            pr.id, (CHANNEL_UNKNOWN, None, "no destination resolved"))
        out[pr.id] = state
        if state == CHANNEL_UNKNOWN and pr.slack_channel_checked_at is not None:
            # Could not look this time. Keep what was last known rather
            # than overwriting a real answer with an absence of one, and
            # record why the refresh did not land.
            pr.slack_channel_error = err
            continue
        pr.slack_channel_id = cid
        pr.slack_channel_checked_at = utcnow()
        pr.slack_channel_error = err
    await session.commit()
    return out


_RANK = {CHANNEL_PRESENT: 0, CHANNEL_UNKNOWN: 1, CHANNEL_MISSING: 2}


def _worse(a: str, b: str) -> bool:
    return _RANK.get(a, 1) > _RANK.get(b, 1)


def channel_state(pr) -> str:
    """The stored answer for one project, without asking Slack."""
    if pr.slack_channel_id:
        return CHANNEL_PRESENT
    if pr.slack_channel_checked_at is None:
        return CHANNEL_UNKNOWN
    # Looked, and did not find it. An error that is not "missing" means
    # the look itself failed, which is still unknown.
    if (pr.slack_channel_error or "").startswith("#"):
        return CHANNEL_MISSING
    return CHANNEL_MISSING if not pr.slack_channel_error else CHANNEL_UNKNOWN


async def announce(session, project, text: str,
                   thread: str | None = None) -> list[Posted]:
    """Post one line to every destination the project has. Never raises."""
    try:
        dests = await targets_for(session, project)
    except Exception as e:                       # noqa: BLE001
        log.warning("could not resolve slack destinations: %s", e)
        return []
    return [await post(tok, ch, text, thread_ts=thread) for tok, ch in dests]


async def announce_finding(session, project, *, severity: str, host: str,
                           title: str, port=None, protocol=None,
                           detail=None, url=None) -> list[Posted]:
    """The one-liner in the channel, the detail in its thread.

    Two calls rather than one long message: the channel stays scannable
    and the detail is still one click away. If the first fails there is
    nothing to thread under, so the second is skipped rather than
    posted loose into the channel.
    """
    results = []
    for tok, ch in await targets_for(session, project):
        head = await post(tok, ch, finding_line(severity, host, title))
        results.append(head)
        if head.ok and head.ts:
            results.append(await post(
                tok, head.channel or ch,
                finding_thread(port, protocol, detail, url),
                thread_ts=head.ts))
    return results
