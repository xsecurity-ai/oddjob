"""Jaws agents: enrolment, the task queue, and results coming home.

**The agent dials out.** Jaws opens a websocket to the server and keeps
it open; the server never has to reach it. That is what makes it work
from a client's network, behind NAT, with nothing listening. The
reverse path — the server calling into the agent — exists for waking
it promptly, and is a convenience rather than the channel the system
depends on.

**Two keys, two directions.** The agent proves itself with a callback
key on every connection. The server proves itself with a separate
call-in key when it reaches in. Only hashes are stored: a dump of the
agents table must not let anyone impersonate either side. Each
plaintext is shown exactly once, at enrolment.

**Results come back as the tool's own output.** An nmap task returns
nmap XML, a masscan task returns masscan XML, and the server hands it
to the importer that already reads that format. A scan run remotely
therefore lands exactly as one run locally — same upserts, same scope
policy, same timeline — instead of through a second, subtly different
path that drifts.
"""
from __future__ import annotations

import json
import secrets
import time
from urllib.parse import urlsplit

import httpx
from datetime import datetime, timedelta, timezone

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..models import Agent, AgentTask, Project, Setting, User
from ..scopegate import check_task_targets, index_for, refuse
from ..security import (get_current_user, new_agent_key, require_project,
                        verify_key)
from .. import agentcrypto
from ..timeline import record
from .scans import HostDecision

router = APIRouter(prefix="/api/agents", tags=["agents"])

#: An agent that has not checked in for this long is called offline.
#: Three missed heartbeats rather than one: a single slow network
#: moment should not light up the console.
OFFLINE_AFTER = timedelta(seconds=90)

#: What an agent may be asked to install. An open-ended "install this
#: package" instruction from the server is remote code execution with
#: extra steps, and the agent runs privileged. The server can authorise
#: anything on this list and nothing else.
INSTALLABLE = ("amass", "nmap", "masscan", "gobuster", "gospider", "nuclei",
               "httpx", "subfinder", "ffuf", "whatweb", "nikto", "dnsx",
               "naabu")

#: How long an unused enrolment token stays good. Short, because a
#: token sitting in a terminal history or a chat message is a way onto
#: the engagement, and the operator is normally pasting it immediately.
ENROL_TTL = timedelta(hours=2)

#: Task kinds the agent knows how to run, and the importer that reads
#: each one's output. None means the result is not a scan import.
TASK_KINDS: dict[str, str | None] = {
    "nmap": "nmap",
    "masscan": "masscan",
    "amass": None,
    "gobuster": None,
    "gospider": None,
    "nuclei": "nuclei",
    "httpx": "httpx",
    "nslookup": None,
    "reverse_ip": None,
    "install": None,
    "shell": None,
}


# --------------------------------------------------------------- shapes
class AgentOut(BaseModel):
    id: int
    project_code: str
    name: str
    status: str
    platform: str | None = None
    arch: str | None = None
    version: str | None = None
    hostname: str | None = None
    privileged: bool = False
    tools: dict = {}
    #: Reported by the agent from its own routing table.
    outbound_ip: str | None = None
    interfaces: list[str] = []
    call_in_url: str | None = None
    last_seen: datetime | None = None
    last_ip: str | None = None
    queued_tasks: int = 0
    #: Tasks actually in flight, as distinct from waiting. An operator
    #: watching a scan wants to know something is happening, and
    #: "queued" does not say that.
    running_tasks: int = 0
    connection_mode: str = "callback"
    target_os: str | None = None
    #: Whether the agent has completed the identity exchange. Until it
    #: has, it is enrolled but has never connected.
    priority: int = 100
    regions: list[str] = []
    has_identity: bool = False
    enrolled_pending: bool = False
    created_at: datetime | None = None


class AgentEnrolled(BaseModel):
    """Returned once, at enrolment. None of this is recoverable later."""
    agent: AgentOut
    callback_key: str = Field(description="Give this to Jaws. It authenticates "
                                          "the agent to the server.")
    call_in_key: str = Field(description="Jaws requires this on inbound calls, "
                                         "so the agent can tell the server from "
                                         "anyone else who finds the port.")
    enrol_token: str = Field(
        description="One-time. The agent exchanges it for an identity on "
                    "first run and it is burned.")
    enrol_expires_at: datetime = Field(
        description="After this the token is refused and the agent must be "
                    "enrolled again.")
    server_public_key: str = Field(
        description="This Oddjob's Ed25519 public key. The agent pins it, so "
                    "it will only ever take tasking from this instance.")


class EnrolIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    notes: str | None = None
    connection_mode: str = Field(
        "callback",
        description="callback (the agent dials out; works from inside a "
                    "client network with nothing exposed) or call_in (the "
                    "server reaches the agent)")
    target_os: str | None = Field(
        None, description="linux | darwin | windows — which binary and "
                          "install snippet to hand the operator")


class RegisterIn(BaseModel):
    """What Jaws reports about itself when it connects."""
    platform: str | None = None
    arch: str | None = None
    version: str | None = None
    hostname: str | None = None
    privileged: bool = False
    tools: dict[str, str] = {}
    outbound_ip: str | None = None
    interfaces: list[str] = []
    call_in_url: str | None = None


class AgentPatch(BaseModel):
    name: str | None = None
    #: Lower runs first when the project is in primary mode.
    priority: int | None = Field(None, ge=0, le=10000)
    #: Comma-separated region labels, for geo routing.
    regions: str | None = None
    notes: str | None = None


class RoutingIn(BaseModel):
    mode: str = Field(description="mesh | primary | geo")


class RoutingOut(BaseModel):
    mode: str
    #: In primary mode, who is actually serving right now. Derived from
    #: live heartbeats, so this is an observation and not a setting.
    current_primary: int | None = None
    current_primary_name: str | None = None
    eligible: int = 0
    unassigned_tasks: int = 0


class TaskIn(BaseModel):
    kind: str
    args: dict = {}
    #: Override the importer. Normally derived from `kind`.
    import_as: str | None = None
    #: For a project routing by region: where this work must run from.
    region: str | None = None


class TaskOut(BaseModel):
    id: int
    #: Null while the task is in the project pool waiting for the
    #: routing policy to pick an agent.
    agent_id: int | None
    project_code: str
    kind: str
    args: dict = {}
    status: str
    summary: str | None = None
    exit_code: int | None = None
    error: str | None = None
    region: str | None = None
    import_as: str | None = None
    import_result: dict | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ResultIn(BaseModel):
    status: str = Field(description="done | failed")
    output: str | None = None
    stderr: str | None = None
    summary: str | None = None
    exit_code: int | None = None
    error: str | None = None


def _tools(raw: str | None) -> dict:
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def _jlist(raw: str | None) -> list[str]:
    """A stored JSON list, or an empty one. Separate from `_tools`
    because that falls back to a dict, and handing a dict to a field
    typed as a list fails somewhere less obvious than here."""
    try:
        v = json.loads(raw) if raw else []
    except ValueError:
        return []
    return [str(x) for x in v] if isinstance(v, list) else []


def _agent_out(a: Agent, code: str, queued: int = 0,
               running: int = 0) -> AgentOut:
    return AgentOut(
        id=a.id, project_code=code, name=a.name, status=a.status,
        platform=a.platform, arch=a.arch, version=a.version,
        hostname=a.hostname, privileged=a.privileged, tools=_tools(a.tools),
        call_in_url=a.call_in_url, last_seen=a.last_seen, last_ip=a.last_ip,
        outbound_ip=a.outbound_ip, interfaces=_jlist(a.interfaces),
        queued_tasks=queued, running_tasks=running,
        connection_mode=a.connection_mode, target_os=a.target_os,
        priority=a.priority, regions=sorted(_regions_of(a)),
        has_identity=bool(a.public_key),
        # Enrolled, token still good, never connected. Distinct from
        # "offline", which means it connected once and then stopped.
        enrolled_pending=bool(a.enrol_token_hash) and not a.public_key,
        created_at=a.created_at)


def _task_out(t: AgentTask, code: str) -> TaskOut:
    def j(v):
        try:
            return json.loads(v) if v else None
        except ValueError:
            return None
    return TaskOut(
        id=t.id, agent_id=t.agent_id, project_code=code, kind=t.kind,
        args=j(t.args) or {}, status=t.status, summary=t.summary,
        exit_code=t.exit_code, error=t.error, region=t.region,
        import_as=t.import_as,
        import_result=j(t.import_result), created_at=t.created_at,
        started_at=t.started_at, finished_at=t.finished_at)


def _stale(a: Agent) -> str:
    """Offline is an observation, disabled is a decision."""
    if a.status == "disabled":
        return "disabled"
    seen = _aware(a.last_seen)
    if seen and (datetime.now(timezone.utc) - seen) < OFFLINE_AFTER:
        return "online"
    return "offline"


# ------------------------------------------------------------ the scope
#: Task kinds that send packets at whatever they are pointed at. Checked
#: against the project's scope lists before they are queued and again
#: before they are handed over.
#:
#: `install` and `shell` are absent because they name no target: install
#: acts on the agent itself, and shell is already refused to everything
#: but a deliberate operator. If a kind is ever added that reaches the
#: network without putting its hosts in `args`, this list is where it
#: would be missed — so the extractor errs wide, see scopegate.task_hosts.
SCOPED_KINDS = tuple(k for k in TASK_KINDS if k not in ("install",))


async def _assert_task_in_scope(session: AsyncSession, pr: Project,
                                kind: str, args: dict | None) -> None:
    """Refuse a task that would reach a host this project may not touch.

    The point of enforcement that matters most. Everything else here
    writes rows; this one puts packets on somebody's network from a
    machine inside it, and the agent cannot be the one to decide — it
    does what it is told, which is the entire design.
    """
    if kind not in SCOPED_KINDS:
        return
    idx = await index_for(session, pr.id)
    if not idx.defined:
        return
    ruling = check_task_targets(idx, args)
    if ruling is not None:
        raise refuse(ruling, f"a {kind} task on {pr.code}")


# ---------------------------------------------------------- dispatching
JAWS_MODES = ("mesh", "primary", "geo")


def _regions_of(a: Agent) -> set[str]:
    return {r.strip().lower() for r in (a.regions or "").split(",") if r.strip()}


async def _eligible_agents(session: AsyncSession, project_id: int) -> list[Agent]:
    """Agents that could take work right now, best first.

    Online and not disabled. Ordered by priority then id so the order
    is total -- with ties broken arbitrarily, two agents could each
    believe they are next.
    """
    rows = (await session.execute(
        select(Agent).where(Agent.project_id == project_id,
                            Agent.status != "disabled")
        .order_by(Agent.priority, Agent.id))).scalars().all()
    return [a for a in rows if _stale(a) == "online"]


async def _may_claim(session: AsyncSession, project: Project, agent: Agent,
                     task: AgentTask) -> bool:
    """Whether this agent is the one that should run this task.

    Called when an agent asks for work and an unassigned task is
    waiting. The decision is made here, on each poll, rather than when
    the task was queued -- which is what lets a primary failover or a
    newly-arrived agent change the answer without anything having to
    re-plan.
    """
    mode = (project.jaws_mode or "mesh").lower()

    if mode == "geo":
        want = (task.region or "").strip().lower()
        if want:
            # A task that names a region runs in that region or not at
            # all. Falling back to "anyone" would quietly send work
            # somewhere the operator deliberately excluded.
            return want in _regions_of(agent)
        # No region asked for: any eligible agent, as mesh.
        return True

    if mode == "primary":
        eligible = await _eligible_agents(session, project.id)
        if not eligible:
            return False
        # The election, such as it is: the best-ranked agent that is
        # currently online. Nothing is stored, so a primary that stops
        # heartbeating simply stops being the answer.
        return eligible[0].id == agent.id

    # mesh: first to ask. An agent mid-scan is not asking, so this
    # spreads by actual capacity rather than by a count we would have
    # to keep accurate.
    return True


# ------------------------------------------------------ server identity
async def server_identity(session: AsyncSession) -> tuple[str, str]:
    """This instance's Ed25519 keypair, made once and kept.

    It is what an agent pins, so rotating it deliberately orphans every
    enrolled agent -- which is the correct behaviour if the private key
    is believed lost, and a bad surprise otherwise. Nothing here
    rotates it automatically.
    """
    row = await session.get(Setting, agentcrypto.SERVER_KEY_SETTING)
    if row is not None and row.value:
        return row.value, agentcrypto.public_of(row.value)
    priv, pub = agentcrypto.generate()
    if row is None:
        session.add(Setting(key=agentcrypto.SERVER_KEY_SETTING, value=priv))
    else:
        row.value = priv
    await session.commit()
    return priv, pub


# ----------------------------------------------------------- agent auth
async def _signed_agent(request: Request, session: AsyncSession,
                        allow_disabled: bool = False) -> Agent | None:
    """Authenticate by Ed25519 signature, or return None if none offered.

    Raises rather than returning None once an agent has been *named*: a
    caller claiming to be agent 7 with a bad signature is a failure, not
    an invitation to try the weaker scheme.
    """
    sig = request.headers.get(agentcrypto.SIG_HEADER, "").strip()
    claimed = request.headers.get(agentcrypto.AGENT_HEADER, "").strip()
    if not sig and not claimed:
        return None

    ts = request.headers.get(agentcrypto.TS_HEADER, "").strip()
    nonce = request.headers.get(agentcrypto.NONCE_HEADER, "").strip()
    if not (sig and claimed and ts and nonce):
        raise HTTPException(401, "a signed request needs agent, timestamp, "
                                 "nonce and signature")
    if not agentcrypto.fresh(ts):
        # Said precisely, because the usual cause is a drifted clock on
        # a host nobody has logged into for weeks, and "unauthorised"
        # sends the operator looking in the wrong place.
        raise HTTPException(401, "timestamp outside the accepted window — "
                                 "check the clock on the agent host")
    if not agentcrypto.nonces.check_and_add(nonce):
        raise HTTPException(401, "nonce already used")

    try:
        a = await session.get(Agent, int(claimed))
    except ValueError:
        raise HTTPException(401, "malformed agent id")
    if a is None or not a.public_key:
        raise HTTPException(401, "unknown agent")

    body = await request.body()
    if not agentcrypto.verify(a.public_key, sig, request.method,
                              request.url.path, body, ts, nonce):
        raise HTTPException(401, "signature does not verify")
    if a.status == "disabled" and not allow_disabled:
        raise HTTPException(403, "this agent is disabled")
    return a


async def _resolve_agent(request: Request, session: AsyncSession,
                         allow_disabled: bool) -> Agent:
    """Authenticate the AGENT to the server.

    Two schemes, and the order matters. An agent that has registered a
    public key must sign; presenting its callback key instead is
    refused. Without that rule an attacker who obtained the weaker
    secret could simply omit the signature and be let in, which would
    make the stronger scheme decorative.

    The key path remains for agents enrolled before identities existed.
    Keys are scanned linearly because only a hash is stored and there
    are tens of agents, not millions.
    """
    signed = await _signed_agent(request, session, allow_disabled)
    if signed is not None:
        return signed

    auth = request.headers.get("Authorization", "")
    key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not key:
        key = request.headers.get("X-Jaws-Key", "").strip()
    if not key:
        raise HTTPException(401, "no agent key supplied")
    for a in (await session.execute(select(Agent))).scalars():
        if verify_key(key, a.callback_key_hash):
            if a.public_key:
                raise HTTPException(
                    401, "this agent has an identity and must sign its "
                         "requests; a key alone is not accepted")
            if a.status == "disabled" and not allow_disabled:
                raise HTTPException(403, "this agent is disabled")
            return a
    raise HTTPException(401, "unknown agent key")


async def agent_from_key(request: Request,
                         session: AsyncSession = Depends(get_session)) -> Agent:
    """The ordinary case: a working agent doing work."""
    return await _resolve_agent(request, session, allow_disabled=False)


async def agent_even_if_killed(request: Request,
                               session: AsyncSession = Depends(get_session)) -> Agent:
    """For the two routes that must be able to answer a killed agent.

    A 403 is not actionable by a process whose whole job is to retry:
    it would reconnect every few seconds forever. Heartbeat and
    register therefore authenticate it, then tell it to exit. No other
    route accepts a disabled agent, so it can be told to stop and can
    do nothing else.
    """
    return await _resolve_agent(request, session, allow_disabled=True)


def _aware(dt: datetime | None) -> datetime | None:
    """Treat a stored timestamp as UTC when the driver returns it naive.

    Postgres hands back tz-aware values for a `DateTime(timezone=True)`
    column; SQLite hands back naive ones for the same column. Comparing
    the two raises, so an expiry check that works against the real
    database fails only on the one the tests use -- or the reverse,
    which is worse.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _project_code(session: AsyncSession, project_id: int) -> str:
    p = await session.get(Project, project_id)
    return p.code if p else "?"


# ------------------------------------------------------ operator routes
@router.post("", response_model=AgentEnrolled, status_code=201)
async def enrol(body: EnrolIn, project: str = Query(...),
                pr: Project = Depends(require_project("admin")),
                user: User = Depends(get_current_user),
                session: AsyncSession = Depends(get_session)):
    """Enrol an agent and mint its two keys.

    Admin on the project, because enrolling an agent creates something
    that can run privileged commands on a machine and send their output
    here. That is not a reader's decision.
    """
    if body.connection_mode not in ("callback", "call_in"):
        raise HTTPException(422, "connection_mode is callback or call_in")
    if body.target_os not in (None, "linux", "darwin", "windows"):
        raise HTTPException(422, "target_os is linux, darwin or windows")

    _, server_pub = await server_identity(session)

    cb_raw, cb_hash = new_agent_key()
    ci_raw, ci_hash = new_agent_key()
    tok_raw, tok_hash = new_agent_key()
    expires = datetime.now(timezone.utc) + ENROL_TTL
    a = Agent(project_id=pr.id, name=body.name.strip(),
              callback_key_hash=cb_hash, call_in_key_hash=ci_hash,
              enrol_token_hash=tok_hash, enrol_expires_at=expires,
              connection_mode=body.connection_mode, target_os=body.target_os,
              notes=body.notes, status="offline")
    session.add(a)
    await session.commit()
    await session.refresh(a)
    await broker.publish("agents", action="enrol", project=pr.code)
    return AgentEnrolled(agent=_agent_out(a, pr.code),
                         callback_key=cb_raw, call_in_key=ci_raw,
                         enrol_token=tok_raw, enrol_expires_at=expires,
                         server_public_key=server_pub)


@router.get("", response_model=list[AgentOut])
async def list_agents(project: str | None = Query(None),
                      pr: Project = Depends(require_project("readonly")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(Agent).where(Agent.project_id == pr.id)
        .order_by(Agent.name))).scalars().all()

    # One grouped count rather than a query per agent. The per-agent
    # version was two round trips per row, which is invisible with three
    # agents and is not the shape to leave in place.
    counts: dict[tuple[int, str], int] = {
        (aid, status): n
        for aid, status, n in (await session.execute(
            select(AgentTask.agent_id, AgentTask.status,
                   func.count(AgentTask.id))
            .where(AgentTask.project_id == pr.id,
                   AgentTask.status.in_(("queued", "claimed", "running")))
            .group_by(AgentTask.agent_id, AgentTask.status))).all()}

    out = []
    for a in rows:
        a.status = _stale(a)
        # Claimed counts as in flight: the agent has taken it and the
        # operator is waiting on it, which is what the column means.
        running = counts.get((a.id, "running"), 0) + counts.get((a.id, "claimed"), 0)
        out.append(_agent_out(a, pr.code, counts.get((a.id, "queued"), 0), running))
    return out


@router.patch("/{agent_id}", response_model=AgentOut)
async def set_agent(agent_id: int, body: AgentPatch | None = None,
                    enabled: bool | None = Query(None),
                    pr: Project = Depends(require_project("admin")),
                    _: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    if enabled is not None:
        # Disabling is remembered; offline is recomputed from last_seen.
        a.status = "offline" if enabled else "disabled"
    if body is not None:
        if body.name is not None:
            a.name = body.name.strip() or a.name
        if body.priority is not None:
            a.priority = body.priority
        if body.regions is not None:
            # Normalised on the way in so "JP, eu " and "jp,eu" are the
            # same thing when the dispatcher compares them.
            a.regions = ",".join(
                sorted({r.strip().lower() for r in body.regions.split(",")
                        if r.strip()})) or None
        if body.notes is not None:
            a.notes = body.notes
    await session.commit()
    await broker.publish("agents", action="update", project=pr.code)
    return _agent_out(a, pr.code)


#: Where the built agent binaries are looked for, in order. The image
#: builds them into the first; a development checkout has them in the
#: second after `make release`.
JAWS_DIRS = (
    Path("/app/jaws-dist"),
    Path(__file__).resolve().parents[3] / "jaws" / "dist",
)

JAWS_BINARIES = {
    ("linux", "amd64"): "jaws-linux-amd64",
    ("linux", "arm64"): "jaws-linux-arm64",
    ("darwin", "amd64"): "jaws-darwin-amd64",
    ("darwin", "arm64"): "jaws-darwin-arm64",
    ("windows", "amd64"): "jaws-windows-amd64.exe",
    ("windows", "arm64"): "jaws-windows-arm64.exe",
}


def _jaws_binary(name: str) -> Path | None:
    for d in JAWS_DIRS:
        p = d / name
        # resolve() then check containment: the name comes from a fixed
        # table rather than the caller, but a path join that can be
        # talked out of its directory is worth closing anyway.
        try:
            rp = p.resolve()
            if rp.is_file() and rp.is_relative_to(d.resolve()):
                return rp
        except (OSError, ValueError):
            continue
    return None


@router.get("/downloads")
async def list_downloads(_: User = Depends(get_current_user)):
    """Which agent binaries this Oddjob can hand out.

    Reported rather than assumed, because an image built without the
    Go stage has none, and a download button that 404s looks like a
    bug rather than a missing build.
    """
    out = []
    for (goos, arch), name in sorted(JAWS_BINARIES.items()):
        p = _jaws_binary(name)
        out.append({"os": goos, "arch": arch, "name": name,
                    "available": p is not None,
                    "bytes": p.stat().st_size if p else 0})
    return {"builds": out,
            "any": any(b["available"] for b in out)}


@router.get("/download/{goos}/{arch}")
async def download_agent(goos: str, arch: str,
                         _: User = Depends(get_current_user)):
    """Hand over the agent binary for a platform.

    Behind a session on purpose. It is a static, non-secret artefact,
    but an unauthenticated endpoint serving an executable from the
    engagement's own server is a thing worth not having.
    """
    name = JAWS_BINARIES.get((goos.lower(), arch.lower()))
    if name is None:
        raise HTTPException(
            404, f"no build for {goos}/{arch}. Available: "
                 f"{', '.join(f'{o}/{a}' for o, a in sorted(JAWS_BINARIES))}")
    p = _jaws_binary(name)
    if p is None:
        raise HTTPException(
            503, f"this Oddjob has no {goos}/{arch} agent binary. They are "
                 f"built into the image; in a development checkout run "
                 f"`make release` in jaws/.")
    return FileResponse(p, filename=name,
                        media_type="application/octet-stream")


class ReachOut(BaseModel):
    ok: bool
    detail: str
    status: dict | None = None


@router.post("/{agent_id}/reach", response_model=ReachOut)
async def reach_agent(agent_id: int,
                      pr: Project = Depends(require_project("user")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """Call into the agent, instead of waiting for it to call us.

    This is the other half of call-in mode, which until now was only a
    stored URL: Oddjob never actually reached in, so the mode was a
    label. It is useful for two things — telling an agent to poll now
    rather than at its next heartbeat, and answering "is it actually
    alive?" when the heartbeat is merely late.

    The request is signed with this instance's private key. The agent
    pinned the matching public key at enrolment and checks it, so
    reaching an agent proves to *it* that the caller is the Oddjob it
    enrolled with -- not merely someone who found the port.
    """
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    if not a.call_in_url:
        raise HTTPException(
            409, f"{a.name} has not advertised a reachable address. It is "
                 f"running in {a.connection_mode} mode; an agent that dials "
                 f"out does not need one.")

    priv, _pub = await server_identity(session)
    url = a.call_in_url.rstrip("/") + "/poll"
    path = urlsplit(url).path or "/"
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(12)
    headers = {
        "X-Jaws-Timestamp": ts,
        "X-Jaws-Nonce": nonce,
        "X-Jaws-Signature": agentcrypto.sign(priv, "POST", path, b"", ts, nonce),
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(url, headers=headers)
    except httpx.HTTPError as e:
        # A failure to reach it is a fact about the network between
        # here and there, not about the agent. Said that way round so
        # nobody concludes the host is down when the route is.
        raise HTTPException(
            502, f"could not reach {a.name} at {a.call_in_url}: {e}. That is "
                 f"this server's view of the path, not proof the agent is down.")
    if r.status_code >= 300:
        raise HTTPException(
            502, f"{a.name} refused the call ({r.status_code}): "
                 f"{r.text[:200]}")
    try:
        body = r.json()
    except ValueError:
        body = None
    return ReachOut(ok=True, detail=f"{a.name} answered and was asked to poll",
                    status=body if isinstance(body, dict) else None)


@router.post("/{agent_id}/kill", response_model=AgentOut)
async def kill_agent(agent_id: int,
                     pr: Project = Depends(require_project("admin")),
                     _: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """Stop an agent, without losing what it found.

    Three things at once, because any one alone leaves a way back in:
    the record is disabled so its credential is refused, its unstarted
    tasking is cancelled so a reconnecting process finds nothing to do,
    and the next heartbeat is answered with an instruction to exit.

    Deliberately not a delete. The tasks carry the output of scans that
    already ran against the client's estate, and that is evidence --
    see `remove_agent`, which will not throw it away by accident
    either. An agent that cannot reach the network any more still has a
    history worth keeping.
    """
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    a.status = "disabled"
    # Queued work is pointless now; work already running will report
    # back if the process is still alive, and is left alone so that
    # result is not lost.
    cancelled = 0
    for t in (await session.execute(
            select(AgentTask).where(AgentTask.agent_id == a.id,
                                    AgentTask.status == "queued"))).scalars():
        t.status = "failed"
        t.error = "cancelled: the agent was killed before this task started"
        t.finished_at = datetime.now(timezone.utc)
        cancelled += 1
    await session.commit()
    await session.refresh(a)
    # Not written to the timeline: an Event hangs off a target, and an
    # agent is not one. Inventing a target_id to get a line in the log
    # would put a false entry on a real host.
    await broker.publish("agents", action="killed", project=pr.code)
    return _agent_out(a, pr.code)


@router.delete("/{agent_id}", status_code=204)
async def remove_agent(agent_id: int,
                       pr: Project = Depends(require_project("admin")),
                       _: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    """Remove the agent record. Its task history is kept.

    The FK is SET NULL, not CASCADE: the tasks hold the raw output of
    scans that ran against the client's estate, and losing that because
    someone tidied up an agent list would be losing evidence.

    Work the agent had taken but not finished is closed out here. It
    can never report back -- the thing that was running it is gone --
    and leaving it `claimed` would show an operator a scan that is
    forever about to produce something.
    """
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    for t in (await session.execute(
            select(AgentTask).where(
                AgentTask.agent_id == a.id,
                AgentTask.status.in_(("queued", "claimed", "running"))))).scalars():
        t.status = "failed"
        t.error = f"the agent {a.name} was deleted while this task was pending"
        t.finished_at = datetime.now(timezone.utc)
    await session.commit()
    await session.delete(a)
    await session.commit()
    await broker.publish("agents", action="deleted", project=pr.code)


@router.post("/{agent_id}/tasks", response_model=TaskOut, status_code=201)
async def create_task(agent_id: int, body: TaskIn,
                      pr: Project = Depends(require_project("user")),
                      user: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """Queue work for an agent.

    The kind is checked here rather than on the agent: an unknown kind
    should be refused by the thing that knows the catalogue, not
    discovered by a privileged process on someone else's network.
    """
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    if body.kind not in TASK_KINDS:
        raise HTTPException(
            422, f"unknown task kind {body.kind!r}. Known: "
                 f"{', '.join(sorted(TASK_KINDS))}")
    if body.kind == "install":
        want = [t for t in (body.args.get("tools") or []) if t]
        bad = [t for t in want if t not in INSTALLABLE]
        if not want:
            raise HTTPException(422, "install needs a non-empty `tools` list")
        if bad:
            # An open-ended install instruction to a privileged agent is
            # remote code execution with extra steps.
            raise HTTPException(
                422, f"not installable: {', '.join(bad)}. Allowed: "
                     f"{', '.join(INSTALLABLE)}")
    await _assert_task_in_scope(session, pr, body.kind, body.args)

    t = AgentTask(agent_id=a.id, project_id=pr.id, requested_by=user.id,
                  kind=body.kind, args=json.dumps(body.args or {}),
                  region=(body.region or "").strip().lower() or None,
                  import_as=body.import_as or TASK_KINDS.get(body.kind),
                  status="queued")
    session.add(t)
    await session.commit()
    await session.refresh(t)
    await broker.publish("agents", action="task", project=pr.code)
    return _task_out(t, pr.code)


@router.get("/routing", response_model=RoutingOut)
async def read_routing(pr: Project = Depends(require_project("readonly")),
                       _: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    eligible = await _eligible_agents(session, pr.id)
    pending = (await session.execute(
        select(func.count(AgentTask.id)).where(
            AgentTask.project_id == pr.id, AgentTask.agent_id.is_(None),
            AgentTask.status == "queued"))).scalar_one()
    first = eligible[0] if eligible else None
    mode = (pr.jaws_mode or "mesh").lower()
    return RoutingOut(
        mode=mode,
        current_primary=first.id if (mode == "primary" and first) else None,
        current_primary_name=first.name if (mode == "primary" and first) else None,
        eligible=len(eligible), unassigned_tasks=pending)


@router.put("/routing", response_model=RoutingOut)
async def set_routing(body: RoutingIn,
                      pr: Project = Depends(require_project("admin")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    mode = (body.mode or "").strip().lower()
    if mode not in JAWS_MODES:
        raise HTTPException(422, f"mode is one of {', '.join(JAWS_MODES)}")
    pr.jaws_mode = mode
    await session.commit()
    await broker.publish("agents", action="routing", project=pr.code)
    return await read_routing(pr=pr, _=_, session=session)


@router.post("/tasks", response_model=TaskOut, status_code=201)
async def create_pooled_task(body: TaskIn,
                             pr: Project = Depends(require_project("user")),
                             user: User = Depends(get_current_user),
                             session: AsyncSession = Depends(get_session)):
    """Queue work for the project rather than for a named agent.

    This is what makes the routing modes mean anything: the task waits
    unassigned until an agent asks for work and the policy says it is
    the one. Queue against an agent directly when you specifically want
    that agent -- a scan that must run from a particular vantage point
    is a real requirement, and the policy does not override it.
    """
    if body.kind not in TASK_KINDS:
        raise HTTPException(
            422, f"unknown task kind {body.kind!r}. Known: "
                 f"{', '.join(sorted(TASK_KINDS))}")
    if body.kind == "install":
        raise HTTPException(
            422, "install is addressed to one agent, not to the pool — "
                 "queue it against the agent you mean to change")
    if (pr.jaws_mode or "mesh").lower() == "geo" and not (body.region or "").strip():
        # Better refused than silently run from wherever answered first,
        # which is the thing geo mode exists to prevent.
        raise HTTPException(
            422, "this project routes by region, so a pooled task needs "
                 "`region` — or queue it against a specific agent")
    await _assert_task_in_scope(session, pr, body.kind, body.args)

    t = AgentTask(agent_id=None, project_id=pr.id, requested_by=user.id,
                  kind=body.kind, args=json.dumps(body.args or {}),
                  region=(body.region or "").strip().lower() or None,
                  import_as=body.import_as or TASK_KINDS.get(body.kind),
                  status="queued")
    session.add(t)
    await session.commit()
    await session.refresh(t)
    await broker.publish("agents", action="task", project=pr.code)
    return _task_out(t, pr.code)


@router.get("/{agent_id}/tasks", response_model=list[TaskOut])
async def list_tasks(agent_id: int, limit: int = Query(50, le=500),
                     pr: Project = Depends(require_project("readonly")),
                     _: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(AgentTask).where(AgentTask.agent_id == agent_id,
                                AgentTask.project_id == pr.id)
        .order_by(AgentTask.id.desc()).limit(limit))).scalars().all()
    return [_task_out(t, pr.code) for t in rows]


class TaskImportBody(BaseModel):
    # Imported here rather than at module scope: the rest of this module
    # pulls scans.py in lazily, and there is no reason to be the one
    # import that reverses that.
    decisions: dict[str, HostDecision] = Field(
        default_factory=dict,
        description="host -> {action: add|map|reject, target: ...}")
    mode: str = Field("strict", description="strict | open")


@router.post("/{agent_id}/tasks/{task_id}/import")
async def import_task_result(agent_id: int, task_id: int,
                             body: TaskImportBody,
                             pr: Project = Depends(require_project("user")),
                             _: User = Depends(get_current_user),
                             session: AsyncSession = Depends(get_session)):
    """Finish the import of a result the agent already delivered.

    A result arrives with no operator attached, so it is imported in
    strict mode with no decisions: anything the project has not seen
    before is surveyed and nothing is written. Without this route that
    is where it stopped -- the scan had run against the client's estate
    and the findings sat in `output` with no way to accept them short of
    editing the database by hand.

    The raw tool output is still on the task, so this re-runs the same
    importer over it with the answers. Unlike a held upload there is
    nothing to consume: the output stays put and the operator can try
    different decisions, which matters when the first answer maps a host
    to the wrong target.
    """
    t = await session.get(AgentTask, task_id)
    if t is None or t.project_id != pr.id or t.agent_id != agent_id:
        raise HTTPException(404, "no such task")
    if not (t.output or "").strip():
        raise HTTPException(409, "this task carries no tool output to import")
    if not t.import_as:
        raise HTTPException(
            409, f"a {t.kind} result is not an importable scan format")

    from .scans import _run
    a = await session.get(Agent, agent_id)
    res = await _run(session, pr, t.output, t.import_as,
                     f"jaws:{a.name if a else agent_id}",
                     mode=body.mode,
                     decisions={k: v for k, v in body.decisions.items()})
    t.import_result = res.model_dump_json()
    await session.commit()
    await broker.publish("agents", action="result", project=pr.code)
    for ch in ("targets", "services", "vulns", "web"):
        await broker.publish(ch, action="agent", project=pr.code)
    return res


# --------------------------------------------------------- agent routes
class IdentityIn(BaseModel):
    """What the agent presents once, to trade a token for an identity."""
    enrol_token: str
    public_key: str = Field(description="Ed25519, base64 raw. The agent made "
                                        "this on its own host; the private "
                                        "half is not sent.")


@router.post("/enrol", response_model=dict)
async def claim_identity(body: IdentityIn,
                         session: AsyncSession = Depends(get_session)):
    """Trade a one-time token for a mutual identity.

    This is the only moment the two sides learn each other. The agent
    sends the public half of a key it generated locally; it gets back
    this instance's public key, which it pins. From then on neither
    side accepts the other on a shared secret.

    The token is burned on success. It is not burned on a *failed*
    attempt, because the common failure is a typo and invalidating the
    token would mean re-enrolling for a slip -- but it is single-use
    and short-lived, so a burned-on-success token cannot be replayed to
    register a second key against the same agent.
    """
    tok = (body.enrol_token or "").strip()
    key = (body.public_key or "").strip()
    if not tok or not key:
        raise HTTPException(422, "both enrol_token and public_key are required")
    try:
        if len(agentcrypto.unb64(key)) != 32:
            raise ValueError
    except Exception:
        raise HTTPException(422, "public_key must be a base64 Ed25519 key")

    now = datetime.now(timezone.utc)
    match: Agent | None = None
    for a in (await session.execute(
            select(Agent).where(Agent.enrol_token_hash.is_not(None)))).scalars():
        if verify_key(tok, a.enrol_token_hash or ""):
            match = a
            break
    if match is None:
        raise HTTPException(401, "unknown or already-used enrolment token")
    if match.enrol_used_at is not None:
        raise HTTPException(409, "this enrolment token has already been used")
    expires = _aware(match.enrol_expires_at)
    if expires and expires < now:
        raise HTTPException(
            401, "this enrolment token has expired — enrol the agent again")

    match.public_key = key
    match.enrol_used_at = now
    # Burned, so the same token cannot register a second key later.
    match.enrol_token_hash = None
    _, server_pub = await server_identity(session)
    code = await _project_code(session, match.project_id)
    await session.commit()
    await broker.publish("agents", action="identity", project=code)
    return {"ok": True, "agent_id": match.id, "project": code,
            "server_public_key": server_pub,
            "connection_mode": match.connection_mode}


@router.post("/register", response_model=dict)
async def register(body: RegisterIn, request: Request,
                   a: Agent = Depends(agent_even_if_killed),
                   session: AsyncSession = Depends(get_session)):
    """Jaws announcing itself. Idempotent: it runs on every reconnect."""
    a.platform, a.arch = body.platform, body.arch
    a.version, a.hostname = body.version, body.hostname
    a.privileged = bool(body.privileged)
    a.tools = json.dumps(body.tools or {})
    a.outbound_ip = body.outbound_ip
    a.interfaces = json.dumps(body.interfaces or [])
    a.call_in_url = body.call_in_url
    a.last_seen = datetime.now(timezone.utc)
    a.last_ip = request.client.host if request.client else None
    if a.status == "disabled":
        # A killed agent that comes back -- a restarted service, a
        # rebooted host -- is told to stop rather than refused. A 403
        # it cannot interpret would have it retry forever.
        await session.commit()
        return {"ok": True, "agent_id": a.id, "shutdown": True,
                "reason": "this agent was killed from Oddjob"}
    a.status = "online"
    await session.commit()
    code = await _project_code(session, a.project_id)
    await broker.publish("agents", action="register", project=code)
    return {"ok": True, "agent_id": a.id, "project": code,
            "installable": list(INSTALLABLE),
            "task_kinds": sorted(TASK_KINDS),
            # Said plainly so the operator sees it in the agent list
            # rather than discovering it in a report six weeks later.
            "note": ("running unprivileged — SYN scans and OS detection "
                     "will silently fall back or fail" if not body.privileged
                     else "privileged")}


@router.post("/heartbeat", response_model=dict)
async def heartbeat(request: Request, a: Agent = Depends(agent_even_if_killed),
                    session: AsyncSession = Depends(get_session)):
    """Keepalive, and the poll that hands out work.

    One task at a time. An agent that grabbed ten and died would strand
    all ten in `claimed`, and the scans this runs are long enough that
    pipelining buys nothing.
    """
    a.last_seen = datetime.now(timezone.utc)
    a.last_ip = request.client.host if request.client else None
    if a.status == "disabled":
        # Killed. Answer the heartbeat rather than refusing it, so the
        # agent is told to stop instead of retrying forever against a
        # 403 it cannot interpret. Recorded first: this is the last
        # thing we will hear from it, and when it stopped is worth
        # knowing.
        await session.commit()
        return {"ok": True, "task": None, "shutdown": True,
                "reason": "this agent was killed from Oddjob"}
    a.status = "online"

    # Scope is re-checked here, not only at queue time. A task may sit
    # in the queue for hours, and the list can move under it — a host
    # added to the out-of-scope list after the scan was planned is
    # exactly the case a one-time check at queue time misses, and the
    # cost of missing it is packets on a host the client told us to
    # leave alone.
    idx = await index_for(session, a.project_id)

    def scope_refusal(task: AgentTask) -> str | None:
        if not idx.defined or task.kind not in SCOPED_KINDS:
            return None
        try:
            args = json.loads(task.args) if task.args else {}
        except ValueError:
            args = {}
        ruling = check_task_targets(idx, args if isinstance(args, dict) else {})
        return ruling.reason if ruling is not None else None

    def drop(task: AgentTask, why: str) -> None:
        """Fail it rather than skip it. A task silently passed over on
        every poll is one an operator watches stay 'queued' forever
        with nothing saying why."""
        task.status = "failed"
        task.error = f"refused by the project's scope at dispatch: {why}"
        task.finished_at = datetime.now(timezone.utc)

    # Work addressed to this agent by name comes first: the operator
    # chose it, and a routing policy should not second-guess that.
    t = None
    for cand in (await session.execute(
            select(AgentTask).where(AgentTask.agent_id == a.id,
                                    AgentTask.status == "queued")
            .order_by(AgentTask.id).limit(25))).scalars():
        why = scope_refusal(cand)
        if why is None:
            t = cand
            break
        drop(cand, why)

    if t is None:
        # Then the project's pool, oldest first, subject to the routing
        # policy. Walked rather than filtered in SQL because "is this
        # agent the primary right now" is a question about live
        # heartbeats, not a column.
        project = await session.get(Project, a.project_id)
        pool = (await session.execute(
            select(AgentTask).where(AgentTask.project_id == a.project_id,
                                    AgentTask.agent_id.is_(None),
                                    AgentTask.status == "queued")
            .order_by(AgentTask.id).limit(25))).scalars().all()
        for cand in pool:
            why = scope_refusal(cand)
            if why is not None:
                drop(cand, why)
                continue
            if project is not None and await _may_claim(session, project, a, cand):
                cand.agent_id = a.id
                t = cand
                break

    task = None
    if t is not None:
        t.status = "claimed"
        t.claimed_at = datetime.now(timezone.utc)
        task = {"id": t.id, "kind": t.kind,
                "args": json.loads(t.args) if t.args else {}}
    await session.commit()
    return {"ok": True, "task": task}


@router.post("/tasks/{task_id}/start", response_model=dict)
async def start_task(task_id: int, a: Agent = Depends(agent_from_key),
                     session: AsyncSession = Depends(get_session)):
    t = await session.get(AgentTask, task_id)
    if t is None or t.agent_id != a.id:
        raise HTTPException(404, "no such task for this agent")
    t.status = "running"
    t.started_at = datetime.now(timezone.utc)
    await session.commit()
    return {"ok": True}


@router.post("/tasks/{task_id}/result", response_model=dict)
async def submit_result(task_id: int, body: ResultIn,
                        a: Agent = Depends(agent_from_key),
                        session: AsyncSession = Depends(get_session)):
    """Results come home, and scan output is imported on arrival.

    Over HTTP rather than the websocket: an nmap XML can be tens of
    megabytes, and a POST can be retried whole. A half-delivered
    result on a dropped frame is not a failure mode worth having.

    The import runs through the ordinary path, so a remote scan lands
    exactly as a local one: same upserts, same scope policy, same
    timeline. Strict mode deliberately — an agent on someone else's
    network should not be able to invent targets in an engagement.
    """
    t = await session.get(AgentTask, task_id)
    if t is None or t.agent_id != a.id:
        raise HTTPException(404, "no such task for this agent")

    t.status = "done" if body.status == "done" else "failed"
    t.output, t.stderr = body.output, body.stderr
    t.summary, t.exit_code, t.error = body.summary, body.exit_code, body.error
    t.finished_at = datetime.now(timezone.utc)
    a.last_seen = t.finished_at
    await session.commit()

    imported = None
    if t.status == "done" and t.import_as and (t.output or "").strip():
        pr = await session.get(Project, t.project_id)
        from .scans import _run
        try:
            res = await _run(session, pr, t.output, t.import_as,
                             f"jaws:{a.name}", mode="strict", decisions={})
            imported = json.loads(res.model_dump_json())
            t.import_result = json.dumps(imported)
            await session.commit()
        except HTTPException as e:
            # The result is kept either way. A scan that ran and could
            # not be imported is still evidence; losing it because the
            # importer disagreed would be the worse outcome.
            t.import_result = json.dumps({"error": str(e.detail)[:500]})
            await session.commit()

    code = await _project_code(session, t.project_id)
    await broker.publish("agents", action="result", project=code)
    for ch in ("targets", "services", "vulns", "web"):
        await broker.publish(ch, action="agent", project=code)
    return {"ok": True, "imported": imported}
