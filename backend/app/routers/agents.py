"""Drone agents: enrollment, the task queue, and results coming home.

**The agent dials out.** Drone opens a websocket to the server and keeps
it open; the server never has to reach it. That is what makes it work
from a client's network, behind NAT, with nothing listening. The
reverse path — the server calling into the agent — exists for waking
it promptly, and is a convenience rather than the channel the system
depends on.

**Two keys, two directions.** The agent proves itself with a callback
key on every connection. The server proves itself with a separate
call-in key when it reaches in. Only hashes are stored: a dump of the
agents table must not let anyone impersonate either side. Each
plaintext is shown exactly once, at enrollment.

**Results come back as the tool's own output.** An nmap task returns
nmap XML, a masscan task returns masscan XML, and the server hands it
to the importer that already reads that format. A scan run remotely
therefore lands exactly as one run locally — same upserts, same scope
policy, same timeline — instead of through a second, subtly different
path that drifts.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import AliasChoices, BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import agentcrypto, audit
from ..db import get_session
from ..events import broker
from ..hosts import validate_host
from ..lookups import LOOKUP_KINDS
from ..models import Agent, AgentTask, Project, Setting, Target, User
from ..scopegate import check_task_targets, index_for, refuse
from ..security import get_current_user, new_agent_key, require_project, verify_key
from ..timeline import record
from .enumerate import apply_auto
from .scans import HostDecision

router = APIRouter(prefix="/api/agents", tags=["agents"])

# The abandoned-task release below logs what it released, and the name it
# logged through was never bound in this module -- so the one path that
# reports a lost task was itself raising NameError.
log = logging.getLogger("oddjob.agents")

#: An agent that has not checked in for this long is called offline.
#: Three missed heartbeats rather than one: a single slow network
#: moment should not light up the console.
OFFLINE_AFTER = timedelta(seconds=90)

#: How long a task an agent is no longer working on stays claimed
#: before it goes back in the queue.
#:
#: Generous on purpose. The only thing that must not happen is racing a
#: result that is still in flight into a second run of the same scan
#: against the client's estate, and ten minutes is far longer than any
#: result POST while being far shorter than an engagement. A task
#: stranded in `claimed` is otherwise stranded for good: nothing else
#: reaps them.
ABANDON_AFTER = timedelta(minutes=10)

#: What an agent may be asked to install. An open-ended "install this
#: package" instruction from the server is remote code execution with
#: extra steps, and the agent runs privileged. The server can authorise
#: anything on this list and nothing else.
INSTALLABLE = ("amass", "nmap", "masscan", "gobuster", "gospider", "nuclei",
               "httpx", "subfinder", "ffuf", "whatweb", "nikto", "dnsx",
               "naabu")

#: How long an unused enrollment token stays good. Short, because a
#: token sitting in a terminal history or a chat message is a way onto
#: the engagement, and the operator is normally pasting it immediately.
ENROLL_TTL = timedelta(hours=2)

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
    #: Reported by the agent about itself, not observed here.
    outbound_ip: str | None = None
    #: And how it found it, because a container's private address and
    #: a real egress address are the same shape.
    outbound_ip_source: str | None = None
    outbound_ip_note: str | None = None
    interfaces: list[str] = []
    #: The OS of the machine underneath, where it differs from
    #: `platform`. Null when undetermined — never defaulted to the
    #: binary's own platform, which is the bug this answers.
    host_platform: str | None = None
    host_platform_source: str | None = None
    container: str | None = None
    call_in_url: str | None = None
    last_seen: datetime | None = None
    last_ip: str | None = None
    queued_tasks: int = 0
    #: Tasks actually in flight, as distinct from waiting. An operator
    #: watching a scan wants to know something is happening, and
    #: "queued" does not say that.
    running_tasks: int = 0
    #: Finished successfully.
    completed_tasks: int = 0
    #: Finished and did not. Reported alongside, because an agent that
    #: has completed nothing and failed forty is broken, and a column
    #: showing only successes would render it as merely idle.
    failed_tasks: int = 0
    #: What this agent decided its host can run at once, and why.
    #: None until it has told us.
    capacity: int | None = None
    #: Set only once the drone has CONFIRMED it stopped. A killed drone
    #: whose host was off never confirms, and the difference between
    #: "killed" and "killed and gone" is the difference between an
    #: engagement that is finished and one with a privileged process
    #: still sitting on somebody's machine.
    retired_at: datetime | None = None
    retired_reason: str | None = None
    #: {removed, kept, failed}. `failed` is cleanup still owed by hand.
    retired_cleanup: dict | None = None
    capacity_reason: str | None = None
    #: {tool: why} for everything this agent tried to install and could
    #: not. Work needing one of these is not sent here.
    missing_tools: dict[str, str] = {}
    #: Task kinds this agent cannot run, derived from the above. The
    #: useful form: an operator cares that it cannot do `nuclei`, not
    #: that it lacks a binary of that name.
    cannot_run: list[str] = []
    #: The effective limit: the lower of its own assessment and the
    #: project's ceiling. What the dispatcher will actually honour.
    max_parallel: int = 1
    #: What is executing right now, so the fleet table can show the
    #: work rather than only a count of it.
    running: list[dict] = []
    connection_mode: str = "callback"
    target_os: str | None = None
    #: Whether the agent has completed the identity exchange. Until it
    #: has, it is enrolled but has never connected.
    priority: int = 100
    regions: list[str] = []
    has_identity: bool = False
    #: Whether its payload is encrypted end to end. False means results
    #: reach us protected only by whatever TLS is in between — an agent
    #: enrolled before sealing existed. Surfaced because an operator
    #: cannot otherwise tell, and "this one reports a client's findings
    #: in the clear" is not a thing to leave invisible.
    sealed: bool = False
    enrolled_pending: bool = False
    created_at: datetime | None = None


class AgentEnrolled(BaseModel):
    """Returned once, at enrollment. None of this is recoverable later."""
    agent: AgentOut
    callback_key: str = Field(description="Give this to Drone. It authenticates "
                                          "the agent to the server.")
    call_in_key: str = Field(description="Drone requires this on inbound calls, "
                                         "so the agent can tell the server from "
                                         "anyone else who finds the port.")
    enroll_token: str = Field(
        description="One-time. The agent exchanges it for an identity on "
                    "first run and it is burned.")
    enroll_expires_at: datetime = Field(
        description="After this the token is refused and the agent must be "
                    "enrolled again.")
    server_public_key: str = Field(
        description="This Oddjob's Ed25519 public key. The agent pins it, so "
                    "it will only ever take tasking from this instance.")


class EnrollIn(BaseModel):
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
    """What Drone reports about itself when it connects."""
    platform: str | None = None
    arch: str | None = None
    version: str | None = None
    hostname: str | None = None
    privileged: bool = False
    tools: dict[str, str] = {}
    #: Tools this host could not get, and why. Used to stop sending it
    #: work that needs them.
    missing_tools: dict[str, str] = {}
    outbound_ip: str | None = None
    #: How the agent arrived at `outbound_ip`. Not validated against a
    #: list here: a newer Drone that learns a seventh way of finding
    #: its address should be able to say so, and a label this server
    #: does not recognise is still more use than silence.
    outbound_ip_source: str | None = Field(None, max_length=32)
    outbound_ip_note: str | None = None
    interfaces: list[str] = []
    #: The OS underneath, where it differs from `platform`. Omitted by
    #: an older Drone and by a newer one that could not tell.
    host_platform: str | None = Field(None, max_length=32)
    host_platform_source: str | None = None
    container: str | None = Field(None, max_length=32)
    call_in_url: str | None = None


class AgentPatch(BaseModel):
    name: str | None = None
    #: Lower runs first when the project is in primary mode.
    priority: int | None = Field(None, ge=0, le=10000)
    #: Comma-separated region labels, for geo routing.
    regions: str | None = None
    notes: str | None = None


class RoutingIn(BaseModel):
    mode: str | None = Field(None, description="mesh | primary | geo")
    #: How many tasks one agent may run at once on this engagement.
    #: A ceiling: the agent's own assessment of its host still applies
    #: and the lower of the two wins.
    max_parallel: int | None = Field(None, ge=1, le=64)


class RoutingOut(BaseModel):
    mode: str
    #: In primary mode, who is actually serving right now. Derived from
    #: live heartbeats, so this is an observation and not a setting.
    current_primary: int | None = None
    current_primary_name: str | None = None
    eligible: int = 0
    unassigned_tasks: int = 0
    #: The engagement's ceiling on simultaneous tasks per agent.
    max_parallel: int = 5


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


def _jdict(raw: str | None) -> dict[str, str]:
    """A stored JSON object, or an empty one."""
    try:
        v = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}


def _jlist(raw: str | None) -> list[str]:
    """A stored JSON list, or an empty one. Separate from `_tools`
    because that falls back to a dict, and handing a dict to a field
    typed as a list fails somewhere less obvious than here."""
    try:
        v = json.loads(raw) if raw else []
    except ValueError:
        return []
    return [str(x) for x in v] if isinstance(v, list) else []


def _json_or_none(raw: str | None) -> dict | None:
    """Stored JSON, or None. A malformed blob reads as absent rather
    than failing the whole agent list — one bad row must not take out
    the page an operator is using to find it."""
    if not raw:
        return None
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else None
    except ValueError:
        return None


def _agent_out(a: Agent, code: str, queued: int = 0,
               running: int = 0, completed: int = 0,
               failed: int = 0, ceiling: int = 5,
               running_rows: list[AgentTask] | None = None) -> AgentOut:
    return AgentOut(
        id=a.id, project_code=code, name=a.name, status=a.status,
        platform=a.platform, arch=a.arch, version=a.version,
        hostname=a.hostname, privileged=a.privileged, tools=_tools(a.tools),
        call_in_url=a.call_in_url, last_seen=a.last_seen, last_ip=a.last_ip,
        retired_at=a.retired_at, retired_reason=a.retired_reason,
        retired_cleanup=_json_or_none(a.retired_cleanup),
        outbound_ip=a.outbound_ip, interfaces=_jlist(a.interfaces),
        outbound_ip_source=a.outbound_ip_source,
        outbound_ip_note=a.outbound_ip_note,
        host_platform=a.host_platform,
        host_platform_source=a.host_platform_source,
        container=a.container,
        queued_tasks=queued, running_tasks=running,
        completed_tasks=completed, failed_tasks=failed,
        capacity=a.capacity, capacity_reason=a.capacity_reason,
        missing_tools=_jdict(a.missing_tools),
        cannot_run=sorted(k for k, tool in KIND_TOOL.items()
                          if not _has_tool(a, k)),
        # The lower of the two, which is what the dispatcher honours.
        # Shown rather than left to be worked out from two numbers in
        # different places.
        max_parallel=max(1, min(ceiling, a.capacity or 1)),
        running=[{"id": t.id, "kind": t.kind,
                  "subject": _subject(t.kind, json.loads(t.args) if t.args else {}),
                  "started_at": t.started_at.isoformat() if t.started_at else None}
                 for t in (running_rows or [])],
        connection_mode=a.connection_mode, target_os=a.target_os,
        priority=a.priority, regions=sorted(_regions_of(a)),
        has_identity=bool(a.public_key),
        sealed=bool(a.kex_public_key),
        # Enrolled, token still good, never connected. Distinct from
        # "offline", which means it connected once and then stopped.
        enrolled_pending=bool(a.enroll_token_hash) and not a.public_key,
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


def _stale(a: Agent, in_flight: int = 0) -> str:
    """Offline is an observation, disabled is a decision, busy is neither.

    `busy` is "connected and working". Agents now beat throughout a
    scan, so this is observed rather than inferred — but the inference
    is kept as the fallback, because it is also what covers an agent
    whose beats are being dropped mid-scan. Before either existed, a
    scan lasting longer than OFFLINE_AFTER made a perfectly healthy
    agent read as offline: wrong on the screen, and worse in `primary`
    routing, where it looked like the primary had died and handed the
    engagement to a standby in the middle of its scan.

    A task claimed by this agent is itself evidence it is alive: it
    asked for it, and nothing else could have.
    """
    if a.status == "disabled":
        return "disabled"
    seen = _aware(a.last_seen)
    if seen and (datetime.now(UTC) - seen) < OFFLINE_AFTER:
        return "online"
    if in_flight > 0:
        return "busy"
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

#: The external tool each kind needs on the agent. The authoritative
#: copy — `tools.Baseline` in the agent installs exactly these, and an
#: agent that could not get one says so on registration.
#:
#: The kinds absent from this map need nothing: nslookup and reverse_ip
#: use the Go resolver, and install and shell are the agent itself.
KIND_TOOL: dict[str, str] = {
    "nmap": "nmap",
    "masscan": "masscan",
    "amass": "amass",
    "gobuster": "gobuster",
    "gospider": "gospider",
    "nuclei": "nuclei",
    "httpx": "httpx",
}

#: Everything an agent is expected to have. Returned by the API so the
#: UI can show a fleet's coverage, and so the list lives in one place
#: rather than being inferred from whichever tasks happen to exist.
REQUIRED_TOOLS = tuple(sorted(set(KIND_TOOL.values())))


def _has_tool(a: Agent, kind: str) -> bool:
    """Can this agent run this kind of task?

    Unknown is treated as yes. An agent that has never reported its
    inventory — one mid-enrollment, or an older build — would otherwise
    be given nothing at all, which is a worse failure than letting it
    try and report honestly.
    """
    need = KIND_TOOL.get(kind)
    if not need:
        return True
    try:
        have = json.loads(a.tools) if a.tools else {}
    except (TypeError, ValueError):
        return True
    if not have:
        return True
    return need in have


#: How many times a failed task goes back in the queue before it waits
#: for a person.
#:
#: Two. Most failures are about the agent or the moment — a container
#: that died mid-scan, a resolver that timed out, a host unreachable
#: for a minute — and another agent will simply succeed. The other
#: kind fails identically everywhere, and the difference between them
#: is not reliably visible from here, so the count is what stops a bad
#: task grinding the queue forever. After that it is failed and stays
#: failed until somebody restarts it, because at that point the thing
#: that needs looking at is the task, not the fleet.
MAX_RETRIES = 2

#: Failures that say something about the REQUEST rather than the run.
#: Retrying these on another agent produces the same result, more
#: slowly, twice.
_PERMANENT = (
    "refused by the project's scope",
    "out of scope",
    "unknown task kind",
    "not installable",
    "takes one domain per task",
    "takes one url per task",
    "is an ip address",
)


def _retryable(error: str) -> bool:
    low = (error or "").lower()
    return not any(p in low for p in _PERMANENT)


#: Task kinds whose output is a list of hostnames rather than a scan
#: file. These do not go through the file importers — there is nothing
#: to parse a format out of — so they get their own path below.
NAME_KINDS = ("amass",)


async def _import_names(session: AsyncSession, pr: Project, t: AgentTask,
                        *, actor: str) -> dict:
    """File the names an agent discovered as targets.

    Unlike `domains.detect`, which extrapolates names from patterns and
    produces hypotheses, these were RESOLVED by a tool on an agent: the
    name exists. So they are created rather than queued for triage —
    which is the difference the operator means by "it found some, add
    them".

    Scope still decides. The generator is not the only thing that
    wanders onto a neighbour's estate; a passive source will happily
    return a name that belongs to someone else, and `index_for` is what
    keeps it out of the inventory.
    """
    try:
        payload = json.loads(t.output or "{}")
    except json.JSONDecodeError as e:
        return {"error": f"output was not JSON: {e}"}
    if isinstance(payload, list):                # tolerate a bare list
        payload = {"names": payload}
    names = [str(n).strip().rstrip(".").lower()
             for n in (payload.get("names") or []) if str(n).strip()]
    domain = str(payload.get("domain") or "").strip().lower()

    idx = await index_for(session, pr.id)
    created: list[str] = []
    existed: list[str] = []
    refused: dict[str, str] = {}
    seen: set[str] = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        try:
            validate_host(name)
        except Exception:                        # noqa: BLE001
            # A tool returning a malformed line is ordinary; it is not a
            # reason to abandon the other four hundred.
            refused[name] = "not a usable hostname"
            continue
        dup = (await session.execute(
            select(Target).where(Target.project_id == pr.id,
                                 Target.host == name))).scalar_one_or_none()
        if dup is not None:
            existed.append(name)
            continue
        ruling = idx.check(name)
        if not ruling.allowed:
            refused[name] = ruling.reason
            continue
        tgt = Target(project_id=pr.id, host=name, alive=None)
        session.add(tgt)
        await session.flush()
        await record(session, tgt.id, "discovered",
                     f"found by {t.kind} under {domain or 'a submitted domain'}",
                     detail=t.summary, actor=None, source=actor)
        created.append(name)
    await session.commit()
    return {"domain": domain, "found": len(seen), "created": created,
            "already_existed": existed, "out_of_scope": refused}


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


#: How many known names to hand a reverse lookup. Each one costs the
#: agent a forward DNS query per address, so a project with thousands
#: of names and thousands of addresses would multiply into something
#: nobody asked for. The cap is on the names; the operator chooses the
#: addresses.
MAX_REVERSE_CANDIDATES = 1500


async def _record_tasking(session: AsyncSession, pr: Project, kind: str,
                          args: dict, user: User, agent: Agent | None,
                          task_id: int | None = None) -> None:
    """Note on each target's timeline that work was queued against it.

    A target's timeline is meant to be the whole story of what was done
    to that host. It had the results — a service found, a name
    resolved, a finding filed — and not the asking, so "was this ever
    scanned, and with what?" could only be answered from the task
    table, by someone who knew to look there and could match a target
    to a row in an arguments blob.

    Recorded at queue time rather than on completion, deliberately: a
    scan that was started and never came back is the case where you
    most want to know it was started.

    Only targets the project actually holds. A task against a CIDR or a
    name not in the inventory has no timeline to write to, and
    inventing a row for one would be inventing a target.
    """
    subjects = [str(t).strip() for t in (args.get("targets") or []) if str(t).strip()]
    if not subjects:
        return
    rows = (await session.execute(
        select(Target).where(Target.project_id == pr.id,
                             Target.host.in_(subjects)))).scalars().all()
    if not rows:
        return

    # What it will actually do, in the words of the thing being run.
    bits = []
    if args.get("ports"):
        bits.append(f"ports {args['ports']}")
    for key in ("mode", "profile", "wordlist", "rate"):
        if args.get(key):
            bits.append(f"{key} {args[key]}")
    if args.get("scripts"):
        bits.append("with NSE scripts")
    where = f" on {agent.name}" if agent else " (project pool)"
    detail = ", ".join(bits) or None

    for t in rows:
        await record(
            session, t.id, "scan",
            f"{kind} queued{where}" + (f" — {detail}" if detail else ""),
            detail=(f"Task {task_id} queued by {user.username}. "
                    if task_id else f"Queued by {user.username}. ")
                   + (f"Arguments: {detail}. " if detail else "")
                   + ("Addressed to this Drone." if agent
                      else "Pooled, so the project's routing decides which "
                           "Drone takes it."),
            actor=user, source=f"drone:{kind}")


async def _candidates(session: AsyncSession, project_id: int) -> list[str]:
    """Names to resolve when answering "what else is at this address".

    Attached when the task is HANDED OUT, not when it is queued.
    Queue-time was fine while one task carried four hundred addresses;
    one task per address means the same fifteen hundred names would be
    written into the arguments column fifteen hundred times over. The
    list is also fresher this way — a name added between queueing and
    dispatch is one the lookup can now confirm.
    """
    rows = (await session.execute(
        select(Target.host).where(Target.project_id == project_id)
        .limit(MAX_REVERSE_CANDIDATES * 2))).scalars().all()
    names = {h for h in rows if h and not _looks_like_ip(h)}
    return sorted(names)[:MAX_REVERSE_CANDIDATES]


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").split("%", 1)[0])
        return True
    except ValueError:
        return False


# ---------------------------------------------------------- dispatching
DRONE_MODES = ("mesh", "primary", "geo")


def _regions_of(a: Agent) -> set[str]:
    return {r.strip().lower() for r in (a.regions or "").split(",") if r.strip()}


async def _eligible_agents(session: AsyncSession, project_id: int) -> list[Agent]:
    """Agents that are present, best first.

    Present, not idle. A busy agent is included on purpose: it is the
    primary's turn whether or not it happens to be mid-scan, and
    dropping it would hand the engagement to a standby every time a
    scan ran longer than a heartbeat interval. Nothing is pushed at an
    agent anyway -- work is only ever handed over when one asks -- so
    counting a busy agent as present cannot give it work it cannot do.

    Ordered by priority then id so the order is total; with ties broken
    arbitrarily, two agents could each believe they are next.
    """
    rows = (await session.execute(
        select(Agent).where(Agent.project_id == project_id,
                            Agent.status != "disabled")
        .order_by(Agent.priority, Agent.id))).scalars().all()
    busy = {aid for (aid,) in (await session.execute(
        select(AgentTask.agent_id).where(
            AgentTask.project_id == project_id,
            AgentTask.status.in_(("claimed", "running"))).distinct())).all()}
    return [a for a in rows
            if _stale(a, 1 if a.id in busy else 0) in ("online", "busy")]


async def _may_claim(session: AsyncSession, project: Project, agent: Agent,
                     task: AgentTask) -> bool:
    """Whether this agent is the one that should run this task.

    Called when an agent asks for work and an unassigned task is
    waiting. The decision is made here, on each poll, rather than when
    the task was queued -- which is what lets a primary failover or a
    newly-arrived agent change the answer without anything having to
    re-plan.
    """
    mode = (project.drone_mode or "mesh").lower()

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
async def server_kex(session: AsyncSession) -> tuple[str, str]:
    """This instance's X25519 pair, made once and kept.

    Separate from the signing identity: one key, one job. Reusing an
    Ed25519 key for key agreement is possible and is the kind of
    cleverness that turns into a paper.
    """
    row = await session.get(Setting, agentcrypto.SERVER_KEX_SETTING)
    if row is not None and row.value:
        return row.value, agentcrypto.kex_public_of(row.value)
    priv, pub = agentcrypto.generate_kex()
    if row is None:
        session.add(Setting(key=agentcrypto.SERVER_KEX_SETTING, value=priv))
    else:
        row.value = priv
    await session.commit()
    return priv, pub


async def sealed_key(session: AsyncSession, a: Agent) -> bytes | None:
    """The symmetric key shared with this agent, or None if it has no
    key-agreement half — an agent enrolled before sealing existed."""
    if not a.kex_public_key:
        return None
    priv, _pub = await server_kex(session)
    return agentcrypto.shared_key(priv, a.kex_public_key)


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
    except ValueError as e:
        raise HTTPException(401, "malformed agent id") from e
    if a is None or not a.public_key:
        raise HTTPException(401, "unknown agent")

    # Sealed requests are signed over the envelope, not its contents:
    # the signature covers exactly what crossed the network. The seal
    # middleware has already swapped in the plaintext by now, so it
    # leaves the original here for this check.
    body = getattr(request.state, "sealed_body", None)
    if body is None:
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
        key = request.headers.get("X-Drone-Key", "").strip()
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
        return dt.replace(tzinfo=UTC)
    return dt


async def _project_code(session: AsyncSession, project_id: int) -> str:
    p = await session.get(Project, project_id)
    return p.code if p else "?"


# ------------------------------------------------------ operator routes
#: [a-z0-9]. No uppercase and no punctuation: the name turns up in
#: container names, log lines and `drone:<name>` audit actors, and a
#: character that needs quoting in one of those is a character that
#: eventually gets mangled in another.
_SUFFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
_SUFFIX_RE = re.compile(r"-[a-z0-9]{6}$")


def _new_suffix() -> str:
    # `secrets` rather than `random`: this is not a secret, but it is an
    # identifier that must not collide, and a seeded PRNG across two
    # processes enrolling at once is exactly how it would.
    return "".join(secrets.choice(_SUFFIX_CHARS) for _ in range(6))


def unique_agent_name(raw: str) -> str:
    """`kodi` -> `kodi-a3f9k2`.

    Two machines are called `kodi`, and an operator naming the second
    one has no way to know the first exists. Worse is the case this was
    actually written for: an agent is deleted server-side while its
    container keeps heartbeating forever, and a later agent takes the
    same name -- so the logs read as one agent that intermittently
    fails authentication rather than as two agents, one of them an
    orphan.

    Applied at ENROLMENT only. A rename is taken exactly as typed --
    see the note there -- so this is about the name nobody chose, not
    about overruling the one somebody did.
    """
    base = _SUFFIX_RE.sub("", (raw or "").strip())[:120] or "drone"
    return f"{base}-{_new_suffix()}"


@router.post("", response_model=AgentEnrolled, status_code=201)
async def enroll(body: EnrollIn, project: str = Query(...),
                pr: Project = Depends(require_project("admin")),
                user: User = Depends(get_current_user),
                session: AsyncSession = Depends(get_session)):
    """Enroll an agent and mint its two keys.

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
    expires = datetime.now(UTC) + ENROLL_TTL
    a = Agent(project_id=pr.id, name=unique_agent_name(body.name),
              callback_key_hash=cb_hash, call_in_key_hash=ci_hash,
              enroll_token_hash=tok_hash, enroll_expires_at=expires,
              connection_mode=body.connection_mode, target_os=body.target_os,
              notes=body.notes, status="offline")
    session.add(a)
    await audit.record(session, "ui", "drone.create", user=user,
                       project_code=pr.code,
                       detail=f"{a.name!r} mode={a.connection_mode} "
                              f"os={a.target_os or 'any'}")
    await session.commit()
    await session.refresh(a)
    await broker.publish("agents", action="enroll", project=pr.code)
    return AgentEnrolled(agent=_agent_out(a, pr.code),
                         callback_key=cb_raw, call_in_key=ci_raw,
                         enroll_token=tok_raw, enroll_expires_at=expires,
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
                   AgentTask.status.in_(("queued", "claimed", "running",
                                         "done", "failed")))
            .group_by(AgentTask.agent_id, AgentTask.status))).all()}

    # The rows themselves, not just their count: the fleet table shows
    # what each agent is working on now that it can be working on
    # several things, and "3 running" does not answer which three.
    in_flight: dict[int, list[AgentTask]] = {}
    for t in (await session.execute(
            select(AgentTask)
            .where(AgentTask.project_id == pr.id,
                   AgentTask.status.in_(("claimed", "running")),
                   AgentTask.agent_id.is_not(None))
            .order_by(AgentTask.id))).scalars():
        in_flight.setdefault(t.agent_id, []).append(t)

    ceiling = max(1, int(pr.drone_max_parallel or 5))
    out = []
    for a in rows:
        # Claimed counts as in flight: the agent has taken it and the
        # operator is waiting on it, which is what the column means.
        running = counts.get((a.id, "running"), 0) + counts.get((a.id, "claimed"), 0)
        a.status = _stale(a, running)
        out.append(_agent_out(
            a, pr.code, counts.get((a.id, "queued"), 0), running,
            completed=counts.get((a.id, "done"), 0),
            failed=counts.get((a.id, "failed"), 0),
            ceiling=ceiling, running_rows=in_flight.get(a.id, [])))
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
            # Taken verbatim. The suffix belongs to ENROLMENT, where
            # the name is generated and nobody is watching; a person
            # typing a name into the dialog has decided what they want
            # it called, and re-imposing a discriminator there would be
            # the tool arguing with its operator. Collisions become
            # possible again at that point, which is the operator's
            # call to make. Bounded only so a long paste cannot exceed
            # the column and turn a rename into a 500.
            a.name = body.name.strip()[:128] or a.name
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
DRONE_DIRS = (
    Path("/app/drone-dist"),
    Path(__file__).resolve().parents[3] / "drone" / "dist",
)

DRONE_BINARIES = {
    ("linux", "amd64"): "drone-linux-amd64",
    ("linux", "arm64"): "drone-linux-arm64",
    ("darwin", "amd64"): "drone-darwin-amd64",
    ("darwin", "arm64"): "drone-darwin-arm64",
    ("windows", "amd64"): "drone-windows-amd64.exe",
    ("windows", "arm64"): "drone-windows-arm64.exe",
}


def _drone_binary(name: str) -> Path | None:
    for d in DRONE_DIRS:
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
    for (goos, arch), name in sorted(DRONE_BINARIES.items()):
        p = _drone_binary(name)
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
    name = DRONE_BINARIES.get((goos.lower(), arch.lower()))
    if name is None:
        raise HTTPException(
            404, f"no build for {goos}/{arch}. Available: "
                 f"{', '.join(f'{o}/{a}' for o, a in sorted(DRONE_BINARIES))}")
    p = _drone_binary(name)
    if p is None:
        raise HTTPException(
            503, f"this Oddjob has no {goos}/{arch} agent binary. They are "
                 f"built into the image; in a development checkout run "
                 f"`make release` in drone/.")
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
    pinned the matching public key at enrollment and checks it, so
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
        "X-Drone-Timestamp": ts,
        "X-Drone-Nonce": nonce,
        "X-Drone-Signature": agentcrypto.sign(priv, "POST", path, b"", ts, nonce),
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
                 f"this server's view of the path, not proof the agent is down.") from e
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


class ReEnrolled(BaseModel):
    agent: AgentOut
    enroll_token: str
    enroll_expires_at: datetime
    server_public_key: str
    server_kex_public_key: str
    #: Both rotate on a re-enrol, so both have to come back. Returning
    #: only the enrolment token meant a CALL-IN agent could be rotated
    #: but never restarted: the server had a new call-in key, the
    #: operator had no way to learn it, and the agent could not be
    #: reached again. Replacing the agent was the only way out, which
    #: threw away its name and everything it had ever run.
    callback_key: str
    call_in_key: str
    #: What the operator has to do on the host, because the agent will
    #: not recover on its own.
    instructions: str


@router.post("/{agent_id}/reenroll", response_model=ReEnrolled)
async def reenroll_agent(agent_id: int,
                         pr: Project = Depends(require_project("admin")),
                         _: User = Depends(get_current_user),
                         session: AsyncSession = Depends(get_session)):
    """Issue a fresh one-time token for an agent that already exists.

    For rotating an agent's keys, and for bringing one enrolled before
    end-to-end encryption onto the sealed channel. Creating a new agent
    would do the same for the channel and orphan everything this one
    has done — its name, its task history, what it found — so the
    record is kept and only the keys change.

    The identity on the host stops working the moment this is called.
    That is the point: a rotation that leaves the old key usable has
    rotated nothing. The agent cannot recover on its own, because the
    key it holds is no longer one the server knows, so the response
    says exactly what to do on the host.
    """
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")

    _, server_pub = await server_identity(session)
    _, server_kex_pub = await server_kex(session)

    cb_raw, cb_hash = new_agent_key()
    ci_raw, ci_hash = new_agent_key()
    tok_raw, tok_hash = new_agent_key()
    expires = datetime.now(UTC) + ENROLL_TTL

    # The old identity goes now, not when the new one is redeemed. An
    # agent whose keys are being rotated because they may be exposed
    # must stop being accepted immediately, and an unredeemed token is
    # not a reason to keep trusting the key it replaces.
    a.public_key = None
    a.kex_public_key = None
    a.enroll_used_at = None
    a.enroll_token_hash = tok_hash
    a.enroll_expires_at = expires
    a.callback_key_hash = cb_hash
    a.call_in_key_hash = ci_hash
    await session.commit()
    await session.refresh(a)
    await broker.publish("agents", action="reenroll", project=pr.code)

    return ReEnrolled(
        agent=_agent_out(a, pr.code),
        enroll_token=tok_raw, enroll_expires_at=expires,
        callback_key=cb_raw, call_in_key=ci_raw,
        server_public_key=server_pub, server_kex_public_key=server_kex_pub,
        instructions=(
            f"{a.name} will fail to authenticate from now until it redeems "
            f"this token. On the host: stop the agent, delete identity.json "
            f"from its workdir (the old keypair is no longer accepted), and "
            f"start it again with --enroll and this token. In Docker, "
            f"removing the state volume does the same thing."))


@router.post("/{agent_id}/kill", response_model=AgentOut)
async def kill_agent(agent_id: int,
                     pr: Project = Depends(require_project("admin")),
                     user: User = Depends(get_current_user),
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
    # Queued work is pointless now. Work already RUNNING is closed out
    # too, which this deliberately did not do: the reasoning was that
    # the process might still be alive and would report back. It
    # cannot. `submit_result` authenticates with `agent_from_key`,
    # which refuses a disabled agent, so a killed agent's result is
    # rejected at the door — and the task sat in `running` for the rest
    # of the engagement, inflating every count that reads it and
    # looking to an operator like a scan still in progress.
    cancelled = running_closed = 0
    now = datetime.now(UTC)
    for t in (await session.execute(
            select(AgentTask).where(
                AgentTask.agent_id == a.id,
                AgentTask.status.in_(("queued", "claimed", "running"))))).scalars():
        was = t.status
        t.status = "failed"
        t.finished_at = now
        if was == "queued":
            t.error = "cancelled: the agent was killed before this task started"
            cancelled += 1
        else:
            t.error = ("the agent was killed while this was running. Its "
                       "credential is refused from that moment, so it could "
                       "not have reported a result even if the scan finished.")
            running_closed += 1
    await session.commit()
    await session.refresh(a)
    # Not the per-target timeline: an Event hangs off a target and an
    # agent is not one, so inventing a target_id to get a line would
    # put a false entry on a real host. The audit trail is keyed on
    # time rather than on an asset, which is the right shape for this.
    await audit.record(session, "ui", "drone.kill", user=user,
                       project_code=pr.code,
                       detail=f"killed {a.name}"
                              + (f", cancelled {cancelled} queued task(s)"
                                 if cancelled else "")
                              + (f", closed {running_closed} in flight"
                                 if running_closed else ""),
                       commit=True)
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
        t.finished_at = datetime.now(UTC)
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
                  kind=body.kind,
                  args=json.dumps(body.args or {}),
                  region=(body.region or "").strip().lower() or None,
                  import_as=body.import_as or TASK_KINDS.get(body.kind),
                  status="queued")
    session.add(t)
    await session.flush()
    await _record_tasking(session, pr, body.kind, body.args or {}, user,
                          a, t.id)
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
    mode = (pr.drone_mode or "mesh").lower()
    return RoutingOut(
        mode=mode, max_parallel=max(1, int(pr.drone_max_parallel or 5)),
        current_primary=first.id if (mode == "primary" and first) else None,
        current_primary_name=first.name if (mode == "primary" and first) else None,
        eligible=len(eligible), unassigned_tasks=pending)


@router.put("/routing", response_model=RoutingOut)
async def set_routing(body: RoutingIn,
                      pr: Project = Depends(require_project("admin")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    if body.mode is not None:
        mode = (body.mode or "").strip().lower()
        if mode not in DRONE_MODES:
            raise HTTPException(422, f"mode is one of {', '.join(DRONE_MODES)}")
        pr.drone_mode = mode
    if body.max_parallel is not None:
        pr.drone_max_parallel = int(body.max_parallel)
    await session.commit()
    await broker.publish("agents", action="routing", project=pr.code)
    return await read_routing(pr=pr, _=_, session=session)


class BulkTaskIn(BaseModel):
    """One task per subject, created in one request."""
    kind: str
    #: One task is made for each of these, with `targets` set to it.
    subjects: list[str] = Field(min_length=1, max_length=5000)
    #: Everything else the tasks share — ports, flags, mode.
    args: dict = {}
    #: Address them all to one agent, or leave null for the pool.
    agent_id: int | None = None
    region: str | None = None


async def queue_per_host(session: AsyncSession, pr: Project, kind: str,
                         subjects: list[str], args: dict, user: User,
                         agent: Agent | None = None,
                         region: str | None = None,
                         source: str = "ui") -> dict:
    """One task per subject, scope-checked individually.

    The single implementation behind both the bulk endpoint and the
    assistant's enumerate tool. Shared deliberately: the scope gate, the
    per-host split and the timeline record are the parts that must not
    differ depending on whether a human clicked or a sentence asked, and
    the surest way to keep them identical is to have one copy.

    Scope is checked per subject. One target being out of scope is not a
    reason to refuse the other 1,737, so refusals come back named.
    """
    idx = await index_for(session, pr.id)
    created: list[int] = []
    refused: dict[str, str] = {}
    seen: set[str] = set()

    for raw in subjects:
        subject = (raw or "").strip()
        if not subject or subject in seen:
            continue
        seen.add(subject)
        ruling = idx.check(subject)
        if not ruling.allowed:
            refused[subject] = ruling.reason
            continue
        t = AgentTask(
            agent_id=agent.id if agent else None, project_id=pr.id,
            requested_by=user.id, kind=kind,
            args=json.dumps({**args, "targets": [subject]}),
            region=region,
            import_as=TASK_KINDS.get(kind), status="queued")
        session.add(t)
        await session.flush()
        await _record_tasking(session, pr, kind,
                              {**args, "targets": [subject]}, user,
                              agent, t.id)
        created.append(t.id)

    await session.commit()
    await broker.publish("agents", action="task", project=pr.code)
    await audit.record(session, source, f"{kind}.bulk", user=user,
                       project_code=pr.code,
                       detail=f"queued {len(created)} {kind} task(s), one "
                              f"per target"
                              + (f"; {len(refused)} refused" if refused else ""),
                       commit=True)
    return {"ids": created, "refused": refused, "queued": len(created)}


@router.post("/tasks/bulk", response_model=dict, status_code=201)
async def create_tasks_bulk(body: BulkTaskIn,
                            pr: Project = Depends(require_project("user")),
                            user: User = Depends(get_current_user),
                            session: AsyncSession = Depends(get_session)):
    """One task per subject, in a single round trip.

    Splitting work into one task per target is what lets the fleet
    share it, lets one failure stay one failure, and makes the queue
    depth mean "how many targets are left". Doing that from the client
    meant one POST per target — 1,738 sequential requests for a
    reverse-lookup sweep, which is a minute of waiting and a minute of
    load for work the server can do in one statement.
    """
    if body.kind not in TASK_KINDS:
        raise HTTPException(
            422, f"unknown task kind {body.kind!r}. Known: "
                 f"{', '.join(sorted(TASK_KINDS))}")
    if body.kind == "install":
        raise HTTPException(
            422, "install is addressed to one agent and takes a tool list, "
                 "not a subject per task")

    agent = None
    if body.agent_id is not None:
        agent = await session.get(Agent, body.agent_id)
        if agent is None or agent.project_id != pr.id:
            raise HTTPException(404, "no such agent")

    return await queue_per_host(
        session, pr, body.kind, list(body.subjects), dict(body.args), user,
        agent, (body.region or "").strip().lower() or None)


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
    if (pr.drone_mode or "mesh").lower() == "geo" and not (body.region or "").strip():
        # Better refused than silently run from wherever answered first,
        # which is the thing geo mode exists to prevent.
        raise HTTPException(
            422, "this project routes by region, so a pooled task needs "
                 "`region` — or queue it against a specific agent")
    await _assert_task_in_scope(session, pr, body.kind, body.args)

    t = AgentTask(agent_id=None, project_id=pr.id, requested_by=user.id,
                  kind=body.kind,
                  args=json.dumps(body.args or {}),
                  region=(body.region or "").strip().lower() or None,
                  import_as=body.import_as or TASK_KINDS.get(body.kind),
                  status="queued")
    session.add(t)
    await session.flush()
    await _record_tasking(session, pr, body.kind, body.args or {}, user,
                          None, t.id)
    await session.commit()
    await session.refresh(t)
    await broker.publish("agents", action="task", project=pr.code)
    return _task_out(t, pr.code)


class QueuedOut(BaseModel):
    """One waiting task, as the queue panel shows it."""
    id: int
    kind: str
    #: What it will act on, shortened. The whole point of opening the
    #: queue is to find the one submission that should not be there,
    #: and "amass" twelve times over does not let anyone do that.
    subject: str
    args: dict = {}
    #: None means the project pool: no agent owns it yet.
    agent_id: int | None = None
    agent_name: str | None = None
    region: str | None = None
    requested_by: str | None = None
    created_at: datetime | None = None
    #: queued everywhere here, but kept explicit so the panel can show
    #: a task that started between the click and the render.
    status: str = "queued"


def _subject(kind: str, args: dict) -> str:
    """The one phrase that says what a task is for."""
    for key in ("domain", "url", "host"):
        if args.get(key):
            return str(args[key])
    for key in ("targets", "domains", "urls"):
        v = args.get(key)
        if isinstance(v, list) and v:
            head = ", ".join(str(x) for x in v[:3])
            return head + (f" and {len(v) - 3} more" if len(v) > 3 else "")
    if kind == "install":
        return ", ".join(str(x) for x in (args.get("tools") or [])) or "tools"
    return "—"


@router.get("/tools", response_model=dict)
async def required_tools(_: User = Depends(get_current_user)):
    """What a Drone is expected to have, and what each one is for.

    One list, here. The agent installs exactly these at startup and
    reports what it could not get; the dispatcher reads that to avoid
    sending work nothing on the other end can run. Published so the UI
    can show a fleet's coverage without inferring the list from
    whichever tasks happen to exist.
    """
    return {
        "required": list(REQUIRED_TOOLS),
        # The kinds that need nothing are as worth stating as the ones
        # that do: "why does this agent still get nslookup work" has an
        # answer, and it is here.
        "by_kind": {k: KIND_TOOL.get(k) for k in sorted(TASK_KINDS)},
    }


@router.get("/queue", response_model=list[QueuedOut])
async def list_queue(limit: int = Query(200, le=1000),
                     pr: Project = Depends(require_project("readonly")),
                     _: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """Everything waiting to run on this project, oldest first.

    Both kinds of waiting: the project pool, which belongs to no agent
    yet, and work addressed to one agent that has not picked it up. A
    panel that showed only the pool would leave an operator unable to
    find the task they actually want to cancel.

    Oldest first, because that is the order it will run in and the
    question is usually "what is in front of mine".
    """
    rows = (await session.execute(
        select(AgentTask).where(AgentTask.project_id == pr.id,
                                AgentTask.status == "queued")
        .order_by(AgentTask.id).limit(limit))).scalars().all()
    names = {a.id: a.name for a in (await session.execute(
        select(Agent).where(Agent.project_id == pr.id))).scalars()}
    who = {u.id: u.username for u in (await session.execute(
        select(User).where(User.id.in_(
            {t.requested_by for t in rows if t.requested_by}))))
        .scalars()} if rows else {}
    out = []
    for t in rows:
        args = json.loads(t.args) if t.args else {}
        out.append(QueuedOut(
            id=t.id, kind=t.kind, subject=_subject(t.kind, args),
            args=args, agent_id=t.agent_id,
            agent_name=names.get(t.agent_id) if t.agent_id else None,
            region=t.region, requested_by=who.get(t.requested_by),
            created_at=t.created_at, status=t.status))
    return out


class TaskRow(BaseModel):
    """One task, as the tasks table on the Drone page shows it."""
    id: int
    kind: str
    subject: str
    #: awaiting | in progress | complete | failed. The stored words are
    #: queued/claimed/running/done/failed; these are what an operator
    #: reading a table means by them.
    state: str
    raw_status: str
    agent_id: int | None = None
    agent_name: str | None = None
    attempts: int = 0
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    #: Why it failed, or why it went back in the queue. The one column
    #: that is empty on a task that behaved.
    notes: str | None = None
    requested_by: str | None = None


#: Stored status -> what the table says. `claimed` is "in progress":
#: an agent has it and the operator is waiting on it, which is what
#: they mean, and a separate word for "taken but not yet started"
#: would be a distinction nobody is acting on.
_STATE = {"queued": "awaiting", "claimed": "in progress",
          "running": "in progress", "done": "complete", "failed": "failed"}


@router.get("/tasks", response_model=list[TaskRow])
async def list_project_tasks(limit: int = Query(500, ge=1, le=5000),
                             pr: Project = Depends(require_project("readonly")),
                             _: User = Depends(get_current_user),
                             session: AsyncSession = Depends(get_session)):
    """Every task on this engagement, newest first.

    The per-agent list answers "what has this scanner done"; this
    answers "what is happening on this engagement", which is the
    question with a queue in it. Includes tasks no agent ever took,
    which the per-agent view by definition cannot.
    """
    rows = (await session.execute(
        select(AgentTask).where(AgentTask.project_id == pr.id)
        .order_by(AgentTask.id.desc()).limit(limit))).scalars().all()
    names = {a.id: a.name for a in (await session.execute(
        select(Agent).where(Agent.project_id == pr.id))).scalars()}
    who = {u.id: u.username for u in (await session.execute(
        select(User).where(User.id.in_(
            {t.requested_by for t in rows if t.requested_by})))).scalars()} \
        if rows else {}
    out = []
    for t in rows:
        args = json.loads(t.args) if t.args else {}
        out.append(TaskRow(
            id=t.id, kind=t.kind, subject=_subject(t.kind, args),
            state=_STATE.get(t.status, t.status), raw_status=t.status,
            agent_id=t.agent_id,
            agent_name=names.get(t.agent_id) if t.agent_id else None,
            attempts=t.attempts or 0,
            created_at=t.created_at, started_at=t.started_at,
            finished_at=t.finished_at, notes=t.error,
            requested_by=who.get(t.requested_by)))
    return out


@router.post("/tasks/{task_id}/retry", response_model=TaskRow)
async def retry_task(task_id: int,
                     pr: Project = Depends(require_project("user")),
                     user: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    """Put a failed task back in the queue by hand.

    The automatic retry stops after two, because a request that is
    simply wrong fails the same way on every agent and would otherwise
    grind the queue. This is the other side of that: once somebody has
    looked at why, they can send it round again. The counter resets —
    they have made a judgement the counter was standing in for.

    Only a failed task. One that is queued is already going to run,
    and one in flight would then exist twice.
    """
    t = await session.get(AgentTask, task_id)
    if t is None or t.project_id != pr.id:
        raise HTTPException(404, "no such task")
    if t.status != "failed":
        raise HTTPException(
            409, f"task {task_id} is {_STATE.get(t.status, t.status)}, not "
                 f"failed. Only a failed task can be restarted — this one is "
                 f"either going to run or running now.")
    was = t.error
    t.status = "queued"
    t.agent_id = None
    t.attempts = 0
    t.claimed_at = t.started_at = t.finished_at = None
    t.output = t.stderr = t.summary = None
    t.exit_code = None
    t.error = f"restarted by {user.username}; previously: {was or 'failed'}"[:4000]
    await session.commit()
    await audit.record(session, "ui", "drone.task.retry", user=user,
                       project_code=pr.code,
                       detail=f"restarted {t.kind} task {t.id}", commit=True)
    await broker.publish("agents", action="task", project=pr.code)
    return TaskRow(
        id=t.id, kind=t.kind,
        subject=_subject(t.kind, json.loads(t.args) if t.args else {}),
        state="awaiting", raw_status="queued", attempts=0,
        created_at=t.created_at, notes=t.error)


@router.delete("/tasks/{task_id}", status_code=204)
async def cancel_task(task_id: int,
                      pr: Project = Depends(require_project("user")),
                      user: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """Take a task back out of the queue.

    Only while it is still waiting. A task an agent has already claimed
    is running on somebody's network, and deleting the row here would
    not stop it — it would only throw away the record of the scan that
    is happening, and lose its result when it reports. Killing the
    agent is the way to stop work that has started, and it says so.
    """
    t = await session.get(AgentTask, task_id)
    if t is None or t.project_id != pr.id:
        raise HTTPException(404, "no such task")
    if t.status != "queued":
        raise HTTPException(
            409, f"task {task_id} is {t.status}, not queued. Deleting it here "
                 f"would not stop the scan — it is already running on the "
                 f"agent — and the result would be lost when it reports. "
                 f"Kill the agent to stop work that has started.")
    subject = _subject(t.kind, json.loads(t.args) if t.args else {})
    await session.delete(t)
    await session.commit()
    await audit.record(session, "ui", "drone.task.cancel", user=user,
                       project_code=pr.code,
                       detail=f"cancelled queued {t.kind} on {subject}",
                       commit=True)
    await broker.publish("agents", action="task", project=pr.code)


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
                     f"drone:{a.name if a else agent_id}",
                     mode=body.mode,
                     decisions=dict(body.decisions))
    t.import_result = res.model_dump_json()
    await session.commit()
    await broker.publish("agents", action="result", project=pr.code)
    for ch in ("targets", "services", "vulns", "web"):
        await broker.publish(ch, action="agent", project=pr.code)
    return res


# --------------------------------------------------------- agent routes
class IdentityIn(BaseModel):
    """What the agent presents once, to trade a token for an identity."""
    #: `enrol_token` was the original spelling. Accepted as an alias so
    #: an agent built before the rename can still redeem a token.
    enroll_token: str = Field(validation_alias=AliasChoices(
        "enroll_token", "enrol_token"))
    public_key: str = Field(description="Ed25519, base64 raw. The agent made "
                                        "this on its own host; the private "
                                        "half is not sent.")
    kex_public_key: str | None = Field(
        None, description="X25519, base64 raw. Omitting it means no sealing, "
                          "which an agent older than this field will do.")


#: The British spelling this route shipped with. Kept as an alias
#: because a deployed agent binary holding a fresh token should not be
#: bricked by a spelling change, and the cost of keeping it is a line.
@router.post("/enrol", response_model=dict, include_in_schema=False)
@router.post("/enroll", response_model=dict)
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
    tok = (body.enroll_token or "").strip()
    key = (body.public_key or "").strip()
    if not tok or not key:
        raise HTTPException(422, "both enroll_token and public_key are required")
    try:
        if len(agentcrypto.unb64(key)) != 32:
            raise ValueError
    except Exception as e:
        raise HTTPException(422, "public_key must be a base64 Ed25519 key") from e

    now = datetime.now(UTC)
    match: Agent | None = None
    for a in (await session.execute(
            select(Agent).where(Agent.enroll_token_hash.is_not(None)))).scalars():
        if verify_key(tok, a.enroll_token_hash or ""):
            match = a
            break
    if match is None:
        raise HTTPException(401, "unknown or already-used enrollment token")
    if match.enroll_used_at is not None:
        raise HTTPException(409, "this enrollment token has already been used")
    expires = _aware(match.enroll_expires_at)
    if expires and expires < now:
        raise HTTPException(
            401, "this enrollment token has expired — enroll the agent again")

    match.public_key = key
    kex = (body.kex_public_key or "").strip()
    if kex:
        try:
            if len(agentcrypto.unb64(kex)) != 32:
                raise ValueError
        except Exception as e:
            raise HTTPException(422, "kex_public_key must be a base64 X25519 key") from e
        match.kex_public_key = kex
    match.enroll_used_at = now
    # Burned, so the same token cannot register a second key later.
    match.enroll_token_hash = None
    _, server_pub = await server_identity(session)
    _, server_kex_pub = await server_kex(session)
    code = await _project_code(session, match.project_id)
    # The moment a scanner gains a credential against this
    # installation. Source `drone`, not `ui`: no person is on the other
    # end of this request, and attributing it to one would be a lie
    # about who did it. The key itself is never recorded — only that
    # one was accepted, and for which agent.
    await audit.record(
        session, "drone", "drone.enroll", username=f"drone:{match.name}",
        project_code=code,
        detail=f"{match.name} enrolled an identity"
               + (" with key agreement" if match.kex_public_key else ""))
    await session.commit()
    await broker.publish("agents", action="identity", project=code)
    return {"ok": True, "agent_id": match.id, "project": code,
            "server_public_key": server_pub,
            "server_kex_public_key": server_kex_pub,
            # Said back so the agent can refuse to run unsealed against
            # a server that cannot seal, rather than discovering it by
            # sending a scan result in the clear.
            "sealing": bool(match.kex_public_key),
            "connection_mode": match.connection_mode}


@router.post("/register", response_model=dict)
async def register(body: RegisterIn, request: Request,
                   a: Agent = Depends(agent_even_if_killed),
                   session: AsyncSession = Depends(get_session)):
    """Drone announcing itself. Idempotent: it runs on every reconnect."""
    a.platform, a.arch = body.platform, body.arch
    a.version, a.hostname = body.version, body.hostname
    a.privileged = bool(body.privileged)
    a.tools = json.dumps(body.tools or {})
    a.missing_tools = json.dumps(body.missing_tools or {})
    a.outbound_ip = body.outbound_ip
    a.outbound_ip_source = body.outbound_ip_source or None
    a.outbound_ip_note = body.outbound_ip_note or None
    a.interfaces = json.dumps(body.interfaces or [])
    # Blank is stored as NULL, not "". An older Drone sends nothing and
    # a newer one that could not tell sends nothing, and both mean "no
    # answer" — which is not the same as `linux`, and not the same as
    # "no container". Flattening them here is how a UI ends up
    # asserting something nobody established.
    a.host_platform = body.host_platform or None
    a.host_platform_source = body.host_platform_source or None
    a.container = body.container or None
    a.call_in_url = body.call_in_url
    a.last_seen = datetime.now(UTC)
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


class HeartbeatIn(BaseModel):
    """What the agent says about itself when it checks in.

    Optional in full: an older agent sends an empty body, and the
    fallback below infers the same thing from what it is holding. A
    field here is the agent's own statement and is believed over the
    inference, because it is the only one of the two that cannot be
    stale.
    """
    #: False while at capacity. The queue is held until true.
    ready: bool | None = None
    #: What it is working on, 0/None when idle. Kept for agents that
    #: run one task at a time; `running_tasks` is the general form.
    running_task: int | None = None
    #: Everything it is running. The server trusts this over its own
    #: record, because the agent is the only one that can be sure.
    running_tasks: list[int] | None = None
    #: How many more it will accept right now, as the agent sees it:
    #: its own view of what the host can stand, which the project's
    #: ceiling is then applied to. None from an agent that does not
    #: know, which is read as one.
    slots_free: int | None = None
    #: What it decided it can run in total, and why. Recorded so an
    #: operator can see a number the agent chose for itself rather
    #: than wondering why a 32-core box is running two things.
    capacity: int | None = None
    capacity_reason: str | None = None


class RetiredIn(BaseModel):
    """A drone's last message: it has stopped, and this is what it took."""
    reason: str = ""
    removed: list[str] = []
    kept: list[str] = []
    failed: list[str] = []


@router.post("/retired", response_model=dict)
async def retired(body: RetiredIn,
                  a: Agent = Depends(agent_even_if_killed),
                  session: AsyncSession = Depends(get_session)):
    """A drone confirming it has shut down and cleaned up after itself.

    `agent_even_if_killed`, necessarily: this arrives from an agent that
    has just been killed, and the whole value of the message is that it
    comes after the kill.

    Pressing Kill records an intention. This records what happened,
    which is a different fact and the one that matters at the end of an
    engagement — a drone killed while its host was powered off never
    sends this, stays unretired, and that is the honest answer, because
    the tools really are still sitting on that machine.
    """
    now = datetime.now(UTC)
    a.retired_at = now
    a.retired_reason = (body.reason or "retired")[:300]
    a.retired_cleanup = json.dumps({"removed": body.removed[:100],
                                    "kept": body.kept[:100],
                                    "failed": body.failed[:100]})
    # Killed is how it stays. Retirement is the confirmation of a kill,
    # not a state an agent can put itself into to dodge one — and a
    # drone that retired on the dead-man switch must not come back as
    # enabled the moment somebody restarts its host.
    a.status = "disabled"
    a.last_seen = now
    detail = f"{a.name} confirmed shutdown: {a.retired_reason}"
    if body.removed:
        detail += f"; uninstalled {', '.join(body.removed[:8])}"
    if body.failed:
        detail += f"; COULD NOT remove {', '.join(body.failed[:8])}"
    pr = await session.get(Project, a.project_id)
    await audit.record(session, "drone", "drone.retired",
                       project_code=pr.code if pr else None, detail=detail)
    await session.commit()
    await broker.publish("agents", action="retired",
                         project=pr.code if pr else None)
    return {"ok": True, "recorded": True}


@router.post("/heartbeat", response_model=dict)
async def heartbeat(request: Request, body: HeartbeatIn | None = None,
                    a: Agent = Depends(agent_even_if_killed),
                    session: AsyncSession = Depends(get_session)):
    """Keepalive, and the poll that hands out work.

    **One task at a time, and the queue is held here.** The agent beats
    throughout a scan, not only between scans — a 45-minute enumeration
    used to mean 45 minutes of silence, which is indistinguishable from
    having died — so a beat does NOT mean "give me work". Readiness is
    stated in the body, and nothing is dispatched until it is true.

    That used to be an emergent property of the client: the server
    handed work to anyone who asked and trusted a sequential agent not
    to ask twice. It is an invariant the server holds now, so a second
    process, a modified agent or a replayed request cannot take work
    this one is still running.

    Stranded work is self-healing for the same reason. An agent that
    checks in ready while the server still has a task against it did
    not survive to finish that task, so after a grace period it goes
    back in the queue rather than sitting in `claimed` for the rest of
    the engagement with nothing left to complete it.
    """
    a.last_seen = datetime.now(UTC)
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
        task.finished_at = datetime.now(UTC)

    # What this agent is already holding. Anything here means the last
    # dispatch has not come back.
    held = (await session.execute(
        select(AgentTask).where(AgentTask.agent_id == a.id,
                                AgentTask.status.in_(("claimed", "running")))
        .order_by(AgentTask.id))).scalars().all()
    # The agent's own word on what it is doing and what it can take.
    # It beats while it is working, so the beat alone says nothing
    # about readiness.
    said = body.ready if body is not None else None
    doing_list = list(body.running_tasks or []) if body is not None else []
    if body is not None and body.running_task:
        doing_list.append(body.running_task)
    doing = set(doing_list)

    # How many it will accept. The project sets a ceiling and the agent
    # reports what its host can stand; the lower wins, because either
    # one saying "no more" is a reason not to send more. An agent that
    # reports nothing is read as one at a time, which is what every
    # agent did before any of this existed.
    pr_obj = await session.get(Project, a.project_id)
    ceiling = max(1, int(getattr(pr_obj, "drone_max_parallel", 5) or 5))
    if body is not None and body.capacity is not None:
        a.capacity = max(1, int(body.capacity))
    if body is not None and body.capacity_reason:
        a.capacity_reason = body.capacity_reason[:300]
    agent_cap = a.capacity or 1
    allowed = min(ceiling, agent_cap)
    if body is not None and body.slots_free is not None:
        free = max(0, min(int(body.slots_free), allowed - len(doing)))
    elif said is None:
        free = 0 if doing else 1          # silent agent: one at a time
    else:
        free = max(0, allowed - len(doing)) if said else 0

    if held:
        now = datetime.now(UTC)
        released = 0
        for h in held:
            if h.id in doing:
                # It says it is running exactly this. Nothing to decide.
                continue
            since = _aware(h.started_at or h.claimed_at)
            if since is None or (now - since) < ABANDON_AFTER:
                # Inside the grace window. Usually a result POST still
                # in flight on another connection, which must not be
                # raced into a duplicate run.
                continue
            if said is False and not doing:
                # At capacity, but will not say with what. An older
                # agent, so the claim is left alone rather than raced.
                continue
            h.status = "queued"
            h.agent_id = None
            h.claimed_at = h.started_at = None
            h.error = (f"released after {int(ABANDON_AFTER.total_seconds())}s: "
                       f"{a.name} checked in "
                       + ("ready for work" if said else "without it")
                       + " while still holding this, so it did not survive "
                         "to finish it")
            released += 1
        if released:
            log.warning("released %d abandoned task(s) from %s", released, a.name)
            await session.commit()
        live = [h.id for h in held if h.status in ("claimed", "running")]
        if live and body is None:
            # A silent agent runs one at a time, so anything it holds
            # means the queue waits here.
            await session.commit()
            return {"ok": True, "task": None, "holding": live,
                    "slots_free": 0, "max_parallel": ceiling}
        free = max(0, min(free, allowed - len(live)))

    if free <= 0:
        await session.commit()
        return {"ok": True, "task": None, "holding": sorted(doing),
                "slots_free": 0, "max_parallel": ceiling}

    # Up to `free`, not one. Work addressed to this agent by name
    # comes first: the operator chose it, and a routing policy should
    # not second-guess that.
    chosen: list[AgentTask] = []
    for cand in (await session.execute(
            select(AgentTask).where(AgentTask.agent_id == a.id,
                                    AgentTask.status == "queued")
            .order_by(AgentTask.id).limit(100))).scalars():
        if len(chosen) >= free:
            break
        why = scope_refusal(cand)
        if why is not None:
            drop(cand, why)
            continue
        if not _has_tool(a, cand.kind):
            # Addressed to this agent, which does not have what it
            # needs. Failed rather than left waiting forever: nothing
            # about this agent is going to change, and a task queued
            # against it is a task that will never run.
            drop(cand, f"{a.name} does not have {KIND_TOOL[cand.kind]} and "
                       f"could not install it. Queue this against an agent "
                       f"that has it, or to the project pool.")
            continue
        chosen.append(cand)

    if len(chosen) < free:
        # Then the project's pool, oldest first, subject to the routing
        # policy. Walked rather than filtered in SQL because "is this
        # agent the primary right now" is a question about live
        # heartbeats, not a column.
        project = await session.get(Project, a.project_id)
        pool = (await session.execute(
            select(AgentTask).where(AgentTask.project_id == a.project_id,
                                    AgentTask.agent_id.is_(None),
                                    AgentTask.status == "queued")
            .order_by(AgentTask.id).limit(100))).scalars().all()
        for cand in pool:
            if len(chosen) >= free:
                break
            why = scope_refusal(cand)
            if why is not None:
                drop(cand, why)
                continue
            if not _has_tool(a, cand.kind):
                # Left in the pool, not failed: another agent may well
                # have the tool, and this is exactly what pooling is
                # for. It only becomes a problem if none of them do,
                # which the queue depth makes visible.
                continue
            if project is not None and await _may_claim(session, project, a, cand):
                cand.agent_id = a.id
                chosen.append(cand)

    now = datetime.now(UTC)
    out = []
    _reverse_candidates: list[str] | None = None
    for t in chosen:
        t.status = "claimed"
        t.claimed_at = now
        targs = json.loads(t.args) if t.args else {}
        if t.kind == "reverse_ip" and not targs.get("candidates"):
            # Filled in here rather than stored per task. See _candidates.
            if _reverse_candidates is None:
                _reverse_candidates = await _candidates(session, a.project_id)
            if _reverse_candidates:
                targs = {**targs, "candidates": _reverse_candidates}
        out.append({"id": t.id, "kind": t.kind, "args": targs})
    await session.commit()
    # `task` singular is kept alongside `tasks`: an agent built before
    # this reads only the first field and would otherwise be handed
    # nothing at all by a server that had moved on without it.
    return {"ok": True, "task": out[0] if out else None, "tasks": out,
            "slots_free": free, "max_parallel": ceiling}


@router.post("/tasks/{task_id}/start", response_model=dict)
async def start_task(task_id: int, a: Agent = Depends(agent_from_key),
                     session: AsyncSession = Depends(get_session)):
    t = await session.get(AgentTask, task_id)
    if t is None or t.agent_id != a.id:
        raise HTTPException(404, "no such task for this agent")
    t.status = "running"
    t.started_at = datetime.now(UTC)
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

    t.output, t.stderr = body.output, body.stderr
    t.summary, t.exit_code, t.error = body.summary, body.exit_code, body.error
    now = datetime.now(UTC)
    a.last_seen = now

    requeued = False
    if body.status == "done":
        t.status = "done"
        t.finished_at = now
    else:
        t.attempts = (t.attempts or 0) + 1
        if t.attempts <= MAX_RETRIES and _retryable(body.error or ""):
            # Back in the queue, and back in the POOL: the agent that
            # just failed is the least likely to succeed, and leaving
            # it addressed there is how a broken host retries its own
            # failure twice more. An operator who addressed it on
            # purpose keeps that; a pooled task stays pooled.
            t.status = "queued"
            t.agent_id = None
            t.claimed_at = t.started_at = t.finished_at = None
            t.error = (f"attempt {t.attempts} on {a.name} failed, requeued: "
                       f"{(body.error or body.summary or 'no reason given')}")[:4000]
            requeued = True
        else:
            t.status = "failed"
            t.finished_at = now
            why = ("not retryable" if not _retryable(body.error or "")
                   else f"{t.attempts} attempts")
            t.error = (f"{(body.error or body.summary or 'failed')} "
                       f"[{why}; restart it by hand to try again]")[:4000]
    # The agent authenticates by key, not as a person, so the actor is
    # the agent's own name -- which is the honest answer to "who sent
    # this" and the one worth having when a result looks wrong.
    await audit.record(session, "drone", "drone.result",
                       username=f"drone:{a.name}",
                       project_code=(await session.get(Project, t.project_id)).code
                       if t.project_id else None,
                       detail=f"task {t.id} {t.status}"
                              + (f" (requeued, attempt {t.attempts})"
                                 if requeued else "")
                              + (f" exit={t.exit_code}" if t.exit_code is not None else "")
                              + (f" import={t.import_as}" if t.import_as else ""))
    await session.commit()

    imported = None
    # Name discovery does not go through the file importers: there is no
    # file, only a list of names an agent resolved. Handled here so the
    # result of asking an agent to enumerate a domain actually appears
    # in the inventory, which is the entire reason the task was queued.
    if t.status == "done" and t.kind in NAME_KINDS and (t.output or "").strip():
        pr = await session.get(Project, t.project_id)
        try:
            imported = await _import_names(session, pr, t, actor=f"drone:{a.name}")
            t.import_result = json.dumps(imported)
            await session.commit()
        except Exception as e:                   # noqa: BLE001
            # The names are kept on the task either way. A lookup that
            # ran and could not be filed is still evidence.
            t.import_result = json.dumps({"error": f"{type(e).__name__}: {e}"[:500]})
            await session.commit()

    # A finished DNS lookup resolves itself, here, rather than waiting
    # for somebody to open the Targets page. Most of what one returns
    # stopped being a decision when addresses became many-to-many — a
    # host with four addresses has four addresses — and what is left
    # genuinely ambiguous is still queued for a person. The rule, and
    # the argument for where the line falls, is in app/lookups.py.
    if t.status == "done" and t.kind in LOOKUP_KINDS and (t.output or "").strip():
        pr = await session.get(Project, t.project_id)
        try:
            rep = await apply_auto(session, pr, actor=f"drone:{a.name}")
            await session.commit()
            resolved = rep.model_dump()
        except Exception:                        # noqa: BLE001
            # Never fail the result submission over this. The agent has
            # delivered its work and that must land; a lookup that could
            # not be applied is still on the task, and the Targets page
            # will offer it the next time anybody looks.
            await session.rollback()
            # The detail goes to the log, not down the wire. This
            # response is read by a Drone sitting inside a client's
            # network, and the exception text here can carry a SQL
            # fragment, a column name or a filesystem path — the shape
            # of this server, handed to the least trusted place it
            # talks to. CodeQL called it py/stack-trace-exposure and
            # was right.
            #
            # The agent gets a stable marker instead: enough to know
            # the lookup did not apply and to say so, and useless to
            # anyone who has got hold of a drone's key.
            log.warning("applying lookup results for task %s failed",
                        t.id, exc_info=True)
            resolved = {"error": "could not be applied; see the server log"}
        imported = {**(imported or {}), "lookup": resolved}

    if t.status == "done" and t.import_as and (t.output or "").strip():
        pr = await session.get(Project, t.project_id)
        from .scans import _run
        try:
            res = await _run(session, pr, t.output, t.import_as,
                             f"drone:{a.name}", mode="strict", decisions={})
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
