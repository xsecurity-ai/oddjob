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
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..events import broker
from ..models import Agent, AgentTask, Project, User
from ..security import (get_current_user, new_agent_key, require_project,
                        verify_key)
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
INSTALLABLE = ("amass", "nmap", "masscan", "gobuster", "nuclei", "httpx",
               "subfinder", "ffuf", "whatweb", "nikto", "dnsx", "naabu")

#: Task kinds the agent knows how to run, and the importer that reads
#: each one's output. None means the result is not a scan import.
TASK_KINDS: dict[str, str | None] = {
    "nmap": "nmap",
    "masscan": "masscan",
    "amass": None,
    "gobuster": None,
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
    call_in_url: str | None = None
    last_seen: datetime | None = None
    last_ip: str | None = None
    queued_tasks: int = 0
    created_at: datetime | None = None


class AgentEnrolled(BaseModel):
    """Returned once, at enrolment. The keys are never shown again."""
    agent: AgentOut
    callback_key: str = Field(description="Give this to Jaws. It authenticates "
                                          "the agent to the server.")
    call_in_key: str = Field(description="Jaws requires this on inbound calls, "
                                         "so the agent can tell the server from "
                                         "anyone else who finds the port.")


class EnrolIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    notes: str | None = None


class RegisterIn(BaseModel):
    """What Jaws reports about itself when it connects."""
    platform: str | None = None
    arch: str | None = None
    version: str | None = None
    hostname: str | None = None
    privileged: bool = False
    tools: dict[str, str] = {}
    call_in_url: str | None = None


class TaskIn(BaseModel):
    kind: str
    args: dict = {}
    #: Override the importer. Normally derived from `kind`.
    import_as: str | None = None


class TaskOut(BaseModel):
    id: int
    agent_id: int
    project_code: str
    kind: str
    args: dict = {}
    status: str
    summary: str | None = None
    exit_code: int | None = None
    error: str | None = None
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


def _agent_out(a: Agent, code: str, queued: int = 0) -> AgentOut:
    return AgentOut(
        id=a.id, project_code=code, name=a.name, status=a.status,
        platform=a.platform, arch=a.arch, version=a.version,
        hostname=a.hostname, privileged=a.privileged, tools=_tools(a.tools),
        call_in_url=a.call_in_url, last_seen=a.last_seen, last_ip=a.last_ip,
        queued_tasks=queued, created_at=a.created_at)


def _task_out(t: AgentTask, code: str) -> TaskOut:
    def j(v):
        try:
            return json.loads(v) if v else None
        except ValueError:
            return None
    return TaskOut(
        id=t.id, agent_id=t.agent_id, project_code=code, kind=t.kind,
        args=j(t.args) or {}, status=t.status, summary=t.summary,
        exit_code=t.exit_code, error=t.error, import_as=t.import_as,
        import_result=j(t.import_result), created_at=t.created_at,
        started_at=t.started_at, finished_at=t.finished_at)


def _stale(a: Agent) -> str:
    """Offline is an observation, disabled is a decision."""
    if a.status == "disabled":
        return "disabled"
    if a.last_seen and (datetime.now(timezone.utc) - a.last_seen) < OFFLINE_AFTER:
        return "online"
    return "offline"


# ----------------------------------------------------------- agent auth
async def agent_from_key(request: Request,
                         session: AsyncSession = Depends(get_session)) -> Agent:
    """Authenticate the AGENT to the server, by its callback key.

    Scanned linearly because the key is not stored in any form we can
    index on — only a hash — and there are tens of agents, not
    millions. If that ever stops being true, store a short public
    prefix alongside the hash and look up on that, exactly as the API
    keys do.
    """
    auth = request.headers.get("Authorization", "")
    key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not key:
        key = request.headers.get("X-Jaws-Key", "").strip()
    if not key:
        raise HTTPException(401, "no agent key supplied")
    for a in (await session.execute(select(Agent))).scalars():
        if verify_key(key, a.callback_key_hash):
            if a.status == "disabled":
                raise HTTPException(403, "this agent is disabled")
            return a
    raise HTTPException(401, "unknown agent key")


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
    cb_raw, cb_hash = new_agent_key()
    ci_raw, ci_hash = new_agent_key()
    a = Agent(project_id=pr.id, name=body.name.strip(),
              callback_key_hash=cb_hash, call_in_key_hash=ci_hash,
              notes=body.notes, status="offline")
    session.add(a)
    await session.commit()
    await session.refresh(a)
    await broker.publish("agents", action="enrol", project=pr.code)
    return AgentEnrolled(agent=_agent_out(a, pr.code),
                         callback_key=cb_raw, call_in_key=ci_raw)


@router.get("", response_model=list[AgentOut])
async def list_agents(project: str | None = Query(None),
                      pr: Project = Depends(require_project("readonly")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(Agent).where(Agent.project_id == pr.id)
        .order_by(Agent.name))).scalars().all()
    out = []
    for a in rows:
        a.status = _stale(a)
        queued = len((await session.execute(
            select(AgentTask.id).where(AgentTask.agent_id == a.id,
                                       AgentTask.status.in_(
                                           ("queued", "claimed", "running"))))).all())
        out.append(_agent_out(a, pr.code, queued))
    return out


@router.patch("/{agent_id}", response_model=AgentOut)
async def set_agent(agent_id: int, enabled: bool = Query(...),
                    pr: Project = Depends(require_project("admin")),
                    _: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    # Disabling is remembered; offline is recomputed from last_seen.
    a.status = "offline" if enabled else "disabled"
    await session.commit()
    return _agent_out(a, pr.code)


@router.delete("/{agent_id}", status_code=204)
async def remove_agent(agent_id: int,
                       pr: Project = Depends(require_project("admin")),
                       _: User = Depends(get_current_user),
                       session: AsyncSession = Depends(get_session)):
    a = await session.get(Agent, agent_id)
    if a is None or a.project_id != pr.id:
        raise HTTPException(404, "no such agent")
    await session.delete(a)
    await session.commit()


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

    t = AgentTask(agent_id=a.id, project_id=pr.id, requested_by=user.id,
                  kind=body.kind, args=json.dumps(body.args or {}),
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
@router.post("/register", response_model=dict)
async def register(body: RegisterIn, request: Request,
                   a: Agent = Depends(agent_from_key),
                   session: AsyncSession = Depends(get_session)):
    """Jaws announcing itself. Idempotent: it runs on every reconnect."""
    a.platform, a.arch = body.platform, body.arch
    a.version, a.hostname = body.version, body.hostname
    a.privileged = bool(body.privileged)
    a.tools = json.dumps(body.tools or {})
    a.call_in_url = body.call_in_url
    a.last_seen = datetime.now(timezone.utc)
    a.last_ip = request.client.host if request.client else None
    if a.status != "disabled":
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
async def heartbeat(request: Request, a: Agent = Depends(agent_from_key),
                    session: AsyncSession = Depends(get_session)):
    """Keepalive, and the poll that hands out work.

    One task at a time. An agent that grabbed ten and died would strand
    all ten in `claimed`, and the scans this runs are long enough that
    pipelining buys nothing.
    """
    a.last_seen = datetime.now(timezone.utc)
    a.last_ip = request.client.host if request.client else None
    if a.status != "disabled":
        a.status = "online"

    t = (await session.execute(
        select(AgentTask).where(AgentTask.agent_id == a.id,
                                AgentTask.status == "queued")
        .order_by(AgentTask.id).limit(1))).scalar_one_or_none()
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
