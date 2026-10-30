"""Building proofs for the findings a project asked to have proved.

The `auto_poc` standing order names a severity FLOOR; this is what
acts on it. Structurally `remediate.py`: one finding at a time, worst
first, a pause between them, failure bounded per finding. Scanners
deliver findings in bulk and firing those at a model concurrently
saturates a shared inference server.

What it does per finding, and the order is deliberate:

    1. ask the model for a nuclei template     (agent/pocbuild.py)
    2. check what came back                    (pocbuild.check)
    3. store it as a Poc row
    4. queue a `poc` task at HIGH PRIORITY     the Ghost runs it
    5. the verdict comes home                  (app/pocwork.py)

Steps 1-3 happen here; 4 is a row in the task table and 5 is the
result handler. Nothing in this module sends anything at a client --
it writes a template and asks for it to be run, and the thing that
runs it is the thing the rules of engagement already govern.

**It needs both halves of the agent and refuses without them.** No
model configured and there is nothing to write the template; no Ghost
online and there is nothing to run it, so the proof would sit forever
reading "not validated" with no way to tell that from a failure. Both
are reported as the reason rather than looking idle.

**High priority, because a proof is a question somebody is waiting
on.** Everything else in the queue is a sweep; this is "is the thing
you just told me about real". `AgentTask.priority` already exists and
the dispatcher already orders by it.
"""
from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import SessionLocal
from ..events import broker
from ..models import SEVERITIES, Agent, AgentTask, Poc, Project, Target, Vuln
from .pocbuild import SYSTEM, Rejected, check

log = logging.getLogger("oddjob.pocworker")

IDLE_SLEEP = 30.0
ERROR_SLEEP = 60.0
#: Between findings. A proof is a model call and a queued task, and
#: the point of pacing is the model rather than the queue.
STEP_DELAY = 3.0
#: Above every sweep in the queue. See the module docstring.
PRIORITY = 100

#: Worst first, so a worker that is switched off after twenty
#: findings proved the twenty that mattered.
_RANK = case({s: i for i, s in enumerate(SEVERITIES)},
             value=Vuln.severity, else_=99)


async def _next(session: AsyncSession, project_id: int,
                severities: tuple[str, ...]) -> Vuln | None:
    """The worst finding in this project that has no proof yet."""
    if not severities:
        return None
    has_poc = select(Poc.id).where(Poc.vuln_id == Vuln.id).exists()
    return (await session.execute(
        select(Vuln)
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == project_id,
               Vuln.severity.in_(severities),
               ~has_poc)
        .order_by(_RANK, Vuln.id)
        .limit(1))).scalars().first()


async def _ask(session: AsyncSession, project: Project, vuln: Vuln,
               host: str) -> str:
    """Put one finding to the model and return the raw reply."""
    from ..routers.agent import _resolve
    from .providers import anthropic_chat, openai_chat

    provider, token, model, _src, base_url, _cfg = await _resolve(
        session, project)
    body = "\n".join(x for x in [
        f"Title: {vuln.title}",
        f"Severity: {vuln.severity}",
        f"Host: {host}" + (f":{vuln.port}" if vuln.port else ""),
        f"Reference: {vuln.external_id}" if vuln.external_id else None,
        "",
        (vuln.description or "(no description was recorded)")[:8000],
    ] if x is not None)

    args = (token, model, SYSTEM, [{"role": "user", "content": body}],
            [], _no_tools, 0)
    reply = (await anthropic_chat(*args) if provider == "anthropic"
             else await openai_chat(*args, base_url=base_url))
    return (reply.text or "").strip()


async def _no_tools(_tool, _args):      # writing a template gets no tools
    return "{}"


def _url_for(vuln: Vuln, host: str) -> str:
    """Where to point the proof.

    The scheme is a guess from the port and is the one thing here
    that can be wrong without being detectable: 443 and 8443 are
    https, everything else http. A wrong guess reports "could not
    test" rather than a wrong verdict, because the runner proves
    reachability before it runs anything.
    """
    port = vuln.port or 0
    scheme = "https" if port in (443, 8443, 8444, 9443) else "http"
    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


async def build_one(session: AsyncSession, vuln: Vuln, project: Project,
                    host: str) -> Poc:
    """Write a proof for one finding and queue its validation.

    Raises `Rejected` when the model's answer must not be stored, and
    the caller records that against the finding rather than retrying
    forever -- a finding that cannot be expressed as an HTTP check
    will not become expressible on the third attempt.
    """
    template = check(await _ask(session, project, vuln, host))
    url = _url_for(vuln, host)
    poc = Poc(target_id=vuln.target_id, vuln_id=vuln.id,
              title=f"Proof: {vuln.title}"[:500],
              status="unconfirmed", template=template, target_url=url)
    session.add(poc)
    await session.flush()

    # Unassigned, so the project's routing policy picks the agent --
    # the same way every other queued task is placed.
    session.add(AgentTask(
        agent_id=None, project_id=project.id, requested_by=None,
        kind="poc", priority=PRIORITY, status="queued",
        args=json.dumps({"poc_id": poc.id, "url": url,
                         "template": template})))
    return poc


async def _one(project_id: int, severities: tuple[str, ...]) -> str:
    """One finding. -> 'done' | 'skipped' | 'empty' | 'error'."""
    async with SessionLocal() as session:
        vuln = await _next(session, project_id, severities)
        if vuln is None:
            return "empty"
        target = await session.get(Target, vuln.target_id)
        project = await session.get(Project, project_id)
        if target is None or project is None:
            return "empty"

        try:
            poc = await build_one(session, vuln, project, target.host)
        except Rejected as e:
            # A real answer, recorded as one. "We could not write a
            # check for this" is not "we wrote one and it failed",
            # and a row saying so is what stops the worker picking
            # the same finding up on every cycle for ever.
            session.add(Poc(
                target_id=vuln.target_id, vuln_id=vuln.id,
                title=f"Proof: {vuln.title}"[:500],
                status="unconfirmed", exit_code=None,
                verdict=f"no proof was written — {e}"[:4000]))
            await session.commit()
            log.info("poc for vuln %s not written: %s", vuln.id, e)
            return "skipped"
        except Exception as e:                   # noqa: BLE001
            log.warning("poc for vuln %s failed: %s", vuln.id, e)
            return "error"

        await session.commit()
        await broker.publish("pocs", action="create", project=project.code,
                             id=poc.id)
        await broker.publish("agents", action="task", project=project.code)
        return "done"


async def _projects() -> list[tuple[int, str, tuple[str, ...]]]:
    """Projects with a floor set, and what that floor covers.

    Only those with a Ghost online. A proof queued with nothing to
    run it sits reading "not validated" for ever, which is
    indistinguishable on screen from one that was run and settled
    nothing -- so it is not queued at all, and the reason is said.
    """
    from ..automation import poc_severities
    out = []
    async with SessionLocal() as session:
        rows = (await session.execute(
            select(Project).where(
                func.coalesce(Project.auto_poc, "off") != "off"))).scalars()
        for pr in rows:
            sev = poc_severities(str(pr.auto_poc or "off"))
            if not sev:
                continue
            live = (await session.execute(
                select(Agent.id).where(Agent.project_id == pr.id,
                                       Agent.status == "online")
                .limit(1))).first()
            if live is None:
                continue
            out.append((pr.id, pr.code, sev))
    return out


class Worker:
    """The single background task. Started once, at startup."""

    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.running = False
        self.last: str | None = None
        self.consecutive_errors = 0

    async def _loop(self) -> None:
        log.info("poc worker started")
        while True:
            try:
                if not await _configured():
                    self.last = "no agent is configured to write proofs"
                    await asyncio.sleep(IDLE_SLEEP)
                    continue
                projects = await _projects()
                if not projects:
                    self.last = ("no project has auto_poc on with a Ghost "
                                 "online")
                    await asyncio.sleep(IDLE_SLEEP)
                    continue

                did = 0
                for pid, code, sev in projects:
                    outcome = await _one(pid, sev)
                    if outcome == "error":
                        self.consecutive_errors += 1
                        await asyncio.sleep(
                            min(ERROR_SLEEP * self.consecutive_errors, 600))
                        break
                    if outcome in ("done", "skipped"):
                        did += 1
                        self.last = f"{code}: {outcome}"
                        self.consecutive_errors = 0
                        await asyncio.sleep(STEP_DELAY)
                if did == 0:
                    self.last = "nothing outstanding"
                    await asyncio.sleep(IDLE_SLEEP)
            except asyncio.CancelledError:
                log.info("poc worker stopped")
                raise
            except Exception:
                # Must outlive any single failure: a crashed
                # background task fails silently and for ever.
                log.exception("poc worker iteration failed")
                await asyncio.sleep(ERROR_SLEEP)

    def start(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop())
            self.running = True

    async def stop(self) -> None:
        if self.task is not None:
            self.task.cancel()
            self.running = False


async def _configured() -> bool:
    from ..routers.settings import load_all
    async with SessionLocal() as session:
        cfg = await load_all(session)
    provider = str(cfg.get("agent.provider") or "anthropic")
    return bool(str(cfg.get("agent.local_base_url") or "").strip()
                if provider == "local" else
                str(cfg.get(f"agent.{provider}_token") or "").strip())


worker = Worker()
