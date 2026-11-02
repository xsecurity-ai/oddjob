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

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import SessionLocal
from ..events import broker
from ..models import (
    SEVERITIES,
    Agent,
    AgentTask,
    FindingSecret,
    Poc,
    Project,
    Target,
    Vuln,
)
from .pocbuild import SECRET_VAR, SYSTEM, Rejected, check

log = logging.getLogger("oddjob.pocworker")

IDLE_SLEEP = 30.0
ERROR_SLEEP = 60.0
#: Between findings. A proof is a model call and a queued task, and
#: the point of pacing is the model rather than the queue.
STEP_DELAY = 3.0
#: Above every sweep in the queue. See the module docstring.
PRIORITY = 100

#: The two things a proof of a credential can claim. `EXPOSURE` is
#: the default everywhere, including when a stored request has lost
#: its mode: asking "is the key still served here" sends nothing of
#: the client's anywhere, and defaulting to the other one would have
#: a dropped column decide to authenticate.
EXPOSURE = "exposure"
AUTH = "auth"

#: Worst first, so a worker that is switched off after twenty
#: findings proved the twenty that mattered.
_RANK = case({s: i for i, s in enumerate(SEVERITIES)},
             value=Vuln.severity, else_=99)


async def _next(session: AsyncSession, project_id: int,
                severities: tuple[str, ...]) -> Vuln | None:
    """The next finding in this project that has no proof yet.

    Two sources, and asked-for beats swept:

      requested  somebody clicked "prove these" on a host, a
                 vulnerability or a credential. Regardless of
                 severity -- the floor is a policy about the
                 engagement and this is a person pointing at a row.
      the floor  `auto_poc`, worst first.

    Requested findings come first because a request is a question
    somebody is waiting on and the sweep is a backlog. Without the
    ordering, asking for a proof of one low-severity credential
    behind 4,000 swept criticals means waiting three hours for it,
    which reads as the button having done nothing.
    """
    has_poc = select(Poc.id).where(Poc.vuln_id == Vuln.id).exists()
    wanted = [Vuln.poc_requested_at.is_not(None)]
    if severities:
        wanted.append(Vuln.severity.in_(severities))
    return (await session.execute(
        select(Vuln)
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == project_id, or_(*wanted), ~has_poc)
        # `is_(None)` sorts False(0) before True(1), so "has a
        # request" lands above "has none" without a DESC that would
        # also flip the severity rank under it.
        .order_by(Vuln.poc_requested_at.is_(None), _RANK, Vuln.id)
        .limit(1))).scalars().first()


def _target_url(vuln: Vuln, host: str,
                secret: FindingSecret | None) -> str:
    """Where to point the proof.

    The credential's own asset, not the bare host. A key found in a
    JS bundle is not provable at `https://host/` -- the check has to
    fetch the file it is in, and a proof pointed anywhere else
    reports "could not test" for ever, which reads on screen exactly
    like one that was run and settled nothing.
    """
    if secret is not None and secret.asset_url:
        return secret.asset_url
    return _url_for(vuln, host)


async def _secret_for(session: AsyncSession, vuln: Vuln) -> FindingSecret | None:
    """The credential behind this finding, if it is one.

    Fetched for its LOCATION, never its value -- see `_ask`.
    """
    return (await session.execute(
        select(FindingSecret).where(FindingSecret.vuln_id == vuln.id)
        .limit(1))).scalars().first()


def _auth_brief(sec: FindingSecret) -> list[str]:
    """What the model is told when the ask is "does this key work".

    **Still no value.** The model writes the SHAPE of the check and
    nuclei substitutes `{{secret}}` at run time from a value the
    Ghost fetches with its own identity. So the credential reaches
    the service it belongs to and nothing else -- not the model, not
    the prompt logs, not the stored template, not the task args.

    **Only against the host being tested.** A leaked key's natural
    validator is the third party that issued it, and that host is not
    in the engagement's scope: presenting a client's credential to a
    service nobody authorised us to touch is a different act from
    testing the client's own system. `check(carries_secret=True)`
    refuses a template that addresses anything but `{{BaseURL}}`, and
    the model is told to say so rather than write one.
    """
    where = sec.asset_url or sec.path or "(location not recorded)"
    return [
        "",
        "This finding is an EXPOSED CREDENTIAL, and the question is "
        "whether it STILL WORKS.",
        f"Seen in: {where}" + (f" line {sec.line}" if sec.line else ""),
        f"Detector: {sec.detector}" if sec.detector else None,
        "",
        "Write a template that presents the credential to the host under "
        "test and matches on a reply that only a VALID credential "
        "produces — an authenticated response body, a principal or "
        "account identifier, a 200 where an invalid key gives 401 or 403. "
        "Matching merely 'not 401' is not enough: many endpoints answer "
        "200 to anyone.",
        "",
        f"Use {SECRET_VAR} wherever the credential goes. You are not "
        f"given its value and must not invent one; it is substituted at "
        f"run time.",
        "",
        "Send ONLY to {{BaseURL}}. If this kind of credential can only be "
        "validated against a third-party service — a cloud provider, a "
        "SaaS API — then it cannot be checked here, because that host is "
        "not in this engagement's scope. Reply cannot-prove and say so.",
        "Do not use `raw`.",
        "Do not change anything: authenticate and read, never write, "
        "delete or rotate.",
    ]


def _secret_brief(sec: FindingSecret) -> list[str]:
    """What the model is told about an exposed credential.

    **The value is not in here and must never be.** `FindingSecret`
    exists precisely so a credential stays out of everything that
    leaves the platform -- descriptions, exports, reports, Slack --
    and the model is the furthest-travelling of those: the prompt
    goes to a third party and may be logged there, and a key found
    on a client's estate is still live after the engagement ends.
    The same argument already keeps `get_finding_secret` off MCP.

    What CAN go is where it was seen and what kind of thing it is,
    which is not the secret. That is enough for a real check: fetch
    the asset and match the detector's key FORMAT. A proof that says
    "this URL still serves something shaped like an AWS access key"
    is evidence the exposure is unfixed, and it is the honest limit
    of what can be proved without replaying the credential at the
    service -- which would be using it, not testing it.
    """
    where = sec.asset_url or sec.path or "(location not recorded)"
    return [
        "",
        "This finding is an EXPOSED CREDENTIAL.",
        f"Seen in: {where}" + (f" line {sec.line}" if sec.line else ""),
        f"Detector: {sec.detector}" if sec.detector else None,
        "The credential's VALUE is deliberately withheld from you, and a "
        "template that tries to authenticate with it would be using the "
        "credential rather than testing the exposure. Prove instead that "
        "the asset above STILL SERVES a value of this kind: request it and "
        "match on the key's well-known format for that detector. If you do "
        "not know a format specific enough to avoid matching ordinary "
        "text, say cannot-prove rather than writing a loose matcher.",
    ]


async def _ask(session: AsyncSession, project: Project, vuln: Vuln,
               host: str, secret: FindingSecret | None = None,
               mode: str | None = None) -> str:
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
        *([] if secret is None else
           _auth_brief(secret) if mode == AUTH else _secret_brief(secret)),
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
                    host: str, mode: str | None = None) -> Poc:
    """Write a proof for one finding and queue its validation.

    Raises `Rejected` when the model's answer must not be stored, and
    the caller records that against the finding rather than retrying
    forever -- a finding that cannot be expressed as an HTTP check
    will not become expressible on the third attempt.
    """
    # The credential's own asset, not the bare host. A secret found
    # in a JS bundle is not provable at `https://host/` -- the check
    # has to fetch the file it is in, and pointing it anywhere else
    # produces a proof that reports "could not test" for ever.
    secret = await _secret_for(session, vuln)
    # `auth` only means anything when there IS a credential to
    # present. Asked for on an ordinary finding it falls back to the
    # normal proof rather than refusing: the operator asked for the
    # finding to be proved, and there is a way to do that.
    auth = mode == AUTH and secret is not None
    template = check(
        await _ask(session, project, vuln, host, secret, mode),
        carries_secret=auth)
    # An authenticating proof goes at the SERVICE, not at the file the
    # key was found in: you present a credential to something that
    # checks it, and a JS bundle does not.
    url = _url_for(vuln, host) if auth else _target_url(vuln, host, secret)
    poc = Poc(target_id=vuln.target_id, vuln_id=vuln.id,
              title=f"Proof: {vuln.title}"[:500],
              status="unconfirmed", template=template, target_url=url,
              needs_secret=auth)
    session.add(poc)
    await session.flush()

    # Unassigned, so the project's routing policy picks the agent --
    # the same way every other queued task is placed.
    #
    # `needs_secret` is a FLAG, not the credential. The value stays
    # out of `args` because the tasks view lists them: a key written
    # here would be a key on screen for anyone who can see the queue,
    # which is the whole thing `FindingSecret` exists to prevent. The
    # agent fetches it over its own route when it runs the task.
    session.add(AgentTask(
        agent_id=None, project_id=project.id, requested_by=None,
        kind="poc", priority=PRIORITY, status="queued",
        args=json.dumps({"poc_id": poc.id, "url": url,
                         "template": template, "needs_secret": auth})))
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
            poc = await build_one(session, vuln, project, target.host,
                                  vuln.poc_request_mode)
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
    """Projects with work: a floor set, outstanding requests, or both.

    A project with `auto_poc` off is still here if somebody asked for
    specific proofs. That is the whole point of a request -- proving
    the findings on one host must not mean turning a standing order
    on for the engagement, because the floor would then cover every
    finding at that severity for ever and switching it back off does
    not un-send what went out meanwhile.

    The returned severities are the FLOOR's, and may be empty: an
    empty tuple means "requests only", which `_next` reads correctly.

    Only projects with a Ghost online. A proof queued with nothing to
    run it sits reading "not validated" for ever, which is
    indistinguishable on screen from one that was run and settled
    nothing -- so it is not queued at all, and the reason is said.
    """
    from ..automation import poc_severities
    out = []
    async with SessionLocal() as session:
        asked = (select(Vuln.id)
                 .join(Target, Target.id == Vuln.target_id)
                 .where(Target.project_id == Project.id,
                        Vuln.poc_requested_at.is_not(None),
                        ~select(Poc.id).where(Poc.vuln_id == Vuln.id).exists())
                 .exists())
        rows = (await session.execute(
            select(Project).where(or_(
                func.coalesce(Project.auto_poc, "off") != "off",
                asked)))).scalars()
        for pr in rows:
            sev = poc_severities(str(pr.auto_poc or "off"))
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
