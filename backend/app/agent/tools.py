"""What the agent is allowed to do, and the schemas it sees.

These are the same operations the MCP server exposes, implemented against
the session directly rather than over HTTP — the agent is already inside
the app, and round-tripping through its own API would add a second auth
path to get wrong.

Two boundaries matter:

**The project is fixed by the caller, never by the model.** Every tool runs
against the project the chat was opened on. A tool cannot name a different
one, so a prompt-injected instruction in some imported scan output cannot
walk the agent into another customer's engagement.

**Writes are off unless switched on.** With `agent.allow_writes` false the
write tools are not merely refused, they are *not offered* — the model
never sees them, which is a far stronger guarantee than asking it nicely.
Scan output, page titles and NSE results are attacker-influenced text, and
an agent reading them is being fed untrusted input all day.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..domains import registrable
from ..hosts import InvalidHost, validate_host
from ..models import (Credential, DomainCandidate, Implant, Poc, Project,
                      Service, Target, User, Vuln, WebAddress)
from ..timeline import record


class Tool:
    def __init__(self, name: str, description: str, schema: dict,
                 fn: Callable, writes: bool = False):
        self.name = name
        self.description = description
        self.schema = schema
        self.fn = fn
        self.writes = writes


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


def _rows(items: list[dict], limit: int, total: int) -> dict:
    """Always say how much was left out. A model shown 50 of 6,000 findings
    and not told so will answer as though it saw all of them."""
    out: dict[str, Any] = {"items": items, "returned": len(items), "total": total}
    if total > len(items):
        out["truncated"] = (f"showing {len(items)} of {total}; narrow with "
                            f"`search` or raise `limit` (max {limit})")
    return out


MAX_ROWS = 200


def build(session: AsyncSession, project: Project, user: User,
          allow_writes: bool) -> list[Tool]:
    pid = project.id

    async def _target(host: str) -> Target | None:
        return (await session.execute(
            select(Target).where(Target.project_id == pid,
                                 Target.host == host.strip().lower()))).scalar_one_or_none()

    # ------------------------------------------------------------ reads
    async def overview(**_) -> dict:
        async def count(model, *where):
            stmt = select(func.count()).select_from(model)
            if model is Target:
                stmt = stmt.where(Target.project_id == pid, *where)
            else:
                stmt = (stmt.join(Target, Target.id == model.target_id)
                        .where(Target.project_id == pid, *where))
            return int((await session.execute(stmt)).scalar_one())

        sev = {s: await count(Vuln, Vuln.severity == s)
               for s in ("critical", "high", "medium", "low", "info")}
        return {
            "project": project.code, "name": project.name, "client": project.client,
            "targets": await count(Target),
            "alive": await count(Target, Target.alive.is_(True)),
            "compromised": await count(Target, Target.hacked.is_(True)),
            "services": await count(Service),
            "open_ports": await count(Service, Service.state == "open"),
            "unidentified_open_ports": await count(
                Service, Service.state == "open", Service.name == "UNKNOWN"),
            "web_addresses": await count(WebAddress),
            "implants": await count(Implant),
            "findings_by_severity": sev,
            "pocs": await count(Poc),
        }

    async def list_targets(search: str = "", only_alive: bool = False,
                           only_compromised: bool = False, limit: int = 50) -> dict:
        stmt = select(Target).where(Target.project_id == pid)
        if search:
            like = f"%{search}%"
            stmt = stmt.where(or_(Target.host.ilike(like), Target.ip_address.ilike(like),
                                  Target.os.ilike(like), Target.notes.ilike(like)))
        if only_alive:
            stmt = stmt.where(Target.alive.is_(True))
        if only_compromised:
            stmt = stmt.where(Target.hacked.is_(True))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.order_by(Target.host).limit(n))).scalars().all()
        return _rows([{"host": t.host, "ip": t.ip_address, "alive": t.alive,
                       "compromised": t.hacked, "os": t.os} for t in rows], MAX_ROWS, total)

    async def get_host(host: str) -> dict:
        t = await _target(host)
        if t is None:
            return {"error": f"no target {host!r} in {project.code}"}
        svcs = (await session.execute(
            select(Service).where(Service.target_id == t.id)
            .order_by(Service.port))).scalars().all()
        vulns = (await session.execute(
            select(Vuln).where(Vuln.target_id == t.id))).scalars().all()
        imps = (await session.execute(
            select(Implant).where(Implant.target_id == t.id))).scalars().all()
        urls = (await session.execute(
            select(WebAddress.url, WebAddress.status_code, WebAddress.title)
            .where(WebAddress.target_id == t.id).limit(100))).all()
        return {
            "host": t.host, "ip": t.ip_address, "alive": t.alive,
            "compromised": t.hacked, "os": t.os, "os_accuracy": t.os_accuracy,
            "notes": t.notes,
            "services": [{"port": s.port, "protocol": s.protocol, "state": s.state,
                          "service": s.name, "banner": s.banner} for s in svcs],
            "findings": [{"title": v.title, "severity": v.severity,
                          "status": v.status, "port": v.port} for v in vulns],
            "implants": [{"framework": i.framework, "id": i.implant_id,
                          "user": i.user, "integrity": i.integrity} for i in imps],
            "web_addresses": [{"url": u, "status": sc, "title": ti}
                              for u, sc, ti in urls],
        }

    async def list_findings(severity: str = "", search: str = "",
                            host: str = "", limit: int = 50) -> dict:
        stmt = (select(Vuln, Target.host).join(Target, Target.id == Vuln.target_id)
                .where(Target.project_id == pid))
        if severity:
            stmt = stmt.where(Vuln.severity == severity.lower())
        if host:
            stmt = stmt.where(Target.host == host.strip().lower())
        if search:
            like = f"%{search}%"
            stmt = stmt.where(or_(Vuln.title.ilike(like), Vuln.description.ilike(like)))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.limit(n))).all()
        return _rows([{"host": h, "title": v.title, "severity": v.severity,
                       "status": v.status, "port": v.port,
                       "external_id": v.external_id,
                       "description": (v.description or "")[:1500]}
                      for v, h in rows], MAX_ROWS, total)

    async def list_services(port: int = 0, service: str = "",
                            only_unknown: bool = False, limit: int = 50) -> dict:
        stmt = (select(Service, Target.host).join(Target, Target.id == Service.target_id)
                .where(Target.project_id == pid))
        if port:
            stmt = stmt.where(Service.port == int(port))
        if service:
            stmt = stmt.where(Service.name.ilike(f"%{service}%"))
        if only_unknown:
            stmt = stmt.where(Service.name == "UNKNOWN", Service.state == "open")
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.order_by(Service.port).limit(n))).all()
        return _rows([{"host": h, "port": s.port, "protocol": s.protocol,
                       "state": s.state, "service": s.name, "banner": s.banner}
                      for s, h in rows], MAX_ROWS, total)

    async def list_web(search: str = "", status_code: int = 0, limit: int = 50) -> dict:
        stmt = (select(WebAddress, Target.host)
                .join(Target, Target.id == WebAddress.target_id)
                .where(Target.project_id == pid))
        if search:
            like = f"%{search}%"
            stmt = stmt.where(or_(WebAddress.url.ilike(like), WebAddress.title.ilike(like)))
        if status_code:
            stmt = stmt.where(WebAddress.status_code == int(status_code))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.order_by(WebAddress.url).limit(n))).all()
        return _rows([{"host": h, "url": w.url, "status": w.status_code,
                       "title": w.title, "sources": w.sources} for w, h in rows],
                     MAX_ROWS, total)

    async def list_credentials(search: str = "", limit: int = 50) -> dict:
        stmt = select(Credential).where(Credential.project_id == pid)
        if search:
            like = f"%{search}%"
            stmt = stmt.where(or_(Credential.username.ilike(like),
                                  Credential.host.ilike(like),
                                  Credential.service.ilike(like)))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.limit(n))).scalars().all()
        # The secret is deliberately not returned. The agent can reason about
        # which accounts were captured without the plaintext passing through
        # a third-party model.
        return _rows([{"host": c.host, "username": c.username, "kind": c.kind,
                       "service": c.service, "port": c.port,
                       "validated": c.validated, "secret_captured": bool(c.secret)}
                      for c in rows], MAX_ROWS, total)

    async def timeline(host: str, limit: int = 40) -> dict:
        t = await _target(host)
        if t is None:
            return {"error": f"no target {host!r}"}
        from ..models import Event
        rows = (await session.execute(
            select(Event).where(Event.target_id == t.id)
            .order_by(Event.at.desc()).limit(max(1, min(int(limit), MAX_ROWS))))).scalars().all()
        return {"host": t.host, "entries": [
            {"at": e.at.isoformat() if e.at else None, "kind": e.kind,
             "summary": e.summary, "actor": e.actor,
             "detail": (e.detail or "")[:800]} for e in rows]}

    async def suggest_domains(domain: str, limit: int = 30) -> dict:
        from ..routers.domains import known_hosts
        from ..domains import generate
        d = (domain or "").strip().lower().lstrip("*.").rstrip(".")
        if "." not in d:
            return {"error": f"{d!r} is a single label, not a domain"}
        hosts = await known_hosts(session, pid)
        existing = {c.name for c in (await session.execute(
            select(DomainCandidate).where(DomainCandidate.project_id == pid))).scalars()}
        out = generate(d, hosts, limit=max(1, min(int(limit), 200)), already=existing)
        return {"domain": d, "note": "generated offline from known hosts; "
                                     "no lookups were performed",
                "candidates": [{"name": c.name, "source": c.source,
                                "score": c.score, "why": c.reason} for c in out]}

    reads = [
        Tool("project_overview", "Counts across the whole engagement: targets, "
             "services, findings by severity, web addresses, C2 implants. Start here.",
             _obj({}), overview),
        Tool("list_targets", "List or search hosts in this engagement.",
             _obj({"search": {"type": "string", "description": "match host, IP, OS or notes"},
                   "only_alive": {"type": "boolean"},
                   "only_compromised": {"type": "boolean"},
                   "limit": {"type": "integer", "description": f"max {MAX_ROWS}"}}),
             list_targets),
        Tool("get_host", "Everything known about one host: services, findings, "
             "C2 implants and web addresses.",
             _obj({"host": {"type": "string"}}, ["host"]), get_host),
        Tool("list_findings", "Search the findings. Filter by severity or host.",
             _obj({"severity": {"type": "string",
                                "enum": ["critical", "high", "medium", "low", "info"]},
                   "search": {"type": "string"}, "host": {"type": "string"},
                   "limit": {"type": "integer"}}), list_findings),
        Tool("list_services", "Search services and open ports. `only_unknown` "
             "finds open ports whose service could not be identified.",
             _obj({"port": {"type": "integer"}, "service": {"type": "string"},
                   "only_unknown": {"type": "boolean"}, "limit": {"type": "integer"}}),
             list_services),
        Tool("list_web_addresses", "Search URLs found on http(s) services.",
             _obj({"search": {"type": "string"}, "status_code": {"type": "integer"},
                   "limit": {"type": "integer"}}), list_web),
        Tool("list_credentials", "Captured credentials. Usernames and metadata "
             "only — the secrets themselves are never returned.",
             _obj({"search": {"type": "string"}, "limit": {"type": "integer"}}),
             list_credentials),
        Tool("host_timeline", "What was found and done to one host, newest first.",
             _obj({"host": {"type": "string"}, "limit": {"type": "integer"}}, ["host"]),
             timeline),
        Tool("suggest_domains", "Candidate hostnames under a domain, extrapolated "
             "from names this project already knows. Sends no packets and performs "
             "no lookups; every result is a hypothesis.",
             _obj({"domain": {"type": "string"}, "limit": {"type": "integer"}},
                  ["domain"]), suggest_domains),
    ]
    if not allow_writes:
        return reads

    # ----------------------------------------------------------- writes
    async def add_note(host: str, note: str) -> dict:
        t = await _target(host)
        if t is None:
            return {"error": f"no target {host!r}"}
        first = note.strip().splitlines()[0] if note.strip() else "note"
        await record(session, t.id, "note", first, detail=note.strip(),
                     actor=f"agent({user.username})")
        await session.commit()
        return {"ok": True, "host": t.host}

    async def add_target(host: str, notes: str = "") -> dict:
        try:
            clean = validate_host(host)
        except InvalidHost as e:
            return {"error": str(e)}
        if await _target(clean):
            return {"error": f"{clean} already exists in {project.code}"}
        t = Target(project_id=pid, host=clean, notes=notes or None, alive=None)
        session.add(t)
        await session.flush()
        await record(session, t.id, "discovered",
                     f"added by the agent on behalf of {user.username}",
                     detail=notes or None, actor=f"agent({user.username})")
        await session.commit()
        return {"ok": True, "host": clean}

    async def add_finding(host: str, title: str, severity: str = "info",
                          description: str = "") -> dict:
        t = await _target(host)
        if t is None:
            return {"error": f"no target {host!r}"}
        sev = severity.lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            return {"error": f"severity must be one of critical/high/medium/low/info"}
        v = Vuln(target_id=t.id, title=title[:1000], severity=sev,
                 description=description or None)
        session.add(v)
        await record(session, t.id, "vuln", f"{sev.upper()}: {title}"[:400],
                     detail=description or None, actor=f"agent({user.username})")
        await session.commit()
        return {"ok": True, "host": t.host, "title": title}

    return reads + [
        Tool("add_note", "Append a note to a host's timeline.",
             _obj({"host": {"type": "string"}, "note": {"type": "string"}},
                  ["host", "note"]), add_note, writes=True),
        Tool("add_target", "Add a host to this engagement. It is recorded as "
             "not probed, because adding it checks nothing.",
             _obj({"host": {"type": "string"}, "notes": {"type": "string"}},
                  ["host"]), add_target, writes=True),
        Tool("add_finding", "File a finding against a host.",
             _obj({"host": {"type": "string"}, "title": {"type": "string"},
                   "severity": {"type": "string",
                                "enum": ["critical", "high", "medium", "low", "info"]},
                   "description": {"type": "string"}},
                  ["host", "title"]), add_finding, writes=True),
    ]


async def run(tool: Tool, args: dict) -> str:
    """Call a tool and return its JSON result, or a readable error.

    A tool that raises must not end the conversation: the model can often
    recover from "you passed the wrong argument" if it is told, and cannot
    recover from a 500.
    """
    try:
        out = await tool.fn(**(args or {}))
    except TypeError as e:
        out = {"error": f"bad arguments for {tool.name}: {e}"}
    except Exception as e:
        out = {"error": f"{type(e).__name__}: {e}"}
    try:
        return json.dumps(out, default=str)[:60000]
    except Exception:
        return json.dumps({"error": "result could not be serialised"})
