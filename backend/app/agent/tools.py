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

import collections
import json
from datetime import datetime, timezone
import re
from typing import Any, Callable

from sqlalchemy import false as sa_false, func, or_, select, true as sa_true, distinct
#: `select` is also the name of a tool parameter (which hosts to pick),
#: and a tool's parameter names are part of its API — renaming it to
#: dodge the shadowing would make the schema worse to read.
from sqlalchemy import select as select_
from sqlalchemy.ext.asyncio import AsyncSession

from ..domains import registrable
from ..hosts import InvalidHost, validate_host
from ..models import (ROLE_ORDER, Agent, AgentTask, Credential, DomainCandidate,
                      Event, Exploit,
                      Implant, Poc, Project,
                      Service, Target, User, Vuln, WebAddress)
from ..scopegate import check_task_targets, index_for
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


def build(session: AsyncSession, project: Project | None, user: User,
          allow_writes: bool, scope_ids: list[int] | None = None,
          role: str | None = None) -> list[Tool]:
    """Tools for one project, or for everything the user may read.

    `project` is the engagement in view; None means the operator is
    asking across all of them, which is the ordinary case for a
    question like "which hosts anywhere run an SSH we should look at".

    `scope_ids` bounds that: the projects this user is allowed to see.
    It is not an optimisation. Without it, widening the assistant's
    reach would quietly hand every user every client's data, which is
    the one mistake in this codebase that would matter outside it.
    None means site admin — genuinely everything.

    Writes stay addressed to a single project. "Add this host" with no
    engagement named is not a thing to guess at.
    """
    pid = project.id if project else None
    #: The caller's role on the project in view. Some actions need more
    #: than "writes are allowed": enrolling an agent creates something
    #: that runs privileged commands on a machine, which is an admin's
    #: decision and not a contributor's.
    rank = ROLE_ORDER.get(role or "", -1)

    def scoped(col):
        """The project predicate for whichever scope is in force."""
        if pid is not None:
            return col == pid
        if scope_ids is None:
            return sa_true()
        if not scope_ids:
            # No readable projects: match nothing. An empty IN () is
            # not portable, and `false` is the honest answer anyway.
            return sa_false()
        return col.in_(scope_ids)

    async def _target(host: str) -> Target | None:
        return (await session.execute(
            select(Target).where(scoped(Target.project_id),
                                 Target.host == host.strip().lower()))).scalar_one_or_none()

    # ------------------------------------------------------------ reads
    async def overview(**_) -> dict:
        async def count(model, *where):
            stmt = select(func.count()).select_from(model)
            if model is Target:
                stmt = stmt.where(scoped(Target.project_id), *where)
            else:
                stmt = (stmt.join(Target, Target.id == model.target_id)
                        .where(scoped(Target.project_id), *where))
            return int((await session.execute(stmt)).scalar_one())

        sev = {s: await count(Vuln, Vuln.severity == s)
               for s in ("critical", "high", "medium", "low", "info")}
        return {
            # Which engagement these numbers cover, said in the answer
            # rather than assumed: across all of them, a total with no
            # scope on it invites being quoted as one client's figure.
            "scope": (project.code if project else
                      ("every project" if scope_ids is None
                       else f"{len(scope_ids)} project(s) you can read")),
            "project": project.code if project else None,
            "name": project.name if project else None,
            "client": project.client if project else None,
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
        stmt = select(Target).where(scoped(Target.project_id))
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
            where = project.code if project else "any project you can read"
            return {"error": f"no target {host!r} in {where}"}
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
        # What has already been done to it, which is the half of the
        # context that stops the same scan being queued twice.
        events = (await session.execute(
            select(Event).where(Event.target_id == t.id)
            .order_by(Event.at.desc()).limit(15))).scalars().all()
        creds = int((await session.execute(
            select(func.count()).select_from(Credential)
            .where(Credential.target_id == t.id))).scalar_one())

        # Is it even allowed to be touched? Asked here rather than
        # discovered when a task is refused: an agent deciding what to
        # do next should know the answer before it proposes anything.
        idx = await index_for(session, t.project_id)
        ruling = idx.check(t.host)

        # What is NOT known. The most useful thing to tell something
        # about to act, and the thing an inventory record never says:
        # every field it holds is a fact, and the gaps are silent.
        gaps = []
        if t.ip_address is None and t.kind == "host":
            gaps.append("no address resolved for this name")
        if t.alive is None:
            gaps.append("never probed — liveness is unknown, not false")
        if not svcs:
            gaps.append("no ports recorded; nothing has been scanned here")
        if t.os is None:
            gaps.append("no OS identified")
        if svcs and not any(s.product for s in svcs):
            gaps.append("ports are known but no versions — a -sV pass "
                        "would make exploit matching possible")

        return {
            "host": t.host, "ip": t.ip_address, "alive": t.alive,
            "kind": t.kind, "provider": t.provider,
            "compromised": t.hacked, "os": t.os, "os_accuracy": t.os_accuracy,
            "notes": t.notes,
            # product and version, not just the service name: "http" is
            # not actionable and "Apache 2.4.49" is.
            "services": [{"port": s.port, "protocol": s.protocol, "state": s.state,
                          "service": s.name, "product": s.product,
                          "version": s.version, "banner": s.banner}
                         for s in svcs],
            "findings": [{"title": v.title, "severity": v.severity,
                          "status": v.status, "port": v.port} for v in vulns],
            "implants": [{"framework": i.framework, "id": i.implant_id,
                          "user": i.user, "integrity": i.integrity} for i in imps],
            "web_addresses": [{"url": u, "status": sc, "title": ti}
                              for u, sc, ti in urls],
            "credentials_held": creds,
            "in_scope": ruling.allowed,
            "scope_reason": None if ruling.allowed else ruling.reason,
            "recent_activity": [{"at": e.at.isoformat() if e.at else None,
                                 "kind": e.kind, "summary": e.summary,
                                 "actor": e.actor} for e in events],
            "not_known": gaps,
        }

    async def rank_targets(limit: int = 10) -> dict:
        """Which hosts are worth going after first, and WHY.

        Ranked, not scored into a single number nobody can argue with:
        the reasons are returned so an operator can disagree with the
        order. A host at the top because it has one critical finding is
        a different proposition from one there because it exposes
        fifteen unversioned services, and collapsing both into "87"
        hides exactly the thing being decided.
        """
        tsel = select(Target)
        if project:
            tsel = tsel.where(Target.project_id == project.id)
        rows = (await session.execute(tsel)).scalars().all()
        if not rows:
            return {"targets": [], "note": "this engagement has no targets yet"}

        ids = [t.id for t in rows]
        svc = {}
        for sv in (await session.execute(
                select(Service).where(Service.target_id.in_(ids)))).scalars():
            svc.setdefault(sv.target_id, []).append(sv)
        vul = {}
        for v in (await session.execute(
                select(Vuln).where(Vuln.target_id.in_(ids)))).scalars():
            vul.setdefault(v.target_id, []).append(v)

        WEIGHT = {"critical": 100, "high": 40, "medium": 10, "low": 2, "info": 0}
        out = []
        for t in rows:
            vs, ss = vul.get(t.id, []), svc.get(t.id, [])
            score, why = 0, []
            for sev, n in sorted(collections.Counter(
                    (v.severity or "info").lower() for v in vs).items()):
                score += WEIGHT.get(sev, 0) * n
                if WEIGHT.get(sev, 0):
                    why.append(f"{n} {sev} finding{'' if n == 1 else 's'}")
            if t.hacked:
                # Already in. Ranked high because it is a foothold, and
                # said plainly so nobody reads it as "still to do".
                score += 60
                why.append("already compromised — this is a foothold, not a target")
            remote = [x for x in ss if x.port in (21, 22, 23, 445, 3389, 5985, 1433,
                                                  3306, 5432, 6379, 27017)]
            if remote:
                score += 8 * len(remote)
                why.append("remote-access or database ports: "
                           + ", ".join(f"{x.port}/{x.protocol}" for x in remote[:6]))
            versioned = [x for x in ss if x.product and x.version]
            if versioned:
                score += 3 * len(versioned)
                why.append(f"{len(versioned)} service(s) with an identified "
                           f"version, which is what exploit matching needs")
            if ss and not versioned:
                why.append("ports open but unversioned — a -sV pass would "
                           "say more than this ranking can")
            if not ss:
                why.append("nothing scanned here yet, so this ranking knows "
                           "almost nothing about it")
            out.append({"host": t.host, "ip": t.ip_address, "score": score,
                        "compromised": t.hacked, "open_ports": len(ss),
                        "findings": len(vs), "why": why})
        out.sort(key=lambda r: (-r["score"], r["host"]))
        return {"targets": out[:max(1, min(limit, 100))],
                "ranked_of": len(out),
                "caveat": "Ordered by what this engagement has RECORDED. A "
                          "host nothing has scanned scores low because it is "
                          "unknown, not because it is safe."}

    async def find_by_technology(technology: str, limit: int = 50) -> dict:
        """Hosts running a given technology — php, wordpress, nginx, jboss.

        Matched against the service product, version and banner, and
        against captured page titles and URLs, because which of those
        carries the evidence depends entirely on the tool that found it.
        """
        q = (technology or "").strip().lower()
        if not q:
            return {"error": "give a technology to look for, e.g. 'php'"}
        like = f"%{q}%"

        tsel = select(Target)
        if project:
            tsel = tsel.where(Target.project_id == project.id)
        rows = {t.id: t for t in (await session.execute(tsel)).scalars()}
        if not rows:
            return {"hosts": [], "technology": q}

        hits: dict[int, list[str]] = {}
        for sv in (await session.execute(
                select(Service).where(
                    Service.target_id.in_(list(rows)),
                    or_(func.lower(Service.product).like(like),
                        func.lower(Service.name).like(like),
                        func.lower(Service.version).like(like),
                        func.lower(Service.banner).like(like))))).scalars():
            hits.setdefault(sv.target_id, []).append(
                f"{sv.port}/{sv.protocol}: "
                + " ".join(x for x in (sv.product, sv.version) if x)
                  or (sv.name or "service"))
        for w in (await session.execute(
                select(WebAddress).where(
                    WebAddress.target_id.in_(list(rows)),
                    or_(func.lower(WebAddress.url).like(like),
                        func.lower(WebAddress.title).like(like),
                        func.lower(WebAddress.server).like(like))))).scalars():
            hits.setdefault(w.target_id, []).append(
                f"web: {w.url}" + (f" ({w.title})" if w.title else ""))

        out = [{"host": rows[tid].host, "ip": rows[tid].ip_address,
                "evidence": ev[:8]}
               for tid, ev in hits.items() if tid in rows]
        out.sort(key=lambda r: r["host"])
        return {"technology": q, "hosts": out[:max(1, min(limit, 500))],
                "matched": len(out),
                "caveat": "Found in what has been RECORDED. A host running "
                          "this and never scanned does not appear."}

    async def exploit_leads(host: str = "", product: str = "",
                            version: str = "", limit: int = 15) -> dict:
        """Public exploits and CVEs that might apply.

        Give a host and every service it exposes is looked up, or give
        a product and version directly.

        Matched against a LOCAL copy of Exploit-DB and NVD. Nothing
        about the target is sent anywhere to answer this — which is the
        point: asking a third-party API "anything for Apache 2.4.49?"
        on behalf of a host tells them the client runs it.
        """
        from .. import vulnfeed
        feeds = await vulnfeed.status(session)

        if product or version:
            out = await vulnfeed.leads_for_service(
                session, product or None, version or None, limit=limit)
            return {"product": product, "version": version, **out}

        if not host:
            return {"error": "give a host, or a product and version"}
        t = await _target(host)
        if t is None:
            return {"error": f"no target {host!r} here"}
        svcs = (await session.execute(
            select(Service).where(Service.target_id == t.id)
            .order_by(Service.port))).scalars().all()
        if not svcs:
            return {"host": t.host, "services": [], "feeds": feeds,
                    "note": "no ports recorded for this host, so there is "
                            "nothing to match on. That is a gap in what has "
                            "been scanned, not an absence of exposure."}

        per = []
        for sv in svcs:
            r = await vulnfeed.leads_for_service(
                session, sv.product, sv.version, sv.name, sv.banner,
                limit=limit)
            per.append({"port": sv.port, "protocol": sv.protocol,
                        "product": sv.product, "version": sv.version,
                        "cves": r["cves"], "exploits": r["exploits"],
                        "searched_for": r["terms"]})
        return {
            "host": t.host, "ip": t.ip_address, "services": per,
            "feeds": feeds,
            "caveat": "Leads, not findings. A patched host reports the same "
                      "version as an unpatched one, banners are frequently "
                      "wrong, and CPE version matching is approximate. "
                      "Confirming any of this against the target is the "
                      "engagement, not this list.",
        }

    async def search_exploits(query: str, limit: int = 25) -> dict:
        """`searchsploit`, against the local Exploit-DB copy."""
        from .. import vulnfeed
        q = (query or "").strip()
        if len(q) < 2:
            return {"error": "give something to search for"}
        rows = (await session.execute(
            select(Exploit).where(Exploit.title.ilike(f"%{q}%"))
            .order_by(Exploit.verified.desc(), Exploit.id.desc())
            .limit(max(1, min(limit, 200))))).scalars().all()
        return {"query": q,
                "results": [{"edb_id": e.id, "title": e.title, "type": e.type,
                             "platform": e.platform, "verified": e.verified,
                             "published": e.published, "path": e.path,
                             "cves": (e.cves or "").split(",") if e.cves else []}
                            for e in rows],
                "feeds": await vulnfeed.status(session)}

    async def list_findings(severity: str = "", search: str = "",
                            host: str = "", limit: int = 50) -> dict:
        stmt = (select(Vuln, Target.host).join(Target, Target.id == Vuln.target_id)
                .where(scoped(Target.project_id)))
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
                .where(scoped(Target.project_id)))
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
                .where(scoped(Target.project_id)))
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
        stmt = select(Credential).where(scoped(Credential.project_id))
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

    async def port_summary(top: int = 20, protocol: str | None = None) -> dict:
        """Counts per port, computed in SQL over the whole project.

        Without this the only way to answer "most common ports" was
        `list_services`, which caps at 200 rows. Asked for the top
        three, the model dutifully counted the sample it was given and
        reported 80/53/25 — the real answer is 443 (2,014), 80 (1,457),
        8443 (90). It even said the data was truncated and then did the
        arithmetic anyway, which is the failure mode worth designing
        out rather than warning about.
        """
        q = (select(Service.port, Service.protocol,
                    func.count().label("services"),
                    func.count(distinct(Service.target_id)).label("hosts"))
             .join(Target, Target.id == Service.target_id)
             .where(scoped(Target.project_id)))
        if protocol:
            q = q.where(Service.protocol == protocol.strip().lower())
        q = (q.group_by(Service.port, Service.protocol)
              .order_by(func.count().desc())
              .limit(max(1, min(int(top or 20), 200))))
        rows = (await session.execute(q)).all()
        return {"ports": [{"port": p, "protocol": pr, "services": n, "hosts": h}
                          for p, pr, n, h in rows],
                "note": "counted across the whole project, not a sample"}

    async def list_projects(**_) -> dict:
        """Which engagements are in scope for this conversation."""
        stmt = select(Project).order_by(Project.code)
        if pid is not None:
            stmt = stmt.where(Project.id == pid)
        elif scope_ids is not None:
            if not scope_ids:
                return {"projects": [],
                        "note": "you have access to no projects"}
            stmt = stmt.where(Project.id.in_(scope_ids))
        rows = (await session.execute(stmt)).scalars().all()
        out = []
        for p in rows:
            n = (await session.execute(
                select(func.count()).select_from(Target)
                .where(Target.project_id == p.id))).scalar_one()
            out.append({"code": p.code, "name": p.name,
                        "codename": p.codename, "client": p.client,
                        "targets": int(n)})
        return {"projects": out, "count": len(out)}

    def _tools_of(a: Agent) -> dict:
        try:
            return json.loads(a.tools) if a.tools else {}
        except ValueError:
            return {}

    async def list_drone(**_) -> dict:
        """The agents deployed on this engagement."""
        if pid is None:
            return {"error": "listing agents needs one engagement in view"}
        rows = (await session.execute(
            select(Agent).where(Agent.project_id == pid)
            .order_by(Agent.name))).scalars().all()
        out = []
        for a in rows:
            queued = int((await session.execute(
                select(func.count()).select_from(AgentTask)
                .where(AgentTask.agent_id == a.id,
                       AgentTask.status.in_(("queued", "claimed", "running"))))
            ).scalar_one())
            out.append({
                "id": a.id, "name": a.name, "status": a.status,
                "platform": a.platform, "hostname": a.hostname,
                "address": a.outbound_ip or a.last_ip,
                # Said plainly: an agent without raw sockets cannot run
                # masscan and will silently connect-scan with nmap, so
                # it changes what tasking is worth sending.
                "raw_sockets": a.privileged,
                "tools": sorted(_tools_of(a)),
                "work_in_flight": queued,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None})
        return {"agents": out, "count": len(out)}

    reads = [
        Tool("list_drone",
             "Drone agents on this engagement: where each is deployed, "
             "whether it can raw-socket scan, what tools it has, and what "
             "it is working on.",
             _obj({}), list_drone),
        Tool("list_projects",
             "The engagements you can see, with a target count for each. "
             "Use this first when asked about more than one engagement, or "
             "to break a total down by project.",
             _obj({}), list_projects),
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
        Tool("port_summary", "How many services on each port, across the WHOLE "
             "project. Use this for 'most common ports' and any other counting "
             "question — list_services returns at most 200 rows, and counting "
             "those gives a wrong answer for the project.",
             _obj({"top": {"type": "integer"},
                   "protocol": {"type": "string"}}), port_summary),
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
        Tool("rank_targets",
             "Which hosts are worth going after first, with the reason for "
             "each. Ranked rather than scored: the reasons come back so the "
             "order can be argued with.",
             _obj({"limit": {"type": "integer"}}), rank_targets),
        Tool("find_by_technology",
             "Hosts running a given technology — php, wordpress, nginx, "
             "jboss. Matches service product, version and banner, and "
             "captured page titles and URLs.",
             _obj({"technology": {"type": "string",
                                  "description": "e.g. php, wordpress, nginx"},
                   "limit": {"type": "integer"}}, ["technology"]),
             find_by_technology),
        Tool("exploit_leads",
             "Public exploits and CVEs that might apply to a host's "
             "services, or to a product and version. Matched against a "
             "local copy — nothing about the target is sent anywhere.",
             _obj({"host": {"type": "string"},
                   "product": {"type": "string"},
                   "version": {"type": "string"},
                   "limit": {"type": "integer"}}), exploit_leads),
        Tool("search_exploits",
             "searchsploit, against the local Exploit-DB copy.",
             _obj({"query": {"type": "string"}, "limit": {"type": "integer"}},
                  ["query"]), search_exploits),
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
        if pid is None or project is None:
            # Guessing which engagement a new host belongs to is the
            # kind of mistake that puts one client's asset in another
            # client's report.
            return {"error": "adding a host needs one engagement in view; "
                             "pick a project and ask again"}
        try:
            clean = validate_host(host)
        except InvalidHost as e:
            return {"error": str(e)}
        if await _target(clean):
            return {"error": f"{clean} already exists in {project.code}"}
        # The assistant is a person's words turned into a write. The
        # scope list is the one thing in that chain that did not come
        # out of a sentence, so it gets the last say.
        ruling = (await index_for(session, pid)).check(clean)
        if not ruling.allowed:
            return {"error": f"refused: {ruling.reason}"}
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

    # ------------------------------------------------------ drone writes
    async def task_drone(kind: str, targets: str, agent: str = "",
                        ports: str = "", region: str = "") -> dict:
        """Queue work for an agent, or for the project's pool."""
        from ..routers.agents import TASK_KINDS
        if pid is None or project is None:
            return {"error": "tasking needs one engagement in view"}
        kind = (kind or "").strip().lower()
        if kind not in TASK_KINDS:
            return {"error": f"unknown task {kind!r}. Known: "
                             f"{', '.join(sorted(TASK_KINDS))}"}
        if kind in ("install", "shell"):
            # Installing software on, or running arbitrary commands on,
            # a privileged process inside a client network is not
            # something to do because a sentence asked for it.
            return {"error": f"{kind} is not available through the "
                             f"assistant; queue it yourself from the Drone "
                             f"page, where the allowlist and the agent are "
                             f"both in front of you"}
        hosts = [t for t in re.split(r"[\s,]+", targets or "") if t]
        if not hosts:
            return {"error": "no targets given"}

        chosen: Agent | None = None
        if agent.strip():
            chosen = (await session.execute(
                select(Agent).where(Agent.project_id == pid,
                                    Agent.name == agent.strip()))).scalar_one_or_none()
            if chosen is None:
                return {"error": f"no agent named {agent!r} on {project.code}"}
            if chosen.status == "disabled":
                return {"error": f"{chosen.name} has been killed"}

        args: dict = {"targets": hosts}
        if ports.strip():
            args["ports"] = ports.strip()
        # Same gate as the Drone page, reached the same way. A scan the
        # operator could not queue by hand must not become queueable by
        # asking for it in a sentence.
        idx = await index_for(session, pid)
        if idx.defined:
            ruling = check_task_targets(idx, args)
            if ruling is not None:
                return {"error": f"refused: {ruling.reason}"}
        t = AgentTask(
            agent_id=chosen.id if chosen else None,
            project_id=pid, requested_by=user.id, kind=kind,
            args=json.dumps(args),
            region=(region or "").strip().lower() or None,
            import_as=TASK_KINDS.get(kind), status="queued")
        session.add(t)
        await session.commit()
        await session.refresh(t)
        return {"ok": True, "task_id": t.id, "kind": kind,
                "targets": hosts,
                "assigned_to": chosen.name if chosen else
                               "the project pool — routing will pick an agent",
                "note": "queued; results import when the agent reports back"}

    #: What `select` accepts, and what each one means. Kept beside the
    #: tool rather than in the description so the error can list them.
    _SELECTORS = {
        "all": "every target in the project",
        "unscanned": "targets with no recorded ports — the actual gap",
        "web": "targets with a recorded web address or an http/https port",
        "hacked": "targets already marked compromised",
        "technology": "targets matching `technology`, e.g. php",
        "hosts": "exactly the hosts given in `hosts`",
    }

    async def enumerate_drones(kind: str, select: str = "unscanned",
                               technology: str = "", hosts: str = "",
                               ports: str = "", agent: str = "",
                               region: str = "", limit: int = 500,
                               confirm: bool = False) -> dict:
        """Queue enumeration across the project's own targets.

        One task per host, so the fleet shares the work, one failure
        stays one failure, and the queue depth means "how many hosts are
        left". Picks the hosts from what the project already knows
        rather than making you list them.

        **Previews unless `confirm` is true.** A sweep is hundreds of
        tasks against a client's estate, and "have a look at the web
        hosts" is not a sentence that should start one on its own. The
        preview says exactly which hosts, how many, and what scope
        refused, so the decision is made against the list and not the
        adjective.
        """
        from ..routers.agents import TASK_KINDS, queue_per_host
        if pid is None or project is None:
            return {"error": "tasking needs one engagement in view"}
        if not allow_writes:
            return {"error": "this assistant is read-only; enable writes in "
                             "Site Config to let it queue work"}

        kind = (kind or "").strip().lower()
        if kind not in TASK_KINDS:
            return {"error": f"unknown task {kind!r}. Known: "
                             f"{', '.join(sorted(TASK_KINDS))}"}
        if kind in ("install", "shell"):
            # Installing software on, or running commands on, a
            # privileged process inside a client network is not
            # something to do because a sentence asked for it.
            return {"error": f"{kind} is never queued by the assistant. It "
                             f"belongs on the Drone page, where the allowlist "
                             f"and the agent are both in front of you"}

        sel = (select or "").strip().lower()
        if sel not in _SELECTORS:
            return {"error": f"unknown selection {sel!r}",
                    "selections": _SELECTORS}

        # ------------------------------------------------ choose hosts
        chosen_hosts: list[str] = []
        if sel == "hosts":
            chosen_hosts = [h for h in re.split(r"[\s,]+", hosts or "") if h]
            if not chosen_hosts:
                return {"error": "select='hosts' needs a list in `hosts`"}
        elif sel == "technology":
            if not technology.strip():
                return {"error": "select='technology' needs `technology`, "
                                 "e.g. php"}
            found = await find_by_technology(technology, limit=limit)
            chosen_hosts = [h["host"] for h in found.get("hosts", [])]
        else:
            tsel = select_(Target).where(Target.project_id == pid)
            if sel == "hacked":
                tsel = tsel.where(Target.hacked.is_(True))
            targets = (await session.execute(tsel)).scalars().all()
            if sel in ("unscanned", "web"):
                with_ports: set[int] = set()
                for sv in (await session.execute(
                        select_(Service.target_id, Service.port, Service.name)
                        .where(Service.target_id.in_(
                            [t.id for t in targets] or [0])))).all():
                    with_ports.add(sv[0])
                if sel == "unscanned":
                    targets = [t for t in targets if t.id not in with_ports]
                else:
                    webbed = {w.target_id for w in (await session.execute(
                        select_(WebAddress).where(WebAddress.target_id.in_(
                            [t.id for t in targets] or [0])))).scalars()}
                    http = {sv[0] for sv in (await session.execute(
                        select_(Service.target_id, Service.port, Service.name)
                        .where(Service.target_id.in_(
                            [t.id for t in targets] or [0])))).all()
                        if sv[1] in (80, 443, 8080, 8443, 8000)
                        or "http" in (sv[2] or "")}
                    targets = [t for t in targets
                               if t.id in webbed or t.id in http]
            chosen_hosts = [t.host for t in targets]

        # A project's inventory holds more than network hosts — an S3
        # ARN, a mobile package name, a cloud resource id. Those are
        # worth recording and cannot be scanned, and a scanner pointed
        # at one burns a task to produce an error. Dropped here, and
        # reported rather than quietly removed: "I queued 1,700 of your
        # 1,738" is a fact the operator needs in order to notice that
        # thirty-eight assets are being covered by nothing at all.
        unscannable: dict[str, str] = {}
        scannable: list[str] = []
        for h in chosen_hosts:
            try:
                scannable.append(validate_host(h))
            except InvalidHost as e:
                unscannable[h] = str(e)
        chosen_hosts = scannable

        chosen_hosts = chosen_hosts[:max(1, min(int(limit or 500), 5000))]
        if not chosen_hosts:
            return {"queued": 0, "hosts": [],
                    "not_network_hosts": unscannable,
                    "note": f"nothing matched {sel!r} that can be scanned. "
                            f"That is a statement about what this project has "
                            f"recorded, not about what exists out there."}

        # --------------------------------------------- who runs it
        chosen_agent = None
        if agent.strip():
            chosen_agent = (await session.execute(
                select_(Agent).where(Agent.project_id == pid,
                                     Agent.name == agent.strip()))).scalar_one_or_none()
            if chosen_agent is None:
                return {"error": f"no agent named {agent!r} on {project.code}"}
            if chosen_agent.status == "disabled":
                return {"error": f"{chosen_agent.name} has been killed"}

        args: dict = {}
        if ports.strip():
            args["ports"] = ports.strip()

        # ------------------------------------------------- preview
        if not confirm:
            idx = await index_for(session, pid)
            allowed, refused = [], {}
            for h in chosen_hosts:
                r = idx.check(h)
                (allowed.append(h) if r.allowed
                 else refused.update({h: r.reason}))
            return {
                "preview": True,
                "kind": kind, "selection": sel,
                "would_queue": len(allowed),
                "one_task_per_host": True,
                "hosts": allowed[:25],
                "more": max(0, len(allowed) - 25),
                "refused_by_scope": dict(list(refused.items())[:25]),
                "refused_count": len(refused),
                "not_network_hosts": dict(list(unscannable.items())[:10]),
                "not_network_count": len(unscannable),
                "assigned_to": chosen_agent.name if chosen_agent
                               else "the project pool",
                "next": "call again with confirm=true to queue this",
            }

        res = await queue_per_host(session, project, kind, chosen_hosts, args,
                                   user, chosen_agent,
                                   (region or "").strip().lower() or None,
                                   source="agent")
        return {"ok": True, "kind": kind, "selection": sel,
                "queued": res["queued"], "task_ids": res["ids"][:25],
                "refused_by_scope": res["refused"],
                "not_network_hosts": dict(list(unscannable.items())[:10]),
                "not_network_count": len(unscannable),
                "assigned_to": chosen_agent.name if chosen_agent
                               else "the project pool — routing will pick",
                "note": "one task per host; results import as each reports back"}

    async def drone_task_status(task_id: int) -> dict:
        if pid is None:
            return {"error": "needs one engagement in view"}
        t = await session.get(AgentTask, int(task_id))
        if t is None or t.project_id != pid:
            return {"error": f"no task {task_id} on this engagement"}
        a = await session.get(Agent, t.agent_id) if t.agent_id else None
        imp = None
        if t.import_result:
            try:
                imp = json.loads(t.import_result)
            except ValueError:
                imp = None
        return {"id": t.id, "kind": t.kind, "status": t.status,
                "agent": a.name if a else None,
                "summary": t.summary, "error": t.error,
                "needs_decision": bool(imp and imp.get("needs_decision")),
                "unknown_hosts": [u.get("host") for u in
                                  (imp or {}).get("unknown_hosts", [])]}

    async def enroll_drone(name: str, target_os: str = "linux",
                         connection_mode: str = "callback") -> dict:
        """Create an agent and return what the operator must run."""
        from ..routers.agents import ENROLL_TTL, server_identity
        from ..security import new_agent_key
        if pid is None or project is None:
            return {"error": "enrolling needs one engagement in view"}
        if rank < ROLE_ORDER["admin"]:
            # Enrolling creates something that will run privileged
            # commands on a machine and send their output here. A
            # contributor asking nicely is not the same as an admin
            # deciding.
            return {"error": "enrolling a Drone is an admin action on this "
                             "project; ask someone with that role"}
        if target_os not in ("linux", "darwin", "windows"):
            return {"error": "target_os is linux, darwin or windows"}
        if connection_mode not in ("callback", "call_in"):
            return {"error": "connection_mode is callback or call_in"}

        _, server_pub = await server_identity(session)
        cb_raw, cb_hash = new_agent_key()
        ci_raw, ci_hash = new_agent_key()
        tok_raw, tok_hash = new_agent_key()
        expires = datetime.now(timezone.utc) + ENROLL_TTL
        a = Agent(project_id=pid, name=name.strip(),
                  callback_key_hash=cb_hash, call_in_key_hash=ci_hash,
                  enroll_token_hash=tok_hash, enroll_expires_at=expires,
                  connection_mode=connection_mode, target_os=target_os,
                  status="offline")
        session.add(a)
        await session.commit()
        await session.refresh(a)
        return {
            "ok": True, "agent_id": a.id, "name": a.name,
            "project": project.code,
            # Returned once. It is a credential, so it is said plainly
            # that it will not be shown again.
            "enroll_token": tok_raw,
            "expires_at": expires.isoformat(),
            "run": (f"drone run --server <this oddjob url> "
                    f"--enroll {tok_raw} --name {a.name}"),
            "note": ("this token is shown once and is good for a short "
                     "while; the agent trades it for a keypair it makes "
                     "itself, and will then only take tasking from this "
                     "Oddjob"),
            "server_public_key": server_pub,
        }

    return reads + [
        Tool("task_drone",
             "Queue a scan on a Drone agent. Name an agent to pin the work "
             "to it, or leave it out to let the project's routing choose. "
             "Results import automatically when the agent reports back.",
             _obj({"kind": {"type": "string",
                            "description": "nmap, masscan, amass, gobuster, "
                                           "gospider, nuclei, httpx, "
                                           "nslookup, reverse_ip"},
                   "targets": {"type": "string",
                               "description": "hosts or ranges, space or "
                                              "comma separated"},
                   "agent": {"type": "string",
                             "description": "agent name; omit for the pool"},
                   "ports": {"type": "string"},
                   "region": {"type": "string"}},
                  ["kind", "targets"]), task_drone, writes=True),
        Tool("enumerate_drones",
             "Queue enumeration across the project's own targets — one "
             "task per host, picked by selection rather than listed by "
             "hand: all, unscanned, web, hacked, technology, or an "
             "explicit host list. PREVIEWS by default; pass confirm=true "
             "to actually queue. Use this for a sweep, and task_drone for "
             "one specific scan.",
             _obj({"kind": {"type": "string",
                            "description": "nmap, masscan, amass, gobuster, "
                                           "gospider, nuclei, httpx, "
                                           "nslookup, reverse_ip"},
                   "select": {"type": "string",
                              "description": "all | unscanned | web | hacked "
                                             "| technology | hosts"},
                   "technology": {"type": "string",
                                  "description": "with select=technology"},
                   "hosts": {"type": "string",
                             "description": "with select=hosts"},
                   "ports": {"type": "string"},
                   "agent": {"type": "string",
                             "description": "agent name; omit for the pool"},
                   "region": {"type": "string"},
                   "limit": {"type": "integer"},
                   "confirm": {"type": "boolean",
                               "description": "false previews, true queues"}},
                  ["kind"]), enumerate_drones, writes=True),
        Tool("drone_task_status",
             "How a queued Drone task is getting on, and whether its results "
             "are waiting on a decision about unknown hosts.",
             _obj({"task_id": {"type": "integer"}}, ["task_id"]),
             drone_task_status),
        Tool("enroll_drone",
             "Create a new Drone agent for this engagement and return the "
             "one-time command to run on the host. Admin only.",
             _obj({"name": {"type": "string"},
                   "target_os": {"type": "string",
                                 "enum": ["linux", "darwin", "windows"]},
                   "connection_mode": {"type": "string",
                                       "enum": ["callback", "call_in"]}},
                  ["name"]), enroll_drone, writes=True),
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
