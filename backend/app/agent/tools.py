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
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import distinct, func, or_, select
from sqlalchemy import false as sa_false

#: `select` is also the name of a tool parameter (which hosts to pick),
#: and a tool's parameter names are part of its API — renaming it to
#: dodge the shadowing would make the schema worse to read.
from sqlalchemy import select as select_
from sqlalchemy import true as sa_true
from sqlalchemy.ext.asyncio import AsyncSession

from .. import assetsearch
from ..hosts import InvalidHost, dns_subject, validate_host
from ..models import (
    ROLE_ORDER,
    Action,
    Agent,
    AgentTask,
    Credential,
    Event,
    Exploit,
    Implant,
    Poc,
    PortScanCoverage,
    Project,
    ProjectScope,
    Report,
    Service,
    Target,
    TargetAddress,
    User,
    Vuln,
    WebAddress,
    WebAsset,
    target_address_links,
)
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

#: How many engagements one "what lookups are waiting" question will
#: walk when none is in view. Each project costs a few queries, and a
#: site admin asking across two hundred of them wants an answer, not a
#: timeout. The reply says when it stopped short.
LOOKUP_PROJECT_CAP = 25


def _as_dict(v):
    """A router's return value, as something JSON-safe for a tool reply."""
    if hasattr(v, "model_dump"):
        return v.model_dump(mode="json")
    if isinstance(v, list):
        return [_as_dict(x) for x in v]
    return v


async def _via(fn, **kw):
    """Call a router function in-process and return its payload.

    The agent and the HTTP API are two front doors onto one product,
    and for a long time they had two implementations of the same
    question -- which is how eighteen tools ended up on one surface
    and not the other with nobody noticing. These wrappers call the
    SAME function the endpoint calls, so the two cannot answer
    differently; only the transport differs.

    `HTTPException` becomes an error dict rather than propagating. A
    model that asked for a host that does not exist should be told
    that in a sentence it can act on, not have the turn fail.
    """
    from fastapi import HTTPException
    try:
        return _as_dict(await fn(**kw))
    except HTTPException as e:
        return {"error": str(e.detail), "status": e.status_code}



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
            # EXISTS over the address table, not a column and not a
            # join: a host with four addresses that all match must come
            # back once, and a join would return it four times.
            at_address = (
                select(TargetAddress.id)
                .join(target_address_links,
                      target_address_links.c.address_id == TargetAddress.id)
                .where(target_address_links.c.target_id == Target.id,
                       TargetAddress.address.ilike(like))
                .exists())
            stmt = stmt.where(or_(Target.host.ilike(like), at_address,
                                  Target.os.ilike(like), Target.notes.ilike(like)))
        if only_alive:
            stmt = stmt.where(Target.alive.is_(True))
        if only_compromised:
            stmt = stmt.where(Target.hacked.is_(True))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.order_by(Target.host).limit(n))).scalars().all()
        return _rows([{"host": t.host, "ip": t.ip_address, "ips": t.ip_addresses,
                      "alive": t.alive,
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
        # Credentials hang off the PROJECT and name their host as a
        # string; they have no `target_id`. Asking for one raised
        # AttributeError before the query was built, so `get_host` —
        # the tool the agent reaches for first about any host — failed
        # outright on every call. Matched on project and host instead,
        # which is the relationship the table actually has.
        creds = int((await session.execute(
            select(func.count()).select_from(Credential)
            .where(Credential.project_id == t.project_id,
                   func.lower(Credential.host) == t.host))).scalar_one())

        # Is it even allowed to be touched? Asked here rather than
        # discovered when a task is refused: an agent deciding what to
        # do next should know the answer before it proposes anything.
        idx = await index_for(session, t.project_id)
        ruling = idx.check(t.host)

        # What is NOT known. The most useful thing to tell something
        # about to act, and the thing an inventory record never says:
        # every field it holds is a fact, and the gaps are silent.
        gaps = []
        if not t.ip_addresses and t.kind == "host":
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
            "host": t.host, "ip": t.ip_address, "ips": t.ip_addresses,
                      "alive": t.alive,
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
        # `scoped()`, not `if project:`. The conditional looked
        # equivalent and was not: with no engagement in view it dropped
        # the WHERE entirely and ranked every target in the
        # installation, for any user, ignoring `scope_ids` completely.
        # That is the one mistake in this file that matters outside it
        # — one client's hosts in another client's answer — and it was
        # reachable from the ordinary "which hosts anywhere are worth
        # attacking" question the all-projects mode exists for.
        rows = (await session.execute(
            select(Target).where(scoped(Target.project_id)))).scalars().all()
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

        # `scoped()` — see the note in `rank_targets`. The same
        # `if project:` was here and had the same hole: asked with no
        # engagement in view it searched every target in the
        # installation regardless of what the caller may read.
        rows = {t.id: t for t in (await session.execute(
            select(Target).where(scoped(Target.project_id)))).scalars()}
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
                    # `webserver`, not `server`. There is no `server`
                    # column, so this raised AttributeError before the
                    # query was even built — every call to this tool
                    # that got past the empty-project check failed, and
                    # the only coverage it had asserted that the tool
                    # was REGISTERED. A tool reachable from a Slack
                    # channel wants better than that.
                    or_(func.lower(WebAddress.url).like(like),
                        func.lower(WebAddress.title).like(like),
                        func.lower(WebAddress.webserver).like(like))))).scalars():
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

    async def list_pocs(host: str = "", status: str = "",
                        limit: int = 50) -> dict:
        stmt = (select(Poc, Target.host)
                .join(Target, Target.id == Poc.target_id)
                .where(scoped(Target.project_id)))
        if host:
            stmt = stmt.where(Target.host == host.strip().lower())
        if status:
            stmt = stmt.where(Poc.status == status.strip().lower())
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.limit(n))).all()
        return _rows([{"host": h, "title": p.title, "status": p.status,
                       # 0 reproduced | 1 not reproduced | 2 could not
                       # test. Three answers, and the third is not the
                       # second: "could not test" is a gap, not a pass.
                       "exit_code": p.exit_code, "path": p.path,
                       "notes": (p.notes or "")[:1000]}
                      for p, h in rows], MAX_ROWS, total)

    async def list_reports(limit: int = 50) -> dict:
        stmt = (select(Report).where(scoped(Report.project_id))
                .order_by(Report.id.desc()))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.limit(n))).scalars().all()
        # Deliberately NOT the rendered document. It runs to megabytes
        # of HTML and belongs in a download, not in a model's context.
        return _rows([{"id": r.id, "kind": r.kind, "title": r.title,
                       "status": r.status, "size_bytes": r.size_bytes,
                       "created_at": str(r.created_at)}
                      for r in rows], MAX_ROWS, total)

    async def list_actions(kind: str = "", limit: int = 50) -> dict:
        stmt = (select(Action, Target.host)
                .join(Service, Service.id == Action.service_id)
                .join(Target, Target.id == Service.target_id)
                .where(scoped(Target.project_id))
                .order_by(Action.id.desc()))
        if kind:
            stmt = stmt.where(Action.kind == kind.strip().lower())
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(stmt.limit(n))).all()
        return _rows([{"host": h, "kind": a.kind, "status": a.status,
                       "at": str(a.created_at)}
                      for a, h in rows], MAX_ROWS, total)

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

    # ---------------------------------------------------- static assets
    #
    # The files the client's pages LOAD, as opposed to the pages
    # themselves. A separate table because the host serving jQuery is
    # usually a CDN -- somebody else's infrastructure, barred as a
    # target -- so "our page depends on this" is recorded against the
    # project rather than as something to scan.
    #
    # Until these three existed the model could not see them at all.
    # Asked to find hardcoded keys it would search `web_addresses`,
    # which holds URLs and page titles and no file content whatever,
    # find nothing, and report that there were none -- the exact
    # "we did not look" / "there is nothing there" collapse the
    # system prompt forbids, made unavoidable by the tool surface.

    async def search_web_assets(query: str = "", mode: str = "secrets",
                                limit: int = 50) -> dict:
        want = (mode or "secrets").strip().lower()
        if want not in ("secrets", "text"):
            return {"error": "mode is 'secrets' or 'text'"}
        if want == "text" and not query.strip():
            return {"error": "text mode needs a `query`"}

        pattern = None
        if want == "text":
            try:
                pattern = assetsearch.compile_pattern(query, "text")
            except assetsearch.BadPattern as e:
                return {"error": str(e)}

        stmt = (select(WebAsset)
                .where(scoped(WebAsset.project_id),
                       WebAsset.body.is_not(None)))
        if want == "text" and query.strip():
            # Narrowed in SQL first. A project's bundles are the
            # largest text this database holds and most of them will
            # not contain the term.
            stmt = stmt.where(WebAsset.body.ilike(f"%{query.strip()}%"))
        rows = (await session.execute(
            stmt.order_by(WebAsset.third_party, WebAsset.url)
            .limit(assetsearch.MAX_ASSETS))).scalars().all()

        n = max(1, min(int(limit), MAX_ROWS))
        out: list[dict] = []
        matches = 0
        for a in rows:
            hits, capped = (assetsearch.scan_secrets(a.body or "")
                            if want == "secrets"
                            else assetsearch.search_body(a.body or "", pattern))
            if not hits:
                continue
            matches += len(hits)
            if len(out) < n:
                out.append({
                    "asset_id": a.id, "url": a.url, "host": a.host,
                    "third_party": a.third_party, "name": a.name,
                    "bytes": a.bytes, "more_hits_in_file": capped,
                    # Snippets, never the file. See app/assetsearch.py.
                    "hits": [{"offset": h.offset, "snippet": h.snippet,
                              "rule": h.rule, "confidence": h.confidence}
                             for h in hits],
                })

        # The number that stops this being read as "there are no
        # secrets". Fetching bodies is opt-in per crawl, so the
        # ordinary state of a new project is that nothing has been
        # pulled back and there is nothing to grep.
        searched = int((await session.execute(
            select(func.count()).select_from(WebAsset)
            .where(scoped(WebAsset.project_id),
                   WebAsset.body.is_not(None)))).scalar_one())
        stored = int((await session.execute(
            select(func.count()).select_from(WebAsset)
            .where(scoped(WebAsset.project_id)))).scalar_one())
        res: dict[str, Any] = {
            "mode": want, "query": query, "assets": out,
            "files_with_hits": len(out), "matches": matches,
            "files_searched": searched, "files_known": stored,
        }
        if not searched:
            res["nothing_was_searched"] = (
                f"{stored} asset(s) are known but NONE have had their bytes "
                f"fetched, so no file was read. This is not evidence that "
                f"there are no keys. Re-run web discovery with "
                f"`fetch_assets` to pull the files back first.")
        if len(rows) >= assetsearch.MAX_ASSETS:
            res["truncated"] = (
                f"only the first {assetsearch.MAX_ASSETS} files were read")
        return res

    async def list_web_assets(search: str = "", contains: str = "",
                              third_party: bool | None = None,
                              fetched_only: bool = False,
                              limit: int = 50) -> dict:
        stmt = select(WebAsset).where(scoped(WebAsset.project_id))
        if search:
            like = f"%{search}%"
            stmt = stmt.where(or_(WebAsset.url.ilike(like),
                                  WebAsset.name.ilike(like),
                                  WebAsset.host.ilike(like)))
        if contains.strip():
            # Matched against the FILE. Escaped, because % and _ are
            # ILIKE wildcards: a search for `%` would otherwise match
            # every asset while looking like it had found them.
            t = contains.strip()
            esc = t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(WebAsset.body.ilike(f"%{esc}%", escape="\\"))
        if third_party is not None:
            stmt = stmt.where(WebAsset.third_party == bool(third_party))
        if fetched_only:
            stmt = stmt.where(WebAsset.body.is_not(None))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(
            stmt.order_by(WebAsset.third_party.desc(), WebAsset.seen_on.desc())
            .limit(n))).scalars().all()
        return _rows([{
            "asset_id": a.id, "url": a.url, "host": a.host, "kind": a.kind,
            "name": a.name,
            # Absent means the URL did not say -- a fingerprinted
            # bundle. NOT "current": unknown and up-to-date are
            # different answers and must not read the same.
            "version": a.version or "unknown",
            "third_party": a.third_party, "bytes": a.bytes,
            "on_pages": a.seen_on,
            "body_fetched": a.body is not None,
        } for a in rows], MAX_ROWS, total)

    async def get_web_asset(asset_id: int = 0, url: str = "",
                            offset: int = 0, length: int = 8000) -> dict:
        stmt = select(WebAsset).where(scoped(WebAsset.project_id))
        if asset_id:
            stmt = stmt.where(WebAsset.id == int(asset_id))
        elif url.strip():
            stmt = stmt.where(WebAsset.url == url.strip())
        else:
            return {"error": "give `asset_id` or `url`"}
        a = (await session.execute(stmt)).scalars().first()
        if a is None:
            return {"error": "no such asset in this engagement"}

        body = a.body or ""
        # A window, not the file. A minified bundle is routinely a
        # megabyte on one line; handing that back whole would fill the
        # context with one file and answer nothing. Paged instead, so
        # the model can walk it if it genuinely needs to -- though
        # `search_web_assets` is almost always the right tool and this
        # one is for reading around a hit.
        start = max(0, int(offset))
        take = max(1, min(int(length), 20000))
        return {
            "asset_id": a.id, "url": a.url, "name": a.name,
            "version": a.version or "unknown", "bytes": a.bytes,
            "content_type": a.content_type, "sha256": a.sha256,
            "third_party": a.third_party, "on_pages": a.seen_on,
            "body_fetched": a.body is not None,
            "offset": start, "length": len(body[start:start + take]),
            "total_length": len(body),
            "content": body[start:start + take],
            "more": start + take < len(body),
        } if a.body is not None else {
            "asset_id": a.id, "url": a.url, "name": a.name,
            "body_fetched": False,
            "note": "This asset is known by reference only — its bytes have "
                    "never been fetched, so there is nothing to read. That "
                    "is not the same as the file being empty.",
        }

    async def get_web_packet(web_id: int = 0, url: str = "") -> dict:
        """The exchange itself, for one recorded URL."""
        stmt = (select(WebAddress, Target.host)
                .join(Target, Target.id == WebAddress.target_id)
                .where(scoped(Target.project_id)))
        if web_id:
            stmt = stmt.where(WebAddress.id == int(web_id))
        elif url.strip():
            stmt = stmt.where(WebAddress.url == url.strip())
        else:
            return {"error": "give `web_id` or `url`"}
        row = (await session.execute(stmt)).first()
        if row is None:
            return {"error": "no such web address in this engagement"}
        w, host = row
        if not (w.request or w.response):
            # A status with no exchange behind it is the normal state
            # for a content-discovery hit: gobuster reports a code and
            # keeps no packet. Saying so is the difference between
            # "no evidence was kept" and "the request was empty".
            return {"id": w.id, "host": host, "url": w.url,
                    "status": w.status_code, "sources": w.sources,
                    "packet_kept": False,
                    "note": "No request or response was recorded for this "
                            "URL — it is known from a tool that reported a "
                            "status without keeping the exchange. The status "
                            "code above is still a real observation."}
        return {"id": w.id, "host": host, "url": w.url, "method": w.method,
                "status": w.status_code, "content_type": w.content_type,
                "sources": w.sources, "packet_kept": True,
                "truncated_at_capture": w.truncated,
                "request": (w.request or "")[:20000],
                "response": (w.response or "")[:60000]}

    async def list_scope(search: str = "", limit: int = 100) -> dict:
        """What this engagement is authorised against."""
        stmt = select(ProjectScope).where(scoped(ProjectScope.project_id))
        if search:
            stmt = stmt.where(ProjectScope.value.ilike(f"%{search}%"))
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(
            stmt.order_by(ProjectScope.included.desc(), ProjectScope.kind,
                          ProjectScope.value).limit(n))).scalars().all()
        return _rows([{
            "value": r.value, "kind": r.kind,
            # Exclusions live in the same list and out always trumps
            # in. Flattening them to one boolean per row is why they
            # are shown rather than filtered out.
            "included": r.included,
        } for r in rows], MAX_ROWS, total)

    async def scan_coverage(host: str = "", limit: int = 50) -> dict:
        """Which port-scan techniques have actually been run where.

        syn < connect < version: a host swept with -sS has NOT been
        version-detected, and reporting it as "scanned" hides the
        difference between knowing a port is open and knowing what is
        behind it.
        """
        stmt = (select(PortScanCoverage, Target.host)
                .join(Target, Target.id == PortScanCoverage.target_id)
                .where(scoped(Target.project_id)))
        if host.strip():
            stmt = stmt.where(Target.host == host.strip().lower())
        total = int((await session.execute(
            select(func.count()).select_from(stmt.subquery()))).scalar_one())
        n = max(1, min(int(limit), MAX_ROWS))
        rows = (await session.execute(
            stmt.order_by(Target.host, PortScanCoverage.port_lo)
            .limit(n))).all()
        return _rows([{
            "host": h, "technique": c.technique, "protocol": c.protocol,
            "ports": (f"{c.port_lo}-{c.port_hi}" if c.port_hi != c.port_lo
                      else str(c.port_lo)),
            "scanned_at": c.scanned_at.isoformat() if c.scanned_at else None,
            "source": c.source,
        } for c, h in rows], MAX_ROWS, total)

    # ------------------------------------------------- parity with MCP
    #
    # The MCP server exposed 58 tools and the agent 30, which meant the
    # same product answered differently depending on which door you
    # came in by. These close the read half of that gap. Each one calls
    # the function the HTTP endpoint calls, so the two surfaces cannot
    # drift -- see `_via`.

    def _need_project():
        return None if project is not None else {
            "error": "this needs one engagement in view; name the project"}

    def _confined():
        """Guard for tools that delegate to a router with a nullable project.

        Those routers scope by what the USER can see. In here the bound
        is `scope_ids`, which is narrower — a Slack channel bound to one
        engagement hands the assistant one project id while the account
        behind it may read several. With no project in view the router
        would fall back to the wider bound and quietly answer across
        engagements, which is the one mistake in this file that would
        matter outside it.

        So: a project in view is fine, and no bound at all (site admin)
        is fine. A narrower bound with nothing in view is refused rather
        than silently widened.
        """
        if project is not None or scope_ids is None:
            return None
        return {"error": "name an engagement for this one — it cannot be "
                         "asked across several from here"}

    async def whoami() -> dict:
        from ..routers.auth import me
        return await _via(me, user=user, session=session)

    async def list_ports(search: str = "", host: str = "",
                         limit: int = 100) -> dict:
        from ..routers.services import list_ports as _lp
        if (bad := _confined()):
            return bad
        return await _via(_lp, project=project.code if project else None,
                          q=search or None, host=host or None,
                          sort="host", order="asc",
                          limit=max(1, min(int(limit), MAX_ROWS)), offset=0,
                          user=user, session=session)

    async def list_web_urls(search: str = "", limit: int = 100) -> dict:
        """One row per URL rather than per captured exchange."""
        from ..routers.web import list_web_grouped
        if (bad := _confined()):
            return bad
        return await _via(list_web_grouped,
                          project=project.code if project else None,
                          host=None, q=search or None, status_code=None,
                          status_in=None, scheme=None, crawled=None,
                          found_by=None, filters=None, logic="and",
                          sort="url", order="asc",
                          limit=max(1, min(int(limit), 500)), offset=0,
                          user=user, session=session)

    async def explore(dimension: str, value: str,
                      protocol: str = "") -> dict:
        """Every host answering on one port, or running one service."""
        from ..routers.explore import explore as _ex
        if (bad := _confined()):
            return bad
        if dimension not in ("port", "service"):
            return {"error": "dimension is 'port' or 'service'"}
        return await _via(_ex, dimension=dimension, value=str(value),
                          project=project.code if project else None,
                          protocol=protocol or None, limit_hosts=3000,
                          user=user, session=session)

    async def scope_violations() -> dict:
        from ..routers.projects import scope_violations as _sv
        if (bad := _need_project()):
            return bad
        return await _via(_sv, project=project.code, pr=project,
                          session=session)

    async def domain_roots() -> dict:
        from ..routers.domains import roots
        if (bad := _need_project()):
            return bad
        return await _via(roots, project=project.code, pr=project,
                          session=session)

    async def domain_candidates(state: str = "", root: str = "") -> dict:
        from ..routers.domains import candidates
        if (bad := _need_project()):
            return bad
        return await _via(candidates, project=project.code,
                          state=state or None, root=root or None,
                          pr=project, session=session)

    async def ghost_queue(limit: int = 100) -> dict:
        from ..routers.agents import list_queue
        if (bad := _need_project()):
            return bad
        return {"queued": await _via(
            list_queue, limit=max(1, min(int(limit), 1000)), pr=project,
            _=user, session=session)}

    async def ghost_routing() -> dict:
        from ..routers.agents import read_routing
        if (bad := _need_project()):
            return bad
        return await _via(read_routing, pr=project, _=user, session=session)

    async def ghost_task_kinds() -> dict:
        from ..routers.agents import required_tools
        return await _via(required_tools, _=user)

    async def list_ghost_tasks(limit: int = 100) -> dict:
        from ..routers.agents import list_project_tasks
        if (bad := _need_project()):
            return bad
        return {"tasks": await _via(
            list_project_tasks, limit=max(1, min(int(limit), 5000)),
            pr=project, _=user, session=session)}

    async def feed_status() -> dict:
        from ..routers.vulnfeeds import feed_status as _fs
        return await _via(_fs, _=user, session=session)

    async def get_cve(cve_id: str) -> dict:
        from ..routers.vulnfeeds import get_cve as _cve
        return await _via(_cve, cve_id=cve_id, _=user, session=session)

    async def service_leads(product: str = "", version: str = "",
                            name: str = "", banner: str = "",
                            limit: int = 25) -> dict:
        from ..routers.vulnfeeds import service_leads as _sl
        return await _via(_sl, product=product, version=version, name=name,
                          banner=banner, limit=max(1, min(int(limit), 100)),
                          _=user, session=session)

    async def site_health() -> dict:
        """How the Oddjob install itself is doing. Site admins only."""
        from ..routers.health import site_health as _sh
        if rank < ROLE_ORDER.get("admin", 99):
            return {"error": "site health is for site admins"}
        return await _via(_sh, _=user, session=session)

    async def import_formats() -> dict:
        from ..routers.scans import formats
        return await _via(formats, _=user)

    async def get_finding_secret(finding_id: int) -> dict:
        """The actual credential behind a secret finding.

        Exists because the agent used to say "the database doesn't
        hold the actual secret values, only the findings recording
        that they exist" -- half right in a way that stopped the
        work. The value IS stored, in `finding_secrets`, and the UI
        has always had a reveal button for it. There was simply no
        tool, so the model reasoned correctly from a premise nobody
        had told it was false.

        Routed through the same endpoint the UI calls, so all three
        of its guards apply unchanged: `user` role rather than
        readonly, an audit entry written BEFORE the value is
        returned, and the project visibility rule. Reading a
        credential through the assistant leaves exactly the record
        reading it through the UI does.
        """
        from ..routers.findings import reveal_secret
        return await _via(reveal_secret, vuln_id=int(finding_id),
                          user=user, session=session)

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

    async def list_ghost(**_) -> dict:
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
                # The OS of the machine, where that differs from the
                # binary's. Omitted when the agent could not tell —
                # the model must not read a missing key as "linux".
                **({"host_platform": a.host_platform} if a.host_platform else {}),
                **({"container": a.container} if a.container else {}),
                "address": a.outbound_ip or a.last_ip,
                # Which of the six ways the agent found that address.
                # Sent because a model asked "what IP will the client
                # see" has no other way to tell a container's private
                # address from a real egress one: they are the same
                # shape and only this says which is which.
                **({"address_source": a.outbound_ip_source}
                   if a.outbound_ip_source else {}),
                # Said plainly: an agent without raw sockets cannot run
                # masscan and will silently connect-scan with nmap, so
                # it changes what tasking is worth sending.
                "raw_sockets": a.privileged,
                "tools": sorted(_tools_of(a)),
                "work_in_flight": queued,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None})
        return {"agents": out, "count": len(out)}

    async def _projects_in_view() -> list[Project]:
        """Every engagement this question may touch, bounded by the scope.

        `scoped()` is the single place that decides which projects the
        caller can see, so this goes through it rather than re-deriving
        the rule. A tool that worked out its own answer would be the
        one place the bound did not apply, and that is the mistake in
        this file that would matter outside it.
        """
        return list((await session.execute(
            select(Project).where(scoped(Project.id))
            .order_by(Project.code))).scalars().all())

    async def lookup_results(limit: int = 50) -> dict:
        """Finished DNS lookups and what the inventory will do with them."""
        from ..routers.enumerate import lookup_decisions
        projects = await _projects_in_view()
        if len(projects) > LOOKUP_PROJECT_CAP:
            projects = projects[:LOOKUP_PROJECT_CAP]
        automatic: list[dict] = []
        needs_you: list[dict] = []
        nothing_to_pick: list[dict] = []
        for pr in projects:
            for _task, t, subject, field, options, partial, _note, d in \
                    await lookup_decisions(session, pr):
                row = {
                    "project": pr.code, "subject": subject,
                    "lookup": ("address → names" if field == "host"
                               else "name → addresses"),
                    "target": t.host, "returned": options,
                }
                if partial:
                    row["partial"] = ("a source did not answer, so this list "
                                      "is a floor and not a total")
                if d.refused:
                    row["not_allowed"] = d.refused
                if d.verdict == "auto":
                    automatic.append({**row, "will": d.plan,
                                      "applies": d.apply})
                elif d.verdict == "choice":
                    needs_you.append({**row, "question": d.plan,
                                      "candidates": d.apply})
                else:
                    nothing_to_pick.append({**row, "why": d.plan})
        total = len(automatic) + len(needs_you) + len(nothing_to_pick)
        return {
            "automatic": automatic[:limit],
            "needs_you": needs_you[:limit],
            "nothing_to_pick": nothing_to_pick[:limit],
            "total": total,
            **({"not_every_project": (
                f"only the first {LOOKUP_PROJECT_CAP} engagements were "
                f"checked; open one to see the rest")}
               if len(projects) == LOOKUP_PROJECT_CAP and pid is None else {}),
            # Spelled out, because the distinction is the point and a
            # model handed three lists with no explanation will present
            # them as three kinds of to-do.
            "how_to_read_this": (
                "`automatic` applies itself — a host having several "
                "addresses is not a decision, and neither is an "
                "address-named row learning the one name it answers to. "
                "`needs_you` is genuinely ambiguous: several names answer "
                "at one address and nothing in the data says which owns "
                "the row, or a resolver did not finish so we cannot tell "
                "whether the address is shared. `nothing_to_pick` is "
                "reported, not asked: the lookup found nothing, or the "
                "scope list refused every name, or somebody already did. "
                "Scope decides every name and address individually."),
        }

    reads = [
        Tool("list_ghost",
             "Ghost agents on this engagement: where each is deployed, "
             "whether it can raw-socket scan, what tools it has, and what "
             "it is working on.",
             _obj({}), list_ghost),
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
        Tool("get_finding_secret",
             "The actual credential value behind a secret finding, by "
             "finding id. The values ARE stored -- `list_findings` and "
             "the secrets list tell you a secret exists and where; this "
             "returns what it is, so you can say what it unlocks. Needs "
             "`user` role and is written to the audit log.",
             _obj({"finding_id": {"type": "integer"}},
                  ["finding_id"]), get_finding_secret),
        Tool("list_findings", "Search the findings. Filter by severity or host.",
             _obj({"severity": {"type": "string",
                                "enum": ["critical", "high", "medium", "low", "info"]},
                   "search": {"type": "string"}, "host": {"type": "string"},
                   "limit": {"type": "integer"}}), list_findings),
        Tool("list_pocs", "Proof-of-concept records: what was actually "
             "DEMONSTRATED, as opposed to what a scanner reported. "
             "`exit_code` is 0 reproduced, 1 not reproduced, 2 could not "
             "test -- and the third is not the second.",
             _obj({"host": {"type": "string"},
                   "status": {"type": "string",
                              "enum": ["confirmed", "unconfirmed"]},
                   "limit": {"type": "integer"}}), list_pocs),
        Tool("list_reports", "Reports generated for this engagement. Lists "
             "what exists and when; the rendered document is a download, "
             "not something to read into an answer.",
             _obj({"limit": {"type": "integer"}}), list_reports),
        Tool("list_actions", "Active probes requested against this "
             "engagement's services, newest first. The record of the WORK "
             "rather than of its results -- this is how you answer "
             "'has anybody looked at this yet'.",
             _obj({"kind": {"type": "string"},
                   "limit": {"type": "integer"}}), list_actions),
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
        # The files the pages LOAD. `list_web_addresses` holds URLs
        # and titles and no file content at all, so without these a
        # question about hardcoded keys has nowhere to look.
        Tool("search_web_assets",
             "Grep the contents of the static files the project's pages "
             "load — JavaScript bundles, stylesheets, config blobs. THIS "
             "is the tool for 'find hardcoded keys / secrets / tokens / "
             "credentials in the web', and for any question about what is "
             "INSIDE a file. mode='secrets' (the default) runs the "
             "built-in patterns for API keys, AWS key ids, JWTs, private "
             "keys and the like across every file whose bytes were "
             "fetched; mode='text' finds a literal string. Returns "
             "snippets with offsets, never whole files. Check "
             "`files_searched`: zero means nothing has been fetched yet "
             "and NO file was read, which is not the same as finding "
             "nothing. Do NOT use list_web_addresses for this — it holds "
             "URLs, titles and status codes and no file content at all, "
             "so searching it for a key finds nothing and proves nothing.",
             _obj({"query": {"type": "string",
                             "description": "literal to find; omit for "
                                            "mode=secrets"},
                   "mode": {"type": "string", "enum": ["secrets", "text"]},
                   "limit": {"type": "integer"}}),
             search_web_assets),
        Tool("list_web_assets",
             "The inventory of static files the project's pages pull in, "
             "with versions. Use for 'what libraries are we on', 'what do "
             "we load from third parties', 'which bundles have no "
             "version'. `contains` narrows to files whose CONTENT holds a "
             "string. `body_fetched` false means the file is known by "
             "reference only and has never been read.",
             _obj({"search": {"type": "string",
                              "description": "matches url, name or host"},
                   "contains": {"type": "string",
                                "description": "matches the file content"},
                   "third_party": {"type": "boolean"},
                   "fetched_only": {"type": "boolean"},
                   "limit": {"type": "integer"}}),
             list_web_assets),
        Tool("get_web_asset",
             "Read one static file, by `asset_id` or exact `url`. Returns "
             "a WINDOW, not the whole file — a minified bundle is often a "
             "megabyte on one line. Use `offset` and `length` to walk it, "
             "and prefer search_web_assets to find where to look first.",
             _obj({"asset_id": {"type": "integer"},
                   "url": {"type": "string"},
                   "offset": {"type": "integer"},
                   "length": {"type": "integer",
                              "description": "max 20000 characters"}}),
             get_web_asset),
        Tool("get_web_packet",
             "The raw request and response recorded for one URL, by "
             "`web_id` or exact `url`. Use it to read the evidence behind "
             "a status code — which WAF answered, what realm a 401 names. "
             "`packet_kept` false means the URL is known from a tool that "
             "reported a status without keeping the exchange.",
             _obj({"web_id": {"type": "integer"}, "url": {"type": "string"}}),
             get_web_packet),
        Tool("list_scope",
             "What this engagement is authorised to touch. Exclusions are "
             "in the same list with `included` false, and an exclusion "
             "always beats an inclusion. Use it before saying whether "
             "something is in scope.",
             _obj({"search": {"type": "string"}, "limit": {"type": "integer"}}),
             list_scope),
        Tool("scan_coverage",
             "Which port-scan techniques have run against which ports. "
             "syn < connect < version: a host swept with -sS has NOT been "
             "version-detected. Use for 'what have we actually scanned' "
             "and before claiming a host is finished.",
             _obj({"host": {"type": "string"}, "limit": {"type": "integer"}}),
             scan_coverage),
        Tool("whoami", "Who the assistant is acting as, and what it may do.",
             _obj({}), whoami),
        Tool("list_ports", "Open ports as a flat list, one row per port. "
             "`port_summary` counts them; this one shows them.",
             _obj({"search": {"type": "string"}, "host": {"type": "string"},
                   "limit": {"type": "integer"}}), list_ports),
        Tool("list_web_urls",
             "URLs, one row each, with the methods and statuses seen. The "
             "inventory view. `list_web_addresses` is one row per captured "
             "exchange, which is what you want for evidence and not for "
             "counting.",
             _obj({"search": {"type": "string"}, "limit": {"type": "integer"}}),
             list_web_urls),
        Tool("explore",
             "Every host answering on one port, or running one service, "
             "across the engagement. Use for 'who else has 3389 open'.",
             _obj({"dimension": {"type": "string", "enum": ["port", "service"]},
                   "value": {"type": "string",
                             "description": "a port number, or a service name"},
                   "protocol": {"type": "string"}},
                  ["dimension", "value"]), explore),
        Tool("scope_violations",
             "Targets this engagement holds that its own scope list would "
             "refuse. Changes nothing — it is the question 'are we inside "
             "what we were authorised to do'.",
             _obj({}), scope_violations),
        Tool("domain_roots",
             "Registrable domains this engagement covers, commonest first. "
             "What domain enumeration would be pointed at.",
             _obj({}), domain_roots),
        Tool("domain_candidates",
             "Hostnames seen alongside targets that are not targets yet, "
             "and whether each has been accepted, rejected or neither.",
             _obj({"state": {"type": "string"}, "root": {"type": "string"}}),
             domain_candidates),
        Tool("ghost_queue", "Work waiting to run on this engagement, oldest "
             "first — both the project pool and work addressed to one agent.",
             _obj({"limit": {"type": "integer"}}), ghost_queue),
        Tool("ghost_routing", "Which agents are eligible for this project's "
             "work, and how much is waiting for one.",
             _obj({}), ghost_routing),
        Tool("ghost_task_kinds", "The task kinds agents can run, and which "
             "tool each needs installed.", _obj({}), ghost_task_kinds),
        Tool("list_ghost_tasks", "Every task on this engagement, newest "
             "first. Use for 'what is happening' and 'what failed'.",
             _obj({"limit": {"type": "integer"}}), list_ghost_tasks),
        Tool("feed_status", "Whether the exploit and CVE feeds have synced, "
             "and when. A feed that never synced means a lookup returning "
             "nothing is 'not held', NOT 'does not exist'.",
             _obj({}), feed_status),
        Tool("get_cve", "One CVE from the local table, with its score and "
             "description.",
             _obj({"cve_id": {"type": "string"}}, ["cve_id"]), get_cve),
        Tool("service_leads",
             "CVEs and exploits matching a product/version/banner, without "
             "needing a host. Use to judge a version string.",
             _obj({"product": {"type": "string"}, "version": {"type": "string"},
                   "name": {"type": "string"}, "banner": {"type": "string"},
                   "limit": {"type": "integer"}}), service_leads),
        Tool("import_formats", "The report formats this install can import.",
             _obj({}), import_formats),
        Tool("site_health",
             "How this Oddjob install is doing — database, feeds, agents. "
             "About the tool, not the engagement. Site admins only.",
             _obj({}), site_health),
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
        # Phrased for the questions people actually ask. The agent could
        # already QUEUE a reverse-IP or nslookup lookup and then had no
        # way to read what came back, so "what did that find?" and "add
        # all the lookup results" both ended in the model saying it did
        # not know what was meant. A tool nobody's phrasing matches is
        # nearly as bad as no tool, so the wording carries the phrases.
        Tool("lookup_results",
             "What DNS lookups came back with, and what will happen to "
             "each. Use for \"what lookups are waiting\", \"any lookup "
             "results?\", \"did the reverse-IP finish\", \"which hostnames "
             "did we find\", or before adding lookup results. Separates "
             "the results that resolve themselves from the ones that "
             "genuinely need a person to choose, and says why for each. "
             "Read-only.",
             _obj({"limit": {"type": "integer"}}), lookup_results),
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

    async def apply_lookup_results(**_) -> dict:
        """Apply the lookup results that are not in doubt. Report the rest."""
        from ..routers.enumerate import apply_auto, lookup_decisions
        if pid is None or project is None:
            return {"error": "applying lookup results needs one engagement "
                             "in view; pick a project and ask again"}
        # The same function the HTTP route and the Ghost result handler
        # call. Not a reimplementation: if the agent's path and the API
        # path could disagree about what scope allows, that difference
        # would be the bug, and sharing the function is the only way to
        # be sure there is no difference to find.
        report = await apply_auto(session, project)
        await session.commit()

        # What is LEFT is reported, never guessed at. An agent quietly
        # deciding which of four hostnames takes over an address-named
        # row is the exact failure this whole change is built to avoid,
        # and it is worse through a chat window, where nobody sees the
        # choice being made.
        waiting = [
            {"subject": subject, "target": t.host, "returned": options,
             "question": d.plan, "candidates": d.apply}
            for _task, t, subject, _field, options, _partial, _note, d
            in await lookup_decisions(session, project)
            if d.verdict == "choice"]
        return {
            "project": project.code,
            "addresses_added": report.addresses_added,
            "renamed": report.renamed,
            "merged": report.merged,
            "created": report.created,
            "not_allowed": report.refused,
            "still_needs_a_person": waiting,
            "note": (
                "Everything deterministic has been applied. Anything under "
                "`still_needs_a_person` was NOT touched: which name takes "
                "over an address-named row is a decision, and guessing it "
                "sends future findings to the wrong host. Offer the "
                "candidates and let them choose. `not_allowed` is what the "
                "scope list refused — that is fixed by editing the scope "
                "list, not here."),
        }

    async def add_finding(host: str, title: str, severity: str = "info",
                          description: str = "") -> dict:
        t = await _target(host)
        if t is None:
            return {"error": f"no target {host!r}"}
        sev = severity.lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            return {"error": "severity must be one of critical/high/medium/low/info"}
        v = Vuln(target_id=t.id, title=title[:1000], severity=sev,
                 description=description or None)
        session.add(v)
        await record(session, t.id, "vuln", f"{sev.upper()}: {title}"[:400],
                     detail=description or None, actor=f"agent({user.username})")
        await session.commit()
        return {"ok": True, "host": t.host, "title": title}

    # ------------------------------------------------------ ghost writes
    async def task_ghost(kind: str, targets: str, agent: str = "",
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
                             f"assistant; queue it yourself from the Ghost "
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
        # Same gate as the Ghost page, reached the same way. A scan the
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

    #: Task kinds whose subject is a NAME rather than a machine:
    #: amass enumerates under a zone, nslookup asks a resolver about a
    #: hostname. A target whose identifier is not a DNS name has
    #: nothing for either to work on — see `hosts.dns_subject`.
    _NAME_SUBJECT_KINDS = frozenset({"amass", "nslookup"})

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

    async def enumerate_ghosts(kind: str, select: str = "unscanned",
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
                             f"belongs on the Ghost page, where the allowlist "
                             f"and the agent are both in front of you"}

        sel = (select or "").strip().lower()
        if sel not in _SELECTORS:
            return {"error": f"unknown selection {sel!r}",
                    "selections": _SELECTORS}

        # ------------------------------------------------ choose hosts
        chosen_hosts: list[str] = []
        #: What was picked by the selection and then dropped, with the
        #: reason. Reported rather than quietly removed -- see below.
        unscannable: dict[str, str] = {}
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
            if kind in _NAME_SUBJECT_KINDS:
                # amass and nslookup take a NAME. A cloud resource id
                # and a mobile bundle id are not names, and
                # `validate_host` below does not catch them all: an
                # ARN has a colon in it and is refused, but a bucket
                # called `acme-backups` is a well-formed hostname and
                # simply is not one. The kind column is what knows.
                #
                # Only these kinds. A cloud resource usually has an
                # address, so dropping it from an nmap sweep would
                # leave a real asset unscanned.
                for t in targets:
                    if not dns_subject(t.kind):
                        unscannable[t.host] = (
                            f"a {t.kind} target is named by an identifier, "
                            f"not by a hostname, so there is nothing for "
                            f"{kind} to ask about")
                targets = [t for t in targets if dns_subject(t.kind)]
            chosen_hosts = [t.host for t in targets]

        # A project's inventory holds more than network hosts — an S3
        # ARN, a mobile package name, a cloud resource id. Those are
        # worth recording and cannot be scanned, and a scanner pointed
        # at one burns a task to produce an error. Dropped here, and
        # reported rather than quietly removed: "I queued 1,700 of your
        # 1,738" is a fact the operator needs in order to notice that
        # thirty-eight assets are being covered by nothing at all.
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

    async def ghost_task_status(task_id: int) -> dict:
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

    async def enroll_ghost(name: str, target_os: str = "linux",
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
            return {"error": "enrolling a Ghost is an admin action on this "
                             "project; ask someone with that role"}
        if target_os not in ("linux", "darwin", "windows"):
            return {"error": "target_os is linux, darwin or windows"}
        if connection_mode not in ("callback", "call_in"):
            return {"error": "connection_mode is callback or call_in"}

        _, server_pub = await server_identity(session)
        cb_raw, cb_hash = new_agent_key()
        ci_raw, ci_hash = new_agent_key()
        tok_raw, tok_hash = new_agent_key()
        expires = datetime.now(UTC) + ENROLL_TTL
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
            "run": (f"ghost run --server <this oddjob url> "
                    f"--enroll {tok_raw} --name {a.name}"),
            "note": ("this token is shown once and is good for a short "
                     "while; the agent trades it for a keypair it makes "
                     "itself, and will then only take tasking from this "
                     "Oddjob"),
            "server_public_key": server_pub,
        }

    # ------------------------------------- parity with MCP: the writes
    #
    # Same reasoning as the read half above: one product, two front
    # doors, and they must not answer differently. Each calls the
    # function the endpoint calls. `require_project` is not re-run --
    # the caller's role was already resolved into `rank` -- so the
    # role each one needs is checked here explicitly.

    def _needs(level: str):
        if project is None:
            return {"error": "this needs one engagement in view"}
        if rank < ROLE_ORDER.get(level, 99):
            return {"error": f"this needs {level} on {project.code}; "
                             f"you have {role or 'no role'}"}
        return None

    async def set_target_flags(host: str, hacked: bool | None = None,
                               notes: str = "", kind: str = "") -> dict:
        from ..routers.targets import update_target
        from ..schemas import TargetUpdate
        if (bad := _needs("user")):
            return bad
        patch: dict[str, Any] = {}
        if hacked is not None:
            patch["hacked"] = bool(hacked)
        if notes:
            patch["notes"] = notes
        if kind:
            patch["kind"] = kind
        if not patch:
            return {"error": "nothing to change"}
        return await _via(update_target, project=project.code, host=host,
                          body=TargetUpdate(**patch), _=project, user=user,
                          session=session)

    async def add_scope(values: str, included: bool = True) -> dict:
        from ..routers.projects import add_scope as _add
        from ..schemas import ScopeAdd
        # Admin, and deliberately so: this is the list every other
        # path consults before sending a packet. Widening it from a
        # sentence is the one write here that could put traffic on
        # something nobody authorised.
        if (bad := _needs("admin")):
            return bad
        items = [v.strip() for v in values.replace(",", " ").split() if v.strip()]
        if not items:
            return {"error": "no values given"}
        return await _via(_add, project=project.code,
                          body=ScopeAdd(values=items, included=bool(included)),
                          pr=project, session=session)

    async def enumerate_domains(domains: str = "", mode: str = "passive",
                                agent: str = "") -> dict:
        from ..routers.domains import EnumerateRequest
        from ..routers.domains import enumerate_domains as _en
        if (bad := _needs("user")):
            return bad
        want = [d.strip() for d in domains.replace(",", " ").split() if d.strip()]
        body = EnumerateRequest(domains=want, mode=mode,
                                **({"agent": agent} if agent else {}))
        return await _via(_en, body=body, project=project.code, pr=project,
                          user=user, session=session)

    async def promote_domain_candidates(names: str) -> dict:
        from ..routers.domains import PromoteRequest, promote
        if (bad := _needs("user")):
            return bad
        want = [n.strip() for n in names.replace(",", " ").split() if n.strip()]
        if not want:
            return {"error": "no names given"}
        return await _via(promote, body=PromoteRequest(names=want),
                          project=project.code, pr=project, user=user,
                          session=session)

    async def reject_domain_candidates(names: str) -> dict:
        from ..routers.domains import PromoteRequest, reject
        if (bad := _needs("user")):
            return bad
        want = [n.strip() for n in names.replace(",", " ").split() if n.strip()]
        if not want:
            return {"error": "no names given"}
        return await _via(reject, body=PromoteRequest(names=want),
                          project=project.code, pr=project, user=user,
                          session=session)

    async def cancel_ghost_task(task_id: int) -> dict:
        from ..routers.agents import cancel_task
        if (bad := _needs("user")):
            return bad
        r = await _via(cancel_task, task_id=int(task_id), pr=project,
                       user=user, session=session)
        return r if isinstance(r, dict) and "error" in r else {
            "ok": True, "task_id": int(task_id), "status": "cancelled"}

    async def retry_ghost_task(task_id: int) -> dict:
        from ..routers.agents import retry_task
        if (bad := _needs("user")):
            return bad
        return await _via(retry_task, task_id=int(task_id), pr=project,
                          user=user, session=session)

    async def import_ghost_task(agent_id: int, task_id: int,
                                import_as: str = "") -> dict:
        from ..routers.agents import TaskImportBody, import_task_result
        if (bad := _needs("user")):
            return bad
        return await _via(import_task_result, agent_id=int(agent_id),
                          task_id=int(task_id),
                          body=TaskImportBody(
                              **({"import_as": import_as} if import_as else {})),
                          pr=project, _=user, session=session)

    async def import_report(content: str, fmt: str = "auto",
                            mode: str = "strict") -> dict:
        from ..routers.scans import ImportBody
        from ..routers.scans import import_report as _imp
        if (bad := _needs("user")):
            return bad
        if not content.strip():
            return {"error": "nothing to import"}
        return await _via(_imp,
                          body=ImportBody(content=content, format=fmt,
                                          mode=mode),
                          project=project, _=user, session=session)

    async def create_project(code: str, name: str = "", client: str = "",
                             scope: str = "") -> dict:
        from ..routers.projects import create_project as _cp
        from ..schemas import ProjectCreateFull
        # Site-level, not project-level: there is no project in view to
        # hold a role on, so this asks for site admin.
        if rank < ROLE_ORDER.get("admin", 99):
            return {"error": "creating an engagement needs admin"}
        lines = [v.strip() for v in scope.replace(",", "\n").splitlines()
                 if v.strip()]
        return await _via(_cp, body=ProjectCreateFull(
            code=code.strip().upper(), name=name or code.strip().upper(),
            client=client or None, scope=lines),
            user=user, session=session)

    async def bulk_import(rows: str) -> dict:
        """Create targets, services, findings and PoCs in one pass."""
        from ..routers.bulk import BulkPayload
        from ..routers.bulk import bulk_import as _bulk
        if (bad := _needs("user")):
            return bad
        try:
            payload = json.loads(rows)
        except ValueError as e:
            return {"error": f"rows must be JSON: {e}"}
        if not isinstance(payload, dict):
            return {"error": "rows must be a JSON object keyed by kind"}
        payload.setdefault("project", project.code)
        try:
            body = BulkPayload(**payload)
        except Exception as e:                           # noqa: BLE001
            return {"error": f"not a usable bulk payload: {e}"}
        return await _via(_bulk, payload=body, user=user, session=session)

    async def import_nmap(xml: str) -> dict:
        from ..routers.scans import import_nmap as _in
        if (bad := _needs("user")):
            return bad
        if not xml.strip():
            return {"error": "nothing to import"}
        return await _via(_in, body={"xml": xml}, project=project, _=user,
                          session=session)

    async def kill_ghost(agent_id: int) -> dict:
        from ..routers.agents import kill_agent
        # Admin. It disables a credential and cancels queued work --
        # recoverable, but not something a sentence should cause by
        # accident.
        if (bad := _needs("admin")):
            return bad
        return await _via(kill_agent, agent_id=int(agent_id), pr=project,
                          user=user, session=session)

    return reads + [
        Tool("set_target_flags",
             "Change a host's own fields: mark it compromised, set its "
             "notes, or correct its kind.",
             _obj({"host": {"type": "string"},
                   "hacked": {"type": "boolean"},
                   "notes": {"type": "string"},
                   "kind": {"type": "string"}}, ["host"]),
             set_target_flags, writes=True),
        Tool("add_scope",
             "Add entries to what this engagement is authorised against. "
             "`included=false` adds an EXCLUSION, which beats any "
             "inclusion. Needs admin: this is the list every other path "
             "consults before sending a packet.",
             _obj({"values": {"type": "string",
                              "description": "hosts, CIDRs or wildcards, "
                                             "space or comma separated"},
                   "included": {"type": "boolean"}}, ["values"]),
             add_scope, writes=True),
        Tool("enumerate_domains",
             "Hand domains to Ghost for subdomain enumeration. What comes "
             "back arrives as candidates to accept, not as targets.",
             _obj({"domains": {"type": "string"},
                   "mode": {"type": "string", "enum": ["passive", "active"]},
                   "agent": {"type": "string"}}), enumerate_domains,
             writes=True),
        Tool("promote_domain_candidates",
             "Turn discovered hostnames into targets. They are scope-gated "
             "on the way in.",
             _obj({"names": {"type": "string"}}, ["names"]),
             promote_domain_candidates, writes=True),
        Tool("reject_domain_candidates",
             "Mark discovered hostnames as not worth pursuing, so they "
             "stop being offered.",
             _obj({"names": {"type": "string"}}, ["names"]),
             reject_domain_candidates, writes=True),
        Tool("cancel_ghost_task", "Take a queued task back out of the queue.",
             _obj({"task_id": {"type": "integer"}}, ["task_id"]),
             cancel_ghost_task, writes=True),
        Tool("retry_ghost_task", "Put a failed task back in the queue.",
             _obj({"task_id": {"type": "integer"}}, ["task_id"]),
             retry_ghost_task, writes=True),
        Tool("import_ghost_task",
             "Import a finished task's output by hand, for one that came "
             "back but was not filed — usually because the format had to "
             "be named.",
             _obj({"agent_id": {"type": "integer"},
                   "task_id": {"type": "integer"},
                   "import_as": {"type": "string"}},
                  ["agent_id", "task_id"]), import_ghost_task, writes=True),
        Tool("import_report",
             "Import a scan report pasted as text — nmap XML, nuclei "
             "JSONL, gobuster and the rest; `fmt=auto` detects it. "
             "`mode=strict` (the default) holds hosts the engagement does "
             "not already have, rather than creating them silently.",
             _obj({"content": {"type": "string"},
                   "fmt": {"type": "string"},
                   "mode": {"type": "string", "enum": ["strict", "open"]}},
                  ["content"]), import_report, writes=True),
        Tool("create_project",
             "Start a new engagement, optionally with its scope list. "
             "Needs admin.",
             _obj({"code": {"type": "string"}, "name": {"type": "string"},
                   "client": {"type": "string"},
                   "scope": {"type": "string",
                             "description": "one entry per line or comma "
                                            "separated"}}, ["code"]),
             create_project, writes=True),
        Tool("bulk_import",
             "Create or update many rows in one pass, as a JSON object "
             "keyed by kind (targets, services, vulns, pocs). For a "
             "handful of rows prefer add_target / add_finding, which "
             "validate one thing at a time and say what happened to it.",
             _obj({"rows": {"type": "string",
                            "description": "JSON object keyed by kind"}},
                  ["rows"]), bulk_import, writes=True),
        Tool("import_nmap",
             "Import nmap XML specifically. `import_report` does the same "
             "for every tool and detects the format; this exists because "
             "it predates that one and scripts point at it.",
             _obj({"xml": {"type": "string"}}, ["xml"]),
             import_nmap, writes=True),
        Tool("kill_ghost",
             "Stop an agent: disable its credential and cancel its "
             "unstarted work, keeping everything it found. Needs admin.",
             _obj({"agent_id": {"type": "integer"}}, ["agent_id"]),
             kill_ghost, writes=True),
        Tool("task_ghost",
             "Queue a scan on a Ghost agent. Name an agent to pin the work "
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
                  ["kind", "targets"]), task_ghost, writes=True),
        Tool("enumerate_ghosts",
             "Queue enumeration across the project's own targets — one "
             "task per host, picked by selection rather than listed by "
             "hand: all, unscanned, web, hacked, technology, or an "
             "explicit host list. PREVIEWS by default; pass confirm=true "
             "to actually queue. Use this for a sweep, and task_ghost for "
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
                  ["kind"]), enumerate_ghosts, writes=True),
        Tool("ghost_task_status",
             "How a queued Ghost task is getting on, and whether its results "
             "are waiting on a decision about unknown hosts.",
             _obj({"task_id": {"type": "integer"}}, ["task_id"]),
             ghost_task_status),
        Tool("enroll_ghost",
             "Create a new Ghost agent for this engagement and return the "
             "one-time command to run on the host. Admin only.",
             _obj({"name": {"type": "string"},
                   "target_os": {"type": "string",
                                 "enum": ["linux", "darwin", "windows"]},
                   "connection_mode": {"type": "string",
                                       "enum": ["callback", "call_in"]}},
                  ["name"]), enroll_ghost, writes=True),
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
        Tool("apply_lookup_results",
             "Add the lookup results: write every finished DNS lookup whose "
             "answer is not in doubt into the inventory — addresses onto "
             "the hosts that resolved to them, and a hostname onto a target "
             "still named by its address. Use for \"add all the lookup "
             "results\", \"apply the lookups\", \"add the hostnames we "
             "found\". Safe to run twice. It does NOT decide the ambiguous "
             "ones: those come back under `still_needs_a_person` with the "
             "candidates, to be offered rather than chosen. Scope is "
             "enforced on every name and address, exactly as in the UI.",
             _obj({}), apply_lookup_results, writes=True),
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
