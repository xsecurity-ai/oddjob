#!/usr/bin/env python3
"""MCP server for Oddjob — lets an MCP client read and write engagement data.

Run it over stdio (what Claude Code and Claude Desktop expect):

    ODDJOB_API_KEY=msk_... uv run python oddjob_mcp.py

Register it with Claude Code:

    claude mcp add oddjob --env ODDJOB_API_KEY=msk_... -- \
        uv --directory /path/to/oddjob/backend run python oddjob_mcp.py

It is a THIN CLIENT over the HTTP API, not a second path into the database.
That matters for authorisation: every call carries the API key, so the server
applies exactly the same per-project ACL it applies to the browser. An MCP
server talking straight to SQLite would silently bypass the whole ACL model.

Mint a key in the UI, or:
    curl -X POST 'http://127.0.0.1:8000/api/auth/keys?name=mcp' \
         -H "Authorization: Bearer <jwt>"

------------------------------------------------------------------------
WHY THIS FILE HAS A MANIFEST
------------------------------------------------------------------------
Oddjob has two tool surfaces and they are not the same program:

  * `app/agent/tools.py` runs IN-PROCESS. It holds an `AsyncSession`, the
    project is fixed by the caller, and writes are gated by a site switch.
  * this file runs OUT-OF-PROCESS. It holds an API key and nothing else,
    and every permission it has is a permission the server granted that
    key when it checked the ACL.

Different transport, different auth, different trust. They cannot share an
implementation and should not try to: an in-process tool that took a
`project` argument from the model would be a hole, and an out-of-process
tool that did not would be useless.

What they CAN share is a definition of what the surface IS. So every tool
here is registered through `@tool(...)` rather than `@mcp.tool()`, which
does two things at once: it registers with MCP exactly as before, and it
records the tool in `MANIFEST` along with `agent_equivalent` — the name of
the in-process tool it corresponds to, or None where there is no such
thing.

That one extra word is the whole mechanism. `tests/mcptest.py` enumerates
the agent's tools by calling `app.agent.tools.build()` with a null session
(it builds closures and touches no database), enumerates this manifest,
and fails if an agent tool is neither claimed by an MCP tool nor listed in
`AGENT_ONLY` below with a reason. It fails in the other direction too: an
`agent_equivalent` naming a tool that no longer exists catches a rename,
and a stale `AGENT_ONLY` entry catches a deletion.

The drift this is built to stop already happened once — eighteen of the
agent's twenty-two tools had no equivalent here, including the entire
Drone subsystem — and it happened because the only thing keeping the two
aligned was somebody noticing. Nobody noticed for eighteen tools.

**When this test fails because a new agent tool appeared, that is the
mechanism working.** Add the MCP tool, or add an `AGENT_ONLY` entry saying
why not. Do not delete the assertion.

The agent is a yardstick, not a ceiling. This server talks to the HTTP API
and so reaches things the in-platform agent never needed — scope entries,
domain candidates, the task queue, site health. Those tools carry
`agent_equivalent=None`, which is a fact and not a gap.
"""
from __future__ import annotations

import collections
import inspect
import os
from collections.abc import Callable
from typing import Any

import httpx

# mcp 2.x renamed FastMCP -> MCPServer; the decorator API is otherwise the same.
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations


# Read at call time rather than bound at import. Two reasons, and the
# second is the one that matters: a test needs to stand the server up on
# an ephemeral port and mint a key before it can import this module, and
# an import-time constant makes that ordering impossible to satisfy
# without reloading the module. The first is merely nice — an operator
# who exports the variable after launching gets what they expect.
def _base() -> str:
    return os.environ.get("ODDJOB_URL", "http://127.0.0.1:8000").rstrip("/")


def _key() -> str:
    return os.environ.get("ODDJOB_API_KEY", "")


mcp = MCPServer("oddjob",
                instructions="Engagement data store: projects, targets, "
                             "ports/services, vulns and PoCs, scope, "
                             "domain enumeration and the Drone agent fleet. "
                             "All access is scoped by the API key's "
                             "per-project ACL.")


# ===================================================================== manifest
class McpTool:
    """One tool, as a record rather than only as a registration.

    `params` is derived from the function signature rather than written
    out again, because a hand-written copy is one more thing to drift.
    """

    def __init__(self, fn: Callable, *, agent_equivalent: str | None,
                 writes: bool, destructive: bool):
        self.name = fn.__name__
        self.description = inspect.getdoc(fn) or ""
        self.fn = fn
        self.agent_equivalent = agent_equivalent
        self.writes = writes
        self.destructive = destructive
        sig = inspect.signature(fn)
        self.params = {
            p.name: {
                "annotation": ("" if p.annotation is inspect.Parameter.empty
                               else str(p.annotation)),
                "required": p.default is inspect.Parameter.empty,
            }
            for p in sig.parameters.values()
        }

    @property
    def required(self) -> list[str]:
        return [n for n, p in self.params.items() if p["required"]]


#: Every tool this server exposes, keyed by name, in declaration order.
#: This is the single list the README table and the drift test both read.
MANIFEST: dict[str, McpTool] = {}


def tool(*, agent_equivalent: str | None = None, writes: bool = False,
         destructive: bool = False) -> Callable:
    """Register a tool with MCP and record it in the manifest.

    `agent_equivalent` is the name of the tool in `app/agent/tools.py`
    that covers the same ground, or None where the agent has no such
    tool. It is not decoration: it is the join key the drift test uses,
    and a wrong one fails the test rather than being ignored.

    `writes` and `destructive` become MCP tool annotations, so a client
    that asks before mutating has something to ask about. They are
    advisory to the client and enforced nowhere here — the API key's ACL
    is the only real gate, and it is applied server-side.
    """
    def deco(fn: Callable) -> Callable:
        rec = McpTool(fn, agent_equivalent=agent_equivalent, writes=writes,
                      destructive=destructive)
        if rec.name in MANIFEST:
            raise RuntimeError(f"two tools named {rec.name!r}")
        MANIFEST[rec.name] = rec
        mcp.tool(annotations=ToolAnnotations(
            read_only_hint=not writes,
            destructive_hint=destructive,
        ))(fn)
        return fn
    return deco


#: Agent tools deliberately WITHOUT an MCP equivalent, and why. An entry
#: here is a decision on the record, not a backlog item — the test prints
#: the reason when it reports coverage, so the reason has to be one you
#: would still defend when it is read back to you.
AGENT_ONLY: dict[str, str] = {
    "rank_targets":
        "Ranking is a scoring rule — weights per severity, a bonus for a "
        "foothold, a bonus for remote-access ports — and the rule lives in "
        "app/agent/tools.py. There is no HTTP endpoint for it, so covering "
        "it here would mean writing those weights a second time in a second "
        "process. Two copies of a scoring rule is exactly the drift this "
        "file is organised to prevent, and the second copy would be the one "
        "nobody updates. The fix is to lift ranking into the API (see the "
        "note in README) and then delete this entry; until then an MCP "
        "caller composes rank_targets out of list_vulns and port_summary, "
        "which is slower but is not a second opinion.",
}


# ==================================================================== transport
async def _req(method: str, path: str, *, params: dict | None = None,
               json: Any | None = None) -> Any:
    if not _key():
        return {"error": "ODDJOB_API_KEY is not set; mint one at POST /api/auth/keys"}
    # Drop unset query params rather than sending `None`, which httpx
    # would encode as the literal string "None" and FastAPI would then
    # try to coerce into an int.
    clean = {k: v for k, v in (params or {}).items() if v is not None}
    async with httpx.AsyncClient(base_url=_base(), timeout=120) as c:
        r = await c.request(method, path, params=clean or None, json=json,
                            headers={"Authorization": f"Bearer {_key()}"})
    if r.status_code >= 400:
        # Hand the server's own message back. "403 user required on FALCON-1;
        # you have readonly" is actionable; "HTTP 403" is not.
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text[:400]
        out = {"error": f"HTTP {r.status_code}", "detail": detail}
        if r.status_code == 404:
            # The API answers "you hold no role on this project" with 404,
            # not 403, so that a probe cannot enumerate project codes. That
            # is right for the API and misleading for a model, which will
            # otherwise report "no such project" to an operator who is
            # looking at it in the UI. Said here, once, rather than in
            # fifteen tool descriptions.
            out["note"] = ("a 404 on a project route can also mean the key "
                           "holds no role on it at all — the API does not "
                           "distinguish the two on purpose")
        return out
    return r.json() if r.content else {"ok": True}


def _failed(x: Any) -> bool:
    return isinstance(x, dict) and "error" in x


def _rows(page: Any, fields: tuple[str, ...], limit: int) -> Any:
    """Trim a paginated response to the fields that matter.

    A raw dump of 1,600 targets with every column is tens of thousands of
    tokens and mostly nulls; the model asked for an inventory, not a database
    export. `total` is always reported so truncation is never silent.
    """
    if _failed(page):
        return page
    items = page.get("items", [])
    return {
        "total": page.get("total", len(items)),
        "returned": min(len(items), limit),
        "truncated": len(items) > limit,
        "items": [{k: r.get(k) for k in fields} for r in items[:limit]],
    }


def _bare(rows: Any, fields: tuple[str, ...] | None, limit: int) -> Any:
    """Same, for the routes that answer with a plain JSON array.

    Several routers return `list[X]` rather than `Page[X]` — the agents
    router does it for every read, and so do the scope and domain routes.
    They carry no `total`, so the count here IS the total and saying so
    is the difference between "there are four drones" and "I was shown
    four drones".
    """
    if _failed(rows):
        return rows
    if not isinstance(rows, list):
        return rows
    keep = rows[:limit]
    return {
        "total": len(rows),
        "returned": len(keep),
        "truncated": len(rows) > limit,
        "items": [({k: r.get(k) for k in fields} if fields and isinstance(r, dict)
                   else r) for r in keep],
    }


# ------------------------------------------------------------------- projects
@tool(agent_equivalent="list_projects")
async def list_projects() -> Any:
    """List engagements you have access to, with target/vuln counts."""
    return _rows(await _req("GET", "/api/projects"),
                 ("code", "name", "client", "status", "total_targets",
                  "total_services", "total_vulns", "total_pocs"), 200)


@tool(writes=True)
async def create_project(code: str, name: str, client: str | None = None,
                         description: str | None = None,
                         scope: list[str] | None = None) -> Any:
    """Create an engagement. ANY user may; the caller becomes its admin.

    `scope` is a list of free-text entries — CIDR, IPv4, IPv6 or FQDN. The
    kind is detected per entry; prefix with ! or - to record an exclusion.

    Returns an envelope, not a bare project:
      {project, scope, contacts, members, scope_errors, member_errors}
    Always check scope_errors — unparseable lines are skipped and named
    rather than failing the whole create.
    """
    return await _req("POST", "/api/projects",
                      json={"code": code, "name": name, "client": client,
                            "description": description, "scope": scope or []})


# ---------------------------------------------------------------------- scope
@tool()
async def list_scope(project: str) -> Any:
    """The scope entries for an engagement — what may be touched, and what may not.

    Read `include_subdomains` on every fqdn entry. It is the difference
    between `acme.example` meaning one name and meaning the whole zone,
    and the gate enforces exactly what the entry says, so an entry
    without it will refuse `www.acme.example`. `included: false` is an
    exclusion and out-wins: an excluded entry beats any inclusion that
    also matches.
    """
    return _bare(await _req("GET", f"/api/projects/{project}/scope"),
                 ("id", "kind", "value", "included", "include_subdomains",
                  "country", "notes"), 2000)


@tool(writes=True)
async def add_scope(project: str, lines: list[str],
                    included: bool = True,
                    include_subdomains: bool = False,
                    countries: list[str] | None = None) -> Any:
    """Add scope entries to an engagement. Admin on the project.

    Each line is free text — CIDR, IPv4, IPv6 or FQDN — and the kind is
    detected per line. Prefix with ! or - to record an exclusion, or
    pass included=false for the whole batch.

    `include_subdomains` applies only to fqdn lines and only widens: a
    name already in scope cannot be widened to its whole zone through
    this call, because quietly turning one host into a zone is a
    decision rather than an edit. That line comes back in
    `scope_errors` and the rest of the batch still lands — so read
    `scope_errors` every time, it is where the refusals are, not the
    HTTP status.

    `countries` is operator-declared ISO 3166-1 alpha-2, never looked up.
    """
    return await _req("POST", f"/api/projects/{project}/scope",
                      json={"lines": lines, "included": included,
                            "include_subdomains": include_subdomains,
                            "countries": countries or []})


@tool()
async def scope_violations(project: str) -> Any:
    """Targets currently recorded that the project's scope would refuse.

    Reports only; changes nothing. A non-empty list usually means an
    import brought in neighbours, or the scope was tightened after the
    fact. `scope_defined: false` means no scope has been declared at
    all, in which case an empty violation list says nothing — there is
    no rule for anything to violate.
    """
    return await _req("GET", f"/api/projects/{project}/scope/violations")


# -------------------------------------------------------------------- targets
@tool(agent_equivalent="list_targets")
async def list_targets(project: str | None = None, search: str | None = None,
                       hacked: bool | None = None, alive: bool | None = None,
                       limit: int = 100) -> Any:
    """Targets, newest counts included. `search` matches any column."""
    params = {"limit": 10000, "project": project, "q": search,
              "hacked": hacked, "alive": alive}
    return _rows(await _req("GET", "/api/targets", params=params),
                 ("host", "ip_address", "project_code", "alive", "hacked",
                  "total_vulns", "total_criticals", "total_highs",
                  "total_pocs", "total_ports"), limit)


@tool(agent_equivalent="get_host")
async def get_target(project: str, host: str) -> Any:
    """Everything known about one target: detail, ports, services, vulns, PoCs, implants.

    One round trip. This used to be four — detail, then services, then
    vulns, then PoCs — until `/detail` turned out to exist and to return
    exactly this shape for the host modal in the UI. The four-call
    version also silently had no implants in it, because nobody adding
    C2 tracking thought to come and add a fifth call.
    """
    detail = await _req("GET", f"/api/targets/{project}/{host}/detail")
    if _failed(detail):
        return detail
    return {
        "target": detail.get("target"),
        # product and version are carried deliberately: they are what
        # service_leads matches on, and without them the obvious next
        # question — "is anything known about what this is running?" —
        # needs another round trip to find out what it is running.
        "services": [{k: s.get(k) for k in ("port", "protocol", "state",
                                            "name", "product", "version",
                                            "banner")}
                     for s in detail.get("services", [])],
        "vulns": [{k: v.get(k) for k in ("title", "severity", "status", "port",
                                         "external_id")}
                  for v in detail.get("vulns", [])],
        "pocs": [{k: p.get(k) for k in ("title", "status", "exit_code", "path")}
                 for p in detail.get("pocs", [])],
        "implants": [{k: i.get(k) for k in ("framework", "implant_id", "user",
                                            "integrity", "last_seen")}
                     for i in detail.get("implants", [])],
    }


@tool(agent_equivalent="add_target", writes=True)
async def add_target(project: str, host: str, ip_address: str | None = None,
                     kind: str = "host", provider: str | None = None,
                     notes: str | None = None) -> Any:
    """Add one host to an engagement. Needs `user` on the project.

    Recorded as NOT PROBED, because adding it checks nothing: `alive`
    stays null, which is a different claim from false.

    `kind` is host, mobile or cloud, and it changes what a blank address
    means — unresolved on a host, nothing-to-resolve on a mobile app —
    as well as how the identifier is validated. A cloud resource is
    named as its provider names it, so an ARN is accepted under
    kind=cloud and refused under kind=host.

    The project's scope gate has the last say and will refuse a host
    outside it. Use bulk_import for more than a handful.
    """
    return await _req("POST", "/api/targets", params={"project": project},
                      json={"host": host, "ip_address": ip_address, "kind": kind,
                            "provider": provider, "notes": notes})


@tool(writes=True)
async def set_target_flags(project: str, host: str,
                           hacked: bool | None = None,
                           alive: bool | None = None,
                           notes: str | None = None) -> Any:
    """Mark a target pwned, alive/dead, or attach notes. Needs `user` on the project.

    `alive` is tri-state in the data model: leaving it unset means "not
    probed", which is a different claim from alive=false ("probed, no
    response"). Only set it when you actually probed.
    """
    body = {k: v for k, v in (("hacked", hacked), ("alive", alive), ("notes", notes))
            if v is not None}
    if not body:
        return {"error": "nothing to change"}
    return await _req("PATCH", f"/api/targets/{project}/{host}", json=body)


@tool(agent_equivalent="find_by_technology")
async def find_by_technology(technology: str, project: str | None = None,
                             limit: int = 50) -> Any:
    """Hosts running a given technology — php, wordpress, nginx, jboss.

    Two searches, unioned: the service product/version/banner, and the
    captured web addresses' URL, title and server header. Which of those
    carries the evidence depends entirely on which tool found it — nmap
    puts it in a banner, httpx puts it in a header — so searching only
    one of them answers confidently and wrongly.

    Found in what has been RECORDED. A host running this and never
    scanned does not appear, and that is a gap in coverage rather than
    evidence of absence.
    """
    q = (technology or "").strip()
    if not q:
        return {"error": "give a technology to look for, e.g. 'php'"}
    svc = await _req("GET", "/api/services",
                     params={"q": q, "project": project, "limit": 20000})
    if _failed(svc):
        return svc
    web = await _req("GET", "/api/web",
                     params={"q": q, "project": project, "limit": 10000})
    if _failed(web):
        return web

    hits: dict[str, list[str]] = {}
    for s in svc.get("items", []):
        bits = " ".join(x for x in (s.get("product"), s.get("version")) if x)
        hits.setdefault(s.get("host") or "", []).append(
            f"{s.get('port')}/{s.get('protocol')}: " + (bits or s.get("name") or "service"))
    for w in web.get("items", []):
        hits.setdefault(w.get("host") or "", []).append(
            f"web: {w.get('url')}" + (f" ({w['title']})" if w.get("title") else ""))
    hits.pop("", None)

    out = [{"host": h, "evidence": ev[:8]} for h, ev in sorted(hits.items())]
    return {"technology": q, "matched": len(out),
            "hosts": out[:max(1, min(limit, 500))],
            "caveat": "Found in what has been RECORDED. A host running this "
                      "and never scanned does not appear."}


# --------------------------------------------------------- ports and services
@tool()
async def list_ports(project: str | None = None, host: str | None = None,
                     search: str | None = None, limit: int = 200) -> Any:
    """Open ports only — the state is pinned server-side, not passed in.

    Oddjob records ONLY open ports, deliberately: one `-sU` sweep
    produced 42,890 `open|filtered` rows against 13 genuinely open
    ports, and a store full of maybes is worse than no store. So an
    absent port here means "not recorded open", which covers both
    "closed" and "never scanned" — use list_services with a state
    filter, or the host's timeline, to tell those two apart.
    """
    return _rows(await _req("GET", "/api/ports",
                            params={"limit": 20000, "project": project,
                                    "host": host, "q": search}),
                 ("host", "port", "protocol", "banner", "project_code"), limit)


@tool(agent_equivalent="list_services")
async def list_services(project: str | None = None, host: str | None = None,
                        search: str | None = None, limit: int = 200) -> Any:
    """Services in any state (open, closed, filtered)."""
    return _rows(await _req("GET", "/api/services",
                            params={"limit": 20000, "project": project,
                                    "host": host, "q": search}),
                 ("host", "name", "port", "protocol", "state", "banner",
                  "project_code"), limit)


@tool(agent_equivalent="port_summary")
async def port_summary(project: str | None = None, top: int = 20,
                       protocol: str | None = None) -> Any:
    """How many services on each port, counted across the WHOLE project.

    Use this for "most common ports" and every other counting question.
    `list_services` returns at most a couple of hundred rows to a model,
    and a model asked for the top three will count the sample it was
    given and answer 80/53/25 when the real answer is 443, 80, 8443. It
    will even say the data was truncated and then do the arithmetic
    anyway, which is the failure worth designing out rather than warning
    about.

    The counting happens HERE, in this process, over every row the API
    will hand back — not in the model's context. That is the point: the
    row cap that produces the wrong answer is a context budget, not an
    HTTP limit, and this side of the pipe has no context budget.
    """
    page = await _req("GET", "/api/services",
                      params={"project": project, "limit": 100000})
    if _failed(page):
        return page
    want = (protocol or "").strip().lower() or None
    counts: collections.Counter = collections.Counter()
    hosts: dict[tuple, set] = {}
    for s in page.get("items", []):
        pr = (s.get("protocol") or "").lower()
        if want and pr != want:
            continue
        k = (s.get("port"), pr)
        counts[k] += 1
        hosts.setdefault(k, set()).add(s.get("host"))
    ranked = counts.most_common(max(1, min(int(top or 20), 200)))
    total = page.get("total", 0)
    out: dict[str, Any] = {
        "ports": [{"port": p, "protocol": pr, "services": n,
                   "hosts": len(hosts[(p, pr)])} for (p, pr), n in ranked],
        "counted_services": sum(counts.values()),
        "note": "counted across every service row the API returned, not a sample",
    }
    if total > len(page.get("items", [])):
        # Honesty beats a tidy number. If the API itself paginated us
        # short, the counts below are a sample after all and must say so.
        out["incomplete"] = (f"the API returned {len(page.get('items', []))} of "
                             f"{total} services; these counts are a sample and "
                             f"the ordering may be wrong")
    return out


# ----------------------------------------------------------- findings and web
@tool(agent_equivalent="list_findings")
async def list_vulns(project: str | None = None, host: str | None = None,
                     severity: str | None = None, search: str | None = None,
                     limit: int = 100) -> Any:
    """Vulnerabilities. `severity` is critical|high|medium|low|info."""
    return _rows(await _req("GET", "/api/vulns",
                            params={"limit": 20000, "project": project,
                                    "host": host, "severity": severity,
                                    "q": search}),
                 ("host", "title", "severity", "status", "port", "external_id"), limit)


@tool(agent_equivalent="add_finding", writes=True)
async def add_finding(project: str, host: str, title: str,
                      severity: str = "info", description: str | None = None,
                      remediation: str | None = None,
                      port: int | None = None,
                      external_id: str | None = None) -> Any:
    """File a finding against a host. Needs `user` on the project.

    `severity` is critical|high|medium|low|info. `external_id` is the id
    the scanner or the tracker knows it by — fill it when there is one,
    because it is what stops a re-import filing the same thing twice.
    """
    return await _req("POST", "/api/vulns", params={"project": project},
                      json={"host": host, "title": title, "severity": severity,
                            "description": description, "remediation": remediation,
                            "port": port, "external_id": external_id})


@tool(agent_equivalent="list_web_addresses")
async def list_web_addresses(project: str | None = None, host: str | None = None,
                             search: str | None = None,
                             status_code: int | None = None,
                             limit: int = 100) -> Any:
    """URLs found on http(s) services.

    One row is one CAPTURED EXCHANGE, not one URL: the same endpoint
    probed ten ways is ten rows, and the differences between the
    responses are usually the finding. Ask for `grouped=true` to collapse
    them back under the URL with the methods and statuses seen, which is
    what you want for an inventory and not what you want for evidence.
    """
    return _rows(await _req("GET", "/api/web",
                            params={"limit": 10000, "project": project,
                                    "host": host, "q": search,
                                    "status_code": status_code}),
                 ("host", "url", "method", "status_code", "title", "webserver",
                  "content_type", "sources", "project_code"), limit)


@tool()
async def list_web_urls(project: str | None = None, host: str | None = None,
                        search: str | None = None, limit: int = 100) -> Any:
    """The same web addresses, collapsed to one row per URL.

    `hits` is how many exchanges were captured against it, and `methods`
    and `statuses` are what was seen across them. Use this to answer
    "what is there", and list_web_addresses to look at the evidence.
    """
    return _rows(await _req("GET", "/api/web/grouped",
                            params={"limit": 2000, "project": project,
                                    "host": host, "q": search}),
                 ("host", "url", "hits", "methods", "statuses", "title",
                  "webserver", "project_code"), limit)


@tool(agent_equivalent="list_credentials")
async def list_credentials(project: str | None = None, search: str | None = None,
                           limit: int = 100) -> Any:
    """Captured credentials — usernames and metadata only.

    THE SECRET IS NOT RETURNED, and that is a decision taken here rather
    than one the API makes for us. `GET /api/credentials` hands back the
    plaintext to anyone holding `user` on the project, because the UI has
    a reveal button and a human clicking it is the point. This tool
    serves a model whose context is shipped to a third party and may be
    logged there, and a captured password is the one thing in this
    database that is still live on the client's estate after the
    engagement ends.

    `secret_captured` tells you whether there is one to go and look at,
    which is all the reasoning needs.
    """
    page = await _req("GET", "/api/credentials",
                      params={"limit": 5000, "project": project, "q": search})
    if _failed(page):
        return page
    items = page.get("items", [])
    keep = items[:limit]
    return {
        "total": page.get("total", len(items)),
        "returned": len(keep),
        "truncated": len(items) > limit,
        "items": [{"host": c.get("host"), "username": c.get("username"),
                   "kind": c.get("kind"), "service": c.get("service"),
                   "port": c.get("port"), "validated": c.get("validated"),
                   "project_code": c.get("project_code"),
                   "secret_captured": bool(c.get("secret_set") or c.get("secret"))}
                  for c in keep],
        "note": "secrets are withheld by this tool, not absent from the store",
    }


# --------------------------------------------------------------------- bulk
@tool(writes=True)
async def bulk_import(project: str,
                      targets: list[dict] | None = None,
                      services: list[dict] | None = None,
                      vulns: list[dict] | None = None,
                      pocs: list[dict] | None = None,
                      create_project: bool = False) -> Any:
    """Upsert many records into one project, in a single transaction.

    Shapes (every field except the keys is optional):
      targets  {host, ip_address, alive, hacked, os, notes, tags}
      services {host, port, protocol, state, name, product, version, banner}
      vulns    {host, title, severity, status, port, description, external_id}
      pocs     {host, title, status, path, exit_code, notes}

    IDEMPOTENT: re-running the same payload updates in place and creates
    nothing. Rows whose host is not a real host -- wildcards like `*.acme.example`,
    anything with whitespace -- are skipped and listed in `errors` rather than
    failing the batch, so check `skipped` and `errors` in the result.
    """
    return await _req("POST", "/api/bulk", json={
        "project": project, "create_project": create_project,
        "targets": targets or [], "services": services or [],
        "vulns": vulns or [], "pocs": pocs or [],
    })


@tool()
async def import_formats() -> Any:
    """Which scanner and C2 formats `import_report` accepts."""
    return await _req("GET", "/api/scans/formats")


@tool(writes=True)
async def import_report(project: str, content: str, format: str = "auto",
                        mode: str = "strict", decisions: dict | None = None) -> Any:
    """Import a report from any supported tool into a project.

    Handles nmap, masscan, Nessus, Metasploit (db_export -f xml), Burp,
    Nikto, nuclei, httpx/naabu, and C2 session lists from Cobalt Strike,
    Mythic, Merlin, Sliver and Havoc. `format` defaults to sniffing the
    content; pass a name from `import_formats` to be explicit.

    Targets, services, findings, credentials and C2 callbacks all land in
    one pass. An open port whose service could not be identified is recorded
    as UNKNOWN, never blank. A C2 callback marks its host compromised.
    Everything is upserted, so re-importing updates rather than duplicates.

    `mode` defaults to "strict": only hosts the project ALREADY HAS are
    written, and any others come back under `unknown_hosts` with nothing
    imported. That guard exists because a report from one engagement
    imported into another silently created fourteen targets belonging to a
    different client.

    To proceed, call again with the same content and `decisions`, a map of
    host -> {"action": "add"|"map"|"reject", "target": "existing.host"}.
    A host you leave out is REJECTED, not created. Use mode="open" only
    when you intend the file to define the estate.
    """
    return await _req("POST", "/api/scans/import",
                      params={"project": project},
                      json={"content": content, "format": format,
                            "mode": mode, "decisions": decisions or {}})


@tool(writes=True)
async def import_nmap(project: str, xml: str) -> Any:
    """Import an `nmap -oX` report into a project.

    Keeps everything `-sV -O -A` produces: service and version detection, OS
    matches with their accuracy, MAC and vendor, uptime, traceroute, and both
    per-port and host-level NSE script output. An open port whose service
    could not be identified is recorded as UNKNOWN rather than left blank,
    and counted separately in `services_unknown`.

    Upserts: re-importing updates the existing targets and services instead
    of duplicating them, and every change is written to the target timeline.
    """
    return await _req("POST", "/api/scans/nmap",
                      params={"project": project}, json={"xml": xml})


# ------------------------------------------------------------------ timeline
@tool(agent_equivalent="host_timeline")
async def target_timeline(project: str, host: str, kind: str | None = None,
                          limit: int = 100) -> Any:
    """What was found and done to one target, newest first.

    `kind` filters to one of: discovered, note, scan, service, vuln, poc,
    credential, change, status.
    """
    page = await _req("GET", f"/api/targets/{project}/{host}/timeline",
                      params={"kind": kind, "limit": limit})
    return _rows(page, ("at", "kind", "summary", "actor", "source", "detail"), limit)


@tool(agent_equivalent="add_note", writes=True)
async def add_target_note(project: str, host: str, text: str) -> Any:
    """Add a note to a target's timeline.

    The first line becomes the summary; the rest is kept as the detail.
    Only notes can be added this way — scan results, field changes and
    findings are recorded by the code that performs them.
    """
    lines = text.strip().split("\n")
    return await _req("POST", f"/api/targets/{project}/{host}/timeline",
                      json={"kind": "note", "summary": lines[0][:2000],
                            "detail": text.strip() if len(lines) > 1 else None})


# =================================================================== the fleet
# Everything below talks to /api/agents, which the product calls Drone. The
# whole subsystem was invisible over MCP until now: you could not see a
# drone, task one, check a task or enrol one, which is half of what Oddjob
# does.
#
# Two things about this router that will bite a client and are not visible
# in its OpenAPI schema:
#
#   * `?project=` is MANDATORY on nearly every route and is read straight
#     off the request rather than declared as a parameter, so it does not
#     appear in the schema and omitting it is a 422, not a default.
#   * holding no role at all on a project answers 404, not 403. `_req`
#     attaches a note saying so, because "no such project" to an operator
#     looking at the project in their browser is a wrong answer.
#
# Deliberately NOT exposed here: /api/agents/enroll, /register, /retired,
# /heartbeat, /tasks/{id}/start and /tasks/{id}/result. Those authenticate
# with an AGENT credential — an Ed25519 request signature or a drone_ key —
# not with a user API key, and they are the drone's side of the protocol.
# A user key is refused by them anyway, so a tool for them could only ever
# return 401; wrapping them would be offering the model a lever attached to
# nothing.
# ----------------------------------------------------------------------------
@tool(agent_equivalent="list_drone")
async def list_drones(project: str) -> Any:
    """The Drone agents on an engagement, and what each can actually do.

    Read these together, because tasking decisions turn on them:

    * `status` — online, busy, offline or disabled. Derived from the last
      heartbeat, so offline means "has not called home for 90 seconds",
      not "was shut down".
    * `raw_sockets` (the agent's `privileged` flag) — without it masscan
      cannot run and nmap silently falls back to a connect scan, which
      changes what tasking is worth sending rather than failing it.
    * `cannot_run` — task kinds this drone has no tool for, and
      `missing_tools` says why each install failed.
    * `host_platform` and `container` — the machine UNDERNEATH the agent,
      where that differs from the binary's own platform. Both are omitted
      when the drone could not tell; a missing `host_platform` must not be
      read as "linux".
    * `address` and `address_source` — a drone finds its outbound address
      in one of several ways, and a container's private address and a real
      egress address are the same shape. Only `address_source` says which
      one you are looking at, so a question like "what will the client see
      in their logs" cannot be answered from the address alone.
    * `max_parallel`, `work_in_flight`, `running` — how much it is already
      carrying before you add to it.
    """
    rows = await _req("GET", "/api/agents", params={"project": project})
    if _failed(rows):
        return rows
    out = []
    for a in rows:
        rec = {
            "id": a.get("id"), "name": a.get("name"), "status": a.get("status"),
            "platform": a.get("platform"), "arch": a.get("arch"),
            "version": a.get("version"), "hostname": a.get("hostname"),
            "raw_sockets": a.get("privileged"),
            "tools": sorted(a.get("tools") or {}),
            "cannot_run": a.get("cannot_run") or [],
            "missing_tools": a.get("missing_tools") or {},
            "address": a.get("outbound_ip") or a.get("last_ip"),
            "regions": a.get("regions") or [],
            "connection_mode": a.get("connection_mode"),
            "target_os": a.get("target_os"),
            "max_parallel": a.get("max_parallel"),
            "work_in_flight": (a.get("queued_tasks") or 0) + (a.get("running_tasks") or 0),
            "running": a.get("running") or [],
            "completed_tasks": a.get("completed_tasks"),
            "failed_tasks": a.get("failed_tasks"),
            "has_identity": a.get("has_identity"),
            "sealed": a.get("sealed"),
            "enrolled_pending": a.get("enrolled_pending"),
            "last_seen": a.get("last_seen"),
        }
        # Omitted rather than sent as null. A key that is absent reads as
        # "the drone could not tell us"; a key present and null reads to a
        # model as a value it may reason about, and it is not one.
        for k, src in (("host_platform", "host_platform"),
                       ("host_platform_source", "host_platform_source"),
                       ("container", "container"),
                       ("address_source", "outbound_ip_source"),
                       ("address_note", "outbound_ip_note"),
                       ("retired_at", "retired_at"),
                       ("retired_reason", "retired_reason")):
            if a.get(src):
                rec[k] = a[src]
        out.append(rec)
    return {"agents": out, "count": len(out),
            "note": "status is derived from the last heartbeat; offline means "
                    "nothing has been heard for 90 seconds"}


@tool()
async def drone_task_kinds() -> Any:
    """The task kinds a Drone can be given, and which tool each one needs.

    `by_kind` maps a kind to the binary that must be installed for it;
    null means the kind needs no external tool. `required` is the set a
    fully-equipped drone carries. Cross-check against `cannot_run` on a
    specific drone before tasking it.
    """
    return await _req("GET", "/api/agents/tools")


@tool()
async def drone_routing(project: str) -> Any:
    """How this engagement hands pooled work out, and how much is waiting.

    `mode` is mesh (first drone to ask takes it), primary (the highest
    priority eligible drone takes everything) or geo (a task runs only
    where its `region` matches). `unassigned_tasks` is the pool depth.
    """
    return await _req("GET", "/api/agents/routing", params={"project": project})


@tool()
async def drone_queue(project: str, limit: int = 100) -> Any:
    """Work waiting to start, oldest first.

    `agent_id: null` means the task is in the project pool and no drone
    has claimed it. A queue that is not draining with drones online is
    usually a routing mismatch — a geo project with tasks carrying no
    region, or a kind no online drone has the tool for.
    """
    return _bare(await _req("GET", "/api/agents/queue",
                            params={"project": project, "limit": 1000}),
                 ("id", "kind", "subject", "agent_id", "agent_name", "region",
                  "requested_by", "created_at"), limit)


@tool()
async def list_drone_tasks(project: str, limit: int = 100) -> Any:
    """Drone tasks across the whole engagement, newest first.

    Includes pooled tasks no drone ever took. `state` is the readable
    form — awaiting, in progress, complete, failed — and `raw_status` is
    the stored one. `notes` carries why a task failed or why it went back
    in the queue, which is the field worth reading first.
    """
    return _bare(await _req("GET", "/api/agents/tasks",
                            params={"project": project, "limit": 5000}),
                 ("id", "kind", "subject", "state", "raw_status", "agent_id",
                  "agent_name", "attempts", "created_at", "started_at",
                  "finished_at", "notes", "requested_by"), limit)


@tool(agent_equivalent="drone_task_status")
async def drone_task_status(project: str, task_id: int) -> Any:
    """How one Drone task is getting on, and whether its results need a decision.

    Two calls, because the API has no route for a single task: the
    engagement-wide list carries the state and the failure reason, and
    the per-drone list is the only thing that carries `args` and
    `import_result`. A pooled task that no drone ever claimed has no
    per-drone row at all, so the richer half is simply absent and says
    so rather than reporting an empty import.

    `needs_decision` means the scan brought back hosts the project does
    not have, and strict mode held the whole import rather than creating
    them. Nothing is imported until you answer — see import_drone_task.
    """
    rows = await _req("GET", "/api/agents/tasks",
                      params={"project": project, "limit": 5000})
    if _failed(rows):
        return rows
    row = next((t for t in rows if t.get("id") == int(task_id)), None)
    if row is None:
        return {"error": f"no task {task_id} on {project}",
                "note": "the engagement-wide list was searched; a task from "
                        "another project is not visible here even if it exists"}
    out = {k: row.get(k) for k in ("id", "kind", "subject", "state", "raw_status",
                                   "agent_id", "agent_name", "attempts",
                                   "created_at", "started_at", "finished_at",
                                   "notes", "requested_by")}
    if not row.get("agent_id"):
        out["detail_available"] = False
        out["note"] = ("still in the project pool, so there is no per-drone "
                       "record and no import result yet")
        return out
    full = await _req("GET", f"/api/agents/{row['agent_id']}/tasks",
                      params={"project": project, "limit": 500})
    if _failed(full):
        out["detail_available"] = False
        out["detail_error"] = full
        return out
    rich = next((t for t in full if t.get("id") == int(task_id)), None)
    if rich is None:
        # It was requeued to the pool after this drone had it, so the
        # per-drone list no longer carries it. Saying nothing here would
        # read as "no import result", which is a different claim.
        out["detail_available"] = False
        out["note"] = ("this task is no longer attached to the drone that ran "
                       "it — a retry returns a task to the pool — so its args "
                       "and import result could not be read")
        return out
    imp = rich.get("import_result") or {}
    out.update({
        "detail_available": True,
        "args": rich.get("args"),
        "summary": rich.get("summary"),
        "exit_code": rich.get("exit_code"),
        "error": rich.get("error"),
        "import_as": rich.get("import_as"),
        "needs_decision": bool(imp.get("needs_decision")),
        "unknown_hosts": [u.get("host") for u in imp.get("unknown_hosts", [])],
        "import_result": imp or None,
    })
    return out


@tool(agent_equivalent="task_drone", writes=True)
async def task_drone(project: str, kind: str, targets: str,
                     agent_id: int | None = None, ports: str | None = None,
                     region: str | None = None) -> Any:
    """Queue ONE scan, on a named Drone or on the project's pool.

    `kind` is one of drone_task_kinds — nmap, masscan, amass, gobuster,
    gospider, nuclei, httpx, nslookup, reverse_ip. `targets` is hosts or
    ranges, space or comma separated.

    Leave `agent_id` out to queue to the pool and let the project's
    routing choose; a geo-routed project then needs a `region`. Results
    import automatically when the drone reports back.

    The project's scope gate is applied ALL-OR-NOTHING here: one target
    outside scope refuses the whole task with a 403 or 422. That is
    deliberate, and it is why enumerate_drones exists — a sweep wants one
    task per host so a single refusal stays a single refusal.

    `install` and `shell` are refused by this tool. Installing software
    on, or running arbitrary commands on, a privileged process inside a
    client's network is not something to do because a sentence asked for
    it; queue those from the Drone page where the allowlist and the drone
    are both in front of you.
    """
    k = (kind or "").strip().lower()
    if k in ("install", "shell"):
        return {"error": f"{k} is not available through MCP. Queue it from the "
                         f"Drone page, where the allowlist and the agent are "
                         f"both in front of you."}
    hosts = [t for t in (targets or "").replace(",", " ").split() if t]
    if not hosts:
        return {"error": "no targets given"}
    args: dict[str, Any] = {"targets": hosts}
    if (ports or "").strip():
        args["ports"] = ports.strip()
    body = {"kind": k, "args": args, "region": (region or "").strip().lower() or None}
    path = (f"/api/agents/{agent_id}/tasks" if agent_id is not None
            else "/api/agents/tasks")
    return await _req("POST", path, params={"project": project}, json=body)


@tool(agent_equivalent="enumerate_drones", writes=True)
async def enumerate_drones(project: str, kind: str, hosts: str,
                           agent_id: int | None = None,
                           ports: str | None = None,
                           region: str | None = None) -> Any:
    """Queue a SWEEP — one task per host — across many hosts at once.

    One task per host, so the fleet shares the work, one failure stays
    one failure, and the queue depth means "how many hosts are left".

    Scope is checked PER HOST here rather than all-or-nothing: a refused
    host comes back in `refused_by_scope` with its reason and the rest of
    the batch still queues. Read that map — "I queued 1,700 of your
    1,738" is the fact an operator needs in order to notice that
    thirty-eight assets are covered by nothing at all.

    Unlike the in-platform agent's version of this tool, there is no
    `select` and no preview. Selection means reading the project's own
    inventory and deciding which hosts qualify, and that reading is a
    separate query an MCP caller makes for itself — list_targets,
    find_by_technology or list_ports — which also means the list is in
    front of you before you commit to it, rather than summarised by a
    preview. Compose the host list, look at it, then call this.
    """
    k = (kind or "").strip().lower()
    if k in ("install", "shell"):
        return {"error": f"{k} is never queued as a sweep. It belongs on the "
                         f"Drone page, where the allowlist and the agent are "
                         f"both in front of you."}
    subjects = [h for h in (hosts or "").replace(",", " ").split() if h]
    if not subjects:
        return {"error": "no hosts given"}
    args: dict[str, Any] = {}
    if (ports or "").strip():
        args["ports"] = ports.strip()
    return await _req("POST", "/api/agents/tasks/bulk",
                      params={"project": project},
                      json={"kind": k, "subjects": subjects, "args": args,
                            "agent_id": agent_id,
                            "region": (region or "").strip().lower() or None})


@tool(writes=True)
async def retry_drone_task(project: str, task_id: int) -> Any:
    """Put a FAILED Drone task back in the queue.

    Only a failed task can be restarted; anything else answers 409. The
    task returns to the POOL even if it was addressed to one drone, so
    routing picks again — which is usually what you want when the drone
    that failed it is the reason it failed.
    """
    return await _req("POST", f"/api/agents/tasks/{task_id}/retry",
                      params={"project": project})


@tool(writes=True, destructive=True)
async def cancel_drone_task(project: str, task_id: int) -> Any:
    """Delete a QUEUED Drone task that has not started.

    Refused with a 409 once the task is running, and rightly: deleting
    the row here would not stop the scan — it is already executing on the
    drone — and would only throw away the result when it reports. Killing
    the drone is what stops work that has started.
    """
    return await _req("DELETE", f"/api/agents/tasks/{task_id}",
                      params={"project": project})


@tool(writes=True)
async def import_drone_task(project: str, agent_id: int, task_id: int,
                            decisions: dict | None = None,
                            mode: str = "strict") -> Any:
    """Import a finished Drone task's output, answering any held decisions.

    A scan that came back with hosts the project does not have is held
    rather than imported, because a drone pointed slightly wide creates
    targets belonging to someone else. drone_task_status reports those
    under `unknown_hosts`.

    `decisions` maps host -> {"action": "add"|"map"|"reject", "target":
    "existing.host"}. A host you leave out is REJECTED, not created. The
    task's output is not consumed, so you may run this again with
    different decisions.
    """
    return await _req("POST", f"/api/agents/{agent_id}/tasks/{task_id}/import",
                      params={"project": project},
                      json={"decisions": decisions or {}, "mode": mode})


@tool(agent_equivalent="enroll_drone", writes=True)
async def enroll_drone(project: str, name: str, target_os: str = "linux",
                       connection_mode: str = "callback") -> Any:
    """Create a Drone agent and return the one-time command to run on the host.

    ADMIN on the project. Enrolling creates something that will run
    privileged commands on a machine inside a client's network and send
    their output here, which is an admin's decision rather than a
    contributor's.

    `callback` means the drone dials out to Oddjob and needs no inbound
    reachability; `call_in` means Oddjob calls it, and it must advertise
    a reachable address.

    EVERY SECRET IN THE RESPONSE IS SHOWN ONCE. `enroll_token` is good
    for two hours and is traded by the drone for a keypair it generates
    itself, after which it will only take tasking from this Oddjob.
    `callback_key` and `call_in_key` cannot be read back. Losing them
    means re-enrolling, which invalidates the running drone immediately.

    The name you pass gets a short random suffix, so the agent created is
    not the name you asked for — read it back from the response.
    """
    return await _req("POST", "/api/agents", params={"project": project},
                      json={"name": name, "target_os": target_os,
                            "connection_mode": connection_mode})


@tool(writes=True, destructive=True)
async def kill_drone(project: str, agent_id: int) -> Any:
    """Disable a Drone and fail everything it was carrying. Admin on the project.

    Its credential is refused from this moment, so a scan that was
    running could not report a result even if it finished. Queued work is
    marked cancelled and in-flight work is marked failed with that said
    plainly in the error — the drone is not asked politely to stop, it is
    locked out.

    This does not delete the agent or its task history.
    """
    return await _req("POST", f"/api/agents/{agent_id}/kill",
                      params={"project": project})


# ================================================================ domain names
@tool()
async def domain_roots(project: str) -> Any:
    """The registrable domains this engagement touches, with host counts.

    Collected from two places and `source` says which: `targets` means
    the zone was derived from hosts already recorded, `scope` means it
    was typed into the scope list and may have no hosts under it yet.

    `known_hosts` counts TARGETS only, so a scope-only root reads 0 —
    that is a zone nobody has enumerated, which is the interesting case
    rather than an empty one. Ignore `searched`; it is vestigial and
    always false.
    """
    return _bare(await _req("GET", "/api/domains/roots",
                            params={"project": project}),
                 ("domain", "known_hosts", "source"), 500)


@tool(writes=True)
async def enumerate_domains(project: str, domains: str = "",
                            kitchen_sink: bool = False,
                            mode: str = "passive",
                            rescan: bool = False) -> Any:
    """Queue subdomain enumeration (amass), by name or across the whole estate.

    KITCHEN SINK LOOKUP is `kitchen_sink=true`: instead of naming zones,
    it walks every host the project knows back up through its parents to
    its registrable domain — `a.b.c.acme.example` yields `b.c.acme.example`,
    `c.acme.example` and `acme.example` — and queues each one. The point is
    that an estate's zones are not the ones anybody typed in; they are the
    ones its hosts imply, and those are the zones with forgotten names in
    them.

    Each generated parent is re-checked against the scope gate on its own.
    Scope does NOT flow upwards: being allowed to touch `www.acme.example`
    says nothing about `acme.example`, and a parent that scope refuses
    comes back in `refused` rather than being queued.

    `mode` is passive or active. Zones already enumerated are skipped and
    listed in `skipped` with when they last ran, unless `rescan=true`.
    At most 200 tasks are queued in one call; the rest come back in
    `deferred`.

    Needs at least one drone ONLINE — enumeration is drone work, and the
    call is refused with a 409 rather than queueing into a fleet that
    cannot run it.
    """
    return await _req("POST", "/api/domains/enumerate",
                      params={"project": project},
                      json={"domains": domains, "mode": mode,
                            "kitchen_sink": kitchen_sink, "rescan": rescan})


@tool()
async def domain_candidates(project: str, state: str | None = None,
                            root: str | None = None, limit: int = 200) -> Any:
    """Names enumeration found that are not targets yet, best first.

    `state` filters to new, accepted, rejected or exists. `score` and
    `reason` are why the name is thought to be worth something. Nothing
    here has been added to the engagement — promote_domain_candidates
    does that, and the scope gate still has the last say when it does.
    """
    return _bare(await _req("GET", "/api/domains/candidates",
                            params={"project": project, "state": state,
                                    "root": root}),
                 ("id", "name", "root_domain", "source", "score", "reason",
                  "state", "times_seen", "created_at"), limit)


@tool(writes=True)
async def promote_domain_candidates(project: str, ids: list[int]) -> Any:
    """Turn discovered names into targets. Needs `user` on the project.

    Each is checked against the project's scope gate individually.
    Refused names come back in `out_of_scope` with the reason and are
    LEFT IN THEIR PREVIOUS STATE rather than marked rejected — a scope
    refusal is a fact about the scope, not a decision about the name, and
    recording it as a decision would hide the name once the scope widens.

    Pass ids from domain_candidates.
    """
    return await _req("POST", "/api/domains/candidates/promote",
                      params={"project": project}, json={"ids": ids})


@tool(writes=True)
async def reject_domain_candidates(project: str, ids: list[int]) -> Any:
    """Mark discovered names as not worth adding. Needs `user` on the project."""
    return await _req("POST", "/api/domains/candidates/reject",
                      params={"project": project}, json={"ids": ids})


# ---------------------------------------------------------------------------
# RESERVED, and deliberately not implemented here.
#
# Lookup results — GET /api/enumerate/pending and POST /api/enumerate/resolve
# — are being reworked right now so that most results resolve
# deterministically, and another agent is adding the in-platform tools for
# them. Two tools will slot in beside the domain ones above when that lands:
# roughly `pending_lookups(project)` over the first and
# `resolve_lookups(project, decisions)` over the second.
#
# They are not stubbed, because a stub is a tool the model can call. When
# the agent's versions land, tests/mcptest.py will FAIL — an agent tool with
# no MCP equivalent and no AGENT_ONLY entry is exactly what it is built to
# catch. That failure is the handover, and pre-waiving it here would be
# switching off the alarm in advance.
# ---------------------------------------------------------------------------


# ========================================================== counts and health
@tool(agent_equivalent="project_overview")
async def stats(project: str | None = None) -> Any:
    """Counts across everything you can see, or one project."""
    return await _req("GET", "/api/stats",
                      params={"project": project} if project else None)


@tool()
async def explore(dimension: str, value: str, project: str | None = None,
                  protocol: str | None = None) -> Any:
    """Everything about one port or one service name, across the whole estate.

    `dimension` is "port" or "service"; `value` is the number or the
    name. Answers "what does 443 actually look like here" in one call:
    how many services and hosts, the open/closed breakdown, which
    products and banners appear behind it, findings on the same
    host/port pairs, and a worst-first host list.
    """
    return await _req("GET", "/api/explore",
                      params={"dimension": dimension, "value": value,
                              "project": project, "protocol": protocol})


@tool()
async def whoami() -> Any:
    """The account this key belongs to, and your role on each project."""
    return await _req("GET", "/api/auth/me")


@tool()
async def site_health() -> Any:
    """Deployment health: database, feeds, Slack, SMTP, the drone fleet, audit.

    SITE ADMIN ONLY — an ordinary key gets a 403, which is the correct
    answer and not a fault.

    Returned verbatim rather than field-filtered. This is the one place
    where "what version is the server, and is the fleet on the same one"
    will be answered, and that aggregation is being added right now; a
    filter written today would silently drop it the day it lands. The
    cost is a wordier result, and it is worth paying here because the
    shape of this response is the thing most likely to change.
    """
    return await _req("GET", "/api/health/site")


# =================================================================== exploits
@tool(agent_equivalent="search_exploits")
async def search_exploits(query: str, limit: int = 25) -> Any:
    """searchsploit, against Oddjob's local Exploit-DB copy.

    Matched locally. Nothing about the engagement leaves the deployment
    to answer this — which is the point, because asking a third party
    "anything for Apache 2.4.49?" on behalf of a host tells them the
    client runs it.
    """
    return await _req("GET", "/api/vulnfeeds/search",
                      params={"q": query, "limit": limit})


@tool()
async def service_leads(product: str = "", version: str = "",
                        name: str = "", banner: str = "",
                        limit: int = 25) -> Any:
    """Public exploits and CVEs that might apply to one piece of software.

    Takes the SOFTWARE, never a host — that is the boundary, and it is
    why there is no host parameter to pass one through.

    Read `version_match` on every CVE before believing it: `exact` means
    a CPE names this version, `product only` means the CPE covers every
    version and is not evidence about yours, and `unknown` means NVD has
    not analysed it yet. Leads, not findings.
    """
    return await _req("GET", "/api/vulnfeeds/leads",
                      params={"product": product, "version": version,
                              "name": name, "banner": banner,
                              "limit": limit})


@tool(agent_equivalent="exploit_leads")
async def exploit_leads(project: str, host: str, limit: int = 15) -> Any:
    """Public exploits and CVEs that might apply to everything ONE HOST runs.

    service_leads takes software and keeps the host out of it on
    purpose. This tool is the other shape of the same question, and it
    keeps the boundary in a different place: the host is resolved to its
    recorded services HERE, and only the product and version of each are
    then looked up. Nothing about the target is sent anywhere either way
    — the match is against a local copy of Exploit-DB and NVD.

    A host with no recorded ports returns nothing, and that is a gap in
    what has been scanned rather than an absence of exposure. Said in the
    result, because the two read identically otherwise.

    Leads, not findings. A patched host reports the same version as an
    unpatched one, banners are frequently wrong, and CPE version matching
    is approximate.
    """
    svc = await _req("GET", "/api/services",
                     params={"project": project, "host": host, "limit": 1000})
    if _failed(svc):
        return svc
    feeds = await _req("GET", "/api/vulnfeeds/status")
    items = svc.get("items", [])
    if not items:
        return {"host": host, "services": [], "feeds": feeds,
                "note": "no ports recorded for this host, so there is nothing "
                        "to match on. That is a gap in what has been scanned, "
                        "not an absence of exposure."}
    per = []
    for s in items:
        r = await _req("GET", "/api/vulnfeeds/leads",
                       params={"product": s.get("product") or "",
                               "version": s.get("version") or "",
                               "name": s.get("name") or "",
                               "banner": s.get("banner") or "",
                               "limit": limit})
        if _failed(r):
            per.append({"port": s.get("port"), "protocol": s.get("protocol"),
                        "product": s.get("product"), "version": s.get("version"),
                        "lookup_failed": r})
            continue
        per.append({"port": s.get("port"), "protocol": s.get("protocol"),
                    "product": s.get("product"), "version": s.get("version"),
                    "cves": r.get("cves"), "exploits": r.get("exploits"),
                    "searched_for": r.get("terms")})
    return {"host": host, "services": per, "feeds": feeds,
            "caveat": "Leads, not findings. Confirming any of this against the "
                      "target is the engagement, not this list."}


@tool()
async def get_cve(cve_id: str) -> Any:
    """One CVE: score, vector, summary, and any local exploits citing it."""
    return await _req("GET", f"/api/vulnfeeds/cve/{cve_id}")


@tool()
async def feed_status() -> Any:
    """How current the exploit and CVE data is.

    Worth reading before trusting an empty result. "No known exploits"
    from a feed synced this morning and from one that has never run are
    different claims, and only this says which you are looking at.
    """
    return await _req("GET", "/api/vulnfeeds/status")


if __name__ == "__main__":
    mcp.run(transport="stdio")
