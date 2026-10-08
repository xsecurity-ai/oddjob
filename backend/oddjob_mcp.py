#!/usr/bin/env python3
"""MCP server for Oddjob — lets an MCP client read and write engagement data.

Run it over stdio (what Claude Code and Claude Desktop expect):

    ODDJOB_API_KEY=msk_... uv run python oddjob_mcp.py

Register it with Claude Code:

    claude mcp add oddjob --env ODDJOB_API_KEY=msk_... -- \
        uv --directory /Users/brandon/Desktop/oddjob/backend run python oddjob_mcp.py

It is a THIN CLIENT over the HTTP API, not a second path into the database.
That matters for authorisation: every call carries the API key, so the server
applies exactly the same per-project ACL it applies to the browser. An MCP
server talking straight to SQLite would silently bypass the whole ACL model.

Mint a key in the UI, or:
    curl -X POST 'http://127.0.0.1:8000/api/auth/keys?name=mcp' \
         -H "Authorization: Bearer <jwt>"
"""
from __future__ import annotations

import os
from typing import Any

import httpx

# mcp 2.x renamed FastMCP -> MCPServer; the decorator API is otherwise the same.
from mcp.server.mcpserver import MCPServer

BASE = os.environ.get("ODDJOB_URL", "http://127.0.0.1:8000").rstrip("/")
KEY = os.environ.get("ODDJOB_API_KEY", "")

mcp = MCPServer("oddjob",
                instructions="Engagement data store: projects, targets, "
                             "ports/services, vulns and PoCs. All access is "
                             "scoped by the API key's per-project ACL.")


async def _req(method: str, path: str, *, params: dict | None = None,
               json: Any | None = None) -> Any:
    if not KEY:
        return {"error": "ODDJOB_API_KEY is not set; mint one at POST /api/auth/keys"}
    async with httpx.AsyncClient(base_url=BASE, timeout=120) as c:
        r = await c.request(method, path, params=params, json=json,
                            headers={"Authorization": f"Bearer {KEY}"})
    if r.status_code >= 400:
        # Hand the server's own message back. "403 user required on FALCON-1;
        # you have readonly" is actionable; "HTTP 403" is not.
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text[:400]
        return {"error": f"HTTP {r.status_code}", "detail": detail}
    return r.json() if r.content else {"ok": True}


def _rows(page: Any, fields: tuple[str, ...], limit: int) -> Any:
    """Trim list responses to the fields that matter.

    A raw dump of 1,600 targets with every column is tens of thousands of
    tokens and mostly nulls; the model asked for an inventory, not a database
    export. `total` is always reported so truncation is never silent.
    """
    if isinstance(page, dict) and "error" in page:
        return page
    items = page.get("items", [])
    return {
        "total": page.get("total", len(items)),
        "returned": min(len(items), limit),
        "truncated": len(items) > limit,
        "items": [{k: r.get(k) for k in fields} for r in items[:limit]],
    }


# ------------------------------------------------------------- projects
@mcp.tool()
async def list_projects() -> Any:
    """List engagements you have access to, with target/vuln counts."""
    return _rows(await _req("GET", "/api/projects"),
                 ("code", "name", "client", "status", "total_targets",
                  "total_services", "total_vulns", "total_pocs"), 200)


@mcp.tool()
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


# -------------------------------------------------------------- targets
@mcp.tool()
async def list_targets(project: str | None = None, search: str | None = None,
                       hacked: bool | None = None, alive: bool | None = None,
                       limit: int = 100) -> Any:
    """Targets, newest counts included. `search` matches any column."""
    params = {"limit": 10000}
    for k, v in (("project", project), ("q", search),
                 ("hacked", hacked), ("alive", alive)):
        if v is not None:
            params[k] = v
    return _rows(await _req("GET", "/api/targets", params=params),
                 ("host", "ip_address", "project_code", "alive", "hacked",
                  "total_vulns", "total_criticals", "total_highs",
                  "total_pocs", "total_ports"), limit)


@mcp.tool()
async def get_target(project: str, host: str) -> Any:
    """Everything known about one target: detail, ports, services, vulns, PoCs."""
    detail = await _req("GET", f"/api/targets/{project}/{host}")
    if isinstance(detail, dict) and "error" in detail:
        return detail
    svc = await _req("GET", "/api/services",
                     params={"project": project, "host": host, "limit": 1000})
    vul = await _req("GET", "/api/vulns",
                     params={"project": project, "host": host, "limit": 1000})
    poc = await _req("GET", "/api/pocs",
                     params={"project": project, "host": host, "limit": 1000})
    return {
        "target": detail,
        # product and version are carried deliberately: they are what
        # service_leads matches on, and without them the obvious next
        # question — "is anything known about what this is running?" —
        # needs another round trip to find out what it is running.
        "services": [{k: s.get(k) for k in ("port", "protocol", "state",
                                            "name", "product", "version",
                                            "banner")}
                     for s in svc.get("items", [])],
        "vulns": [{k: v.get(k) for k in ("title", "severity", "status", "port", "external_id")}
                  for v in vul.get("items", [])],
        "pocs": [{k: p.get(k) for k in ("title", "status", "exit_code", "path")}
                 for p in poc.get("items", [])],
    }


@mcp.tool()
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


# ------------------------------------------------------- ports/services
@mcp.tool()
async def list_ports(project: str | None = None, host: str | None = None,
                     search: str | None = None, limit: int = 200) -> Any:
    """Open ports only."""
    params = {"limit": 20000}
    for k, v in (("project", project), ("host", host), ("q", search)):
        if v is not None:
            params[k] = v
    return _rows(await _req("GET", "/api/ports", params=params),
                 ("host", "port", "protocol", "banner", "project_code"), limit)


@mcp.tool()
async def list_services(project: str | None = None, host: str | None = None,
                        search: str | None = None, limit: int = 200) -> Any:
    """Services in any state (open, closed, filtered)."""
    params = {"limit": 20000}
    for k, v in (("project", project), ("host", host), ("q", search)):
        if v is not None:
            params[k] = v
    return _rows(await _req("GET", "/api/services", params=params),
                 ("host", "name", "port", "protocol", "state", "banner",
                  "project_code"), limit)


@mcp.tool()
async def list_vulns(project: str | None = None, host: str | None = None,
                     severity: str | None = None, search: str | None = None,
                     limit: int = 100) -> Any:
    """Vulnerabilities. `severity` is critical|high|medium|low|info."""
    params = {"limit": 20000}
    for k, v in (("project", project), ("host", host),
                 ("severity", severity), ("q", search)):
        if v is not None:
            params[k] = v
    return _rows(await _req("GET", "/api/vulns", params=params),
                 ("host", "title", "severity", "status", "port", "external_id"), limit)


# ----------------------------------------------------------------- bulk
@mcp.tool()
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


@mcp.tool()
async def import_formats() -> Any:
    """Which scanner and C2 formats `import_report` accepts."""
    return await _req("GET", "/api/scans/formats")


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
async def target_timeline(project: str, host: str, kind: str | None = None,
                          limit: int = 100) -> Any:
    """What was found and done to one target, newest first.

    `kind` filters to one of: discovered, note, scan, service, vuln, poc,
    credential, change, status.
    """
    page = await _req("GET", f"/api/targets/{project}/{host}/timeline",
                      params={"kind": kind, "limit": limit})
    return _rows(page, ("at", "kind", "summary", "actor", "source", "detail"), limit)


@mcp.tool()
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


@mcp.tool()
async def stats(project: str | None = None) -> Any:
    """Counts across everything you can see, or one project."""
    return await _req("GET", "/api/stats",
                      params={"project": project} if project else None)


@mcp.tool()
async def whoami() -> Any:
    """The account this key belongs to, and your role on each project."""
    return await _req("GET", "/api/auth/me")


@mcp.tool()
async def search_exploits(query: str, limit: int = 25) -> Any:
    """searchsploit, against Oddjob's local Exploit-DB copy.

    Matched locally. Nothing about the engagement leaves the deployment
    to answer this — which is the point, because asking a third party
    "anything for Apache 2.4.49?" on behalf of a host tells them the
    client runs it.
    """
    return await _req("GET", "/api/vulnfeeds/search",
                      params={"q": query, "limit": limit})


@mcp.tool()
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


@mcp.tool()
async def get_cve(cve_id: str) -> Any:
    """One CVE: score, vector, summary, and any local exploits citing it."""
    return await _req("GET", f"/api/vulnfeeds/cve/{cve_id}")


@mcp.tool()
async def feed_status() -> Any:
    """How current the exploit and CVE data is.

    Worth reading before trusting an empty result. "No known exploits"
    from a feed synced this morning and from one that has never run are
    different claims, and only this says which you are looking at.
    """
    return await _req("GET", "/api/vulnfeeds/status")


if __name__ == "__main__":
    mcp.run(transport="stdio")
