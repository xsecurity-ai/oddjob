"""The MCP server, and the thing that keeps it from drifting again.

Oddjob has two tool surfaces. `app/agent/tools.py` runs in-process against
an AsyncSession with the project fixed by the caller; `oddjob_mcp.py` runs
out-of-process and calls the HTTP API with an API key. They cannot share
an implementation — different transport, different auth — and for a while
nothing at all held them together except somebody noticing.

Nobody noticed. Eighteen of the agent's twenty-two tools ended up with no
MCP equivalent, including every single Ghost tool, which is to say that
half the product was invisible to an MCP client while the README said it
was not.

So the first half of this suite is the alignment check, and it is the
reason the file exists. It calls `build()` with a null session to list the
agent's tools, reads `oddjob_mcp.MANIFEST` for ours, and fails if the two
have come apart in either direction:

  * an agent tool nobody covered and nobody waived
  * an `agent_equivalent` pointing at a tool that has been renamed away
  * an `AGENT_ONLY` waiver for a tool that no longer exists
  * a README table that no longer lists what the server exposes

**A failure here is the mechanism working.** When the lookup-results tools
land in the agent, this suite goes red, and that is the handover notice.
Add the MCP tool or add a waiver with a reason. Do not delete the check.

The second half drives the tools against a live server, because a manifest
that lines up perfectly and 404s on every call is worth nothing. The Ghost
tools get the most attention: they are the new ones, and the fleet routes
are the ones whose `?project=` requirement does not appear in the OpenAPI
schema, so a wrong path there fails at runtime and nowhere earlier.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import asyncio
import inspect
import json
import os
import re
import urllib.error
import urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
ROOT = _pathlib.Path(__file__).resolve().parents[2]
ok = fail = 0


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


# =====================================================================
# Part 1 — the alignment check. No server needed for any of this.
# =====================================================================
print("\n--- the two tool surfaces agree ---")

from app.agent.tools import build  # noqa: E402

# `build` is a plain function that defines closures and returns a list of
# Tool records. Every database access is inside those closures and none of
# them is called here, so a null session is enough to enumerate the names.
# That is what makes this check possible without a hook in tools.py — and
# it is why the check does not need to touch that file, which two other
# agents are editing.
AGENT = {t.name: t for t in build(None, None, None, allow_writes=True,
                                  scope_ids=None, role="admin")}
AGENT_READS = {t.name for t in build(None, None, None, allow_writes=False,
                                     scope_ids=None, role="admin")}
check("agent surface enumerated without a database", len(AGENT) >= 20,
      f"{len(AGENT)} tools")
check("the write tools are not offered when writes are off",
      set(AGENT) > AGENT_READS, f"{len(AGENT_READS)} of {len(AGENT)}")

# The MCP module reads its config at call time, so importing it needs no
# key. Set one anyway: an unset key makes every _req return an error
# envelope instead of calling, and a test that passed on that would be
# asserting nothing.
os.environ["ODDJOB_URL"] = BASE
import oddjob_mcp as M  # noqa: E402

MANIFEST = M.MANIFEST
claimed = {r.agent_equivalent: r.name for r in MANIFEST.values() if r.agent_equivalent}

uncovered = sorted(set(AGENT) - set(claimed) - set(M.AGENT_ONLY))
check("every agent tool is covered by MCP or waived with a reason",
      not uncovered,
      "uncovered: " + ", ".join(uncovered) if uncovered else
      f"{len(claimed)} covered, {len(M.AGENT_ONLY)} waived")

dangling = sorted(set(claimed) - set(AGENT))
check("no agent_equivalent names a tool that does not exist",
      not dangling, "dangling: " + ", ".join(dangling) if dangling else "")

stale = sorted(set(M.AGENT_ONLY) - set(AGENT))
check("no AGENT_ONLY waiver is stale",
      not stale, "stale: " + ", ".join(stale) if stale else "")

check("every waiver gives a reason worth reading",
      all(len(v) > 80 for v in M.AGENT_ONLY.values()),
      f"{len(M.AGENT_ONLY)} waiver(s)")

# Two MCP tools claiming the same agent tool means one of them is wrong
# about what it does, and the coverage count above would still be green.
eq = [r.agent_equivalent for r in MANIFEST.values() if r.agent_equivalent]
check("no two MCP tools claim the same agent tool", len(eq) == len(set(eq)))

print("\n--- the manifest describes what is actually registered ---")
registered = {t.name: t for t in asyncio.run(M.mcp.list_tools())}
check("manifest and MCP registry hold the same names",
      set(registered) == set(MANIFEST),
      f"{len(registered)} registered / {len(MANIFEST)} in manifest")
check("every tool has a description the model can act on",
      all(len(t.description or "") > 30 for t in registered.values()))
check("declared params match the registered schemas",
      all(set(MANIFEST[n].required) ==
          set(t.input_schema.get("required", []))
          for n, t in registered.items()))
check("read-only tools are annotated read-only",
      all(bool(registered[n].annotations.read_only_hint) is not r.writes
          for n, r in MANIFEST.items()))
check("every tool is a coroutine function",
      all(inspect.iscoroutinefunction(r.fn) for r in MANIFEST.values()))

print("\n--- the Ghost subsystem is reachable over MCP ---")
# The specific regression: this whole group was missing. Named one by one
# rather than counted, so deleting one fails here instead of quietly
# lowering a total.
for n in ("list_ghosts", "enroll_ghost", "task_ghost", "enumerate_ghosts",
          "ghost_task_status", "list_ghost_tasks", "ghost_queue",
          "ghost_routing", "ghost_task_kinds", "retry_ghost_task",
          "cancel_ghost_task", "import_ghost_task", "kill_ghost"):
    check(f"ghost tool present: {n}", n in MANIFEST)

print("\n--- work merged recently is represented ---")
for n, why in (("enumerate_domains", "Kitchen Sink Lookup"),
               ("domain_roots", "registrable domains"),
               ("domain_candidates", "discovered names"),
               ("list_scope", "scope entries"),
               ("add_scope", "scope entries"),
               ("site_health", "server and fleet health")):
    check(f"{why}: {n}", n in MANIFEST)

src = _pathlib.Path(M.__file__).read_text()
check("Kitchen Sink is described, not just wired",
      "kitchen_sink" in inspect.getdoc(M.enumerate_domains).lower())
check("scope entries expose include_subdomains",
      "include_subdomains" in inspect.signature(M.add_scope).parameters)
check("ghost host identity is surfaced",
      all(k in src for k in ("host_platform", "container", "outbound_ip_source")))
check("site_health is not field-filtered, so a new version key survives",
      "_req(\"GET\", \"/api/health/site\")" in src)

print("\n--- the ghost's own protocol routes are not offered ---")
# These authenticate with an agent credential, not a user API key. A tool
# for one could only ever return 401, and offering the model a lever
# attached to nothing is worse than offering nothing.
# Matched against the paths actually handed to `_req`, not against the
# file text: the file NAMES these routes in a comment explaining why they
# are absent, and a grep over the source would read that explanation as
# the very thing it is explaining.
requested = set(re.findall(r'_req\(\s*"[A-Z]+",\s*f?"([^"]+)"', src))
for p in ("/api/ghosts/register", "/api/ghosts/heartbeat",
          "/api/ghosts/retired", "/api/ghosts/enroll",
          "/api/ghosts/enrol"):
    check(f"not wrapped: {p}", p not in requested)
check("no ghost-protocol task route is wrapped",
      not any(x.endswith(("/result", "/start")) for x in requested), requested)

print("\n--- the README says what the server actually does ---")
readme = (ROOT / "README.md").read_text()
sec = readme.split("## Driving it from outside: the MCP server", 1)
check("README has an MCP section", len(sec) == 2)
if len(sec) == 2:
    body = sec[1].split("\n## ", 1)[0]
    listed = set(re.findall(r"`([a-z][a-z0-9_]+)`", body))
    missing = sorted(set(MANIFEST) - listed)
    check("README lists every tool the server exposes", not missing,
          "missing: " + ", ".join(missing) if missing else f"{len(MANIFEST)} tools")
    # The other direction: a tool deleted from the code must not linger in
    # the table as something a reader will go looking for.
    phantom = sorted(n for n in listed
                     if n not in MANIFEST and n in AGENT and n not in M.AGENT_ONLY)
    check("README lists no tool that does not exist", not phantom,
          "phantom: " + ", ".join(phantom) if phantom else "")
    check("README names the real API key prefix",
          "msk_" in body and "ojk_" not in body)


# =====================================================================
# Part 2 — the tools against a live server.
# =====================================================================
print("\n--- standing up a server and a key ---")
admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
st, key = call("/api/auth/keys?name=mcp", "POST", token=admin)
check("minted an API key", st == 201 and key.get("key", "").startswith("msk_"))
os.environ["ODDJOB_API_KEY"] = key["key"]

call("/api/projects", "POST",
     {"code": "MCPT", "name": "MCP test", "client": "ACME",
      "scope": ["acme.example", "198.51.100.0/24"]}, token=admin)


def run(coro):
    return asyncio.run(coro)


print("\n--- the key is the boundary, and _req reports the server's own words ---")
who = run(M.whoami())
check("whoami reaches the API as the key's owner",
      who.get("user", {}).get("username") == "root", who)
check("...and reports the role the key holds on each project",
      who.get("projects") == {"MCPT": "admin"}, who.get("projects"))
nope = run(M.list_scope("NOSUCH"))
check("an unreachable project returns the server's message",
      nope.get("error", "").startswith("HTTP 404"), nope)
check("...and explains that 404 can mean 'no role', not 'no project'",
      "no role" in nope.get("note", ""), nope.get("note"))

print("\n--- targets, findings and the one-round-trip detail ---")
check("add_target", run(M.add_target("MCPT", "web.acme.example",
                                     ip_address="198.51.100.10")).get("host")
      == "web.acme.example")
refused = run(M.add_target("MCPT", "web.corp.com"))
check("the scope gate still has the last say over MCP",
      "error" in refused, refused.get("detail"))

run(M.bulk_import("MCPT", services=[
    {"host": "web.acme.example", "port": 443, "protocol": "tcp", "state": "open",
     "name": "https", "product": "nginx", "version": "1.18.0"},
    {"host": "web.acme.example", "port": 22, "protocol": "tcp", "state": "open",
     "name": "ssh", "product": "OpenSSH", "version": "8.9"},
]))
check("add_finding",
      run(M.add_finding("MCPT", "web.acme.example", "Directory listing",
                        severity="low")).get("title") == "Directory listing")
v = run(M.list_vulns(project="MCPT"))
check("list_vulns sees it", v["total"] == 1, v)

g = run(M.get_target("MCPT", "web.acme.example"))
check("get_target returns the target", g.get("target", {}).get("host") == "web.acme.example")
check("get_target carries services with product and version",
      any(s["product"] == "nginx" and s["version"] == "1.18.0" for s in g["services"]))
check("get_target carries findings", len(g["vulns"]) == 1)
# The four-call version had no implants in it at all, because nobody
# adding C2 tracking came back to add a fifth call. /detail has them.
check("get_target carries implants (the key the old version dropped)",
      "implants" in g, sorted(g))

print("\n--- counting happens here, not in the model's context ---")
ps = run(M.port_summary(project="MCPT"))
check("port_summary counts over every row", ps["counted_services"] == 2, ps)
check("port_summary ranks correctly", {p["port"] for p in ps["ports"]} == {443, 22}, ps)
check("port_summary does not claim to be complete when it is not",
      "incomplete" not in ps)
check("port_summary filters by protocol",
      run(M.port_summary(project="MCPT", protocol="udp"))["ports"] == [])

print("\n--- web addresses ---")
tid_web = call("/api/targets/MCPT/web.acme.example", token=admin)[1]["id"]
for u, ttl, code in (("https://web.acme.example/", "ACME — WordPress", 200),
                     ("https://web.acme.example/admin", "Login", 401)):
    call("/api/web", "POST", {"target_id": tid_web, "url": u, "method": "GET",
                              "title": ttl, "status_code": code}, token=admin)
# The same URL probed a second way: one captured exchange each, which is
# the distinction list_web_addresses and list_web_urls exist to keep.
call("/api/web", "POST", {"target_id": tid_web, "url": "https://web.acme.example/admin",
                          "method": "POST", "title": "Login", "status_code": 403},
     token=admin)
wa = run(M.list_web_addresses(project="MCPT"))
check("list_web_addresses returns one row per captured exchange",
      wa["total"] == 3, wa)
check("...carrying the method and status that distinguish them",
      {(i["method"], i["status_code"]) for i in wa["items"]}
      == {("GET", 200), ("GET", 401), ("POST", 403)}, wa["items"])
check("list_web_addresses filters by status",
      run(M.list_web_addresses(project="MCPT", status_code=401))["total"] == 1)
wu = run(M.list_web_urls(project="MCPT"))
check("list_web_urls collapses them back under the URL", wu["total"] == 2, wu)
adm = next(i for i in wu["items"] if i["url"].endswith("/admin"))
check("...counting the hits", adm["hits"] == 2, adm)
check("...and listing what was seen across them",
      sorted(adm["methods"]) == ["GET", "POST"]
      and sorted(adm["statuses"]) == [401, 403], adm)

print("\n--- find_by_technology unions services and web ---")
ft = run(M.find_by_technology("nginx", project="MCPT"))
check("matched on the service product", ft["matched"] == 1, ft)
check("...and says what the evidence was",
      any("nginx" in e for e in ft["hosts"][0]["evidence"]), ft["hosts"])
# The other half of the union. nmap puts the evidence in a banner and
# httpx puts it in a page title, so searching only services answers
# confidently and wrongly — this host runs no service called wordpress.
wp = run(M.find_by_technology("wordpress", project="MCPT"))
check("matched on a captured page title, with no service to go on",
      wp["matched"] == 1, wp)
check("...and the evidence names the URL it came from",
      any(e.startswith("web: ") for e in wp["hosts"][0]["evidence"]),
      wp["hosts"][0]["evidence"])
check("an unrecorded technology is absent, and says why",
      run(M.find_by_technology("jboss", project="MCPT"))["matched"] == 0)

print("\n--- credentials: the secret does not leave this process ---")
# The API hands the plaintext back to anyone with `user` on the project,
# because the UI has a reveal button. A model's context is shipped to a
# third party and may be logged there, and a captured password is still
# live on the client's estate after the engagement ends. So the tool
# withholds it, and this is the assertion that keeps it withheld.
call("/api/credentials?project=MCPT", "POST",
     {"host": "web.acme.example", "username": "svc_backup",
      "secret": "hunter2-correct-horse", "kind": "password"}, token=admin)
raw = call("/api/credentials?project=MCPT", token=admin)[1]
check("the API itself does return the plaintext",
      raw["items"][0]["secret"] == "hunter2-correct-horse")
cr = run(M.list_credentials(project="MCPT"))
check("list_credentials finds the credential", cr["total"] == 1, cr)
check("...reports that a secret was captured",
      cr["items"][0]["secret_captured"] is True)
check("...and the plaintext is nowhere in the result",
      "hunter2" not in json.dumps(cr), cr)
check("...and the withholding is stated, not silent", "withheld" in cr["note"])

print("\n--- scope, including the zone a name brings with it ---")
sc = run(M.list_scope("MCPT"))
check("list_scope reads the entries", sc["total"] == 2, sc)
check("include_subdomains is reported on every entry",
      all("include_subdomains" in e for e in sc["items"]), sc["items"])
added = run(M.add_scope("MCPT", ["sub.acme.example"], included=False))
check("add_scope records an exclusion",
      any(e["value"] == "sub.acme.example" and not e["included"]
          for e in added["scope"]), added.get("scope_errors"))
wide = run(M.add_scope("MCPT", ["sub.acme.example"], included=False,
                       include_subdomains=True))
check("widening an excluded entry to its zone is allowed",
      any(e["value"] == "sub.acme.example" and e["include_subdomains"]
          for e in wide["scope"]), wide.get("scope_errors"))
viol = run(M.scope_violations("MCPT"))
check("scope_violations reports rather than acts",
      viol["action"] == "report" and viol["scope_defined"] is True, viol)

print("\n--- Kitchen Sink Lookup ---")
roots = run(M.domain_roots("MCPT"))
names = {r["domain"] for r in roots["items"]}
check("roots walk a host back to its registrable domain",
      "acme.example" in names, names)
check("roots say where each came from",
      all(r["source"] in ("targets", "scope") for r in roots["items"]))
ks = run(M.enumerate_domains("MCPT", kitchen_sink=True))
# No ghost is enrolled yet, so this must refuse rather than queue work
# into a fleet that cannot run it. A 409 here is the correct behaviour
# and the tool description says so.
check("kitchen sink refuses with no ghost online",
      ks.get("error") == "HTTP 409", ks)
cands = run(M.domain_candidates("MCPT"))
check("domain_candidates reads clean with nothing found yet",
      cands["total"] == 0, cands)
check("promote on an empty list is refused, not silently a no-op",
      "error" in run(M.promote_domain_candidates("MCPT", [])))

print("\n--- the fleet ---")
d0 = run(M.list_ghosts("MCPT"))
check("list_ghosts on an empty fleet", d0["count"] == 0, d0)
kinds = run(M.ghost_task_kinds())
check("ghost_task_kinds lists the kinds",
      {"nmap", "masscan", "amass", "nuclei", "httpx"} <= set(kinds["by_kind"]), kinds)
check("...and which tool each needs", kinds["by_kind"]["nmap"] == "nmap")
check("...and that some need none", kinds["by_kind"]["nslookup"] is None)
rt = run(M.ghost_routing("MCPT"))
check("ghost_routing reports the mode", rt["mode"] in ("mesh", "primary", "geo"), rt)

enr = run(M.enroll_ghost("MCPT", "probe", target_os="linux"))
check("enroll_ghost creates an agent", enr.get("agent", {}).get("id"), enr)
check("...and returns a one-time enrol token", enr.get("enroll_token", "").strip() != "")
check("...and the server's public key for the ghost to pin",
      enr.get("server_public_key", "").strip() != "")
# The name is rewritten with a random suffix. A caller that assumed
# otherwise would address every later call to an agent that does not
# exist, so the tool description says to read it back — and so does this.
check("...under a name that is not quite the one asked for",
      enr["agent"]["name"].startswith("probe-")
      and enr["agent"]["name"] != "probe", enr["agent"]["name"])
aid = enr["agent"]["id"]

d1 = run(M.list_ghosts("MCPT"))
check("list_ghosts now sees it", d1["count"] == 1, d1)
a = d1["agents"][0]
check("...with its raw-socket capability stated", "raw_sockets" in a)
check("...and what it cannot run", isinstance(a["cannot_run"], list))
check("...and never a null host_platform, which would read as a value",
      "host_platform" not in a, a)
check("...and no enrolment secret anywhere in the listing",
      enr["enroll_token"] not in json.dumps(d1))

print("\n--- tasking ---")
t = run(M.task_ghost("MCPT", "nmap", "web.acme.example", agent_id=aid))
check("task_ghost queues against a named ghost", t.get("id"), t)
tid = t.get("id")
check("...with the target in its args", t["args"]["targets"] == ["web.acme.example"])
oos = run(M.task_ghost("MCPT", "nmap", "web.corp.com", agent_id=aid))
check("a target outside scope refuses the whole task", "error" in oos, oos)
check("install is refused before a request is sent",
      run(M.task_ghost("MCPT", "install", "x"))["error"].startswith("install"))
check("shell is refused before a request is sent",
      run(M.task_ghost("MCPT", "shell", "x"))["error"].startswith("shell"))
check("no targets is caught here, not by the server",
      run(M.task_ghost("MCPT", "nmap", "   "))["error"] == "no targets given")

sw = run(M.enumerate_ghosts("MCPT", "httpx",
                            "web.acme.example 198.51.100.11 bad.corp.com"))
check("a sweep queues one task per host", sw.get("queued") == 2, sw)
refused = sw.get("refused", {})
if not isinstance(refused, dict):
    refused = {}
check("...and names what scope refused rather than failing the batch",
      "bad.corp.com" in refused, refused)

q = run(M.ghost_queue("MCPT"))
check("ghost_queue shows the waiting work", q["total"] == 3, q)
check("...oldest first", q["items"][0]["id"] == tid, q["items"][0])
lt = run(M.list_ghost_tasks("MCPT"))
check("list_ghost_tasks shows them all", lt["total"] == 3, lt)
check("...newest first", lt["items"][0]["id"] > lt["items"][-1]["id"])

ts = run(M.ghost_task_status("MCPT", tid))
check("ghost_task_status finds the task", ts["id"] == tid, ts)
check("...reports a readable state", ts["state"] == "awaiting", ts)
check("...and its args, from the per-ghost record",
      ts.get("args", {}).get("targets") == ["web.acme.example"], ts)
check("...and that nothing is waiting on a decision yet",
      ts["needs_decision"] is False)
check("an unknown task id is an error, not an empty result",
      "error" in run(M.ghost_task_status("MCPT", 999999)))

pooled = run(M.task_ghost("MCPT", "nmap", "web.acme.example"))
pts = run(M.ghost_task_status("MCPT", pooled["id"]))
check("a pooled task says its detail is unavailable rather than empty",
      pts["detail_available"] is False and "pool" in pts["note"], pts)

print("\n--- stopping work ---")
check("cancel_ghost_task deletes a queued task",
      run(M.cancel_ghost_task("MCPT", pooled["id"])).get("ok") is True)
check("...and it is gone", "error" in run(M.ghost_task_status("MCPT", pooled["id"])))
check("retry refuses a task that has not failed",
      run(M.retry_ghost_task("MCPT", tid)).get("error") == "HTTP 409")
k = run(M.kill_ghost("MCPT", aid))
check("kill_ghost disables the ghost", k.get("status") == "disabled", k)
after = run(M.ghost_task_status("MCPT", tid))
check("...and fails the work it was carrying, saying so plainly",
      after["state"] == "failed" and "killed" in (after["notes"] or ""), after)

print("\n--- site health ---")
sh = run(M.site_health())
check("site_health reaches a site admin's view", "database" in sh, sorted(sh)[:6])
check("...and reports the fleet", "ghosts" in sh)
# Returned verbatim on purpose: the server/fleet version rollup is being
# added right now, and a field filter written today would drop it on the
# day it lands. This asserts the passthrough, not the keys.
check("...verbatim, so a key added later is not filtered away",
      len(sh) >= 8, f"{len(sh)} top-level keys")

st2, key2 = call("/api/users", "POST",
                 {"username": "reader", "password": "reader-password-1"}, token=admin)
tok2 = call("/api/auth/login", "POST",
            {"username": "reader", "password": "reader-password-1"})[1]["access_token"]
k2 = call("/api/auth/keys?name=mcp2", "POST", token=tok2)[1]["key"]
os.environ["ODDJOB_API_KEY"] = k2
check("site_health is refused to a key that is not a site admin",
      run(M.site_health()).get("error") == "HTTP 403", run(M.site_health()))
check("a key with no role on a project cannot read its ghosts",
      run(M.list_ghosts("MCPT")).get("error") == "HTTP 404")
check("...nor its scope", run(M.list_scope("MCPT")).get("error") == "HTTP 404")
check("...nor task one of its ghosts",
      run(M.task_ghost("MCPT", "nmap", "web.acme.example")).get("error")
      == "HTTP 404")
os.environ["ODDJOB_API_KEY"] = key["key"]

print("\n--- exploits keep the host out of the lookup ---")
check("service_leads has no host parameter",
      "host" not in inspect.signature(M.service_leads).parameters)
el = run(M.exploit_leads("MCPT", "web.acme.example"))
check("exploit_leads resolves the host's services here",
      {s["port"] for s in el["services"]} == {22, 443}, el.get("services"))
check("...and reports how current the feeds are", "feeds" in el)
empty = run(M.add_target("MCPT", "dark.acme.example"))
check("a host with no ports is a scanning gap, not an absence of exposure",
      "gap in what has been scanned" in
      run(M.exploit_leads("MCPT", "dark.acme.example"))["note"], empty)

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
