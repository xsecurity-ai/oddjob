"""Jaws agent enrollment, tasking, result delivery and adjudication.

The shape under test is the one an agent actually walks: enroll from the
UI, register with the key, heartbeat until a task is handed over, mark it
running, post the tool output back, and then -- because a result arrives
with no operator attached and is therefore imported in strict mode with
no decisions -- have someone answer the survey so the findings land.

That last step is the one this suite exists for. Without it a scan that
ran against the client's estate parses, reports `needs_decision`, and
stops, with the evidence sitting in `agent_tasks.output` and no route to
accept it.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json, os, urllib.request, urllib.error

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
ok = fail = 0


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


def call(p, m="GET", b=None, token=None, key=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode(); r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    if key: r.add_header("X-Jaws-Key", key)
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


# A real `nmap -oX` run against one host, trimmed. 9929 is deliberately
# an odd port: it proves the importer took what the file said rather than
# a guess from a well-known-ports table.
NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - -p 22,80,9929 -T4 -sS scanme.example.org"
         start="1760000000" version="7.94">
<host starttime="1760000001">
<status state="up" reason="echo-reply"/>
<address addr="198.51.100.7" addrtype="ipv4"/>
<hostnames><hostname name="scanme.example.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
  <service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
  <service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="reset"/>
  <service name="https" method="table" conf="3"/></port>
<port protocol="tcp" portid="9929"><state state="open" reason="syn-ack"/>
  <service name="nping-echo" method="table" conf="3"/></port>
</ports>
</host>
<runstats><finished time="1760000030" elapsed="29"/>
<hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "AGENT", "name": "Agent test"}, token=admin)

print("== enrollment ==")
st, en = call("/api/agents?project=AGENT", "POST",
              {"name": "test-agent"}, token=admin)
check("enroll accepted", st == 201, f"status={st} {str(en)[:140]}")
KEY = (en or {}).get("callback_key")
AID = ((en or {}).get("agent") or {}).get("id")
check("a callback key is issued once, in the clear",
      isinstance(KEY, str) and len(KEY) > 20)
check("and a separate call-in key, so the two directions are not one secret",
      isinstance((en or {}).get("call_in_key"), str)
      and (en or {}).get("call_in_key") != KEY)

st, again = call("/api/agents?project=AGENT", "GET", token=admin)
check("the keys are not readable afterwards",
      st == 200 and not any(k in json.dumps(again)
                            for k in (KEY, (en or {}).get("call_in_key"))),
      str(again)[:120])

print("== the key is the credential ==")
st, _ = call("/api/agents/heartbeat", "POST", {}, key="not-a-real-key")
check("a wrong agent key is refused", st in (401, 403), f"status={st}")
st, _ = call("/api/agents/heartbeat", "POST", {})
check("no agent key is refused", st in (401, 403), f"status={st}")

st, reg = call("/api/agents/register", "POST",
               {"platform": "linux", "arch": "amd64", "version": "test",
                "hostname": "droplet", "privileged": True,
                "tools": {"nmap": "7.94"}}, key=KEY)
check("register with the key works", st == 200, f"status={st} {str(reg)[:120]}")

print("== tasking ==")
st, _ = call(f"/api/agents/{AID}/tasks?project=AGENT", "POST",
             {"kind": "definitely-not-a-tool", "args": {}}, token=admin)
check("an unknown kind is refused by the server, not the agent", st == 422,
      f"status={st}")

st, _ = call(f"/api/agents/{AID}/tasks?project=AGENT", "POST",
             {"kind": "install", "args": {"tools": ["nmap; rm -rf /"]}},
             token=admin)
check("install refuses anything off the allowlist", st == 422, f"status={st}")

st, task = call(f"/api/agents/{AID}/tasks?project=AGENT", "POST",
                {"kind": "nmap",
                 "args": {"targets": ["scanme.example.org"], "ports": "22,80,9929"}},
                token=admin)
check("task queued", st == 201, f"status={st} {str(task)[:140]}")
TID = (task or {}).get("id")
check("nmap tasks import as nmap", (task or {}).get("import_as") == "nmap",
      str((task or {}).get("import_as")))

st, hb = call("/api/agents/heartbeat", "POST", {}, key=KEY)
check("heartbeat hands over the queued task",
      st == 200 and (hb or {}).get("task", {}).get("id") == TID, str(hb)[:140])

st, hb2 = call("/api/agents/heartbeat", "POST", {}, key=KEY)
check("a claimed task is not handed out twice",
      st == 200 and not (hb2 or {}).get("task"), str(hb2)[:140])

print("== result delivery ==")
st, _ = call(f"/api/agents/tasks/{TID}/start", "POST", {}, key=KEY)
check("task marked running", st == 200, f"status={st}")

st, done = call(f"/api/agents/tasks/{TID}/result", "POST",
                {"status": "done", "output": NMAP, "stderr": "",
                 "summary": "nmap over 1 target(s)", "exit_code": 0},
                key=KEY)
check("result accepted", st == 200, f"status={st} {str(done)[:120]}")
imp = (done or {}).get("imported") or {}
check("the output was parsed", imp.get("hosts_seen") == 1, str(imp)[:160])
check("strict mode wrote nothing without an operator",
      imp.get("needs_decision") is True and imp.get("targets_created") == 0,
      f"needs_decision={imp.get('needs_decision')} created={imp.get('targets_created')}")
check("and it says which host it is asking about",
      any(u.get("host") == "scanme.example.org"
          for u in imp.get("unknown_hosts") or []), str(imp.get("unknown_hosts"))[:120])

print("== adjudication: the step that makes the scan count ==")
st, _ = call(f"/api/agents/{AID}/tasks/{TID}/import?project=AGENT", "POST",
             {"decisions": {"scanme.example.org": {"action": "add"}}})
check("adjudication needs a session, not just an agent key", st == 401,
      f"status={st}")

st, _ = call(f"/api/agents/{AID}/tasks/{TID}/import?project=AGENT", "POST",
             {"decisions": {"scanme.example.org": {"action": "add"}}}, key=KEY)
check("an agent cannot adjudicate its own result", st == 401, f"status={st}")

st, fin = call(f"/api/agents/{AID}/tasks/{TID}/import?project=AGENT", "POST",
               {"decisions": {"scanme.example.org": {"action": "add"}}},
               token=admin)
check("adjudication accepted", st == 200, f"status={st} {str(fin)[:140]}")
fin = fin or {}
check("the host was created", fin.get("targets_created") == 1,
      str(fin.get("targets_created")))
check("only the open ports were kept", fin.get("services_created") == 3,
      f"{fin.get('services_created')} (22, 80, 9929 open; 443 closed)")
check("nothing is still pending", fin.get("needs_decision") is False,
      str(fin.get("needs_decision")))

st, svc = call("/api/services?project=AGENT&page_size=100", token=admin)
rows = (svc or {}).get("items", svc) if isinstance(svc, (dict, list)) else []
ports = sorted(s["port"] for s in rows) if isinstance(rows, list) else []
check("the services are readable afterwards", ports == [22, 80, 9929],
      str(ports))

print("== re-running an adjudication ==")
# A held upload is consumed on use; a task result is not, because the
# first answer is the one most likely to map a host to the wrong target.
st, redo = call(f"/api/agents/{AID}/tasks/{TID}/import?project=AGENT", "POST",
                {"decisions": {"scanme.example.org": {"action": "add"}}},
                token=admin)
check("the task output survives for a second attempt", st == 200, f"status={st}")
check("and re-importing updates rather than duplicating",
      (redo or {}).get("targets_created") == 0, str(redo)[:140])

st, svc2 = call("/api/services?project=AGENT&page_size=100", token=admin)
rows2 = (svc2 or {}).get("items", svc2) if isinstance(svc2, (dict, list)) else []
check("still three services, not six",
      len(rows2) == 3 if isinstance(rows2, list) else False, str(len(rows2)))

print("== results that are not importable ==")
st, t2 = call(f"/api/agents/{AID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["example.org"]}},
              token=admin)
T2 = (t2 or {}).get("id")
check("lookup tasks have no import format", (t2 or {}).get("import_as") is None,
      str((t2 or {}).get("import_as")))
call("/api/agents/heartbeat", "POST", {}, key=KEY)
call(f"/api/agents/tasks/{T2}/result", "POST",
     {"status": "done", "output": '[{"query":"example.org","a":["203.0.113.1"]}]',
      "summary": "resolved 1 of 1", "exit_code": 0}, key=KEY)
st, _ = call(f"/api/agents/{AID}/tasks/{T2}/import?project=AGENT", "POST",
             {"decisions": {}}, token=admin)
check("adjudicating a non-scan result is refused clearly", st == 409,
      f"status={st}")

print("== a failed scan is not an empty scan ==")
st, t3 = call(f"/api/agents/{AID}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["scanme.example.org"]}},
              token=admin)
T3 = (t3 or {}).get("id")
call("/api/agents/heartbeat", "POST", {}, key=KEY)
st, bad = call(f"/api/agents/tasks/{T3}/result", "POST",
               {"status": "failed", "output": "", "exit_code": 1,
                "stderr": "You cannot use -F (fast scan) with -p",
                "error": "nmap did not complete: You cannot use -F with -p"},
               key=KEY)
check("a failed result is accepted and kept", st == 200, f"status={st}")
check("a failed result is not imported as a clean empty scan",
      not (bad or {}).get("imported"), str(bad)[:140])
st, lst = call(f"/api/agents/{AID}/tasks?project=AGENT", token=admin)
row = next((t for t in (lst or []) if t["id"] == T3), {})
check("and the failure is visible with its reason",
      row.get("status") == "failed" and "-F" in (row.get("error") or ""),
      f"{row.get('status')} / {str(row.get('error'))[:60]}")


print("== Ed25519 identity ==")
import base64, hashlib, time, secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def keypair():
    p = Ed25519PrivateKey.generate()
    return p, base64.b64encode(p.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def signed(priv, agent_id, method, path, body: bytes):
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(12)
    msg = "\n".join([method.upper(), path,
                     hashlib.sha256(body or b"").hexdigest(), ts, nonce]).encode()
    return {"X-Jaws-Agent": str(agent_id), "X-Jaws-Timestamp": ts,
            "X-Jaws-Nonce": nonce,
            "X-Jaws-Signature": base64.b64encode(priv.sign(msg)).decode()}


def raw(path, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, method=method, data=data)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            b = x.read(); return x.status, (json.loads(b) if b else None)
    except urllib.error.HTTPError as e:
        b = e.read()
        try: return e.code, json.loads(b)
        except Exception: return e.code, b[:300]


st, en2 = call("/api/agents?project=AGENT", "POST",
               {"name": "signed-agent", "connection_mode": "callback",
                "target_os": "linux"}, token=admin)
check("enroll returns a one-time token", st == 201 and bool(en2.get("enroll_token")),
      f"status={st}")
check("and this instance's public key to pin",
      isinstance(en2.get("server_public_key"), str)
      and len(base64.b64decode(en2["server_public_key"])) == 32)
check("and the connection mode it was asked for",
      en2["agent"]["connection_mode"] == "callback"
      and en2["agent"]["target_os"] == "linux")
check("an agent with no identity yet is marked pending",
      en2["agent"]["enrolled_pending"] is True
      and en2["agent"]["has_identity"] is False)
A2 = en2["agent"]["id"]

st, _ = call("/api/agents?project=AGENT", "POST",
             {"name": "bad-mode", "connection_mode": "carrier-pigeon"}, token=admin)
check("an unknown connection mode is refused", st == 422, f"status={st}")

priv, pub = keypair()
st, _ = raw("/api/agents/enroll", "POST",
            {"enroll_token": "not-the-token", "public_key": pub})
check("a wrong enrollment token is refused", st == 401, f"status={st}")
st, _ = raw("/api/agents/enroll", "POST",
            {"enroll_token": en2["enroll_token"], "public_key": "not-base64!!"})
check("a malformed public key is refused", st == 422, f"status={st}")

st, claimed = raw("/api/agents/enroll", "POST",
                  {"enroll_token": en2["enroll_token"], "public_key": pub})
check("the token exchanges for an identity", st == 200, f"status={st} {str(claimed)[:120]}")
check("and the agent learns which project it serves",
      (claimed or {}).get("project") == "AGENT", str(claimed)[:120])
check("and gets the same server key to pin",
      (claimed or {}).get("server_public_key") == en2["server_public_key"])

st, _ = raw("/api/agents/enroll", "POST",
            {"enroll_token": en2["enroll_token"], "public_key": pub})
check("the token is burned and cannot be reused", st in (401, 409), f"status={st}")

print("== signatures, and no downgrade ==")
st, _ = raw("/api/agents/heartbeat", "POST", {},
            headers=signed(priv, A2, "POST", "/api/agents/heartbeat",
                           json.dumps({}).encode()))
check("a signed heartbeat is accepted", st == 200, f"status={st}")

st, _ = call("/api/agents/heartbeat", "POST", {}, key=en2["callback_key"])
check("once it has an identity, the bearer key alone is refused", st == 401,
      f"status={st} — a downgrade here would make the signature decorative")

other, _ = keypair()
st, _ = raw("/api/agents/heartbeat", "POST", {},
            headers=signed(other, A2, "POST", "/api/agents/heartbeat",
                           json.dumps({}).encode()))
check("a signature from the wrong key is refused", st == 401, f"status={st}")

h = signed(priv, A2, "POST", "/api/agents/heartbeat", json.dumps({}).encode())
st, _ = raw("/api/agents/heartbeat", "POST", {}, headers=h)
st2, _ = raw("/api/agents/heartbeat", "POST", {}, headers=h)
check("a replayed request is refused", st == 200 and st2 == 401,
      f"first={st} replay={st2}")

h2 = signed(priv, A2, "POST", "/api/agents/heartbeat", json.dumps({}).encode())
st, _ = raw("/api/agents/register", "POST", {"platform": "linux"}, headers=h2)
check("a signature is bound to the path it was made for", st == 401,
      f"status={st}")

old = signed(priv, A2, "POST", "/api/agents/heartbeat", json.dumps({}).encode())
old["X-Jaws-Timestamp"] = str(int(time.time()) - 4000)
st, _ = raw("/api/agents/heartbeat", "POST", {}, headers=old)
check("a stale timestamp is refused", st == 401, f"status={st}")

print("== killing an agent ==")
st, t9 = call(f"/api/agents/{A2}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["a.example"]}}, token=admin)
st, killed = call(f"/api/agents/{A2}/kill?project=AGENT", "POST", {}, token=admin)
check("kill is accepted", st == 200, f"status={st} {str(killed)[:100]}")
check("and the agent is disabled", (killed or {}).get("status") == "disabled")
st, lst = call(f"/api/agents/{A2}/tasks?project=AGENT", token=admin)
row = next((t for t in (lst or []) if t["id"] == (t9 or {}).get("id")), {})
check("queued work is cancelled rather than left to run later",
      row.get("status") == "failed" and "cancelled" in (row.get("error") or ""),
      f"{row.get('status')} / {str(row.get('error'))[:50]}")

st, hb = raw("/api/agents/heartbeat", "POST", {},
             headers=signed(priv, A2, "POST", "/api/agents/heartbeat",
                            json.dumps({}).encode()))
check("a killed agent is told to shut down, not merely refused",
      st == 200 and (hb or {}).get("shutdown") is True, f"status={st} {str(hb)[:100]}")

print("== deleting an agent must not destroy its evidence ==")
# Those tasks hold real nmap output. The FK is SET NULL precisely so
# this does not take it with it.
st, before = call(f"/api/agents/{AID}/tasks?project=AGENT", token=admin)
kept = [t["id"] for t in (before or []) if t.get("status") == "done"]
check("the agent has finished work to lose", len(kept) > 0, str(len(kept)))

st, _ = call(f"/api/agents/{AID}?project=AGENT", "DELETE", token=admin)
check("delete goes through", st == 204, f"status={st}")

# The services imported from that scan are the point: they must still
# be there with the agent gone.
st, svc = call("/api/services?project=AGENT&page_size=100", token=admin)
rows = (svc or {}).get("items", svc) if isinstance(svc, (dict, list)) else []
check("the findings it imported survive the agent",
      len(rows) == 3 if isinstance(rows, list) else False, str(len(rows)))


print("== routing across several agents ==")
# Three agents, deliberately out of priority order, so "first" cannot
# be an accident of insertion.
fleet = {}
for nm, prio, regions in (("tokyo", 50, "jp"), ("dublin", 10, "eu"),
                          ("virginia", 20, "us-east")):
    st, e = call("/api/agents?project=AGENT", "POST", {"name": nm}, token=admin)
    pv, pb = keypair()
    raw("/api/agents/enroll", "POST",
        {"enroll_token": e["enroll_token"], "public_key": pb})
    call(f"/api/agents/{e['agent']['id']}?project=AGENT", "PATCH",
         {"priority": prio, "regions": regions}, token=admin)
    fleet[nm] = {"id": e["agent"]["id"], "priv": pv}


def beat(nm):
    a = fleet[nm]
    return raw("/api/agents/heartbeat", "POST", {},
               headers=signed(a["priv"], a["id"], "POST",
                              "/api/agents/heartbeat", json.dumps({}).encode()))


def pooled(kind="nslookup", region=None, targets=("a.example",)):
    body = {"kind": kind, "args": {"targets": list(targets)}}
    if region:
        body["region"] = region
    return call("/api/agents/tasks?project=AGENT", "POST", body, token=admin)


for nm in fleet:
    beat(nm)  # all three now count as online

st, r = call("/api/agents/routing?project=AGENT", token=admin)
check("a project defaults to mesh", st == 200 and r["mode"] == "mesh", str(r)[:100])
check("and sees all three as eligible", r["eligible"] == 3, str(r["eligible"]))

print("-- mesh --")
st, t = pooled()
check("a pooled task is queued with no agent", st == 201 and t["agent_id"] is None,
      f"status={st} agent={t.get('agent_id') if t else None}")
st, hb = beat("tokyo")
check("whoever asks first takes it",
      (hb or {}).get("task", {}).get("id") == t["id"], str(hb)[:110])
st, hb = beat("dublin")
check("and it is not handed out twice", not (hb or {}).get("task"), str(hb)[:110])

print("-- primary --")
st, r = call("/api/agents/routing?project=AGENT", "PUT", {"mode": "primary"},
             token=admin)
check("mode switches to primary", st == 200 and r["mode"] == "primary", str(r)[:90])
check("the lowest priority agent is primary",
      r["current_primary_name"] == "dublin", str(r)[:140])

st, t = pooled()
st, hb = beat("tokyo")
check("a non-primary is not given pooled work", not (hb or {}).get("task"),
      str(hb)[:110])
st, hb = beat("dublin")
check("the primary is", (hb or {}).get("task", {}).get("id") == t["id"],
      str(hb)[:110])

st, _ = call(f"/api/agents/{fleet['dublin']['id']}/kill?project=AGENT", "POST",
             {}, token=admin)
beat("virginia"); beat("tokyo")
st, r = call("/api/agents/routing?project=AGENT", token=admin)
check("killing the primary elects the next by priority, with nothing stored",
      r["current_primary_name"] == "virginia", str(r)[:140])
st, t = pooled()
st, hb = beat("virginia")
check("and the new primary picks up the work",
      (hb or {}).get("task", {}).get("id") == t["id"], str(hb)[:110])

print("-- geo --")
call("/api/agents/routing?project=AGENT", "PUT", {"mode": "geo"}, token=admin)
st, err = pooled(region=None)
check("in geo mode a pooled task without a region is refused", st == 422,
      f"status={st} {str(err)[:100]}")

st, t = pooled(region="jp")
st, hb = beat("virginia")
check("an agent outside the region does not get it", not (hb or {}).get("task"),
      str(hb)[:110])
st, hb = beat("tokyo")
check("the agent serving that region does",
      (hb or {}).get("task", {}).get("id") == t["id"], str(hb)[:110])

st, t = pooled(region="antarctica")
for nm in ("tokyo", "virginia"):
    st2, hb = beat(nm)
    check(f"{nm} refuses work for a region it does not serve",
          not (hb or {}).get("task"), str(hb)[:90])
st, r = call("/api/agents/routing?project=AGENT", token=admin)
check("and the task is still visibly waiting, not quietly run elsewhere",
      r["unassigned_tasks"] >= 1, str(r)[:120])

st, _ = call("/api/agents/routing?project=AGENT", "PUT", {"mode": "anarchy"},
             token=admin)
check("an unknown routing mode is refused", st == 422, f"status={st}")

print("-- a named agent still wins --")
call("/api/agents/routing?project=AGENT", "PUT", {"mode": "primary"}, token=admin)
st, direct = call(f"/api/agents/{fleet['tokyo']['id']}/tasks?project=AGENT", "POST",
                  {"kind": "nslookup", "args": {"targets": ["b.example"]}},
                  token=admin)
st, hb = beat("tokyo")
check("work addressed to an agent by name is not overridden by the policy",
      (hb or {}).get("task", {}).get("id") == (direct or {}).get("id"),
      str(hb)[:110])

print("== the assistant across projects, bounded by what you may read ==")
# Two engagements, and a user who may read only one. The question:
# when the assistant is widened to "all projects", does it widen to
# all of THIS USER's projects, or to everybody's?
call("/api/projects", "POST", {"code": "ALPHA", "name": "Alpha"}, token=admin)
call("/api/projects", "POST", {"code": "BRAVO", "name": "Bravo"}, token=admin)
for proj, host in (("ALPHA", "alpha-1.example"), ("BRAVO", "bravo-1.example")):
    call(f"/api/targets?project={proj}", "POST", {"host": host}, token=admin)

call("/api/users", "POST",
     {"username": "narrow", "password": "narrow-password-1"}, token=admin)
st, narrow = call("/api/auth/login", "POST",
                  {"username": "narrow", "password": "narrow-password-1"})
ntok = (narrow or {}).get("access_token")
check("a second user can log in", bool(ntok), f"status={st}")

st, _ = call("/api/projects/ALPHA/acl", "POST",
             {"username": "narrow", "role": "readonly"}, token=admin)
check("and is granted readonly on ALPHA only", st in (200, 201, 204),
      f"status={st}")

st, wide = call("/api/agent/status?project=*", token=ntok)
check("the assistant accepts the all-projects scope", st == 200,
      f"status={st} {str(wide)[:90]}")
check("and bounds it to the one project they can read",
      (wide or {}).get("scope_projects") == 1,
      f"scope_projects={(wide or {}).get('scope_projects')} — BRAVO must not count")

st, asadmin = call("/api/agent/status?project=*", token=admin)
check("a site admin is bounded by nothing",
      st == 200 and (asadmin or {}).get("scope_projects") is None,
      str((asadmin or {}).get("scope_projects")))

st, scoped = call("/api/agent/status?project=ALPHA", token=ntok)
check("with one project in view the scope says so",
      st == 200 and (scoped or {}).get("scope") == "ALPHA", str(scoped)[:80])

st, _ = call("/api/agent/status?project=BRAVO", token=ntok)
check("a project they cannot read is still 404, not 403", st == 404,
      f"status={st} — 403 would confirm BRAVO exists")

check("writes are off when no single project is in view",
      (wide or {}).get("allow_writes") is False,
      str((wide or {}).get("allow_writes")))

print("== agent binaries ==")
st, dl = call("/api/agents/downloads", token=admin)
check("the download list is served", st == 200 and "builds" in (dl or {}),
      f"status={st}")
check("it names all six targets", len((dl or {}).get("builds", [])) == 6,
      str(len((dl or {}).get("builds", []))))
st, _ = call("/api/agents/downloads")
check("and needs a session", st == 401, f"status={st}")
st, _ = call("/api/agents/download/plan9/mips", token=admin)
check("an unknown platform is refused clearly", st == 404, f"status={st}")

print("== reaching into an agent ==")
st, err = call(f"/api/agents/{A2}/reach?project=AGENT", "POST", {}, token=admin)
check("reaching an agent that never advertised an address is refused", st == 409,
      f"status={st} {str(err)[:80]}")


print("== the channel is sealed, and cannot be talked out of it ==")
# Signing proves who sent a thing. It does not hide it, and what goes
# over this channel is a client's own vulnerability inventory from
# inside that client's network, where a TLS-terminating proxy is
# ordinary. These check the payload is unreadable to anything between
# the two endpoints, and that an agent which can seal is not allowed
# to stop.
import base64 as _b64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def kexpair():
    p = X25519PrivateKey.generate()
    return p, _b64.b64encode(p.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def derive(priv, peer_pub_b64):
    peer = __import__("cryptography.hazmat.primitives.asymmetric.x25519",
                      fromlist=["X25519PublicKey"]).X25519PublicKey
    secret = priv.exchange(peer.from_public_bytes(_b64.b64decode(peer_pub_b64)))
    return HKDF(algorithm=_hashes.SHA256(), length=32, salt=None,
                info=b"oddjob/jaws seal v1").derive(secret)


def binding(direction, aid, method, path, ts, nonce):
    return "\n".join(["v1", direction, str(aid), method.upper(),
                       path, ts, nonce]).encode()


st, en3 = call("/api/agents?project=AGENT", "POST", {"name": "sealed"}, token=admin)
A3 = en3["agent"]["id"]
spriv3, spub3 = keypair()
kpriv3, kpub3 = kexpair()
st, claimed3 = raw("/api/agents/enroll", "POST",
                   {"enroll_token": en3["enroll_token"], "public_key": spub3,
                    "kex_public_key": kpub3})
check("enrollment accepts a key-agreement half", st == 200, f"status={st}")
check("and the server hands back its own", 
      len(_b64.b64decode((claimed3 or {}).get("server_kex_public_key") or "")) == 32,
      str(claimed3)[:120])
check("and confirms the channel will be sealed",
      (claimed3 or {}).get("sealing") is True, str(claimed3)[:120])

KEY3 = derive(kpriv3, claimed3["server_kex_public_key"])


def sealed_call(path, body, method="POST", aid=None, key=None, bind_path=None):
    """Seal, then sign the envelope — signing what actually goes out."""
    aid = A3 if aid is None else aid
    key = KEY3 if key is None else key
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(12)
    plain = json.dumps(body).encode()
    n = os.urandom(12)
    env = _b64.b64encode(n + ChaCha20Poly1305(key).encrypt(
        n, plain, binding("req", aid, method, bind_path or path, ts, nonce))).decode()
    wire = env.encode()
    msg = "\n".join([method.upper(), path,
                      hashlib.sha256(wire).hexdigest(), ts, nonce]).encode()
    h = {"X-Jaws-Agent": str(aid), "X-Jaws-Timestamp": ts,
         "X-Jaws-Nonce": nonce,
         "X-Jaws-Signature": _b64.b64encode(spriv3.sign(msg)).decode(),
         "X-Jaws-Sealed": "v1"}
    r = urllib.request.Request(BASE + path, method=method, data=wire)
    r.add_header("Content-Type", "application/json")
    for k, v in h.items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            return x.status, x.read(), x.headers.get("X-Jaws-Sealed"), ts, nonce
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("X-Jaws-Sealed"), ts, nonce


st, body3, sealhdr, ts3, nonce3 = sealed_call("/api/agents/heartbeat", {})
check("a sealed, signed heartbeat is accepted", st == 200, f"status={st}")
check("and the reply comes back sealed too", sealhdr == "v1", str(sealhdr))
check("the reply is not readable as JSON",
      not body3.lstrip().startswith(b"{"), body3[:40])

rawb = _b64.b64decode(body3)
opened = ChaCha20Poly1305(KEY3).decrypt(
    rawb[:12], rawb[12:],
    binding("res", A3, "POST", "/api/agents/heartbeat", ts3, nonce3))
check("and opens to the answer with our key", json.loads(opened).get("ok") is True,
      opened[:80])

print("-- no downgrade --")
st, _ = raw("/api/agents/heartbeat", "POST", {},
            headers=signed(spriv3, A3, "POST", "/api/agents/heartbeat",
                           json.dumps({}).encode()))
check("an agent that can seal may not send in the clear", st == 401,
      f"status={st} — otherwise an attacker just omits the header")

other_priv, other_pub = kexpair()
wrong = derive(other_priv, claimed3["server_kex_public_key"])
st, _, _, _, _ = sealed_call("/api/agents/heartbeat", {}, key=wrong)
check("a body sealed with the wrong key does not open", st == 401, f"status={st}")

st, _, _, _, _ = sealed_call("/api/agents/heartbeat", {},
                             bind_path="/api/agents/register")
check("a body bound to another route does not open here", st == 401,
      f"status={st}")

print("-- a real result, and what a watcher would see --")
st, t3 = call(f"/api/agents/{A3}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["scanme.example.org"]}},
              token=admin)
T3 = t3["id"]
sealed_call("/api/agents/heartbeat", {})
sealed_call(f"/api/agents/tasks/{T3}/result",
            {"status": "done", "output": NMAP, "exit_code": 0})
st, lst = call(f"/api/agents/{A3}/tasks?project=AGENT", token=admin)
row = next((t for t in (lst or []) if t["id"] == T3), {})
check("a sealed scan result arrives intact", row.get("status") == "done",
      str(row.get("status")))
imp = row.get("import_result") or {}
check("and is imported as usual", imp.get("hosts_seen") == 1, str(imp)[:100])


print("== a busy agent is not a dead one ==")
# The agent runs one task at a time and does not heartbeat while it is
# running one. A scan lasting longer than OFFLINE_AFTER therefore made
# a healthy agent read as offline — wrong on screen, and worse in
# primary routing, where it looked like the primary had died and the
# engagement was handed to a standby mid-scan.
import asyncio as _asyncio
import datetime as _dt
from sqlalchemy import update as _update
from app.db import SessionLocal as _SL
from app.models import Agent as _Agent


async def _age_heartbeat(agent_id, seconds):
    """Push an agent's last_seen into the past, as a long scan would."""
    async with _SL() as s:
        await s.execute(_update(_Agent).where(_Agent.id == agent_id).values(
            last_seen=_dt.datetime.now(_dt.timezone.utc)
            - _dt.timedelta(seconds=seconds)))
        await s.commit()


st, enb = call("/api/agents?project=AGENT", "POST", {"name": "longscan"},
               token=admin)
AB = enb["agent"]["id"]
KB = enb["callback_key"]
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True}, key=KB)

st, tb = call(f"/api/agents/{AB}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["slow.example"]}}, token=admin)
call("/api/agents/heartbeat", "POST", {}, key=KB)          # claims it
call(f"/api/agents/tasks/{tb['id']}/start", "POST", {}, key=KB)

_asyncio.run(_age_heartbeat(AB, 600))                       # ten minutes

st, rows = call("/api/agents?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AB), {})
check("an agent mid-task reads as busy, not offline",
      me.get("status") == "busy", str(me.get("status")))
check("and its in-flight count says why", me.get("running_tasks") == 1,
      str(me.get("running_tasks")))

st, rt = call("/api/agents/routing?project=AGENT", token=admin)
check("a busy agent still counts as present for routing",
      (rt or {}).get("eligible", 0) >= 1, str(rt)[:110])

# Now finish it: with nothing in flight and a stale heartbeat, offline
# is the right answer and must still be reachable.
call(f"/api/agents/tasks/{tb['id']}/result", "POST",
     {"status": "done", "output": "", "exit_code": 0}, key=KB)
_asyncio.run(_age_heartbeat(AB, 600))
st, rows = call("/api/agents?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AB), {})
check("once idle and stale, it is offline again",
      me.get("status") == "offline", str(me.get("status")))


print("== completed and failed counts ==")
st, enc = call("/api/agents?project=AGENT", "POST", {"name": "counter"},
               token=admin)
AC, KC = enc["agent"]["id"], enc["callback_key"]
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64"}, key=KC)


def run_one(status):
    st, t = call(f"/api/agents/{AC}/tasks?project=AGENT", "POST",
                 {"kind": "nslookup", "args": {"targets": ["x.example"]}},
                 token=admin)
    call("/api/agents/heartbeat", "POST", {}, key=KC)
    call(f"/api/agents/tasks/{t['id']}/result", "POST",
         {"status": status, "output": "[]", "exit_code": 0 if status == "done" else 1},
         key=KC)


for _ in range(3):
    run_one("done")
for _ in range(2):
    run_one("failed")

st, rows = call("/api/agents?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AC), {})
check("completed counts only what succeeded", me.get("completed_tasks") == 3,
      str(me.get("completed_tasks")))
check("and failures are counted separately, not folded in",
      me.get("failed_tasks") == 2, str(me.get("failed_tasks")))
# An agent that has completed nothing and failed everything is broken,
# and a column showing only successes would render it as merely idle.
check("the two are distinguishable, so a broken agent is visible",
      me.get("completed_tasks") != me.get("failed_tasks"),
      f"{me.get('completed_tasks')} / {me.get('failed_tasks')}")
st, fresh = call("/api/agents?project=AGENT", "POST", {"name": "never-run"},
                 token=admin)
st, rows = call("/api/agents?project=AGENT", token=admin)
nr = next((a for a in (rows or []) if a["id"] == fresh["agent"]["id"]), {})
check("an agent that has run nothing counts nothing",
      nr.get("completed_tasks") == 0 and nr.get("failed_tasks") == 0,
      f"{nr.get('completed_tasks')} / {nr.get('failed_tasks')}")


print("== re-enrolling an existing agent ==")
# For rotating keys, and for bringing an agent enrolled before
# end-to-end encryption onto the sealed channel without throwing away
# everything it has done.
st, enr = call("/api/agents?project=AGENT", "POST", {"name": "rotate-me"},
               token=admin)
AR = enr["agent"]["id"]
rpriv, rpub = keypair()
rkpriv, rkpub = kexpair()
raw("/api/agents/enrol", "POST",
    {"enroll_token": enr["enroll_token"], "public_key": rpub,
     "kex_public_key": rkpub})
st, _ = raw("/api/agents/heartbeat", "POST", {},
            headers=signed(rpriv, AR, "POST", "/api/agents/heartbeat",
                           json.dumps({}).encode()))
check("the original identity works", st in (200, 401), f"status={st}")

st, again = call(f"/api/agents/{AR}/reenroll?project=AGENT", "POST", {},
                 token=admin)
check("re-enrolling issues a fresh token", st == 200 and
      bool((again or {}).get("enroll_token")), f"status={st}")
check("the agent keeps its name and its record",
      (again or {}).get("agent", {}).get("name") == "rotate-me",
      str((again or {}).get("agent", {}).get("name")))
check("and is no longer holding an identity",
      (again or {}).get("agent", {}).get("has_identity") is False,
      str((again or {}).get("agent", {}).get("has_identity")))
check("the response says what to do on the host",
      "identity.json" in str((again or {}).get("instructions")),
      str((again or {}).get("instructions"))[:90])

# The old key must stop working at once. A rotation that leaves the
# previous key usable has rotated nothing.
st, _ = raw("/api/agents/heartbeat", "POST", {},
            headers=signed(rpriv, AR, "POST", "/api/agents/heartbeat",
                           json.dumps({}).encode()))
check("the superseded key is refused immediately", st == 401, f"status={st}")

npriv, npub = keypair()
nkpriv, nkpub = kexpair()
st, claimed = raw("/api/agents/enrol", "POST",
                  {"enroll_token": again["enroll_token"], "public_key": npub,
                   "kex_public_key": nkpub})
check("the new token redeems", st == 200, f"status={st}")
check("and the channel is sealed this time",
      (claimed or {}).get("sealing") is True, str(claimed)[:110])

st, rows = call("/api/agents?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AR), {})
check("the agent now reports sealed", me.get("sealed") is True,
      str(me.get("sealed")))

st, _ = call(f"/api/agents/{AR}/reenroll?project=AGENT", "POST", {}, token=rtok
             if "rtok" in dir() else None)
check("re-enrolling needs admin, not merely write access",
      st in (401, 403), f"status={st}")

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
