"""Jaws agent enrolment, tasking, result delivery and adjudication.

The shape under test is the one an agent actually walks: enrol from the
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

print("== enrolment ==")
st, en = call("/api/agents?project=AGENT", "POST",
              {"name": "test-agent"}, token=admin)
check("enrol accepted", st == 201, f"status={st} {str(en)[:140]}")
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
check("enrol returns a one-time token", st == 201 and bool(en2.get("enrol_token")),
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
st, _ = raw("/api/agents/enrol", "POST",
            {"enrol_token": "not-the-token", "public_key": pub})
check("a wrong enrolment token is refused", st == 401, f"status={st}")
st, _ = raw("/api/agents/enrol", "POST",
            {"enrol_token": en2["enrol_token"], "public_key": "not-base64!!"})
check("a malformed public key is refused", st == 422, f"status={st}")

st, claimed = raw("/api/agents/enrol", "POST",
                  {"enrol_token": en2["enrol_token"], "public_key": pub})
check("the token exchanges for an identity", st == 200, f"status={st} {str(claimed)[:120]}")
check("and the agent learns which project it serves",
      (claimed or {}).get("project") == "AGENT", str(claimed)[:120])
check("and gets the same server key to pin",
      (claimed or {}).get("server_public_key") == en2["server_public_key"])

st, _ = raw("/api/agents/enrol", "POST",
            {"enrol_token": en2["enrol_token"], "public_key": pub})
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

print("== deleting must not quietly destroy evidence ==")
st, _ = call(f"/api/agents/{AID}/tasks/{TID}/import?project=AGENT", "POST",
             {"decisions": {"scanme.example.org": {"action": "add"}}}, token=admin)
st, err = call(f"/api/agents/{AID}?project=AGENT", "DELETE", token=admin)
check("delete is refused while tasks still hold tool output", st == 409,
      f"status={st} {str(err)[:90]}")
st, _ = call(f"/api/agents/{AID}?project=AGENT&force=true", "DELETE", token=admin)
check("and goes through when the loss is stated outright", st == 204, f"status={st}")

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
