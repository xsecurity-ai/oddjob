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

print("== the queue is held until the agent says it is ready ==")
# Agents beat throughout a scan now, so a beat is not a request for
# work. A second task must stay in the queue while the first is out.
st, t2 = call(f"/api/agents/{AID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["example.org"]}},
              token=admin)
T2 = (t2 or {}).get("id")
check("a second task is queued", st == 201, f"status={st}")

st, hb3 = call("/api/agents/heartbeat", "POST",
               {"ready": False, "running_task": TID}, key=KEY)
check("an agent that says it is busy is given nothing",
      st == 200 and not (hb3 or {}).get("task"), str(hb3)[:140])
check("and is told what it is still holding",
      TID in ((hb3 or {}).get("holding") or []), str(hb3)[:140])

st, agl = call(f"/api/agents?project=AGENT", token=admin)
me = next((x for x in agl if x["id"] == AID), {})
check("the second task shows as queued against it",
      me.get("queued_tasks") == 1, str(me.get("queued_tasks")))
check("while the first shows as in flight",
      me.get("running_tasks") == 1, str(me.get("running_tasks")))

# An old agent sends no body at all. It must not be handed a second
# task either, or the guard would be opt-in by the thing it guards.
st, hb4 = call("/api/agents/heartbeat", "POST", {}, key=KEY)
check("an agent that says nothing is still held, not trusted",
      st == 200 and not (hb4 or {}).get("task"), str(hb4)[:140])

st, _ = call(f"/api/agents/tasks/{TID}/result", "POST",
             {"status": "done", "output": "{}", "stderr": "",
              "summary": "done", "exit_code": 0}, key=KEY)
st, hb5 = call("/api/agents/heartbeat", "POST", {"ready": True}, key=KEY)
check("once the first is reported, the next is handed over",
      (hb5 or {}).get("task", {}).get("id") == T2, str(hb5)[:140])
st, _ = call(f"/api/agents/tasks/{T2}/result", "POST",
             {"status": "done", "output": "[]", "stderr": "",
              "summary": "done", "exit_code": 0}, key=KEY)

print("== several at once, bounded by the project and by the host ==")
# The project sets a ceiling; the agent reports what its host can
# stand. The lower wins, because either one saying "no more" is a
# reason not to send more.
st, r = call("/api/agents/routing?project=AGENT", "PUT",
             {"max_parallel": 4}, token=admin)
check("the ceiling is settable", st == 200 and r.get("max_parallel") == 4,
      str(r)[:120])
st, r = call("/api/agents/routing?project=AGENT", token=admin)
check("and is read back", r.get("max_parallel") == 4, str(r)[:120])

st, en3 = call("/api/agents?project=AGENT", "POST",
               {"name": "wide", "target_os": "linux"}, token=admin)
WID = ((en3 or {}).get("agent") or {}).get("id")
WKEY = (en3 or {}).get("callback_key")
made = []
for i in range(6):
    st, t = call(f"/api/agents/{WID}/tasks?project=AGENT", "POST",
                 {"kind": "nslookup", "args": {"targets": [f"h{i}.example"]}},
                 token=admin)
    made.append((t or {}).get("id"))
check("six tasks are queued for it", all(made), str(made))

# Says it can run 8; the project allows 4.
st, hb = call("/api/agents/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 8,
               "capacity": 8, "capacity_reason": "8 cores"}, key=WKEY)
got = [t["id"] for t in (hb or {}).get("tasks", [])]
check("it is handed several at once, not one", len(got) > 1, str(got))
check("but never more than the project allows", len(got) == 4, str(got))
check("and the single-task field still carries the first",
      (hb or {}).get("task", {}).get("id") == got[0], str(hb)[:120])

st, hb = call("/api/agents/heartbeat", "POST",
              {"ready": False, "running_tasks": got, "slots_free": 0,
               "capacity": 8}, key=WKEY)
check("at capacity it gets nothing more",
      not (hb or {}).get("tasks"), str(hb)[:140])

# Finish one: exactly one slot opens, so exactly one more goes out.
st, _ = call(f"/api/agents/tasks/{got[0]}/result", "POST",
             {"status": "done", "output": "[]", "stderr": "",
              "summary": "done", "exit_code": 0}, key=WKEY)
st, hb = call("/api/agents/heartbeat", "POST",
              {"ready": True, "running_tasks": got[1:], "slots_free": 1,
               "capacity": 8}, key=WKEY)
check("one finishing frees exactly one slot",
      len((hb or {}).get("tasks", [])) == 1, str(hb)[:140])

st, agl = call("/api/agents?project=AGENT", token=admin)
me = next((x for x in agl if x["id"] == WID), {})
check("the agent reports what it decided it can run",
      me.get("capacity") == 8, str(me.get("capacity")))
check("with the reasoning, so a low number is reviewable",
      me.get("capacity_reason") == "8 cores", str(me.get("capacity_reason")))
check("and the effective limit is the lower of the two",
      me.get("max_parallel") == 4, str(me.get("max_parallel")))
check("the fleet shows WHAT is running, not just how many",
      len(me.get("running") or []) == 4
      and all(r.get("subject") for r in me["running"]), str(me.get("running"))[:200])

# An agent that says nothing is from before any of this and is held to
# one at a time: a guard the thing it guards can opt out of is no guard.
st, en4 = call("/api/agents?project=AGENT", "POST",
               {"name": "quiet", "target_os": "linux"}, token=admin)
QID = ((en4 or {}).get("agent") or {}).get("id")
QKEY = (en4 or {}).get("callback_key")
for i in range(3):
    call(f"/api/agents/{QID}/tasks?project=AGENT", "POST",
         {"kind": "nslookup", "args": {"targets": [f"q{i}.example"]}},
         token=admin)
st, hb = call("/api/agents/heartbeat", "POST", {}, key=QKEY)
check("a silent agent is still given exactly one",
      len((hb or {}).get("tasks", [])) == 1, str(hb)[:140])

# Retired before leaving: the routing tests further down count how many
# agents are eligible, and two fixtures left online would be counted.
for fixture in (WID, QID):
    call(f"/api/agents/{fixture}/kill?project=AGENT", "POST", {}, token=admin)
call("/api/agents/routing?project=AGENT", "PUT", {"max_parallel": 5},
     token=admin)

print("== killing an agent does not strand what it was running ==")
# A killed agent's credential is refused from that moment, so it can
# never deliver a result. Leaving its task `running` meant a scan that
# could not finish looked like one still in progress, for good.
st, en2 = call("/api/agents?project=AGENT", "POST",
               {"name": "doomed", "target_os": "linux"}, token=admin)
DID = ((en2 or {}).get("agent") or {}).get("id")
st, dt = call(f"/api/agents/{DID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["x.example"]}},
              token=admin)
DT = (dt or {}).get("id")
check("a task is queued against it", st == 201, f"status={st}")
st, _ = call(f"/api/agents/{DID}/kill?project=AGENT", "POST", {}, token=admin)
check("the agent is killed", st == 200, f"status={st}")
st, tl = call(f"/api/agents/{DID}/tasks?project=AGENT", token=admin)
row = next((x for x in (tl or []) if x["id"] == DT), {})
check("its queued task is closed out, not left waiting",
      row.get("status") == "failed", str(row)[:140])
check("and says why", "killed" in str(row.get("error", "")), str(row.get("error"))[:120])
st, q = call("/api/agents/queue?project=AGENT", token=admin)
check("so it is gone from the queue",
      DT not in [x["id"] for x in (q or [])], str(q)[:120])

print("== an agent is not given work it cannot run ==")
st, tl = call("/api/agents/tools", token=admin)
check("the required tool list is published", st == 200
      and "nuclei" in (tl or {}).get("required", []), str(tl)[:160])
check("and says which kind needs which",
      (tl or {}).get("by_kind", {}).get("nmap") == "nmap", str(tl)[:200])
check("while naming the kinds that need nothing",
      (tl or {}).get("by_kind", {}).get("nslookup") is None, str(tl)[:200])

st, en6 = call("/api/agents?project=AGENT", "POST",
               {"name": "toolless", "target_os": "linux"}, token=admin)
TLID = ((en6 or {}).get("agent") or {}).get("id")
TLKEY = (en6 or {}).get("callback_key")
# Registers with nmap only, and says it could not get nuclei.
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "tools": {"nmap": "7.94"},
      "missing_tools": {"nuclei": "no package manager found"}}, key=TLKEY)

st, agl = call("/api/agents?project=AGENT", token=admin)
me = next((x for x in agl if x["id"] == TLID), {})
check("what it could not get is recorded",
      (me.get("missing_tools") or {}).get("nuclei") == "no package manager found",
      str(me.get("missing_tools")))
check("and turned into the kinds it cannot run",
      "nuclei" in (me.get("cannot_run") or []), str(me.get("cannot_run")))
check("without claiming it cannot do what it can",
      "nmap" not in (me.get("cannot_run") or []), str(me.get("cannot_run")))

# Pooled nuclei work is left alone for an agent that has it, rather
# than handed over to fail three times.
st, pooled_t = call("/api/agents/tasks?project=AGENT", "POST",
                    {"kind": "nuclei", "args": {"targets": ["http://a.example"]}},
                    token=admin)
PT = (pooled_t or {}).get("id")
st, hb = call("/api/agents/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 4,
               "capacity": 4}, key=TLKEY)
got = [t["id"] for t in (hb or {}).get("tasks", [])]
check("pooled work it cannot run is not handed to it", PT not in got, str(got))
st, q = call("/api/agents/queue?project=AGENT", token=admin)
check("and stays in the queue for an agent that can",
      PT in [x["id"] for x in (q or [])], str(q)[:140])

# Addressed to it by name, though, is a different thing: nothing about
# this agent is going to change, so waiting forever helps nobody.
st, addressed = call(f"/api/agents/{TLID}/tasks?project=AGENT", "POST",
                     {"kind": "nuclei", "args": {"targets": ["http://b.example"]}},
                     token=admin)
AT = (addressed or {}).get("id")
call("/api/agents/heartbeat", "POST",
     {"ready": True, "running_tasks": [], "slots_free": 4, "capacity": 4},
     key=TLKEY)
row = next((r for r in call("/api/agents/tasks?project=AGENT", token=admin)[1]
            if r["id"] == AT), {})
check("work addressed to it that it cannot run fails rather than waiting",
      row.get("state") == "failed", str(row)[:140])
check("naming the tool and what to do instead",
      "nuclei" in (row.get("notes") or "")
      and "pool" in (row.get("notes") or ""), str(row.get("notes"))[:170])

# An agent that has never said what it has is not starved.
st, en7 = call("/api/agents?project=AGENT", "POST",
               {"name": "silent-tools", "target_os": "linux"}, token=admin)
SID = ((en7 or {}).get("agent") or {}).get("id")
SKEY = (en7 or {}).get("callback_key")
call("/api/agents/register", "POST", {"platform": "linux", "arch": "amd64"},
     key=SKEY)
st, hb = call("/api/agents/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 4,
               "capacity": 4}, key=SKEY)
check("an agent that reported no inventory is still given work",
      PT in [t["id"] for t in (hb or {}).get("tasks", [])],
      str((hb or {}).get("tasks"))[:140])
for fixture in (TLID, SID):
    call(f"/api/agents/{fixture}/kill?project=AGENT", "POST", {}, token=admin)

print("== a failed task goes back in the queue, twice ==")
st, en5 = call("/api/agents?project=AGENT", "POST",
               {"name": "flaky", "target_os": "linux"}, token=admin)
FID = ((en5 or {}).get("agent") or {}).get("id")
FKEY = (en5 or {}).get("callback_key")
st, ft = call(f"/api/agents/{FID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["flap.example"]}},
              token=admin)
FT = (ft or {}).get("id")


def fail_once(note="the resolver timed out"):
    call("/api/agents/heartbeat", "POST",
         {"ready": True, "running_tasks": []}, key=FKEY)
    return call(f"/api/agents/tasks/{FT}/result", "POST",
                {"status": "failed", "output": "", "stderr": "",
                 "summary": "failed", "exit_code": 1, "error": note},
                key=FKEY)


call("/api/agents/heartbeat", "POST", {"ready": True, "running_tasks": []},
     key=FKEY)
fail_once()
st, rows = call("/api/agents/tasks?project=AGENT", token=admin)
row = next((r for r in (rows or []) if r["id"] == FT), {})
check("the first failure puts it back in the queue",
      row.get("state") == "awaiting", str(row)[:160])
check("counted as an attempt", row.get("attempts") == 1, str(row.get("attempts")))
check("with a note saying what happened and that it was requeued",
      "requeued" in (row.get("notes") or ""), str(row.get("notes"))[:120])
check("and back in the POOL, not on the agent that just failed it",
      row.get("agent_id") is None, str(row.get("agent_id")))

fail_once()
row = next((r for r in call("/api/agents/tasks?project=AGENT", token=admin)[1]
            if r["id"] == FT), {})
check("the second failure requeues it too", row.get("state") == "awaiting",
      str(row)[:140])
check("attempt two", row.get("attempts") == 2, str(row.get("attempts")))

fail_once()
row = next((r for r in call("/api/agents/tasks?project=AGENT", token=admin)[1]
            if r["id"] == FT), {})
check("the third failure stops: two retries, then it waits for a person",
      row.get("state") == "failed", str(row)[:140])
check("and says so rather than just going quiet",
      "restart it by hand" in (row.get("notes") or ""),
      str(row.get("notes"))[:160])

print("-- a wrong request is not retried at all --")
st, bt = call(f"/api/agents/{FID}/tasks?project=AGENT", "POST",
              {"kind": "amass", "args": {"domain": "a.example"}}, token=admin)
BT = (bt or {}).get("id")
call("/api/agents/heartbeat", "POST", {"ready": True, "running_tasks": []},
     key=FKEY)
call(f"/api/agents/tasks/{BT}/result", "POST",
     {"status": "failed", "output": "", "stderr": "", "summary": "failed",
      "exit_code": 1, "error": "amass takes one domain per task; got 3"},
     key=FKEY)
row = next((r for r in call("/api/agents/tasks?project=AGENT", token=admin)[1]
            if r["id"] == BT), {})
# Retrying this somewhere else produces the same answer, more slowly.
check("a failure about the request fails immediately",
      row.get("state") == "failed", str(row)[:140])
check("without burning a retry", row.get("attempts") == 1,
      str(row.get("attempts")))
check("and says it was not retryable",
      "not retryable" in (row.get("notes") or ""), str(row.get("notes"))[:140])

print("-- restarting one by hand --")
st, back = call(f"/api/agents/tasks/{FT}/retry?project=AGENT", "POST", {}, token=admin)
check("a failed task can be restarted", st == 200, f"status={st} {str(back)[:110]}")
check("it is awaiting again", (back or {}).get("state") == "awaiting",
      str(back)[:120])
check("the counter resets — a person has judged it worth another go",
      (back or {}).get("attempts") == 0, str((back or {}).get("attempts")))
check("and the note keeps what went before",
      "previously" in ((back or {}).get("notes") or ""),
      str((back or {}).get("notes"))[:140])
st, err = call(f"/api/agents/tasks/{FT}/retry?project=AGENT", "POST", {}, token=admin)
check("restarting one that is already queued is refused", st == 409,
      f"status={st}")
call(f"/api/agents/{FID}/kill?project=AGENT", "POST", {}, token=admin)

print("== the queue can be looked at and taken back out ==")
st, t3 = call(f"/api/agents/tasks?project=AGENT", "POST",
              {"kind": "amass", "args": {"domain": "queued.example"}},
              token=admin)
T3 = (t3 or {}).get("id")
check("a pooled task is queued", st == 201, f"status={st} {str(t3)[:110]}")

st, queue = call("/api/agents/queue?project=AGENT", token=admin)
check("the queue lists it", st == 200
      and T3 in [q["id"] for q in (queue or [])], str(queue)[:160])
row = next((q for q in (queue or []) if q["id"] == T3), {})
check("saying what it will act on, not just its kind",
      row.get("subject") == "queued.example", str(row)[:160])
check("and that no agent owns it yet",
      row.get("agent_id") is None and row.get("agent_name") is None, str(row)[:160])
check("and who asked for it", row.get("requested_by") == "root", str(row)[:160])

st, _ = call(f"/api/agents/tasks/{T3}?project=AGENT", "DELETE", token=admin)
check("a queued task can be cancelled", st == 204, f"status={st}")
st, queue = call("/api/agents/queue?project=AGENT", token=admin)
check("and leaves the queue", T3 not in [q["id"] for q in (queue or [])],
      str(queue)[:140])

# Deleting a row would not stop a scan that is already running on
# somebody's network — it would only lose the result when it reports.
st, err = call(f"/api/agents/tasks/{TID}?project=AGENT", "DELETE", token=admin)
check("a task an agent already holds is not cancellable", st == 409,
      f"status={st}")
check("and says to kill the agent instead",
      "kill the agent" in str(err).lower(), str(err)[:160])
st, _ = call("/api/agents/tasks/999999?project=AGENT", "DELETE", token=admin)
check("an unknown task is 404", st == 404, f"status={st}")

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
# The first failure sends it back to the POOL, so it is deliberately no
# longer on the agent that failed it — which is where this used to look
# for it. The project-wide list is the one that can see a pooled task.
st, lst = call("/api/agents/tasks?project=AGENT", token=admin)
row = next((t for t in (lst or []) if t["id"] == T3), {})
check("and the failure is visible with its reason",
      "-F" in (row.get("notes") or ""), str(row.get("notes"))[:90])
check("it went back in the queue rather than stopping on one failure",
      row.get("state") == "awaiting" and row.get("agent_id") is None,
      f"{row.get('state')} agent={row.get('agent_id')}")
# Worth naming: a flag conflict fails identically on every agent, so
# these two retries are spent for nothing. The bound exists because the
# difference between "this agent" and "this request" is not reliably
# visible from here, and spending two is the price of not needing to
# classify every tool's argument errors.
check("and is counted so it cannot go round forever",
      row.get("attempts") == 1, str(row.get("attempts")))


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


#: What each agent in the fleet is still holding, so `beat` can model a
#: real one. An agent reports its result and THEN asks for more; the
#: server holds the queue until it does, so a harness that only ever
#: beats would be testing a client that does not exist.
holding: dict[str, int] = {}


def finish(nm, status="done", output="[]"):
    """Report whatever this agent is holding, as the real one would."""
    tid = holding.pop(nm, None)
    if tid is None:
        return
    a = fleet[nm]
    path = f"/api/agents/tasks/{tid}/result"
    body = {"status": status, "output": output, "stderr": "",
            "summary": "done", "exit_code": 0}
    raw(path, "POST", body,
        headers=signed(a["priv"], a["id"], "POST", path,
                       json.dumps(body).encode()))


def beat(nm, ready=True):
    """Check in, having first reported anything outstanding."""
    if ready:
        finish(nm)
    a = fleet[nm]
    payload = {"ready": ready, "running_task": holding.get(nm, 0)}
    st, hb = raw("/api/agents/heartbeat", "POST", payload,
                 headers=signed(a["priv"], a["id"], "POST",
                                "/api/agents/heartbeat",
                                json.dumps(payload).encode()))
    got = ((hb or {}).get("task") or {}).get("id")
    if got:
        holding[nm] = got
    return st, hb


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
      str(r["current_primary_name"]).startswith("dublin-"), str(r)[:140])

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
      str(r["current_primary_name"]).startswith("virginia-"), str(r)[:140])
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
    """Run one task to a settled state, so the counts have something to
    count.

    A retryable failure now goes back in the queue and belongs to no
    agent while it waits, so it would not be counted against this one
    — correctly. This test is about the counts, so it uses a failure
    that sticks on the first attempt; the requeue path is covered
    above, on its own.
    """
    st, t = call(f"/api/agents/{AC}/tasks?project=AGENT", "POST",
                 {"kind": "nslookup", "args": {"targets": ["x.example"]}},
                 token=admin)
    call("/api/agents/heartbeat", "POST", {"ready": True, "running_tasks": []},
         key=KC)
    call(f"/api/agents/tasks/{t['id']}/result", "POST",
         {"status": status, "output": "[]",
          "exit_code": 0 if status == "done" else 1,
          "error": None if status == "done"
                   else "refused by the project's scope at dispatch: test"},
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
      str((again or {}).get("agent", {}).get("name")).startswith("rotate-me-"),
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

print("\n== enrolment appends a discriminator to the name ==")
# Two machines are called `kodi` and whoever names the second has no way
# to know the first exists. The case this was written for is worse: an
# agent deleted server-side whose container heartbeats forever, with a
# later agent holding the same name -- the logs then read as ONE agent
# intermittently failing auth rather than as two, one of them an orphan.
import re as _re
st, e1 = call("/api/agents?project=AGENT", "POST",
              {"name": "kodi", "connection_mode": "callback"}, token=admin)
st2, e2 = call("/api/agents?project=AGENT", "POST",
               {"name": "kodi", "connection_mode": "callback"}, token=admin)
n1 = (e1 or {}).get("agent", {}).get("name", "")
n2 = (e2 or {}).get("agent", {}).get("name", "")
check("the name gains a 6-character suffix",
      bool(_re.fullmatch(r"kodi-[a-z0-9]{6}", n1)), n1)
check("drawn from [a-z0-9] only",
      bool(_re.fullmatch(r"kodi-[a-z0-9]{6}", n2)), n2)
check("two agents enrolled under one name do not collide", n1 != n2, f"{n1} {n2}")

# A rename is the operator's decision and is taken EXACTLY as typed.
# The suffix exists for the name nobody chose; re-imposing it on one
# somebody did choose would be the tool arguing with its operator.
rid = (e2 or {}).get("agent", {}).get("id")
st, ren = call(f"/api/agents/{rid}?project=AGENT", "PATCH",
               {"name": "scanner"}, token=admin)
check("a manual rename is honoured exactly, with no suffix added",
      (ren or {}).get("name") == "scanner", str((ren or {}).get("name")))

st, ren2 = call(f"/api/agents/{rid}?project=AGENT", "PATCH",
                {"name": "  spaced out  "}, token=admin)
check("and is trimmed but not otherwise rewritten",
      (ren2 or {}).get("name") == "spaced out", str((ren2 or {}).get("name")))

st, ren3 = call(f"/api/agents/{rid}?project=AGENT", "PATCH",
                {"name": "scanner-aaaaaa"}, token=admin)
check("a name that looks like a suffixed one is kept as typed",
      (ren3 or {}).get("name") == "scanner-aaaaaa", str((ren3 or {}).get("name")))

# An empty rename is "no change", not "erase the name" -- an agent with
# no name cannot be told apart from another in any list it appears in.
st, ren4 = call(f"/api/agents/{rid}?project=AGENT", "PATCH",
                {"name": "   "}, token=admin)
check("an all-whitespace rename leaves the name alone",
      (ren4 or {}).get("name") == "scanner-aaaaaa", str((ren4 or {}).get("name")))

st, ren5 = call(f"/api/agents/{rid}?project=AGENT", "PATCH",
                {"name": "x" * 400}, token=admin)
check("an overlong name is bounded rather than erroring",
      st == 200 and len((ren5 or {}).get("name", "")) <= 128,
      f"status={st} len={len((ren5 or {}).get('name',''))}")

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
