"""Ghost agent enrollment, tasking, result delivery and adjudication.

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
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request

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
    if key: r.add_header("X-Ghost-Key", key)
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
st, en = call("/api/ghosts?project=AGENT", "POST",
              {"name": "test-agent"}, token=admin)
check("enroll accepted", st == 201, f"status={st} {str(en)[:140]}")
KEY = (en or {}).get("callback_key")
AID = ((en or {}).get("agent") or {}).get("id")
check("a callback key is issued once, in the clear",
      isinstance(KEY, str) and len(KEY) > 20)
check("and a separate call-in key, so the two directions are not one secret",
      isinstance((en or {}).get("call_in_key"), str)
      and (en or {}).get("call_in_key") != KEY)

st, again = call("/api/ghosts?project=AGENT", "GET", token=admin)
check("the keys are not readable afterwards",
      st == 200 and not any(k in json.dumps(again)
                            for k in (KEY, (en or {}).get("call_in_key"))),
      str(again)[:120])

print("== the key is the credential ==")
st, _ = call("/api/ghosts/heartbeat", "POST", {}, key="not-a-real-key")
check("a wrong agent key is refused", st in (401, 403), f"status={st}")
st, _ = call("/api/ghosts/heartbeat", "POST", {})
check("no agent key is refused", st in (401, 403), f"status={st}")

st, reg = call("/api/ghosts/register", "POST",
               {"platform": "linux", "arch": "amd64", "version": "test",
                "hostname": "droplet", "privileged": True,
                "tools": {"nmap": "7.94"}}, key=KEY)
check("register with the key works", st == 200, f"status={st} {str(reg)[:120]}")

print("== tasking ==")

print("== a host that cannot hold a task is not given it ==")
# A free slot is not the same as the memory one task of a given kind
# needs. nuclei peaks at 185 MB merely COMPILING its template set,
# before a request is sent, so a 458 MB droplet reporting 143 MB
# available cannot run it however gently it is paced -- `-c 1` does
# not move a template-loading cost. It flattened that host twice.
#
# Skipped BEFORE claiming, on purpose: declining afterwards returns
# the task to the pool for the same small host to take again, which
# is a livelock rather than a retry.
# The agent must HAVE nuclei, or `_has_tool` refuses the task and
# this passes without ever reaching the affordability gate. Proved
# by mutation: with the gate removed the check still went green,
# because the fixture registered only nmap.
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "version": "test",
      "hostname": "droplet", "privileged": True,
      "tools": {"nmap": "7.94", "nuclei": "3.11.1"}}, key=KEY)

st, nt = call("/api/ghosts/tasks?project=AGENT", "POST",
              {"kind": "nuclei", "args": {"targets": ["https://a.acme.example/"]}},
              token=admin)
NT = (nt or {}).get("id")
check("a pooled nuclei task is queued", st == 201, f"status={st}")

st, hbu = call("/api/ghosts/heartbeat", "POST",
               {"ready": True, "slots_free": 4,
                "unaffordable": ["nuclei", "nuclei_tech"]}, key=KEY)
_wrong = (hbu or {}).get("task") or {}
check("an agent that cannot afford nuclei is not handed it",
      st == 200 and not _wrong, str(hbu)[:160])
# If the gate ever breaks, hand the task straight back rather than
# leaving this agent holding it: a failing check should fail, not
# take the three hundred after it down with a cascade. Found by
# mutating the gate away and watching the suite abort instead of go
# red.
if _wrong.get("id"):
    call(f"/api/ghosts/tasks/{_wrong['id']}/result", "POST",
         {"status": "done", "output": "{}", "stderr": "",
          "summary": "handed back by the test", "exit_code": 0}, key=KEY)

# And it must still be USEFUL. Refusing one kind is not a reason to
# idle a host that can perfectly well run the light tools -- that is
# how a small agent goes from constrained to pointless.
st, lt = call("/api/ghosts/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["light.example"]}},
              token=admin)
check("a light task is queued", st == 201, f"status={st}")
st, hbl = call("/api/ghosts/heartbeat", "POST",
               {"ready": True, "slots_free": 4,
                "unaffordable": ["nuclei", "nuclei_tech"]}, key=KEY)
_light = (hbl or {}).get("task") or {}
check("...but it is still given work it CAN hold",
      st == 200 and _light.get("kind") == "nslookup", str(hbl)[:160])

# Finished, so the agent is idle again. This block runs before the
# rest of the suite tasks it, and an agent still holding something
# has no free slot -- which would make the next test fail for a
# reason that has nothing to do with what it is checking.
if _light.get("id"):
    call(f"/api/ghosts/tasks/{_light['id']}/result", "POST",
         {"status": "done", "output": "{}", "stderr": "",
          "summary": "done", "exit_code": 0}, key=KEY)

# The nuclei task is untouched -- still queued for an agent that can
# take it, not failed and not counted as an attempt.
st, allrows = call("/api/ghosts/tasks?project=AGENT", token=admin)
row = next((r for r in (allrows or []) if r.get("id") == NT), {})
# `raw_status`, not `status`: this endpoint reports a friendly
# `state` ("awaiting") alongside the database value, and reading the
# wrong one passes None against a string for ever.
check("the refused task is still queued, not failed",
      row.get("raw_status") == "queued", str(row)[:140])
check("...and no attempt was spent on it",
      (row.get("attempts") or 0) == 0, str(row.get("attempts")))

# Removed again, deliberately. Leaving a queued task behind changes
# what the dispatcher offers next, and that broke an order-sensitive
# check further down the suite -- a test that perturbs the fixture is
# a test that makes the next one lie.
call(f"/api/ghosts/tasks/{NT}", "DELETE", token=admin)

st, _ = call(f"/api/ghosts/{AID}/tasks?project=AGENT", "POST",
             {"kind": "definitely-not-a-tool", "args": {}}, token=admin)
check("an unknown kind is refused by the server, not the agent", st == 422,
      f"status={st}")

st, _ = call(f"/api/ghosts/{AID}/tasks?project=AGENT", "POST",
             {"kind": "install", "args": {"tools": ["nmap; rm -rf /"]}},
             token=admin)
check("install refuses anything off the allowlist", st == 422, f"status={st}")

st, task = call(f"/api/ghosts/{AID}/tasks?project=AGENT", "POST",
                {"kind": "nmap",
                 "args": {"targets": ["scanme.example.org"], "ports": "22,80,9929"}},
                token=admin)
check("task queued", st == 201, f"status={st} {str(task)[:140]}")
TID = (task or {}).get("id")
check("nmap tasks import as nmap", (task or {}).get("import_as") == "nmap",
      str((task or {}).get("import_as")))

st, hb = call("/api/ghosts/heartbeat", "POST", {}, key=KEY)
check("heartbeat hands over the queued task",
      st == 200 and (hb or {}).get("task", {}).get("id") == TID, str(hb)[:140])

st, hb2 = call("/api/ghosts/heartbeat", "POST", {}, key=KEY)
check("a claimed task is not handed out twice",
      st == 200 and not (hb2 or {}).get("task"), str(hb2)[:140])

print("== the queue is held until the agent says it is ready ==")
# Agents beat throughout a scan now, so a beat is not a request for
# work. A second task must stay in the queue while the first is out.
st, t2 = call(f"/api/ghosts/{AID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["example.org"]}},
              token=admin)
T2 = (t2 or {}).get("id")
check("a second task is queued", st == 201, f"status={st}")

st, hb3 = call("/api/ghosts/heartbeat", "POST",
               {"ready": False, "running_task": TID}, key=KEY)
check("an agent that says it is busy is given nothing",
      st == 200 and not (hb3 or {}).get("task"), str(hb3)[:140])
check("and is told what it is still holding",
      TID in ((hb3 or {}).get("holding") or []), str(hb3)[:140])

st, agl = call("/api/ghosts?project=AGENT", token=admin)
me = next((x for x in agl if x["id"] == AID), {})
check("the second task shows as queued against it",
      me.get("queued_tasks") == 1, str(me.get("queued_tasks")))
check("while the first shows as in flight",
      me.get("running_tasks") == 1, str(me.get("running_tasks")))

# An old agent sends no body at all. It must not be handed a second
# task either, or the guard would be opt-in by the thing it guards.
st, hb4 = call("/api/ghosts/heartbeat", "POST", {}, key=KEY)
check("an agent that says nothing is still held, not trusted",
      st == 200 and not (hb4 or {}).get("task"), str(hb4)[:140])

st, _ = call(f"/api/ghosts/tasks/{TID}/result", "POST",
             {"status": "done", "output": "{}", "stderr": "",
              "summary": "done", "exit_code": 0}, key=KEY)
st, hb5 = call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=KEY)
check("once the first is reported, the next is handed over",
      (hb5 or {}).get("task", {}).get("id") == T2, str(hb5)[:140])
st, _ = call(f"/api/ghosts/tasks/{T2}/result", "POST",
             {"status": "done", "output": "[]", "stderr": "",
              "summary": "done", "exit_code": 0}, key=KEY)

print("== several at once, bounded by the project and by the host ==")
# The project sets a ceiling; the agent reports what its host can
# stand. The lower wins, because either one saying "no more" is a
# reason not to send more.
st, r = call("/api/ghosts/routing?project=AGENT", "PUT",
             {"max_parallel": 4}, token=admin)
check("the ceiling is settable", st == 200 and r.get("max_parallel") == 4,
      str(r)[:120])
st, r = call("/api/ghosts/routing?project=AGENT", token=admin)
check("and is read back", r.get("max_parallel") == 4, str(r)[:120])

# A queue depth on its own cannot answer "is anything happening", and
# that is the question an operator actually asks. 416 queued beside 8
# running reads as stalled on a fleet that was finishing 377 tasks an
# hour -- the median task was 25 seconds, so the rows churned faster
# than anyone could watch. Routing carries the rate so the page can
# show a direction rather than a number.
check("routing reports what is running now",
      "running_tasks" in r, sorted(r.keys()))
check("...and what finished in the last hour, which is a RATE",
      "completed_last_hour" in r, sorted(r.keys()))
# A lifetime total would climb whether or not anything had happened
# since the last look, which is the opposite of what is being asked.
check("both are integers, and start at zero on a quiet project",
      isinstance(r.get("running_tasks"), int)
      and isinstance(r.get("completed_last_hour"), int),
      (r.get("running_tasks"), r.get("completed_last_hour")))

st, en3 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "wide", "target_os": "linux"}, token=admin)
WID = ((en3 or {}).get("agent") or {}).get("id")
WKEY = (en3 or {}).get("callback_key")
made = []
for i in range(6):
    st, t = call(f"/api/ghosts/{WID}/tasks?project=AGENT", "POST",
                 {"kind": "nslookup", "args": {"targets": [f"h{i}.example"]}},
                 token=admin)
    made.append((t or {}).get("id"))
check("six tasks are queued for it", all(made), str(made))

# Says it can run 8; the project allows 4.
st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 8,
               "capacity": 8, "capacity_reason": "8 cores"}, key=WKEY)
got = [t["id"] for t in (hb or {}).get("tasks", [])]
check("it is handed several at once, not one", len(got) > 1, str(got))
check("but never more than the project allows", len(got) == 4, str(got))
check("and the single-task field still carries the first",
      (hb or {}).get("task", {}).get("id") == got[0], str(hb)[:120])

st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": False, "running_tasks": got, "slots_free": 0,
               "capacity": 8}, key=WKEY)
check("at capacity it gets nothing more",
      not (hb or {}).get("tasks"), str(hb)[:140])

# Finish one: exactly one slot opens, so exactly one more goes out.
st, _ = call(f"/api/ghosts/tasks/{got[0]}/result", "POST",
             {"status": "done", "output": "[]", "stderr": "",
              "summary": "done", "exit_code": 0}, key=WKEY)
st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": got[1:], "slots_free": 1,
               "capacity": 8}, key=WKEY)
check("one finishing frees exactly one slot",
      len((hb or {}).get("tasks", [])) == 1, str(hb)[:140])

st, agl = call("/api/ghosts?project=AGENT", token=admin)
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

print("\n== an operator can set one ghost's parallelism ==")
# Its own project. Enrolling agents into AGENT perturbs the fleet
# counts a later section asserts on, and a test that breaks a distant
# one is worse than a longer setup here.
call("/api/projects", "POST", {"code": "OVR", "name": "Override"}, token=admin)
_st, _rt = call("/api/ghosts/routing?project=OVR", "PUT",
                {"max_parallel": 4}, token=admin)
check("the engagement ceiling is set for this section",
      (_rt or {}).get("max_parallel") == 4, f"{_st} {str(_rt)[:100]}")


def _ovr_agent(name):
    st, en = call("/api/ghosts?project=OVR", "POST",
                  {"name": name, "target_os": "linux"}, token=admin)
    return ((en or {}).get("agent") or {}).get("id"), (en or {}).get("callback_key")


OID, OKEY = _ovr_agent("override")
for _i in range(8):
    call(f"/api/ghosts/{OID}/tasks?project=OVR", "POST",
         {"kind": "nslookup", "args": {"targets": [f"ov{_i}.example"]}},
         token=admin)

# Three numbers: the agent says 1, the engagement allows 4, and an
# operator is about to say this particular box should do more.
st, r = call(f"/api/ghosts/{OID}?project=OVR", "PATCH",
             {"parallel_override": 2}, token=admin)
check("the override is settable per ghost", st == 200, f"{st} {str(r)[:120]}")
check("...and reported as the operator's number, not the result",
      (r or {}).get("parallel_override") == 2, str(r)[:160])
check("...and the effective number follows it",
      (r or {}).get("max_parallel") == 2, str(r)[:160])

# Above what the agent thinks: the operator wins, because one who sets
# 8 and sees 1 with no explanation concludes the control is broken.
st, r = call(f"/api/ghosts/{OID}?project=OVR", "PATCH",
             {"parallel_override": 8}, token=admin)
check("an override above the agent's own assessment is honoured",
      (r or {}).get("parallel_override") == 8, str(r)[:160])
# ...but the engagement ceiling is about the CLIENT, not the box, and
# no per-ghost number talks its way past it.
check("the engagement ceiling still applies on top",
      (r or {}).get("max_parallel") == 4, str(r)[:160])

# The part that makes it take effect at all. The agent computes
# `slots_free` from its OWN capacity, so honouring that while an
# override is set clamps the override back to what the agent already
# believed: the setting moves in the database and nothing happens.
st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 1,
               "capacity": 1, "capacity_reason": "1 core"}, key=OKEY)
check("a stale slots_free does not clamp the override",
      len((hb or {}).get("tasks", [])) == 4,
      f'{len((hb or {}).get("tasks", []))} task(s)')
check("and the effective number goes down so the agent agrees next time",
      (hb or {}).get("max_parallel") == 4, str(hb)[:160])

st, r = call(f"/api/ghosts/{OID}?project=OVR", "PATCH",
             {"parallel_override": 0}, token=admin)
check("zero hands the decision back to the agent",
      (r or {}).get("parallel_override") is None, str(r)[:160])
check("...and the agent's own assessment governs again",
      (r or {}).get("max_parallel") == 1, str(r)[:160])

st, _ = call(f"/api/ghosts/{OID}?project=OVR", "PATCH",
             {"parallel_override": 999}, token=admin)
check("an absurd number is refused rather than stored", st == 422, st)

# The behaviour this must not have broken: with no override, the
# agent's own count is still what the dispatcher honours.
SID, SKEY = _ovr_agent("selfpaced")
for _i in range(4):
    call(f"/api/ghosts/{SID}/tasks?project=OVR", "POST",
         {"kind": "nslookup", "args": {"targets": [f"sp{_i}.example"]}},
         token=admin)
st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 1,
               "capacity": 1, "capacity_reason": "1 core"}, key=SKEY)
check("with no override the agent's own count still governs",
      len((hb or {}).get("tasks", [])) == 1,
      f'{len((hb or {}).get("tasks", []))} task(s)')

# An agent that says nothing is from before any of this and is held to
# one at a time: a guard the thing it guards can opt out of is no guard.
st, en4 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "quiet", "target_os": "linux"}, token=admin)
QID = ((en4 or {}).get("agent") or {}).get("id")
QKEY = (en4 or {}).get("callback_key")
for i in range(3):
    call(f"/api/ghosts/{QID}/tasks?project=AGENT", "POST",
         {"kind": "nslookup", "args": {"targets": [f"q{i}.example"]}},
         token=admin)
st, hb = call("/api/ghosts/heartbeat", "POST", {}, key=QKEY)
check("a silent agent is still given exactly one",
      len((hb or {}).get("tasks", [])) == 1, str(hb)[:140])

# Retired before leaving: the routing tests further down count how many
# agents are eligible, and two fixtures left online would be counted.
for fixture in (WID, QID):
    call(f"/api/ghosts/{fixture}/kill?project=AGENT", "POST", {}, token=admin)
call("/api/ghosts/routing?project=AGENT", "PUT", {"max_parallel": 5},
     token=admin)

print("== killing an agent does not strand what it was running ==")
# A killed agent's credential is refused from that moment, so it can
# never deliver a result. Leaving its task `running` meant a scan that
# could not finish looked like one still in progress, for good.
st, en2 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "doomed", "target_os": "linux"}, token=admin)
DID = ((en2 or {}).get("agent") or {}).get("id")
st, dt = call(f"/api/ghosts/{DID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["x.example"]}},
              token=admin)
DT = (dt or {}).get("id")
check("a task is queued against it", st == 201, f"status={st}")
st, _ = call(f"/api/ghosts/{DID}/kill?project=AGENT", "POST", {}, token=admin)
check("the agent is killed", st == 200, f"status={st}")
st, tl = call(f"/api/ghosts/{DID}/tasks?project=AGENT", token=admin)
row = next((x for x in (tl or []) if x["id"] == DT), {})
check("its queued task is closed out, not left waiting",
      row.get("status") == "failed", str(row)[:140])
check("and says why", "killed" in str(row.get("error", "")), str(row.get("error"))[:120])
st, q = call("/api/ghosts/queue?project=AGENT", token=admin)
check("so it is gone from the queue",
      DT not in [x["id"] for x in (q or [])], str(q)[:120])

print("== one task per target, created in one request ==")
# A single task holding 1,738 names is one unit of work: one Ghost does
# all of it, a failure anywhere loses the lot, and the queue depth says
# 1 when there are 1,738 things to do.
st, r = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
             {"kind": "nslookup",
              "subjects": ["a.example", "b.example", "c.example",
                           "a.example"]},   # the duplicate is dropped
             token=admin)
check("a bulk create is accepted", st == 201, f"status={st} {str(r)[:120]}")
check("one task per target, deduplicated",
      (r or {}).get("queued") == 3, str(r)[:140])

st, rows = call("/api/ghosts/tasks?project=AGENT", token=admin)
mine = [x for x in (rows or []) if x["id"] in set((r or {}).get("ids", []))]
check("each task carries exactly one target",
      all(x["subject"] in ("a.example", "b.example", "c.example") for x in mine)
      and len(mine) == 3, str([x["subject"] for x in mine]))
check("and they are pooled, so the fleet can share them",
      all(x["agent_id"] is None for x in mine), str(mine)[:140])

# One target out of scope is not a reason to refuse the other 1,737.
call("/api/projects", "POST",
     {"code": "BULKSCOPE", "name": "Bulk scope",
      "scope": ["10.9.0.0/24", "!10.9.0.5"]}, token=admin)
st, r = call("/api/ghosts/tasks/bulk?project=BULKSCOPE", "POST",
             {"kind": "nmap", "subjects": ["10.9.0.4", "10.9.0.5", "10.9.0.6"]},
             token=admin)
check("the in-scope targets are queued", (r or {}).get("queued") == 2, str(r)[:140])
check("and the excluded one is refused by name, not as an error",
      "10.9.0.5" in ((r or {}).get("refused") or {}), str(r)[:180])

st, r = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
             {"kind": "nonsense", "subjects": ["a.example"]}, token=admin)
check("an unknown kind is still refused", st == 422, f"status={st}")
st, r = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
             {"kind": "install", "subjects": ["nmap"]}, token=admin)
check("install is not a per-subject kind", st == 422, f"status={st}")

print("== queuing work shows up on the target's own timeline ==")
# A target's timeline is meant to be the whole story of what was done
# to that host. It had the results and not the asking, so "was this
# ever scanned, and with what?" could only be answered from the task
# table by someone who knew to look there.
call("/api/projects", "POST",
     {"code": "TLINE", "name": "Timeline"}, token=admin)
call("/api/targets?project=TLINE", "POST",
     {"host": "timeline.acme.example"}, token=admin)
st, _ = call("/api/ghosts/tasks?project=TLINE", "POST",
             {"kind": "nmap", "args": {"targets": ["timeline.acme.example"],
                                       "ports": "80,443"}}, token=admin)
check("the task is queued", st == 201, f"status={st}")

st, tl = call("/api/targets/TLINE/timeline.acme.example/timeline", token=admin)
evs = tl if isinstance(tl, list) else (tl or {}).get("items", [])
blob = json.dumps(evs)
check("the target's timeline records it", "nmap queued" in blob, blob[:200])
check("with the ports it will actually use", "80,443" in blob, blob[:200])
check("and that no Ghost owns it yet", "project pool" in blob, blob[:200])
check("attributed to whoever asked", "root" in blob, blob[:160])

# Recorded at QUEUE time: a scan that was started and never came back
# is exactly the case where you want to know it was started.
st, rows = call("/api/ghosts/tasks?project=TLINE", token=admin)
mine = [r for r in (rows or []) if r["subject"] == "timeline.acme.example"]
check("while the task itself is still only queued",
      mine and mine[0]["state"] == "awaiting", str(mine)[:120])

# Bulk goes on each target's own timeline, not one shared entry.
for h in ("bulk-a.acme.example", "bulk-b.acme.example"):
    call("/api/targets?project=TLINE", "POST", {"host": h}, token=admin)
call("/api/ghosts/tasks/bulk?project=TLINE", "POST",
     {"kind": "nslookup",
      "subjects": ["bulk-a.acme.example", "bulk-b.acme.example"]},
     token=admin)
for h in ("bulk-a.acme.example", "bulk-b.acme.example"):
    st, tl = call(f"/api/targets/TLINE/{h}/timeline", token=admin)
    evs = tl if isinstance(tl, list) else (tl or {}).get("items", [])
    check(f"{h} has its own entry",
          "nslookup queued" in json.dumps(evs), json.dumps(evs)[:120])

# A task against something the project does not hold has no timeline
# to write to, and inventing one would be inventing a target.
before = call("/api/targets?project=TLINE&page_size=500", token=admin)[1]["total"]
call("/api/ghosts/tasks?project=TLINE", "POST",
     {"kind": "nmap", "args": {"targets": ["203.0.113.0/24"]}}, token=admin)
after = call("/api/targets?project=TLINE&page_size=500", token=admin)[1]["total"]
check("a task against a range invents no target", before == after,
      f"{before} -> {after}")

print("== reverse lookups are handed the names to resolve ==")
# DNS cannot be asked which names point at an address, only where a
# given name points. So the server supplies the project's own names and
# the agent keeps the ones that land on the address. Attached when the
# task is HANDED OUT, not when it is queued: one task per address means
# storing the same list once per task otherwise.
st, en8 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "revlookup", "target_os": "linux"}, token=admin)
RID = ((en8 or {}).get("agent") or {}).get("id")
RKEY = (en8 or {}).get("callback_key")
call("/api/ghosts/register", "POST", {"platform": "linux", "arch": "amd64"},
     key=RKEY)
call("/api/targets?project=AGENT", "POST",
     {"host": "known-one.acme.example"}, token=admin)
call("/api/targets?project=AGENT", "POST",
     {"host": "known-two.acme.example"}, token=admin)

st, rt = call(f"/api/ghosts/{RID}/tasks?project=AGENT", "POST",
              {"kind": "reverse_ip", "args": {"targets": ["198.51.100.77"]}},
              token=admin)
RT = (rt or {}).get("id")
check("a reverse lookup is queued", st == 201, f"status={st}")

st, stored = call(f"/api/ghosts/{RID}/tasks?project=AGENT", token=admin)
row = next((x for x in (stored or []) if x["id"] == RT), {})
check("the stored arguments do NOT carry the candidate list",
      "candidates" not in (row.get("args") or {}), str(row.get("args"))[:120])

st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 2,
               "capacity": 2}, key=RKEY)
handed = next((t for t in (hb or {}).get("tasks", []) if t["id"] == RT), {})
cands = (handed.get("args") or {}).get("candidates") or []
check("but the agent is handed them when it takes the task",
      len(cands) >= 2, f"{len(cands)} candidate(s)")
check("and they are the project's own names",
      "known-one.acme.example" in cands and "known-two.acme.example" in cands,
      str(cands[:4]))
check("addresses are not offered as names to resolve",
      not any(c.replace(".", "").isdigit() for c in cands), str(cands[:4]))
call(f"/api/ghosts/{RID}/kill?project=AGENT", "POST", {}, token=admin)

print("== an agent is not given work it cannot run ==")
st, tl = call("/api/ghosts/tools", token=admin)
check("the required tool list is published", st == 200
      and "nuclei" in (tl or {}).get("required", []), str(tl)[:160])
check("and says which kind needs which",
      (tl or {}).get("by_kind", {}).get("nmap") == "nmap", str(tl)[:200])
check("while naming the kinds that need nothing",
      (tl or {}).get("by_kind", {}).get("nslookup") is None, str(tl)[:200])

st, en6 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "toolless", "target_os": "linux"}, token=admin)
TLID = ((en6 or {}).get("agent") or {}).get("id")
TLKEY = (en6 or {}).get("callback_key")
# Registers with nmap only, and says it could not get nuclei.
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "tools": {"nmap": "7.94"},
      "missing_tools": {"nuclei": "no package manager found"}}, key=TLKEY)

st, agl = call("/api/ghosts?project=AGENT", token=admin)
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
st, pooled_t = call("/api/ghosts/tasks?project=AGENT", "POST",
                    {"kind": "nuclei", "args": {"targets": ["http://a.example"]}},
                    token=admin)
PT = (pooled_t or {}).get("id")
st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 4,
               "capacity": 4}, key=TLKEY)
got = [t["id"] for t in (hb or {}).get("tasks", [])]
check("pooled work it cannot run is not handed to it", PT not in got, str(got))
st, q = call("/api/ghosts/queue?project=AGENT", token=admin)
check("and stays in the queue for an agent that can",
      PT in [x["id"] for x in (q or [])], str(q)[:140])

# Addressed to it by name, though, is a different thing: nothing about
# this agent is going to change, so waiting forever helps nobody.
st, addressed = call(f"/api/ghosts/{TLID}/tasks?project=AGENT", "POST",
                     {"kind": "nuclei", "args": {"targets": ["http://b.example"]}},
                     token=admin)
AT = (addressed or {}).get("id")
call("/api/ghosts/heartbeat", "POST",
     {"ready": True, "running_tasks": [], "slots_free": 4, "capacity": 4},
     key=TLKEY)
row = next((r for r in call("/api/ghosts/tasks?project=AGENT", token=admin)[1]
            if r["id"] == AT), {})
check("work addressed to it that it cannot run fails rather than waiting",
      row.get("state") == "failed", str(row)[:140])
check("naming the tool and what to do instead",
      "nuclei" in (row.get("notes") or "")
      and "pool" in (row.get("notes") or ""), str(row.get("notes"))[:170])

# An agent that has never said what it has is not starved.
st, en7 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "silent-tools", "target_os": "linux"}, token=admin)
SID = ((en7 or {}).get("agent") or {}).get("id")
SKEY = (en7 or {}).get("callback_key")
call("/api/ghosts/register", "POST", {"platform": "linux", "arch": "amd64"},
     key=SKEY)
st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 4,
               "capacity": 4}, key=SKEY)
check("an agent that reported no inventory is still given work",
      PT in [t["id"] for t in (hb or {}).get("tasks", [])],
      str((hb or {}).get("tasks"))[:140])
for fixture in (TLID, SID):
    call(f"/api/ghosts/{fixture}/kill?project=AGENT", "POST", {}, token=admin)

print("== a failed task goes back in the queue, twice ==")
st, en5 = call("/api/ghosts?project=AGENT", "POST",
               {"name": "flaky", "target_os": "linux"}, token=admin)
FID = ((en5 or {}).get("agent") or {}).get("id")
FKEY = (en5 or {}).get("callback_key")
st, ft = call(f"/api/ghosts/{FID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["flap.example"]}},
              token=admin)
FT = (ft or {}).get("id")


def fail_once(note="the resolver timed out"):
    call("/api/ghosts/heartbeat", "POST",
         {"ready": True, "running_tasks": []}, key=FKEY)
    return call(f"/api/ghosts/tasks/{FT}/result", "POST",
                {"status": "failed", "output": "", "stderr": "",
                 "summary": "failed", "exit_code": 1, "error": note},
                key=FKEY)


call("/api/ghosts/heartbeat", "POST", {"ready": True, "running_tasks": []},
     key=FKEY)
fail_once()
st, rows = call("/api/ghosts/tasks?project=AGENT", token=admin)
row = next((r for r in (rows or []) if r["id"] == FT), {})
check("the first failure puts it back in the queue",
      row.get("state") == "awaiting", str(row)[:160])
check("counted as an attempt", row.get("attempts") == 1, str(row.get("attempts")))
check("with a note saying what happened and that it was requeued",
      "requeued" in (row.get("notes") or ""), str(row.get("notes"))[:120])
check("and back in the POOL, not on the agent that just failed it",
      row.get("agent_id") is None, str(row.get("agent_id")))

fail_once()
row = next((r for r in call("/api/ghosts/tasks?project=AGENT", token=admin)[1]
            if r["id"] == FT), {})
check("the second failure requeues it too", row.get("state") == "awaiting",
      str(row)[:140])
check("attempt two", row.get("attempts") == 2, str(row.get("attempts")))

fail_once()
row = next((r for r in call("/api/ghosts/tasks?project=AGENT", token=admin)[1]
            if r["id"] == FT), {})
check("the third failure stops: two retries, then it waits for a person",
      row.get("state") == "failed", str(row)[:140])
check("and says so rather than just going quiet",
      "restart it by hand" in (row.get("notes") or ""),
      str(row.get("notes"))[:160])

print("-- a wrong request is not retried at all --")
st, bt = call(f"/api/ghosts/{FID}/tasks?project=AGENT", "POST",
              {"kind": "amass", "args": {"domain": "a.example"}}, token=admin)
BT = (bt or {}).get("id")
call("/api/ghosts/heartbeat", "POST", {"ready": True, "running_tasks": []},
     key=FKEY)
call(f"/api/ghosts/tasks/{BT}/result", "POST",
     {"status": "failed", "output": "", "stderr": "", "summary": "failed",
      "exit_code": 1, "error": "amass takes one domain per task; got 3"},
     key=FKEY)
row = next((r for r in call("/api/ghosts/tasks?project=AGENT", token=admin)[1]
            if r["id"] == BT), {})
# Retrying this somewhere else produces the same answer, more slowly.
check("a failure about the request fails immediately",
      row.get("state") == "failed", str(row)[:140])
check("without burning a retry", row.get("attempts") == 1,
      str(row.get("attempts")))
check("and says it was not retryable",
      "not retryable" in (row.get("notes") or ""), str(row.get("notes"))[:140])

print("-- restarting one by hand --")
st, back = call(f"/api/ghosts/tasks/{FT}/retry?project=AGENT", "POST", {}, token=admin)
check("a failed task can be restarted", st == 200, f"status={st} {str(back)[:110]}")
check("it is awaiting again", (back or {}).get("state") == "awaiting",
      str(back)[:120])
check("the counter resets — a person has judged it worth another go",
      (back or {}).get("attempts") == 0, str((back or {}).get("attempts")))
check("and the note keeps what went before",
      "previously" in ((back or {}).get("notes") or ""),
      str((back or {}).get("notes"))[:140])
st, err = call(f"/api/ghosts/tasks/{FT}/retry?project=AGENT", "POST", {}, token=admin)
check("restarting one that is already queued is refused", st == 409,
      f"status={st}")
call(f"/api/ghosts/{FID}/kill?project=AGENT", "POST", {}, token=admin)

print("== the queue can be looked at and taken back out ==")
st, t3 = call("/api/ghosts/tasks?project=AGENT", "POST",
              {"kind": "amass", "args": {"domain": "queued.example"}},
              token=admin)
T3 = (t3 or {}).get("id")
check("a pooled task is queued", st == 201, f"status={st} {str(t3)[:110]}")

st, queue = call("/api/ghosts/queue?project=AGENT", token=admin)
check("the queue lists it", st == 200
      and T3 in [q["id"] for q in (queue or [])], str(queue)[:160])
row = next((q for q in (queue or []) if q["id"] == T3), {})
check("saying what it will act on, not just its kind",
      row.get("subject") == "queued.example", str(row)[:160])
check("and that no agent owns it yet",
      row.get("agent_id") is None and row.get("agent_name") is None, str(row)[:160])
check("and who asked for it", row.get("requested_by") == "root", str(row)[:160])

st, _ = call(f"/api/ghosts/tasks/{T3}?project=AGENT", "DELETE", token=admin)
check("a queued task can be cancelled", st == 204, f"status={st}")
st, queue = call("/api/ghosts/queue?project=AGENT", token=admin)
check("and leaves the queue", T3 not in [q["id"] for q in (queue or [])],
      str(queue)[:140])

# Deleting a row would not stop a scan that is already running on
# somebody's network — it would only lose the result when it reports.
st, err = call(f"/api/ghosts/tasks/{TID}?project=AGENT", "DELETE", token=admin)
check("a task an agent already holds is not cancellable", st == 409,
      f"status={st}")
check("and says to kill the agent instead",
      "kill the agent" in str(err).lower(), str(err)[:160])
st, _ = call("/api/ghosts/tasks/999999?project=AGENT", "DELETE", token=admin)
check("an unknown task is 404", st == 404, f"status={st}")

print("== result delivery ==")
st, _ = call(f"/api/ghosts/tasks/{TID}/start", "POST", {}, key=KEY)
check("task marked running", st == 200, f"status={st}")

st, done = call(f"/api/ghosts/tasks/{TID}/result", "POST",
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
st, _ = call(f"/api/ghosts/{AID}/tasks/{TID}/import?project=AGENT", "POST",
             {"decisions": {"scanme.example.org": {"action": "add"}}})
check("adjudication needs a session, not just an agent key", st == 401,
      f"status={st}")

st, _ = call(f"/api/ghosts/{AID}/tasks/{TID}/import?project=AGENT", "POST",
             {"decisions": {"scanme.example.org": {"action": "add"}}}, key=KEY)
check("an agent cannot adjudicate its own result", st == 401, f"status={st}")

st, fin = call(f"/api/ghosts/{AID}/tasks/{TID}/import?project=AGENT", "POST",
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
st, redo = call(f"/api/ghosts/{AID}/tasks/{TID}/import?project=AGENT", "POST",
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
st, t2 = call(f"/api/ghosts/{AID}/tasks?project=AGENT", "POST",
              {"kind": "nslookup", "args": {"targets": ["example.org"]}},
              token=admin)
T2 = (t2 or {}).get("id")
check("lookup tasks have no import format", (t2 or {}).get("import_as") is None,
      str((t2 or {}).get("import_as")))
call("/api/ghosts/heartbeat", "POST", {}, key=KEY)
call(f"/api/ghosts/tasks/{T2}/result", "POST",
     {"status": "done", "output": '[{"query":"example.org","a":["203.0.113.1"]}]',
      "summary": "resolved 1 of 1", "exit_code": 0}, key=KEY)
st, _ = call(f"/api/ghosts/{AID}/tasks/{T2}/import?project=AGENT", "POST",
             {"decisions": {}}, token=admin)
check("adjudicating a non-scan result is refused clearly", st == 409,
      f"status={st}")

print("== a failed scan is not an empty scan ==")
st, t3 = call(f"/api/ghosts/{AID}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["scanme.example.org"]}},
              token=admin)
T3 = (t3 or {}).get("id")
call("/api/ghosts/heartbeat", "POST", {}, key=KEY)
st, bad = call(f"/api/ghosts/tasks/{T3}/result", "POST",
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
st, lst = call("/api/ghosts/tasks?project=AGENT", token=admin)
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
import base64
import hashlib
import secrets
import time

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
    return {"X-Ghost-Agent": str(agent_id), "X-Ghost-Timestamp": ts,
            "X-Ghost-Nonce": nonce,
            "X-Ghost-Signature": base64.b64encode(priv.sign(msg)).decode()}


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


st, en2 = call("/api/ghosts?project=AGENT", "POST",
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

st, _ = call("/api/ghosts?project=AGENT", "POST",
             {"name": "bad-mode", "connection_mode": "carrier-pigeon"}, token=admin)
check("an unknown connection mode is refused", st == 422, f"status={st}")

priv, pub = keypair()
st, _ = raw("/api/ghosts/enroll", "POST",
            {"enroll_token": "not-the-token", "public_key": pub})
check("a wrong enrollment token is refused", st == 401, f"status={st}")
st, _ = raw("/api/ghosts/enroll", "POST",
            {"enroll_token": en2["enroll_token"], "public_key": "not-base64!!"})
check("a malformed public key is refused", st == 422, f"status={st}")

st, claimed = raw("/api/ghosts/enroll", "POST",
                  {"enroll_token": en2["enroll_token"], "public_key": pub})
check("the token exchanges for an identity", st == 200, f"status={st} {str(claimed)[:120]}")
check("and the agent learns which project it serves",
      (claimed or {}).get("project") == "AGENT", str(claimed)[:120])
check("and gets the same server key to pin",
      (claimed or {}).get("server_public_key") == en2["server_public_key"])

st, _ = raw("/api/ghosts/enroll", "POST",
            {"enroll_token": en2["enroll_token"], "public_key": pub})
check("the token is burned and cannot be reused", st in (401, 409), f"status={st}")

print("== signatures, and no downgrade ==")
st, _ = raw("/api/ghosts/heartbeat", "POST", {},
            headers=signed(priv, A2, "POST", "/api/ghosts/heartbeat",
                           json.dumps({}).encode()))
check("a signed heartbeat is accepted", st == 200, f"status={st}")

st, _ = call("/api/ghosts/heartbeat", "POST", {}, key=en2["callback_key"])
check("once it has an identity, the bearer key alone is refused", st == 401,
      f"status={st} — a downgrade here would make the signature decorative")

other, _ = keypair()
st, _ = raw("/api/ghosts/heartbeat", "POST", {},
            headers=signed(other, A2, "POST", "/api/ghosts/heartbeat",
                           json.dumps({}).encode()))
check("a signature from the wrong key is refused", st == 401, f"status={st}")

h = signed(priv, A2, "POST", "/api/ghosts/heartbeat", json.dumps({}).encode())
st, _ = raw("/api/ghosts/heartbeat", "POST", {}, headers=h)
st2, _ = raw("/api/ghosts/heartbeat", "POST", {}, headers=h)
check("a replayed request is refused", st == 200 and st2 == 401,
      f"first={st} replay={st2}")

h2 = signed(priv, A2, "POST", "/api/ghosts/heartbeat", json.dumps({}).encode())
st, _ = raw("/api/ghosts/register", "POST", {"platform": "linux"}, headers=h2)
check("a signature is bound to the path it was made for", st == 401,
      f"status={st}")

old = signed(priv, A2, "POST", "/api/ghosts/heartbeat", json.dumps({}).encode())
old["X-Ghost-Timestamp"] = str(int(time.time()) - 4000)
st, _ = raw("/api/ghosts/heartbeat", "POST", {}, headers=old)
check("a stale timestamp is refused", st == 401, f"status={st}")

print("== killing an agent ==")
st, t9 = call(f"/api/ghosts/{A2}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["a.example"]}}, token=admin)
st, killed = call(f"/api/ghosts/{A2}/kill?project=AGENT", "POST", {}, token=admin)
check("kill is accepted", st == 200, f"status={st} {str(killed)[:100]}")
check("and the agent is disabled", (killed or {}).get("status") == "disabled")
st, lst = call(f"/api/ghosts/{A2}/tasks?project=AGENT", token=admin)
row = next((t for t in (lst or []) if t["id"] == (t9 or {}).get("id")), {})
check("queued work is cancelled rather than left to run later",
      row.get("status") == "failed" and "cancelled" in (row.get("error") or ""),
      f"{row.get('status')} / {str(row.get('error'))[:50]}")

st, hb = raw("/api/ghosts/heartbeat", "POST", {},
             headers=signed(priv, A2, "POST", "/api/ghosts/heartbeat",
                            json.dumps({}).encode()))
check("a killed agent is told to shut down, not merely refused",
      st == 200 and (hb or {}).get("shutdown") is True, f"status={st} {str(hb)[:100]}")

print("== deleting an agent must not destroy its evidence ==")
# Those tasks hold real nmap output. The FK is SET NULL precisely so
# this does not take it with it.
st, before = call(f"/api/ghosts/{AID}/tasks?project=AGENT", token=admin)
kept = [t["id"] for t in (before or []) if t.get("status") == "done"]
check("the agent has finished work to lose", len(kept) > 0, str(len(kept)))

st, _ = call(f"/api/ghosts/{AID}?project=AGENT", "DELETE", token=admin)
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
    st, e = call("/api/ghosts?project=AGENT", "POST", {"name": nm}, token=admin)
    pv, pb = keypair()
    raw("/api/ghosts/enroll", "POST",
        {"enroll_token": e["enroll_token"], "public_key": pb})
    call(f"/api/ghosts/{e['agent']['id']}?project=AGENT", "PATCH",
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
    path = f"/api/ghosts/tasks/{tid}/result"
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
    st, hb = raw("/api/ghosts/heartbeat", "POST", payload,
                 headers=signed(a["priv"], a["id"], "POST",
                                "/api/ghosts/heartbeat",
                                json.dumps(payload).encode()))
    got = ((hb or {}).get("task") or {}).get("id")
    if got:
        holding[nm] = got
    return st, hb


def pooled(kind="nslookup", region=None, targets=("a.example",)):
    body = {"kind": kind, "args": {"targets": list(targets)}}
    if region:
        body["region"] = region
    return call("/api/ghosts/tasks?project=AGENT", "POST", body, token=admin)


for nm in fleet:
    beat(nm)  # all three now count as online

st, r = call("/api/ghosts/routing?project=AGENT", token=admin)
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
st, r = call("/api/ghosts/routing?project=AGENT", "PUT", {"mode": "primary"},
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

st, _ = call(f"/api/ghosts/{fleet['dublin']['id']}/kill?project=AGENT", "POST",
             {}, token=admin)
beat("virginia"); beat("tokyo")
st, r = call("/api/ghosts/routing?project=AGENT", token=admin)
check("killing the primary elects the next by priority, with nothing stored",
      str(r["current_primary_name"]).startswith("virginia-"), str(r)[:140])
st, t = pooled()
st, hb = beat("virginia")
check("and the new primary picks up the work",
      (hb or {}).get("task", {}).get("id") == t["id"], str(hb)[:110])

print("-- geo --")
call("/api/ghosts/routing?project=AGENT", "PUT", {"mode": "geo"}, token=admin)
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
st, r = call("/api/ghosts/routing?project=AGENT", token=admin)
check("and the task is still visibly waiting, not quietly run elsewhere",
      r["unassigned_tasks"] >= 1, str(r)[:120])

st, _ = call("/api/ghosts/routing?project=AGENT", "PUT", {"mode": "anarchy"},
             token=admin)
check("an unknown routing mode is refused", st == 422, f"status={st}")

print("-- a named agent still wins --")
call("/api/ghosts/routing?project=AGENT", "PUT", {"mode": "primary"}, token=admin)
st, direct = call(f"/api/ghosts/{fleet['tokyo']['id']}/tasks?project=AGENT", "POST",
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


print("\n== the agent thread belongs to the engagement ==")
# It used to live in the browser. An engagement is worked by several
# people, so "what have we already asked" is a fact about the
# engagement rather than about whoever has the tab open.
st, none_yet = call("/api/agent/session?project=ALPHA", token=admin)
check("a project with no thread says so rather than inventing one",
      st == 200 and none_yet is None, f"status={st} {str(none_yet)[:60]}")

st, fresh = call("/api/agent/session/new?project=ALPHA", "POST", {},
                 token=admin)
check("a thread can be started", st == 200 and (fresh or {}).get("id"),
      f"status={st} {str(fresh)[:90]}")
check("...on the project it was asked for",
      (fresh or {}).get("project_code") == "ALPHA", str(fresh)[:70])
check("...and is empty", (fresh or {}).get("turns") == [], str(fresh)[:70])

# The point of the change: the OTHER person on the engagement reads
# the same thread, without having been the one who opened it.
st, seen = call("/api/agent/session?project=ALPHA", token=ntok)
check("a readonly member of the project sees the same thread",
      st == 200 and (seen or {}).get("id") == (fresh or {}).get("id"),
      f"status={st} {str(seen)[:80]}")
check("...and is told who opened it",
      (seen or {}).get("opened_by") == "root", str(seen)[:80])

# Switching engagement must not carry a client's conversation into
# another client's view. That is the one thing this app exists to
# prevent.
st, bravo = call("/api/agent/session?project=BRAVO", token=admin)
check("another engagement has its own thread, not this one",
      st == 200 and (bravo is None or
                     (bravo or {}).get("id") != (fresh or {}).get("id")),
      f"status={st} {str(bravo)[:70]}")
st, _ = call("/api/agent/session?project=BRAVO", token=ntok)
check("a project they cannot read is 404, not an empty thread", st == 404,
      f"status={st} — anything else leaks that BRAVO exists")

st, second = call("/api/agent/session/new?project=ALPHA", "POST", {},
                  token=admin)
check("starting a new thread gives a different one",
      (second or {}).get("id") != (fresh or {}).get("id"),
      f"{(fresh or {}).get('id')} -> {(second or {}).get('id')}")
st, now = call("/api/agent/session?project=ALPHA", token=admin)
check("...and it is the one the project is now on",
      (now or {}).get("id") == (second or {}).get("id"), str(now)[:70])


print("\n== several threads at once, and the list is the engagement's ==")
# "What did the crawl find" and "is this credential worth anything"
# are not one conversation. A second question must not end the first,
# which may also be somebody else's.
st, beside = call("/api/agent/session/new?project=ALPHA&close_current=false",
                  "POST", {}, token=admin)
check("a thread can be opened beside the one already open",
      st == 200 and (beside or {}).get("id") != (second or {}).get("id"),
      f"status={st} {str(beside)[:80]}")

st, threads = call("/api/agent/sessions?project=ALPHA", token=admin)
ids = [t["id"] for t in (threads or [])]
check("both are listed as open",
      st == 200 and (beside or {}).get("id") in ids
      and (second or {}).get("id") in ids, f"status={st} {ids}")
check("...and the one that was replaced is not",
      (fresh or {}).get("id") not in ids,
      f"{(fresh or {}).get('id')} must have stayed closed: {ids}")
check("...newest activity first",
      ids[0] == (beside or {}).get("id"), ids)
check("...with the turn count, so a tab needs no transcript to label it",
      all("turn_count" in t for t in (threads or [])), str(threads)[:90])

# The list is the engagement's, exactly like the threads in it: a
# question a colleague left running is one you can pick up.
st, theirs = call("/api/agent/sessions?project=ALPHA", token=ntok)
check("a readonly member of the project sees the same open threads",
      st == 200 and [t["id"] for t in (theirs or [])] == ids,
      f"status={st} {str(theirs)[:90]}")

st, one = call(f"/api/agent/session?project=ALPHA"
               f"&thread={(second or {}).get('id')}", token=ntok)
check("a named thread is fetched by id, not only the newest",
      st == 200 and (one or {}).get("id") == (second or {}).get("id"),
      f"status={st} {str(one)[:70]}")

# An id belonging to another engagement must not be reachable through
# a project the caller can read -- that would be the one thing the
# per-project thread exists to prevent, done with a number.
st, bsess = call("/api/agent/session/new?project=BRAVO", "POST", {},
                 token=admin)
st, _ = call(f"/api/agent/session?project=ALPHA"
             f"&thread={(bsess or {}).get('id')}", token=admin)
check("another engagement's thread is 404 through this one, not readable",
      st == 404, f"status={st} — a thread id must not cross projects")
st, _ = call(f"/api/agent/session/{(bsess or {}).get('id')}/close"
             f"?project=ALPHA", "POST", {}, token=admin)
check("...and cannot be closed through it either", st == 404, f"status={st}")

# Closing is not deleting. What was asked during an engagement is
# part of the engagement.
bid = (beside or {}).get("id")
st, shut = call(f"/api/agent/session/{bid}/close?project=ALPHA", "POST", {},
                token=admin)
check("a thread can be closed", st == 200 and (shut or {}).get("closed") is True,
      f"status={st} {str(shut)[:70]}")
st, rest = call("/api/agent/sessions?project=ALPHA", token=admin)
check("...and drops out of the open list",
      bid not in [t["id"] for t in (rest or [])], str(rest)[:90])
st, kept = call(f"/api/agent/session?project=ALPHA&thread={bid}", token=admin)
check("...but is still readable by id, because it was kept",
      st == 200 and (kept or {}).get("id") == bid
      and (kept or {}).get("closed") is True, f"status={st} {str(kept)[:70]}")
st, arch = call("/api/agent/sessions?project=ALPHA&closed=true", token=admin)
check("...and is listed when closed threads are asked for",
      bid in [t["id"] for t in (arch or [])], str(arch)[:90])
check("closing one does not touch the others",
      (second or {}).get("id") in [t["id"] for t in (rest or [])],
      str(rest)[:90])

print("\n== a credential never lands in a shared transcript ==")
# `reveal_secret` releases a value only to a `user` role and only
# with an audit entry naming who asked. A thread readable by
# everyone on the project -- readonly included, which exists to be
# handed out more freely -- would be a way around both.
from app.routers import agent as _ag  # noqa: E402


class _Step:
    def __init__(self, tool, result):
        self.kind, self.text, self.tool = "tool", "", tool
        self.args, self.result = {}, result


_red = _ag._redact_steps([
    _Step("get_finding_secret", "hunter2-the-actual-password"),
    _Step("list_findings", "three findings"),
])
check("the secret tool's result is not stored",
      "hunter2" not in json.dumps(_red), json.dumps(_red)[:120])
check("...and says where the value really is, rather than nothing",
      "records who asked" in json.dumps(_red), json.dumps(_red)[:160])
check("every other tool's result is kept",
      any(d["result"] == "three findings" for d in _red), _red)
check("the withholding is narrow, and stays narrow",
      frozenset({"get_finding_secret"}) == _ag.SECRET_TOOLS,
      _ag.SECRET_TOOLS)

print("== read-only tools are available in read-only mode ==")
# These four only read, and they are the ones an analyst actually asks
# for: what is worth attacking, what runs PHP, what has a public
# exploit. Registering them after the allow_writes gate left every one
# of them unreachable in the mode the agent runs in by default, which
# is the mode nearly every deployment uses.
import asyncio as _aio  # noqa: E402

from sqlalchemy import select as _sel  # noqa: E402

from app.agent.tools import build as _build  # noqa: E402
from app.db import SessionLocal as _SL  # noqa: E402
from app.models import Project as _P  # noqa: E402
from app.models import User as _U

_READ_ONLY = ["rank_targets", "find_by_technology", "exploit_leads",
              "search_exploits", "get_host", "host_timeline",
              # Reading what a lookup found is the useful half when the
              # agent is in its default read-only mode: it can already
              # QUEUE a reverse-IP sweep, and being unable to say what
              # came back is the gap this closes.
              "lookup_results"]


async def _names(allow_writes):
    async with _SL() as s:
        pr = (await s.execute(_sel(_P).limit(1))).scalars().first()
        u = (await s.execute(_sel(_U).limit(1))).scalars().first()
        return {t.name: t for t in _build(s, pr, u, allow_writes)}


_ro = _aio.run(_names(False))
_rw = _aio.run(_names(True))
for _n in _READ_ONLY:
    check(f"{_n} is available without writes", _n in _ro,
          "only in write mode" if _n in _rw else "missing entirely")
check("no read-only tool is marked as writing",
      all(getattr(_ro[n], "writes", False) is False for n in _ro), "")
check("and enabling writes only ever adds tools",
      set(_ro).issubset(set(_rw)), str(set(_ro) - set(_rw)))
check("writes really do add the mutating ones",
      {"add_note", "add_target", "add_finding",
       "apply_lookup_results"}.issubset(set(_rw)),
      str(sorted(set(_rw) - set(_ro))))
check("applying lookup results is a WRITE and is not offered without them",
      "apply_lookup_results" not in _ro, "")
# Discoverability is half the bug being fixed. The operator asked the
# agent to "add all the lookup results" and it said it did not know
# what was meant — there was no tool, and a tool nobody's phrasing
# matches would have been nearly as bad.
check("the read tool's description carries the phrases people use",
      all(w in _ro["lookup_results"].description.lower()
          for w in ("lookup", "waiting", "reverse-ip")),
      _ro["lookup_results"].description[:160])
check("the write tool's description carries them too",
      all(w in _rw["apply_lookup_results"].description.lower()
          for w in ("add all the lookup results", "apply the lookups")),
      _rw["apply_lookup_results"].description[:160])
check("and says out loud that it does not decide the ambiguous ones",
      "still_needs_a_person" in _rw["apply_lookup_results"].description,
      _rw["apply_lookup_results"].description[-200:])

print("== no read tool reaches past scope_ids ==")
# `scope_ids` is the bound on what a non-admin may see across all
# engagements. Two read tools wrote `if project: ... where(project_id ==
# project.id)` instead of going through `scoped()`, which looks
# equivalent and is not: with no engagement in view the WHERE was
# dropped entirely and the tool read every target in the installation.
# One client's hosts in another client's answer is the one mistake in
# that file that matters outside it, so this is asserted rather than
# left to review.
async def _as_user(name, scope_ids):
    async with _SL() as s:
        u = (await s.execute(_sel(_U).limit(1))).scalars().first()
        tool = {t.name: t for t in _build(s, None, u, False,
                                          scope_ids=scope_ids)}[name]
        return await tool.fn()


for _tool, _key in (("rank_targets", "targets"), ("find_by_technology", "hosts")):
    _kw = {"technology": "ssh"} if _tool == "find_by_technology" else {}

    async def _run_it(tool=_tool, kw=_kw, ids=[]):      # noqa: B006
        async with _SL() as s:
            u = (await s.execute(_sel(_U).limit(1))).scalars().first()
            t = {x.name: x for x in _build(s, None, u, False, scope_ids=ids)}[tool]
            return await t.fn(**kw)

    _nothing = _aio.run(_run_it())
    check(f"{_tool} with no readable project returns nothing",
          not _nothing.get(_key), str(_nothing)[:160])
    _all = _aio.run(_run_it(ids=None))
    check(f"{_tool} with site-admin scope still works",
          isinstance(_all.get(_key), list), str(_all)[:160])


print("== the assistant can task enumeration, but previews first ==")
# A sweep is hundreds of tasks against a client's estate. "Have a look
# at the web hosts" is a sentence, not an authorisation, so the tool
# returns a plan and queues nothing until it is called again with
# confirm=true. The preview is also the only guard on a project whose
# scope index is not loaded, where every host passes the scope gate.
from sqlalchemy import func as _func  # noqa: E402

from app.models import AgentTask as _AT  # noqa: E402

_HOSTS = "alpha-one.example.com alpha-two.example.com"


async def _enum(**kw):
    async with _SL() as s:
        pr = (await s.execute(_sel(_P).limit(1))).scalars().first()
        u = (await s.execute(_sel(_U).limit(1))).scalars().first()
        tool = {t.name: t for t in _build(s, pr, u, True)}["enumerate_ghosts"]
        before = (await s.execute(_sel(_func.count()).select_from(_AT)
                                  .where(_AT.project_id == pr.id))).scalar_one()
        out = await tool.fn(**kw)
        after = (await s.execute(_sel(_func.count()).select_from(_AT)
                                 .where(_AT.project_id == pr.id))).scalar_one()
        return out, after - before


_prev, _made = _aio.run(_enum(kind="nslookup", select="hosts", hosts=_HOSTS))
check("a preview says what it would do", _prev.get("preview") is True,
      str(_prev)[:120])
check("names the hosts", sorted(_prev.get("hosts", [])) ==
      ["alpha-one.example.com", "alpha-two.example.com"], str(_prev.get("hosts")))
check("and queues absolutely nothing", _made == 0, f"created {_made} task(s)")

_done, _made2 = _aio.run(_enum(kind="nslookup", select="hosts", hosts=_HOSTS,
                               confirm=True))
check("confirm=true queues", _done.get("queued") == 2, str(_done)[:140])
check("as one task per host, not one task holding both", _made2 == 2,
      f"created {_made2} task(s) for 2 hosts")

# Installing software on, or running commands through, a privileged
# process inside a client network is not something a sentence should be
# able to start, however the sentence is phrased.
for _k in ("shell", "install"):
    _r, _n = _aio.run(_enum(kind=_k, select="hosts", hosts=_HOSTS,
                            confirm=True))
    check(f"{_k} is refused even with confirm", "error" in _r and _n == 0,
          str(_r)[:100])

_r, _n = _aio.run(_enum(kind="nmap", select="everything"))
check("an unknown selection lists the real ones",
      "selections" in _r and "unscanned" in _r.get("selections", {}),
      str(_r)[:120])

# A project holds assets that are not network hosts -- an S3 ARN, a
# cloud resource id. Pointing a scanner at one burns a task to produce
# an error, and dropping them silently hides that the asset is covered
# by nothing.
_r, _n = _aio.run(_enum(kind="nmap", select="hosts",
                        hosts="good.example.com arn:aws:s3:::a-bucket"))
check("things that are not network hosts are dropped",
      _r.get("hosts") == ["good.example.com"], str(_r.get("hosts")))
check("and said out loud rather than quietly removed",
      _r.get("not_network_count") == 1
      and "arn:aws:s3:::a-bucket" in _r.get("not_network_hosts", {}),
      str(_r.get("not_network_hosts")))

print("== agent binaries ==")
st, dl = call("/api/ghosts/downloads", token=admin)
check("the download list is served", st == 200 and "builds" in (dl or {}),
      f"status={st}")
check("it names all six targets", len((dl or {}).get("builds", [])) == 6,
      str(len((dl or {}).get("builds", []))))
st, _ = call("/api/ghosts/downloads")
check("and needs a session", st == 401, f"status={st}")
st, _ = call("/api/ghosts/download/plan9/mips", token=admin)
check("an unknown platform is refused clearly", st == 404, f"status={st}")

print("== reaching into an agent ==")
st, err = call(f"/api/ghosts/{A2}/reach?project=AGENT", "POST", {}, token=admin)
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

from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def kexpair():
    p = X25519PrivateKey.generate()
    return p, _b64.b64encode(p.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def derive(priv, peer_pub_b64):
    peer = __import__("cryptography.hazmat.primitives.asymmetric.x25519",
                      fromlist=["X25519PublicKey"]).X25519PublicKey
    secret = priv.exchange(peer.from_public_bytes(_b64.b64decode(peer_pub_b64)))
    return HKDF(algorithm=_hashes.SHA256(), length=32, salt=None,
                # Still "drone": a wire constant, not vocabulary. This
                # is the agent's half of the derivation written out
                # independently, which is the point -- if the server
                # ever changes it, this goes red rather than both
                # moving together and nobody noticing.
                info=b"oddjob/drone seal v1").derive(secret)


def binding(direction, aid, method, path, ts, nonce):
    return "\n".join(["v1", direction, str(aid), method.upper(),
                       path, ts, nonce]).encode()


st, en3 = call("/api/ghosts?project=AGENT", "POST", {"name": "sealed"}, token=admin)
A3 = en3["agent"]["id"]
spriv3, spub3 = keypair()
kpriv3, kpub3 = kexpair()
st, claimed3 = raw("/api/ghosts/enroll", "POST",
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
    h = {"X-Ghost-Agent": str(aid), "X-Ghost-Timestamp": ts,
         "X-Ghost-Nonce": nonce,
         "X-Ghost-Signature": _b64.b64encode(spriv3.sign(msg)).decode(),
         "X-Ghost-Sealed": "v1"}
    r = urllib.request.Request(BASE + path, method=method, data=wire)
    r.add_header("Content-Type", "application/json")
    for k, v in h.items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            return x.status, x.read(), x.headers.get("X-Ghost-Sealed"), ts, nonce
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("X-Ghost-Sealed"), ts, nonce


st, body3, sealhdr, ts3, nonce3 = sealed_call("/api/ghosts/heartbeat", {})
check("a sealed, signed heartbeat is accepted", st == 200, f"status={st}")
check("and the reply comes back sealed too", sealhdr == "v1", str(sealhdr))
check("the reply is not readable as JSON",
      not body3.lstrip().startswith(b"{"), body3[:40])

rawb = _b64.b64decode(body3)
opened = ChaCha20Poly1305(KEY3).decrypt(
    rawb[:12], rawb[12:],
    binding("res", A3, "POST", "/api/ghosts/heartbeat", ts3, nonce3))
check("and opens to the answer with our key", json.loads(opened).get("ok") is True,
      opened[:80])

print("-- no downgrade --")
st, _ = raw("/api/ghosts/heartbeat", "POST", {},
            headers=signed(spriv3, A3, "POST", "/api/ghosts/heartbeat",
                           json.dumps({}).encode()))
check("an agent that can seal may not send in the clear", st == 401,
      f"status={st} — otherwise an attacker just omits the header")

other_priv, other_pub = kexpair()
wrong = derive(other_priv, claimed3["server_kex_public_key"])
st, _, _, _, _ = sealed_call("/api/ghosts/heartbeat", {}, key=wrong)
check("a body sealed with the wrong key does not open", st == 401, f"status={st}")

st, _, _, _, _ = sealed_call("/api/ghosts/heartbeat", {},
                             bind_path="/api/ghosts/register")
check("a body bound to another route does not open here", st == 401,
      f"status={st}")

print("-- a real result, and what a watcher would see --")
st, t3 = call(f"/api/ghosts/{A3}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["scanme.example.org"]}},
              token=admin)
T3 = t3["id"]
sealed_call("/api/ghosts/heartbeat", {})
sealed_call(f"/api/ghosts/tasks/{T3}/result",
            {"status": "done", "output": NMAP, "exit_code": 0})
st, lst = call(f"/api/ghosts/{A3}/tasks?project=AGENT", token=admin)
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

from app.models import Agent as _Agent


async def _age_heartbeat(agent_id, seconds):
    """Push an agent's last_seen into the past, as a long scan would."""
    async with _SL() as s:
        await s.execute(_update(_Agent).where(_Agent.id == agent_id).values(
            last_seen=_dt.datetime.now(_dt.UTC)
            - _dt.timedelta(seconds=seconds)))
        await s.commit()


st, enb = call("/api/ghosts?project=AGENT", "POST", {"name": "longscan"},
               token=admin)
AB = enb["agent"]["id"]
KB = enb["callback_key"]
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True}, key=KB)

st, tb = call(f"/api/ghosts/{AB}/tasks?project=AGENT", "POST",
              {"kind": "nmap", "args": {"targets": ["slow.example"]}}, token=admin)
call("/api/ghosts/heartbeat", "POST", {}, key=KB)          # claims it
call(f"/api/ghosts/tasks/{tb['id']}/start", "POST", {}, key=KB)

# Three minutes. Past OFFLINE_AFTER, which is what this is about, and
# short of LOST_AFTER, which is now a different conclusion entirely.
# This used to say ten minutes, back when any number past ninety
# seconds meant the same thing; it does not any more, and a stale
# agent mid-task is only `busy` inside that window.
_asyncio.run(_age_heartbeat(AB, 180))

st, rows = call("/api/ghosts?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AB), {})
check("an agent mid-task reads as busy, not offline",
      me.get("status") == "busy", str(me.get("status")))
check("and its in-flight count says why", me.get("running_tasks") == 1,
      str(me.get("running_tasks")))

st, rt = call("/api/ghosts/routing?project=AGENT", token=admin)
check("a busy agent still counts as present for routing",
      (rt or {}).get("eligible", 0) >= 1, str(rt)[:110])

# Now finish it: with nothing in flight and a stale heartbeat, offline
# is the right answer and must still be reachable.
call(f"/api/ghosts/tasks/{tb['id']}/result", "POST",
     {"status": "done", "output": "", "exit_code": 0}, key=KB)
_asyncio.run(_age_heartbeat(AB, 180))
st, rows = call("/api/ghosts?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AB), {})
check("once idle and stale, it is offline again",
      me.get("status") == "offline", str(me.get("status")))

# And past five minutes it stops being either. Offline is "not heard
# from lately"; lost is "not coming back", and it is the second one
# that takes the agent out of the routing pool.
_asyncio.run(_age_heartbeat(AB, 600))
st, rows = call("/api/ghosts?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AB), {})
check("quiet past five minutes and it is lost, not merely offline",
      me.get("status") == "lost", str(me.get("status")))

st, rt2 = call("/api/ghosts/routing?project=AGENT", token=admin)
check("a lost agent is not counted as somewhere to send work",
      (rt2 or {}).get("eligible", 0) < (rt or {}).get("eligible", 99),
      f"{(rt or {}).get('eligible')} -> {(rt2 or {}).get('eligible')}")


print("== completed and failed counts ==")
st, enc = call("/api/ghosts?project=AGENT", "POST", {"name": "counter"},
               token=admin)
AC, KC = enc["agent"]["id"], enc["callback_key"]
call("/api/ghosts/register", "POST",
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
    st, t = call(f"/api/ghosts/{AC}/tasks?project=AGENT", "POST",
                 {"kind": "nslookup", "args": {"targets": ["x.example"]}},
                 token=admin)
    call("/api/ghosts/heartbeat", "POST", {"ready": True, "running_tasks": []},
         key=KC)
    call(f"/api/ghosts/tasks/{t['id']}/result", "POST",
         {"status": status, "output": "[]",
          "exit_code": 0 if status == "done" else 1,
          "error": None if status == "done"
                   else "refused by the project's scope at dispatch: test"},
         key=KC)


for _ in range(3):
    run_one("done")
for _ in range(2):
    run_one("failed")

st, rows = call("/api/ghosts?project=AGENT", token=admin)
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
st, fresh = call("/api/ghosts?project=AGENT", "POST", {"name": "never-run"},
                 token=admin)
st, rows = call("/api/ghosts?project=AGENT", token=admin)
nr = next((a for a in (rows or []) if a["id"] == fresh["agent"]["id"]), {})
check("an agent that has run nothing counts nothing",
      nr.get("completed_tasks") == 0 and nr.get("failed_tasks") == 0,
      f"{nr.get('completed_tasks')} / {nr.get('failed_tasks')}")


print("== re-enrolling an existing agent ==")
# For rotating keys, and for bringing an agent enrolled before
# end-to-end encryption onto the sealed channel without throwing away
# everything it has done.
st, enr = call("/api/ghosts?project=AGENT", "POST", {"name": "rotate-me"},
               token=admin)
AR = enr["agent"]["id"]
rpriv, rpub = keypair()
rkpriv, rkpub = kexpair()
raw("/api/ghosts/enrol", "POST",
    {"enroll_token": enr["enroll_token"], "public_key": rpub,
     "kex_public_key": rkpub})
st, _ = raw("/api/ghosts/heartbeat", "POST", {},
            headers=signed(rpriv, AR, "POST", "/api/ghosts/heartbeat",
                           json.dumps({}).encode()))
check("the original identity works", st in (200, 401), f"status={st}")

st, again = call(f"/api/ghosts/{AR}/reenroll?project=AGENT", "POST", {},
                 token=admin)
check("re-enrolling issues a fresh token", st == 200 and
      bool((again or {}).get("enroll_token")), f"status={st}")
check("the agent keeps its name and its record",
      str((again or {}).get("agent", {}).get("name")).startswith("rotate-me-"),
      str((again or {}).get("agent", {}).get("name")))
check("and is no longer holding an identity",
      (again or {}).get("agent", {}).get("has_identity") is False,
      str((again or {}).get("agent", {}).get("has_identity")))
# Both keys rotate on a re-enrol, so both have to come back. Returning
# only the enrolment token left a CALL-IN agent rotated but unreachable
# forever: the server had a new call-in key, the operator had no way to
# learn it, and replacing the agent -- losing its name and everything it
# had run -- was the only way out.
check("re-enrolling returns the rotated call-in key",
      bool((again or {}).get("call_in_key")), str(list((again or {}).keys())))
check("and the rotated callback key",
      bool((again or {}).get("callback_key")), str(list((again or {}).keys())))
check("and they are not the same key",
      (again or {}).get("call_in_key") != (again or {}).get("callback_key"), "")

check("the response says what to do on the host",
      "identity.json" in str((again or {}).get("instructions")),
      str((again or {}).get("instructions"))[:90])

# The old key must stop working at once. A rotation that leaves the
# previous key usable has rotated nothing.
st, _ = raw("/api/ghosts/heartbeat", "POST", {},
            headers=signed(rpriv, AR, "POST", "/api/ghosts/heartbeat",
                           json.dumps({}).encode()))
check("the superseded key is refused immediately", st == 401, f"status={st}")

npriv, npub = keypair()
nkpriv, nkpub = kexpair()
st, claimed = raw("/api/ghosts/enrol", "POST",
                  {"enroll_token": again["enroll_token"], "public_key": npub,
                   "kex_public_key": nkpub})
check("the new token redeems", st == 200, f"status={st}")
check("and the channel is sealed this time",
      (claimed or {}).get("sealing") is True, str(claimed)[:110])

st, rows = call("/api/ghosts?project=AGENT", token=admin)
me = next((a for a in (rows or []) if a["id"] == AR), {})
check("the agent now reports sealed", me.get("sealed") is True,
      str(me.get("sealed")))

# This was written as `token=rtok if "rtok" in dir() else None`, and no
# `rtok` has ever been bound in this suite -- the guard meant the call
# always went out unauthenticated. Written as what it does. Narrowing it
# to a write-role caller needs a write-role user this suite does not
# create, so the stronger claim is not made here.
st, _ = call(f"/api/ghosts/{AR}/reenroll?project=AGENT", "POST", {}, token=None)
check("re-enrolling is refused without credentials",
      st in (401, 403), f"status={st}")

print("\n== enrolment appends a discriminator to the name ==")
# Two machines are called `kodi` and whoever names the second has no way
# to know the first exists. The case this was written for is worse: an
# agent deleted server-side whose container heartbeats forever, with a
# later agent holding the same name -- the logs then read as ONE agent
# intermittently failing auth rather than as two, one of them an orphan.
import re as _re

st, e1 = call("/api/ghosts?project=AGENT", "POST",
              {"name": "kodi", "connection_mode": "callback"}, token=admin)
st2, e2 = call("/api/ghosts?project=AGENT", "POST",
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
st, ren = call(f"/api/ghosts/{rid}?project=AGENT", "PATCH",
               {"name": "scanner"}, token=admin)
check("a manual rename is honoured exactly, with no suffix added",
      (ren or {}).get("name") == "scanner", str((ren or {}).get("name")))

st, ren2 = call(f"/api/ghosts/{rid}?project=AGENT", "PATCH",
                {"name": "  spaced out  "}, token=admin)
check("and is trimmed but not otherwise rewritten",
      (ren2 or {}).get("name") == "spaced out", str((ren2 or {}).get("name")))

st, ren3 = call(f"/api/ghosts/{rid}?project=AGENT", "PATCH",
                {"name": "scanner-aaaaaa"}, token=admin)
check("a name that looks like a suffixed one is kept as typed",
      (ren3 or {}).get("name") == "scanner-aaaaaa", str((ren3 or {}).get("name")))

# An empty rename is "no change", not "erase the name" -- an agent with
# no name cannot be told apart from another in any list it appears in.
st, ren4 = call(f"/api/ghosts/{rid}?project=AGENT", "PATCH",
                {"name": "   "}, token=admin)
check("an all-whitespace rename leaves the name alone",
      (ren4 or {}).get("name") == "scanner-aaaaaa", str((ren4 or {}).get("name")))

st, ren5 = call(f"/api/ghosts/{rid}?project=AGENT", "PATCH",
                {"name": "x" * 400}, token=admin)
check("an overlong name is bounded rather than erroring",
      st == 200 and len((ren5 or {}).get("name", "")) <= 128,
      f"status={st} len={len((ren5 or {}).get('name',''))}")

print("\n== a killed ghost confirms it actually went ==")
# Pressing Kill records an intention. This records what happened, and
# they are different facts: a ghost killed while its host was powered
# off never confirms, and the tools really are still on that machine.
st, renr = call("/api/ghosts?project=AGENT", "POST", {"name": "retire-me"},
                token=admin)
RID = renr["agent"]["id"]
qpriv, qpub = keypair()
raw("/api/ghosts/enrol", "POST",
    {"enroll_token": renr["enroll_token"], "public_key": qpub})

st, before = call("/api/ghosts?project=AGENT", token=admin)
_row = [a for a in (before or []) if a["id"] == RID]
check("a live ghost has no retirement recorded",
      _row and _row[0].get("retired_at") is None, str(_row[:1])[:120])

st, _ = call(f"/api/ghosts/{RID}/kill?project=AGENT", "POST", {}, token=admin)
check("kill is accepted", st == 200, f"status={st}")

_body = json.dumps({"reason": "killed from Oddjob",
                    "removed": ["nuclei", "httpx"], "kept": ["nmap"],
                    "failed": ["gobuster: apt is locked"]}).encode()
st, _why = raw("/api/ghosts/retired", "POST",
               json.loads(_body),
               headers=signed(qpriv, RID, "POST", "/api/ghosts/retired", _body))
# This route has to be on the gatekeeper's allowlist as well as having
# its own agent-key dependency; without that it answers "not
# authenticated" before the endpoint is ever reached, and a ghost can
# never report that it shut down.
check("a KILLED ghost can still report that it shut down", st == 200,
      f"status={st} {str(_why)[:160]}")

st, after = call("/api/ghosts?project=AGENT", token=admin)
_r = [a for a in (after or []) if a["id"] == RID]
check("the confirmation is recorded", _r and _r[0].get("retired_at"),
      str(_r[:1])[:140])
check("with the reason", _r and _r[0].get("retired_reason") == "killed from Oddjob",
      str(_r and _r[0].get("retired_reason")))
_cl = (_r[0].get("retired_cleanup") or {}) if _r else {}
check("and what it uninstalled", _cl.get("removed") == ["nuclei", "httpx"],
      str(_cl))
# The tool that was already there must be reported kept, not removed:
# uninstalling someone's own nmap on the way out is a worse trespass
# than leaving ours behind.
check("what it deliberately left alone", _cl.get("kept") == ["nmap"], str(_cl))
# The list that actually matters -- cleanup still owed by hand.
check("and what it could NOT remove",
      _cl.get("failed") == ["gobuster: apt is locked"], str(_cl))
check("the ghost stays killed, it cannot un-kill itself by retiring",
      _r and _r[0].get("status") == "disabled", str(_r and _r[0].get("status")))

st, _ = raw("/api/ghosts/retired", "POST", {"reason": "nice try"})
check("an unsigned retirement is refused", st in (401, 403), f"status={st}")

# ============================================= which machine, which address
# Two reports that looked right and were not. A ghost in Docker said
# its address was 172.17.0.2, which rendered in the same column as
# every genuine egress address — an operator copying that into an
# incident notification would hand the client a number from a private
# namespace. And a ghost on Windows Server said `linux`, truthfully of
# the binary inside the container and wrongly of the machine.
#
# The agent works both out; the server's job is to keep the two
# answers apart instead of flattening them into one.
print("\n== a ghost says which machine it is on, and where its address came from ==")

st, hostie = call("/api/ghosts?project=AGENT", "POST", {"name": "in-a-box"},
                  token=admin)
HKEY = (hostie or {}).get("callback_key")
# By id, not by name: enrolment appends a random suffix so two ghosts
# called "scanner" do not become one.
HID = ((hostie or {}).get("agent") or {}).get("id")
st, _ = call("/api/ghosts/register", "POST",
             {"platform": "linux", "arch": "amd64", "version": "test",
              "hostname": "wsl-box", "privileged": False,
              "outbound_ip": "172.17.0.2",
              "outbound_ip_source": "container-internal",
              "outbound_ip_note": "ifconfig.me unreachable; this is the "
                                  "docker container's own address",
              "host_platform": "windows",
              "host_platform_source": "WSL2 kernel (5.15.0-microsoft-standard)",
              "container": "docker"}, key=HKEY)
check("a ghost can report what is underneath it", st == 200, f"status={st}")


def ghost(aid):
    """By id. Enrolment appends a random suffix to the name, so two
    ghosts called "scanner" do not become one."""
    st, rows = call("/api/ghosts?project=AGENT", token=admin)
    return next((a for a in (rows or []) if a["id"] == aid), None)


a = ghost(HID)
check("the binary's platform is still reported as it was",
      (a or {}).get("platform") == "linux", str((a or {}).get("platform")))
# The whole point. Both are true and they answer different questions:
# which binary to ship, and which machine this is.
check("and the machine underneath is reported separately",
      (a or {}).get("host_platform") == "windows",
      str((a or {}).get("host_platform")))
check("with the evidence, so the claim can be checked rather than taken",
      "WSL2" in ((a or {}).get("host_platform_source") or ""),
      str((a or {}).get("host_platform_source")))
check("the container runtime is named", (a or {}).get("container") == "docker",
      str((a or {}).get("container")))
check("the address is kept", (a or {}).get("outbound_ip") == "172.17.0.2",
      str((a or {}).get("outbound_ip")))
# Without this the address is indistinguishable from a real one. It is
# the same shape, and nothing else on the record says otherwise.
check("and labelled as the container's own, not an egress address",
      (a or {}).get("outbound_ip_source") == "container-internal",
      str((a or {}).get("outbound_ip_source")))
check("with the note saying which lookup failed",
      "ifconfig.me" in ((a or {}).get("outbound_ip_note") or ""),
      str((a or {}).get("outbound_ip_note")))

print("-- an older ghost says nothing, which is not the same as 'no' --")
st, plain = call("/api/ghosts?project=AGENT", "POST", {"name": "bare-metal"},
                 token=admin)
PKEY = (plain or {}).get("callback_key")
PID = ((plain or {}).get("agent") or {}).get("id")
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "hostname": "metal"}, key=PKEY)
a = ghost(PID)
# Null, never defaulted to `platform`. A server that filled this in
# from the binary's own OS would be asserting "this is a Linux
# machine" on no evidence -- which is exactly the bug, restated.
check("host_platform is null, not copied from the binary's platform",
      (a or {}).get("host_platform") is None, str((a or {}).get("host_platform")))
# Not finding a marker is not proof there is no container.
check("container is null, not 'none'", (a or {}).get("container") is None,
      str((a or {}).get("container")))
check("and the source of an unreported address is null too",
      (a or {}).get("outbound_ip_source") is None,
      str((a or {}).get("outbound_ip_source")))

print("-- a later register corrects an earlier answer --")
# Register is idempotent and runs on every reconnect, so a ghost moved
# out of its container has to be able to withdraw what it said before.
# Leaving the stale `docker` behind would be worse than never having
# recorded it.
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "hostname": "wsl-box",
      "outbound_ip": "203.0.113.9", "outbound_ip_source": "public-service",
      "host_platform": "linux",
      "host_platform_source": "Linux kernel, no WSL or Docker Desktop markers"},
     key=HKEY)
a = ghost(HID)
check("the new address replaces the container one",
      (a or {}).get("outbound_ip") == "203.0.113.9",
      str((a or {}).get("outbound_ip")))
check("and so does its source",
      (a or {}).get("outbound_ip_source") == "public-service",
      str((a or {}).get("outbound_ip_source")))
check("the stale container is cleared rather than left standing",
      (a or {}).get("container") is None, str((a or {}).get("container")))
check("the stale note goes with it",
      (a or {}).get("outbound_ip_note") is None,
      str((a or {}).get("outbound_ip_note")))

print("\n== heavy tasks are capped below the slot count ==")
# The arithmetic that put a 1 GB box into the OOM killer today: the
# capacity model budgets 128 MB a task, which is right for nmap and
# the lookups and wrong for amass -- measured resident at 438 MB, and
# now linked INTO the agent rather than forked, so several at once
# share one process and one memory limit. An agent sized at six slots
# was handed six amass tasks.
from app.routers.agents import heavy_allowance  # noqa: E402

check("a third of the slots, rounded down", heavy_allowance(6) == 2,
      heavy_allowance(6))
check("...scaling with the host rather than a flat number",
      heavy_allowance(30) == 10, heavy_allowance(30))
# Never zero: an agent that may run tasks but never a heavy one would
# leave amass work queued for ever with nothing to say why.
check("never zero, however small the agent", heavy_allowance(1) == 1,
      heavy_allowance(1))
check("...including a nonsense value", heavy_allowance(0) == 1,
      heavy_allowance(0))

call("/api/projects", "POST", {"code": "HEAVY", "name": "Heavy"}, token=admin)
call("/api/ghosts/routing?project=HEAVY", "PUT", {"max_parallel": 6},
     token=admin)
st, _hv = call("/api/ghosts?project=HEAVY", "POST",
               {"name": "heavy", "target_os": "linux"}, token=admin)
HVID = ((_hv or {}).get("agent") or {}).get("id")
HVKEY = (_hv or {}).get("callback_key")
call("/api/projects/HEAVY/scope", "POST",
     {"lines": ["*.heavy.example", "heavy.example"]}, token=admin)
for _i in range(6):
    call(f"/api/ghosts/{HVID}/tasks?project=HEAVY", "POST",
         {"kind": "amass", "args": {"domain": "heavy.example"}}, token=admin)
for _i in range(3):
    call(f"/api/ghosts/{HVID}/tasks?project=HEAVY", "POST",
         {"kind": "nslookup", "args": {"targets": [f"h{_i}.heavy.example"]}},
         token=admin)

st, hb = call("/api/ghosts/heartbeat", "POST",
              {"ready": True, "running_tasks": [], "slots_free": 6,
               "capacity": 6, "capacity_reason": "6 slots"}, key=HVKEY)
_kinds = [t["kind"] for t in (hb or {}).get("tasks", [])]
# Six slots and nine tasks waiting, six of them amass. Without the cap
# it would take six amass; with it, two.
check("no more than two of the six slots go to amass",
      _kinds.count("amass") == 2, str(_kinds))
# The other slots are not wasted on nothing — lighter work fills what
# it can, which is all three nslookups.
check("lighter work fills the rest",
      _kinds.count("nslookup") == 3, str(_kinds))
check("...so it is handed five, not six: there was no more light work",
      len(_kinds) == 5, f"{len(_kinds)}: {_kinds}")
# The four amass it did not take are left QUEUED, not failed. This
# agent will pick them up on a later beat.
st, hb2 = call("/api/ghosts/heartbeat", "POST",
               {"ready": True, "running_tasks": [t["id"] for t in
                (hb or {}).get("tasks", [])],
                "slots_free": 1, "capacity": 6}, key=HVKEY)
check("a later beat is still offered amass, so none were discarded",
      all(t["kind"] == "amass" for t in (hb2 or {}).get("tasks", [])),
      str([t["kind"] for t in (hb2 or {}).get("tasks", [])]))

print("\n== targets nothing has scanned yet ==")
# "Never tasked", not "has no ports". The two differ in both
# directions and the difference is the whole point:
#
#   * a host nmap scanned that answered on nothing has no services,
#     so a ports-based rule would offer it again on every pass, for
#     ever, at a client, for a question already answered
#   * a host whose services came from an IMPORT has ports and has
#     never been scanned by us at all
call("/api/projects", "POST", {"code": "UNSC", "name": "Unscanned"}, token=admin)
_uid, _ukey = None, None
st, _en = call("/api/ghosts?project=UNSC", "POST",
               {"name": "unsc", "target_os": "linux"}, token=admin)
_uid = ((_en or {}).get("agent") or {}).get("id")
for _h in ("fresh-a.example", "fresh-b.example", "scanned.example",
           "emptyscan.example"):
    call("/api/targets?project=UNSC", "POST", {"host": _h}, token=admin)

st, u = call("/api/targets/unscanned?project=UNSC", token=admin)
check("the endpoint answers", st == 200, f"{st} {str(u)[:120]}")
check("with every host, since nothing has been scanned",
      sorted((u or {}).get("hosts", [])) ==
      ["emptyscan.example", "fresh-a.example", "fresh-b.example",
       "scanned.example"], str((u or {}).get("hosts")))

# Task one with nmap. It drops out even though it has no services yet
# — the scan was ASKED FOR, and that is the question being answered.
call(f"/api/ghosts/{_uid}/tasks?project=UNSC", "POST",
     {"kind": "nmap", "args": {"targets": ["scanned.example"]}}, token=admin)
st, u = call("/api/targets/unscanned?project=UNSC", token=admin)
check("a host that has been tasked with nmap drops out",
      "scanned.example" not in (u or {}).get("hosts", []),
      str((u or {}).get("hosts")))
check("...and the rest stay", len((u or {}).get("hosts", [])) == 3,
      str((u or {}).get("hosts")))

# masscan counts too — the request was "not scanned by nmap OR masscan".
call(f"/api/ghosts/{_uid}/tasks?project=UNSC", "POST",
     {"kind": "masscan", "args": {"targets": ["fresh-b.example"]}}, token=admin)
st, u = call("/api/targets/unscanned?project=UNSC", token=admin)
check("masscan counts as scanned as well as nmap",
      "fresh-b.example" not in (u or {}).get("hosts", []),
      str((u or {}).get("hosts")))

# A different kind of task must NOT count. An amass or a lookup says
# nothing about whether the ports were ever looked at.
call(f"/api/ghosts/{_uid}/tasks?project=UNSC", "POST",
     {"kind": "nslookup", "args": {"targets": ["fresh-a.example"]}}, token=admin)
st, u = call("/api/targets/unscanned?project=UNSC", token=admin)
check("a lookup does not make a host count as scanned",
      "fresh-a.example" in (u or {}).get("hosts", []),
      str((u or {}).get("hosts")))

# =====================================================================
# -sS needs raw sockets; -sT and -sV do not
# =====================================================================
print("\n== only a -sS is held back from an unprivileged ghost ==")

# `in-a-box` registered above with privileged: False.
UNPRIV = HID
st, pg = call("/api/ghosts?project=AGENT", "POST", {"name": "rootly"}, token=admin)
PKEY = (pg or {}).get("callback_key")
PID = ((pg or {}).get("agent") or {}).get("id")
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "version": "test",
      "hostname": "rootbox", "privileged": True}, key=PKEY)


def queue(aid, technique):
    st, t = call(f"/api/ghosts/{aid}/tasks?project=AGENT", "POST",
                 {"kind": "nmap", "args": {"targets": ["10.77.0.1"],
                                           "ports": "80",
                                           "technique": technique}},
                 token=admin)
    return st, (t or {}).get("id")


def handed_out(key):
    """Task ids this ghost is given on one beat, then reported done.

    Reporting matters: a ghost still holding a task has no free slot,
    so the next check would fail for that reason rather than for the
    one under test.
    """
    st, hb = call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=key)
    got = hb.get("tasks") or ([hb["task"]] if hb.get("task") else [])
    ids = [t["id"] for t in got]
    for i in ids:
        call(f"/api/ghosts/tasks/{i}/result", "POST",
             {"status": "done", "output": "{}", "stderr": "",
              "summary": "done", "exit_code": 0}, key=key)
    return ids


st, syn_id = queue(UNPRIV, "syn")
check("a -sS can be queued against an unprivileged ghost", st == 201, st)
check("...but it is not handed to it", syn_id not in handed_out(HKEY), syn_id)

# Not vacuous: the same ghost takes a -sT and a -sV happily, because
# neither needs the privilege it lacks.
st, con_id = queue(UNPRIV, "connect")
check("a -sT goes to the same unprivileged ghost", con_id in handed_out(HKEY),
      con_id)
st, ver_id = queue(UNPRIV, "version")
check("a -sV goes to the same unprivileged ghost", ver_id in handed_out(HKEY),
      ver_id)

# And a privileged ghost does get a -sS.
st, psyn = queue(PID, "syn")
check("a privileged ghost is given the -sS", psyn in handed_out(PKEY), psyn)

print("== a lookup already answered with nothing is not asked again ==")
# Re-asking a question a resolver has already answered costs an
# outbound request about a client's estate and returns the same
# nothing. Over a 1,700-name sweep that is 1,700 of them.
#
# The line that matters is between "answered with nothing" and "not
# answered". Only the first may suppress a future lookup; collapsing
# the second into it would let one SERVFAIL retire a live name from
# the engagement for good, and the gap would look like a clean result.
QUIET, ERRED, LIVE = "quiet.example", "erred.example", "live.example"
LOOKED = [QUIET, ERRED, LIVE]

# Its own agent: the one enrolled at the top of this file is killed
# partway through the suite, and a task addressed to a dead agent is
# refused before any of this is reached.
st, _qen = call("/api/ghosts?project=AGENT", "POST",
                {"name": "quiet-sweep"}, token=admin)
QID = ((_qen or {}).get("agent") or {}).get("id")
QSKEY = (_qen or {}).get("callback_key")
check("an agent for the sweep is enrolled", isinstance(QID, int), str(_qen)[:120])


def _answer(ids, outputs):
    """Deliver one result per queued task, by subject."""
    st, rows = call("/api/ghosts/tasks?project=AGENT", token=admin)
    by_id = {x["id"]: x["subject"] for x in (rows or [])}
    call("/api/ghosts/heartbeat", "POST", {}, key=QSKEY)
    for tid in ids:
        subj = by_id.get(tid)
        if subj in outputs:
            call(f"/api/ghosts/tasks/{tid}/result", "POST",
                 {"status": "done", "output": outputs[subj],
                  "summary": "answered", "exit_code": 0}, key=QSKEY)


st, r = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
             {"kind": "nslookup", "subjects": LOOKED, "agent_id": QID},
             token=admin)
check("a first sweep asks about all three", (r or {}).get("queued") == 3,
      str(r)[:140])
check("and nothing is skipped when nothing has been asked before",
      not (r or {}).get("skipped"), str(r)[:140])

_answer((r or {}).get("ids", []), {
    # Answered: the resolver replied and there are no records.
    QUIET: '[{"query":"quiet.example","a":[],"aaaa":[]}]',
    # NOT answered: the resolver failed. A different outcome entirely.
    ERRED: '[{"query":"erred.example","a":[],"error":"SERVFAIL"}]',
    LIVE: '[{"query":"live.example","a":["203.0.113.9"]}]',
})

st, r2 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "nslookup", "subjects": LOOKED, "agent_id": QID},
              token=admin)
sk2 = (r2 or {}).get("skipped") or {}
check("the name answered with nothing is not asked again",
      QUIET in sk2, str(r2)[:200])
check("...the one whose resolver errored IS asked again — a failure is "
      "not an answer", ERRED not in sk2, str(r2)[:200])
check("...and so is the one that resolved", LIVE not in sk2, str(r2)[:200])
check("so two tasks go out, not three", (r2 or {}).get("queued") == 2,
      str(r2)[:160])
check("and the skip names the run it is declining to repeat",
      isinstance(sk2.get(QUIET), int), str(sk2)[:160])

# The override, which is the whole reason the skip is safe to default
# on: records that did not exist last week may exist now.
st, r3 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "nslookup", "subjects": LOOKED, "agent_id": QID,
               "rescan_unresponsive": True}, token=admin)
check("ticking the box asks the quiet one again",
      (r3 or {}).get("queued") == 1, str(r3)[:200])
check("and then reports nothing as skipped",
      not (r3 or {}).get("skipped"), str(r3)[:160])
# The other two are not queued AGAIN, because the run they were given
# a moment ago has not finished. One run of a tool against one
# subject is one task: a second copy is not more work, it is the same
# requests to the same host twice. Reported by name rather than
# dropped, so "I asked for three and got one" has an answer.
check("...and the two still in flight are named, not silently dropped",
      sorted((r3 or {}).get("already_queued") or []) == [ERRED, LIVE],
      (r3 or {}).get("already_queued"))

# Newest answer wins. A name that was quiet in March and resolves in
# April must stop being skipped, or the stale half of the record
# governs forever.
_answer((r3 or {}).get("ids", []),
        {QUIET: '[{"query":"quiet.example","a":["203.0.113.40"]}]'})
st, r4 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "nslookup", "subjects": [QUIET], "agent_id": QID},
              token=admin)
check("a name that has since resolved is no longer skipped",
      not (r4 or {}).get("skipped") and (r4 or {}).get("queued") == 1,
      str(r4)[:180])

# Scoped to the lookup kinds on purpose. "No open ports" is a result
# about a moment on a network, and declining to look again would be a
# far stronger claim than this knows how to make.
st, p1 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "nmap", "subjects": ["203.0.113.77"], "agent_id": QID},
              token=admin)
_answer((p1 or {}).get("ids", []), {"203.0.113.77": "[]"})
st, p2 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "nmap", "subjects": ["203.0.113.77"], "agent_id": QID},
              token=admin)
check("a port scan that found nothing is still re-runnable",
      not (p2 or {}).get("skipped") and (p2 or {}).get("queued") == 1,
      str(p2)[:180])

print("== the project's User-Agent reaches the agent ==")
# Filled in at hand-over, not at queue time, so changing the
# engagement's attribution string does not mean draining the queue.
# Same reasoning as the wordlist and the reverse-lookup candidates.
call("/api/projects/AGENT", "PATCH",
     {"user_agent": "Acme Security (authorised test)"}, token=admin)
st, _uen = call("/api/ghosts?project=AGENT", "POST",
                {"name": "ua-agent"}, token=admin)
UAID = ((_uen or {}).get("agent") or {}).get("id")
UAKEY = (_uen or {}).get("callback_key")

st, _t = call(f"/api/ghosts/{UAID}/tasks?project=AGENT", "POST",
              {"kind": "httpx", "args": {"targets": ["ua.example"]}},
              token=admin)
st, hb = call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=UAKEY)
handed = hb.get("tasks") or ([hb["task"]] if hb.get("task") else [])
mine = [t for t in handed if t["kind"] == "httpx"]
check("the httpx task is handed over", len(mine) == 1, str(handed)[:160])
check("...carrying the project's user agent",
      (mine[0]["args"] if mine else {}).get("user_agent")
      == "Acme Security (authorised test)",
      str(mine[0]["args"] if mine else {})[:200])


def _finish(tasks):
    """Clear the agent's slots so the next heartbeat hands work over."""
    for t in tasks:
        call(f"/api/ghosts/tasks/{t['id']}/result", "POST",
             {"status": "done", "output": "", "stderr": "",
              "summary": "done", "exit_code": 0}, key=UAKEY)


_finish(handed)

# A kind whose tool sends no HTTP at all must not be handed one: an
# argument the runner ignores reads later as though the setting
# applies there, and it does not.
st, _t2 = call(f"/api/ghosts/{UAID}/tasks?project=AGENT", "POST",
               {"kind": "nslookup", "args": {"targets": ["ua2.example"]}},
               token=admin)
st, hb2 = call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=UAKEY)
handed2 = hb2.get("tasks") or ([hb2["task"]] if hb2.get("task") else [])
dns = [t for t in handed2 if t["kind"] == "nslookup"]
check("a DNS task is handed over", len(dns) == 1, str(handed2)[:160])
check("...with no user agent, because nothing there sends one",
      "user_agent" not in (dns[0]["args"] if dns else {"user_agent": 1}),
      str(dns[0]["args"] if dns else {})[:160])

# An explicit per-task value is not overwritten. A dialog offering a
# one-off override would be pointless if the project's value won.
st, _t3 = call(f"/api/ghosts/{UAID}/tasks?project=AGENT", "POST",
               {"kind": "gobuster",
                "args": {"targets": ["http://ua3.example/"],
                         "user_agent": "One Off/1.0"}}, token=admin)
_finish(handed2)
st, hb3 = call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=UAKEY)
handed3 = hb3.get("tasks") or ([hb3["task"]] if hb3.get("task") else [])
gb = [t for t in handed3 if t["kind"] == "gobuster"]
check("a per-task user agent survives the project's",
      (gb[0]["args"] if gb else {}).get("user_agent") == "One Off/1.0",
      str(gb[0]["args"] if gb else {})[:200])

print("== one run of a tool against one URL is one task ==")
# Two separate guarantees, and the incident violated the second.
#
#   each task carries exactly ONE subject   -- always held
#   one subject has at most ONE task open   -- did not
#
# A project reached five queued copies of the same URL and 97,959
# tasks because the planner's filter was wrong by a lowercase. The
# planner is fixed; this is the floor underneath it, so a caller that
# asks twice cannot produce two.
ONEURL = "http://once.example/"
st, q1 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": [ONEURL], "agent_id": QID},
              token=admin)
check("the first ask queues it", (q1 or {}).get("queued") == 1, str(q1)[:160])

st, rows = call("/api/ghosts/tasks?project=AGENT", token=admin)
mine = [x for x in (rows or []) if x["id"] in set((q1 or {}).get("ids", []))]
check("...as a single task carrying a single target",
      len(mine) == 1 and mine[0]["subject"] == ONEURL,
      str([x["subject"] for x in mine])[:120])

st, q2 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": [ONEURL], "agent_id": QID},
              token=admin)
check("asking again while it is unfinished queues nothing",
      (q2 or {}).get("queued") == 0, str(q2)[:160])
check("...and says which subject was already in flight",
      (q2 or {}).get("already_queued") == [ONEURL], str(q2)[:160])

# Case does not get you a second copy either. The two sides of this
# comparison disagreeing on case is precisely what produced the five
# copies, so it is asserted rather than assumed.
st, q3 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": ["http://Once.Example/"],
               "agent_id": QID}, token=admin)
check("...nor does a different spelling of the same URL",
      (q3 or {}).get("queued") == 0, str(q3)[:160])

# Scoped to the same tool. A crawl and a content-discovery run against
# one URL are different work and both are wanted.
st, q4 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "katana", "subjects": [ONEURL], "agent_id": QID},
              token=admin)
check("a different tool against the same URL is still queued",
      (q4 or {}).get("queued") == 1, str(q4)[:160])

# And once the run FINISHES, web discovery still declines — which is
# the one place this differs from the in-flight floor above.
#
# The reason is the client, not the database. A crawl of a site that
# has been crawled sends the same requests to the same host to learn
# the same thing. Until now the only thing standing between a
# finished crawl and a repeat of it was the Enumerate dialog's own
# listing, so a second operator, a dialog left open, the MCP tool or
# any script re-crawled it with nothing asked for and nothing said.
for tid in (q1 or {}).get("ids", []):
    call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=QSKEY)
    call(f"/api/ghosts/tasks/{tid}/result", "POST",
         {"status": "done", "output": "", "stderr": "", "summary": "done",
          "exit_code": 0}, key=QSKEY)
st, q5 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": [ONEURL], "agent_id": QID},
              token=admin)
check("a finished web run is NOT silently repeated",
      (q5 or {}).get("queued") == 0, str(q5)[:160])
check("...and it is reported as done, not as in flight",
      (q5 or {}).get("already_done") == [ONEURL]
      and not (q5 or {}).get("already_queued"), str(q5)[:200])

# The flag is the whole point: declining to repeat is a default, not
# a prohibition. Paths get added to a site, and re-walking one is a
# real thing to want.
st, q6 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": [ONEURL], "agent_id": QID,
               "rescan": True}, token=admin)
check("...unless rescan says to, which queues it",
      (q6 or {}).get("queued") == 1, str(q6)[:160])

# rescan lifts "already done". It does not lift "already in flight" —
# that one is the anti-stacking floor and nothing switches it off,
# because two copies of the same unfinished work is never the ask.
st, q7 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": [ONEURL], "agent_id": QID,
               "rescan": True}, token=admin)
check("rescan still cannot stack a second copy of unfinished work",
      (q7 or {}).get("queued") == 0
      and (q7 or {}).get("already_queued") == [ONEURL], str(q7)[:200])

# Per URL, not per host. One host serves several sites and each owes
# its own crawl — this is the distinction the operator asked for by
# name.
st, q8 = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
              {"kind": "gobuster", "subjects": ["http://once.example/app"],
               "agent_id": QID}, token=admin)
check("another URL on an already-crawled host is still queued",
      (q8 or {}).get("queued") == 1, str(q8)[:160])

# Only the web kinds. "No open ports" is a result about a moment, and
# refusing to look at a host again would be a far stronger claim than
# this is entitled to make.
NMAPPED = "10.44.0.9"
for _ in range(2):
    st, nq = call("/api/ghosts/tasks/bulk?project=AGENT", "POST",
                  {"kind": "nmap", "subjects": [NMAPPED], "agent_id": QID},
                  token=admin)
    for tid in (nq or {}).get("ids", []):
        call("/api/ghosts/heartbeat", "POST", {"ready": True}, key=QSKEY)
        call(f"/api/ghosts/tasks/{tid}/result", "POST",
             {"status": "done", "output": "", "stderr": "", "summary": "d",
              "exit_code": 0}, key=QSKEY)
check("a port scan is not subject to this and can be repeated",
      (nq or {}).get("queued") == 1, str(nq)[:160])

# ------------------------------------------------- a ghost that stops
# A host that dies mid-scan used to be invisible in three places at
# once, all of them downstream of the same reading: a held task counts
# as evidence the holder is alive. It is, for about ten minutes. One
# agent was found still in the fleet five and a half hours after its
# last beat, still holding two crawls that nothing could reap, because
# the only code that releases a claim runs on the beat of the agent
# doing the holding.
print("\n== a ghost that stops answering ==")

import asyncio as _aio  # noqa: E402

from app.db import SessionLocal as _Session  # noqa: E402
from app.models import Agent as _Ag  # noqa: E402
from app.models import AgentTask as _Tk  # noqa: E402
from app.models import Project as _Pr  # noqa: E402
from app.routers.agents import _next_up, _stale, reap_lost  # noqa: E402


def _quiet_for(minutes, status="online"):
    """An agent whose last beat was this long ago."""
    g = _Ag(project_id=1, name="quiet", status=status)
    g.last_seen = _dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=minutes)
    return g


check("a beating agent is online", _stale(_quiet_for(0)) == "online")
check("quiet a couple of minutes while working is busy, not dead",
      _stale(_quiet_for(2), 1) == "busy", _stale(_quiet_for(2), 1))
# The one that was wrong. Holding work used to outrank every clock, so
# this agent read as `busy` for as long as the corpse held the task.
check("quiet past five minutes is lost even while holding work",
      _stale(_quiet_for(6), 1) == "lost", _stale(_quiet_for(6), 1))
check("...and lost with nothing held, too",
      _stale(_quiet_for(6), 0) == "lost", _stale(_quiet_for(6), 0))
_killed = _quiet_for(600, status="disabled")
check("an operator's decision still outranks the clock",
      _stale(_killed) == "disabled", _stale(_killed))
# Enrolled and never started. Not lost: it has not arrived, it holds
# nothing, and there is nothing to take back off it.
_never = _Ag(project_id=1, name="never", status="offline")
_never.last_seen = None
check("an agent that never checked in is not called lost",
      _stale(_never) == "offline", _stale(_never))


async def _lost_ghost_drill():
    out = {}
    async with _Session() as db:
        pid = (await db.execute(
            _sel(_Pr.id).where(_Pr.code == "AGENT"))).scalar_one()
        now = _dt.datetime.now(_dt.UTC)
        # Planted rather than borrowed from the enrolment tests above:
        # those agents are killed and retired as this suite runs, and
        # a drill about who is alive should own its own fleet.
        dead = _Ag(project_id=pid, name="drill-dead", status="online",
                   callback_key_hash="x", last_seen=now - _dt.timedelta(minutes=40))
        alive = _Ag(project_id=pid, name="drill-alive", status="online",
                    callback_key_hash="y", last_seen=now)
        # Lost and holding nothing. Walking out from the held tasks
        # never reaches this one, and its row is exactly as wrong.
        empty = _Ag(project_id=pid, name="drill-empty", status="online",
                    callback_key_hash="w", last_seen=now - _dt.timedelta(minutes=40))
        # Killed by an operator and quiet for a month. A decision is
        # not an observation and must not be overwritten by one.
        off = _Ag(project_id=pid, name="drill-killed", status="disabled",
                  callback_key_hash="v", last_seen=now - _dt.timedelta(days=30))
        db.add_all([dead, alive, empty, off])
        await db.flush()

        def held(agent_id, held_for):
            t = _Tk(project_id=pid, agent_id=agent_id, kind="katana",
                    status="running", claimed_at=now - _dt.timedelta(minutes=held_for),
                    started_at=now - _dt.timedelta(minutes=held_for))
            db.add(t)
            return t

        stranded = held(dead.id, 40)   # dead holder, long held
        justtaken = held(dead.id, 1)   # dead holder, still in the grace
        working = held(alive.id, 40)   # live holder, long held
        await db.commit()
        ids = (stranded.id, justtaken.id, working.id)

        freed = await reap_lost(db, pid)
        await db.commit()
        out["freed"] = freed
        for tag, obj in (("dead", dead), ("alive", alive),
                         ("empty", empty), ("off", off)):
            await db.refresh(obj)
            out["status_" + tag] = obj.status
        for name, tid in zip(("stranded", "justtaken", "working"), ids, strict=True):
            t = (await db.execute(_sel(_Tk).where(_Tk.id == tid))).scalar_one()
            out[name] = (t.status, t.agent_id, t.error or "")
    return out


_d = _aio.run(_lost_ghost_drill())
check("a lost ghost's work goes back in the queue",
      _d["stranded"][0] == "queued" and _d["stranded"][1] is None,
      str(_d["stranded"])[:120])
check("...saying which ghost dropped it and that nothing was imported",
      "stopped answering" in _d["stranded"][2]
      and "nothing was imported" in _d["stranded"][2],
      _d["stranded"][2][:140])
# The ten minutes is not politeness. A result POST still on the wire,
# re-run as a second scan, is extra packets at a client's estate.
check("a claim inside the grace window is left alone even so",
      _d["justtaken"][0] == "running", str(_d["justtaken"])[:120])
check("a working ghost's long scan is not touched",
      _d["working"][0] == "running" and _d["working"][1] is not None,
      str(_d["working"])[:120])
check("and it says how many it took back", _d["freed"] == 1, _d["freed"])

# The column, not just the computed answer. `status` is stored, and
# the only things that ever refreshed it were the agent's own beat and
# a page load -- neither of which a dead agent produces, so the row
# that most needed updating was the one nothing would update.
check("the lost ghost is written down as lost, not left saying online",
      _d["status_dead"] == "lost", _d["status_dead"])
check("...including one that was holding nothing to find it by",
      _d["status_empty"] == "lost", _d["status_empty"])
check("a working ghost is not relabelled",
      _d["status_alive"] in ("online", "busy"), _d["status_alive"])
check("and an operator's kill is not overwritten by a clock",
      _d["status_off"] == "disabled", _d["status_off"])


# Wiring, not just the function. `reap_lost` being correct is worth
# nothing if nothing calls it, and the whole failure being fixed here
# is that the one release path could only be reached by a beat from
# the agent that was not beating. So: a live agent beats, and a DEAD
# agent's work comes back. Deliberately not ready for work, so what is
# observed is the reaping and not a hand-over.
st, enr = call("/api/ghosts?project=AGENT", "POST", {"name": "witness"},
               token=admin)
WITK = (enr or {}).get("callback_key")
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64"}, key=WITK)


async def _plant_corpse():
    async with _Session() as db:
        pid = (await db.execute(
            _sel(_Pr.id).where(_Pr.code == "AGENT"))).scalar_one()
        now = _dt.datetime.now(_dt.UTC)
        corpse = _Ag(project_id=pid, name="corpse", callback_key_hash="z",
                     last_seen=now - _dt.timedelta(minutes=40))
        db.add(corpse)
        await db.flush()
        t = _Tk(project_id=pid, agent_id=corpse.id, kind="katana",
                status="running", claimed_at=now - _dt.timedelta(minutes=40),
                started_at=now - _dt.timedelta(minutes=40))
        db.add(t)
        await db.commit()
        return t.id


async def _task_state(tid):
    async with _Session() as db:
        t = (await db.execute(_sel(_Tk).where(_Tk.id == tid))).scalar_one()
        return t.status, t.agent_id


_corpse_task = _aio.run(_plant_corpse())
check("the planted task starts out held",
      _aio.run(_task_state(_corpse_task))[0] == "running")
call("/api/ghosts/heartbeat", "POST", {"ready": False}, key=WITK)
_after = _aio.run(_task_state(_corpse_task))
check("another agent's heartbeat is enough to free it",
      _after == ("queued", None), str(_after))


async def _starvation_drill():
    """A big batch of one kind must not hide another kind.

    Not "delay" -- hide. Only DISPATCH_WINDOW rows are ever read, so
    under plain id order a batch larger than the window is the entire
    visible queue and nothing behind it exists. Nine hundred version
    scans sat behind a thousand crawls for four hours and were never
    looked at once; every agent had free slots the whole time.
    """
    async with _Session() as db:
        pid = (await db.execute(
            _sel(_Pr.id).where(_Pr.code == "AGENT"))).scalar_one()
        db.add_all([_Tk(project_id=pid, kind="katana", status="queued")
                    for _ in range(300)])
        await db.commit()
        db.add_all([_Tk(project_id=pid, kind="nmap", status="queued")
                    for _ in range(5)])
        await db.commit()
        rows = (await db.execute(_next_up(
            _Tk.project_id == pid, _Tk.agent_id.is_(None),
            _Tk.status == "queued"))).scalars().all()
    return [t.kind for t in rows]


_kinds = _aio.run(_starvation_drill())
check("the window is still bounded", len(_kinds) <= 100, len(_kinds))
check("work queued behind a batch three times the window is still seen",
      "nmap" in _kinds,
      f"{_kinds.count('nmap')} nmap, {_kinds.count('katana')} katana")
check("...and the batch is not starved in turn either",
      "katana" in _kinds, _kinds.count("katana"))
# Round-robin, so the scarce kind is near the front rather than merely
# present: five nmap against three hundred katana should interleave.
_first_nmap = _kinds.index("nmap") if "nmap" in _kinds else -1
check("the scarce kind comes up early, not at the end",
      0 <= _first_nmap <= 2, _first_nmap)


async def _queue_jump_drill():
    """Priority has to beat BOTH orderings, not one of them.

    The window reads DISPATCH_WINDOW rows, so ordering only the final
    result is no use: a task sitting at position 3,000 of its own kind
    is not in the window to be re-ordered in the first place. The row
    number within a kind is computed with priority first, which puts a
    jumping task at rn=1 for its kind and therefore inside the window,
    and the outer ordering then puts it ahead of every other kind's
    rn=1 as well.

    So this is planted the hardest way round: newest of its kind,
    behind a batch three times the window, of a kind that round-robin
    would otherwise take first.
    """
    async with _Session() as db:
        pid = (await db.execute(
            _sel(_Pr.id).where(_Pr.code == "AGENT"))).scalar_one()
        db.add_all([_Tk(project_id=pid, kind="katana", status="queued")
                    for _ in range(300)])
        await db.commit()
        jump = _Tk(project_id=pid, kind="katana", status="queued",
                   priority=100)
        db.add(jump)
        await db.commit()
        jid = jump.id
        rows = (await db.execute(_next_up(
            _Tk.project_id == pid, _Tk.agent_id.is_(None),
            _Tk.status == "queued"))).scalars().all()
    return jid, [(t.id, t.kind) for t in rows]


_jid, _order = _aio.run(_queue_jump_drill())
check("a priority task is handed out first, ahead of everything older",
      _order and _order[0][0] == _jid,
      f"first was #{_order[0][0] if _order else None}, wanted #{_jid}")
check("and is in the window at all, which plain ordering would not manage",
      _jid in [i for i, _ in _order])
# Nothing else moves. Age still orders within a kind -- asserted per
# kind, not across the whole window, because round-robin interleaves
# the kinds on purpose and a globally sorted list would mean THAT had
# been broken instead.
_rest = [(i, k) for i, k in _order[1:]]
check("priority does not otherwise reshuffle the queue: within each kind "
      "the rest is still oldest-first",
      all([i for i, k in _rest if k == kind]
          == sorted(i for i, k in _rest if k == kind)
          for kind in {k for _, k in _rest}),
      str(_order[:6]))

# ------------------------------------------------- the ghost's own log
# Diagnosing a ghost meant an account on the box it runs on, and this
# fleet is a GCP VM behind IAP, a Windows host whose docker lives in
# WSL2, and a droplet. When the GCP host lost its route there was no
# way in at all -- the only channel still working was the one the
# agent dials out on. So the agent gets somewhere to say what it is
# doing, off by default, because its lines name the hosts it scans.
print("\n== the ghost's own log ==")

st, end = call("/api/ghosts?project=AGENT", "POST", {"name": "talkative"},
               token=admin)
DID = ((end or {}).get("agent") or {}).get("id")
DNAME = ((end or {}).get("agent") or {}).get("name")
DKEY = (end or {}).get("callback_key")
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64"}, key=DKEY)

st, me = call("/api/ghosts?project=AGENT", token=admin)
row = next((a for a in (me or []) if a["id"] == DID), {})
check("a new ghost is not collecting its log", row.get("debug") is False,
      row.get("debug"))

st, hb = call("/api/ghosts/heartbeat", "POST", {"ready": False}, key=DKEY)
check("and the heartbeat tells it so", (hb or {}).get("debug") is False,
      str(hb)[:120])

# Refused while off. An agent that has not yet seen the switch move
# keeps posting for a beat or two, and the switch -- not the agent --
# decides whether this engagement keeps a copy.
st, shipped = call("/api/ghosts/debug-lines", "POST",
                   {"lines": [{"line": "while debug is off"}]}, key=DKEY)
check("a line sent while debug is off is not stored",
      st == 200 and (shipped or {}).get("stored") == 0, f"{st} {shipped}")
st, got = call("/api/ghosts/debug?project=AGENT", token=admin)
check("...and nothing is readable", len((got or {}).get("lines", [])) == 0,
      str(got)[:120])
check("...while the view can still say nobody is collecting",
      (got or {}).get("debugging") == [], str(got)[:120])

st, _ = call(f"/api/ghosts/{DID}?project=AGENT", "PATCH", {"debug": True},
             token=admin)
check("debug can be switched on", st == 200, st)
st, hb2 = call("/api/ghosts/heartbeat", "POST", {"ready": False}, key=DKEY)
check("the heartbeat carries the switch to the agent",
      (hb2 or {}).get("debug") is True, str(hb2)[:120])

st, shipped = call("/api/ghosts/debug-lines", "POST", {"lines": [
    {"line": "capacity now 6 (set from Oddjob)"},
    {"line": "WARNING: 101MB free"},
    {"line": "   "},
    {"line": ""},
]}, key=DKEY)
# Two, not four: a line that is empty once stripped is not a line, and
# storing it would put blank rows in the one view whose value is that
# it is short enough to read.
check("lines are stored once it is on, and blank ones are not",
      (shipped or {}).get("stored") == 2, str(shipped)[:120])

st, got = call("/api/ghosts/debug?project=AGENT", token=admin)
lines = (got or {}).get("lines", [])
check("and they come back newest first",
      len(lines) == 2 and lines[0]["line"] == "WARNING: 101MB free",
      str(lines)[:160])
check("...each naming the ghost that said it",
      all(entry["agent"] == DNAME for entry in lines), str(lines)[:140])
check("...and the view knows who is collecting",
      (got or {}).get("debugging") == [DNAME], str(got)[:140])

st, got = call("/api/ghosts/debug?project=AGENT&contains=101MB", token=admin)
check("the log can be searched", len((got or {}).get("lines", [])) == 1,
      str(got)[:140])
# A literal search, not a pattern: `_` is a wildcard in SQL and the
# operator typing it means the character.
st, got = call("/api/ghosts/debug?project=AGENT&contains=1_1MB", token=admin)
check("a wildcard typed into the box is matched literally",
      len((got or {}).get("lines", [])) == 0, str(got)[:140])

# A line is a line. A ghost that tries to push a scan's whole output
# through here gets it clipped rather than losing the batch.
st, _ = call("/api/ghosts/debug-lines", "POST",
             {"lines": [{"line": "x" * 9000}]}, key=DKEY)
st, got = call("/api/ghosts/debug?project=AGENT&contains=xxxx", token=admin)
longest = max((len(entry["line"]) for entry in (got or {}).get("lines", [])),
              default=0)
check("an enormous line is clipped, not refused",
      0 < longest <= 4000, longest)

# The agent's clock is used, but a badly set host must not pin its
# lines to the top of the view for ever.
st, _ = call("/api/ghosts/debug-lines", "POST",
             {"lines": [{"at": "2099-01-01T00:00:00Z",
                         "line": "from the future"}]}, key=DKEY)
st, got = call("/api/ghosts/debug?project=AGENT&contains=future", token=admin)
when = ((got or {}).get("lines") or [{}])[0].get("at") or ""
check("a line from the future is pulled back to now",
      not when.startswith("2099"), when)

# Unbounded growth from a chatty agent left in debug for a week is the
# failure this cap exists for.
for _batch in range(6):
    call("/api/ghosts/debug-lines", "POST",
         {"lines": [{"line": f"flood {_batch}-{i}"} for i in range(500)]},
         key=DKEY)
st, got = call("/api/ghosts/debug?project=AGENT&limit=5000", token=admin)
held = len((got or {}).get("lines", []))
check("the store is capped per ghost", held <= 2000, held)
check("...and it is the newest that survive",
      (got or {}).get("lines", [{}])[0].get("line") == "flood 5-499",
      str((got or {}).get("lines", [{}])[0])[:120])

# Switching off is also "stop keeping a copy of this".
st, _ = call(f"/api/ghosts/{DID}?project=AGENT", "PATCH", {"debug": False},
             token=admin)
st, got = call("/api/ghosts/debug?project=AGENT&limit=5000", token=admin)
check("switching debug off discards what was collected",
      len((got or {}).get("lines", [])) == 0,
      len((got or {}).get("lines", [])))
st, hb3 = call("/api/ghosts/heartbeat", "POST", {"ready": False}, key=DKEY)
check("and the agent is told to stop", (hb3 or {}).get("debug") is False,
      str(hb3)[:120])

# Scope. A debug line names the hosts an engagement is scanning, so it
# is not read more widely than the findings are.
call("/api/projects", "POST", {"code": "DBGX", "name": "Other"}, token=admin)
st, _ = call(f"/api/ghosts/{DID}?project=AGENT", "PATCH", {"debug": True},
             token=admin)
call("/api/ghosts/debug-lines", "POST",
     {"lines": [{"line": "belongs to AGENT"}]}, key=DKEY)
st, other = call("/api/ghosts/debug?project=DBGX", token=admin)
check("another engagement cannot read this one's debug log",
      len((other or {}).get("lines", [])) == 0, str(other)[:140])

# Role, which is a different question from scope. Being ON the
# engagement is not enough: the log is the agent's unedited running
# commentary -- which hosts it is probing right now, in what order,
# and what came back -- so it is read by the same people who can
# switch it on, and switching it on has always been `admin`.
call("/api/users", "POST",
     {"username": "deputy", "password": "deputy-password-1"}, token=admin)
st, deputy = call("/api/auth/login", "POST",
                  {"username": "deputy", "password": "deputy-password-1"})
dtok = (deputy or {}).get("access_token")
check("a non-admin member of the engagement can log in", bool(dtok),
      f"status={st}")
st, _ = call("/api/projects/AGENT/acl", "POST",
             {"username": "deputy", "role": "user"}, token=admin)
check("and is granted `user` on AGENT -- a writer, not an admin",
      st in (200, 201, 204), f"status={st}")

# They can do ordinary work on the engagement, so a refusal below is
# about this endpoint and not about the grant having failed to apply.
st, _ = call("/api/ghosts?project=AGENT", token=dtok)
check("a `user` can see the fleet", st == 200, st)

st, denied = call("/api/ghosts/debug?project=AGENT", token=dtok)
check("but a `user` cannot read the debug log", st == 403,
      f"{st} {str(denied)[:90]}")

# The other half of the same rule, asserted rather than assumed: if
# this ever became writable by a non-admin, collecting the log would
# be open to somebody who still could not read it, which is the
# asymmetry the read being admin-only exists to close.
st, _ = call(f"/api/ghosts/{DID}?project=AGENT", "PATCH", {"debug": True},
             token=dtok)
check("and a `user` cannot switch it on either", st == 403, st)

st, still = call("/api/ghosts/debug?project=AGENT", token=admin)
check("while an admin still reads it", st == 200,
      f"{st} {str(still)[:90]}")

# The allowlist itself, asserted directly. Going through HTTP cannot
# tell these two layers apart: the route's own dependencies refuse an
# anonymous read whether or not the middleware already did, so a test
# that only checks the status code passes with the read wrongly made
# public and proves nothing about which layer stopped it.
from app.gatekeeper import is_public as _is_public  # noqa: E402

check("the ghost's own path is public to the gatekeeper, as it must be",
      _is_public("/api/ghosts/debug-lines"))
check("but the operator's view of the log is not",
      not _is_public("/api/ghosts/debug"),
      "is_public matches on path alone, so sharing one path between the "
      "agent POST and the operator GET would make the read public to "
      "this middleware and leave it standing on its route dependency "
      "by itself")

# The agent's path is on the gatekeeper's allowlist because it carries
# an agent key rather than a session. The operator's path is NOT, and
# these are deliberately different URLs so that stays true -- the
# allowlist matches on path alone, with no idea of the method.
st, _ = call("/api/ghosts/debug?project=AGENT")
check("reading the log needs a session, allowlist or not",
      st in (302, 401, 403), st)
# And an agent key is not a session: it gets a ghost past the door,
# not into the operator's view of every ghost.
st, _ = call("/api/ghosts/debug?project=AGENT", key=DKEY)
check("a ghost's own key does not open the operator's view",
      st in (302, 401, 403), st)


# ================================= the agent can read a secret value
# The assistant told an operator "the database doesn't hold the actual
# secret values, only the findings recording that they exist". Half
# right, in the way that stops the work: the value IS stored in
# `finding_secrets` and the UI has always had a reveal button. There
# was simply no tool, so the model reasoned correctly from a premise
# nobody had told it was false.
print("\n== reading a secret through the assistant ==")
check("get_finding_secret exists at all", "get_finding_secret" in _ro,
      sorted(_ro)[:5])
# Reading a credential is reporting work's dangerous half, not its
# ordinary one -- but it is a READ, so it must not need write mode.
check("...without needing write mode", "get_finding_secret" in _ro)
check("...and is there with writes too", "get_finding_secret" in _rw)

_t = _ro.get("get_finding_secret")
check("it takes a finding id", _t is not None
      and "finding_id" in (_t.schema or {}).get("properties", {}),
      _t and _t.schema)
# The description is what the model reads before deciding whether the
# capability exists. It saying the values ARE stored is the fix.
check("...and its description says the values are stored",
      _t is not None and "ARE stored" in (_t.description or ""),
      _t and (_t.description or "")[:80])

# Routed through the same endpoint the UI calls, so the role check and
# the audit entry are not reimplemented here and cannot drift.
import inspect as _inspect  # noqa: E402

_src = _inspect.getsource(_build)
check("it goes through the HTTP handler rather than its own query",
      "reveal_secret" in _src, "reveal_secret" not in _src)


# ================================================ the proxy endpoints
# These exist because the three of them shipped over six pull requests
# without one test that CALLED them. Every write path had
# `audit.record(session, user, action, detail)` -- four positionals
# against a signature of three plus keywords -- so enabling proxying,
# issuing a credential and revoking one all raised TypeError and
# returned 500. The protocol was tested to the byte; the HTTP in front
# of it was not touched, and the button in the UI did nothing at all.
#
# So what is asserted here is deliberately shallow and deliberately
# end-to-end: that each endpoint returns, with a real session, a real
# project and a real ghost. A unit test of the SOCKS parser cannot
# catch a bad argument list in a router.
print("\n== the proxy endpoints answer at all ==")

# Its own ghost: the one enrolled at the top of this suite has been
# retired, killed and requeued by the time control reaches here, and
# a 404 from a stale id would look exactly like the bug under test.
_pg = call("/api/ghosts?project=AGENT", "POST",
           {"name": "proxy-subject"}, token=admin)[1]
PID = ((_pg or {}).get("agent") or {}).get("id")
check("a ghost to proxy through", isinstance(PID, int), str(_pg)[:120])

st, a = call(f"/api/ghosts/{PID}/proxy?project=AGENT", "PATCH",
             {"enabled": True}, token=admin)
check("enabling proxying on a ghost succeeds", st == 200,
      f"status={st} {str(a)[:200]}")
check("...and the ghost comes back with it on",
      isinstance(a, dict) and a.get("proxy_enabled") is True, str(a)[:120])

st, g = call(f"/api/ghosts/{PID}/proxy/grants?project=AGENT", "POST",
             {"note": "a browser"}, token=admin)
check("issuing a proxy credential succeeds", st in (200, 201),
      f"status={st} {str(g)[:200]}")
_user = (g or {}).get("username")
_pass = (g or {}).get("password")
check("...and hands back a username and a password",
      isinstance(_user, str) and isinstance(_pass, str) and len(_pass) > 12,
      str(_user))

st, lst = call(f"/api/ghosts/{PID}/proxy/grants?project=AGENT", token=admin)
check("the credential is listed", st == 200 and isinstance(lst, list)
      and any(x.get("username") == _user for x in lst), str(lst)[:160])
# The whole point of hashing it is undone if it comes back.
check("...without the password, ever",
      bool(_pass) and _pass not in json.dumps(lst),
      "the password was readable")

_gid = next((x["id"] for x in (lst or []) if x.get("username") == _user), None)
st, r = call(f"/api/ghosts/{PID}/proxy/grants/{_gid}?project=AGENT",
             "DELETE", token=admin)
check("revoking it succeeds", st == 200, f"status={st} {str(r)[:200]}")
check("...and it is marked revoked rather than deleted",
      isinstance(r, dict) and r.get("revoked_at"), str(r)[:120])

st, a = call(f"/api/ghosts/{PID}/proxy?project=AGENT", "PATCH",
             {"enabled": False}, token=admin)
check("switching proxying back off succeeds", st == 200,
      f"status={st} {str(a)[:200]}")
check("...and it is off", isinstance(a, dict)
      and a.get("proxy_enabled") is False, str(a)[:120])

# Admin, not user: this is the difference between a ghost that runs
# its tasks and one that carries arbitrary traffic into a client
# network.
call("/api/auth/users", "POST",
     {"username": "watcher", "password": "watcher-password-1",
      "role": "user"}, token=admin)
_w = call("/api/auth/login", "POST",
          {"username": "watcher", "password": "watcher-password-1"})[1]
_wt = (_w or {}).get("access_token")
if _wt:
    st, _ = call(f"/api/ghosts/{PID}/proxy?project=AGENT", "PATCH",
                 {"enabled": True}, token=_wt)
    check("a non-admin cannot switch proxying on", st in (401, 403, 404),
          f"status={st}")

# Every one of those writes an audit line, and a 500 in `audit.record`
# was what broke them. Proving the entries landed proves the call
# signature is right rather than merely that nothing raised.
st, ev = call("/audit/json?limit=500", token=admin)
_actions = {e.get("action") for e in ((ev or {}).get("entries") or [])}
check("the audit trail has the proxy actions",
      {"ghost.proxy", "ghost.proxy.grant",
       "ghost.proxy.revoke"} <= _actions,
      sorted(a for a in _actions if "proxy" in str(a)))


print("\n== the agent is told things it cannot know ==")
# Asked "what is the current date" it answered 2026-01-22 -- nine
# months out -- because nothing in the prompt said otherwise and a
# model answers from its weights when it has nothing else.
# `_dt` is already imported further up this file.
from app.routers.agent import SYSTEM, _today  # noqa: E402

_t = _today()
check("the prompt carries today's date",
      _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d") in _t, _t)
check("...as ISO, not a local format that reads two ways",
      _t[:4].isdigit() and _t[4] == "-", _t)
_filled = SYSTEM.format(code="X", client="", reach="", writes="", today=_t)
check("...and it reaches the rendered prompt", _t in _filled)

# The other half of that transcript: ten tool calls, three of them
# the same ILIKE search in different cases, and no answer.
check("the prompt says searches are case-insensitive",
      "CASE-INSENSITIVE" in _filled)
check("...and says what to do instead of re-casing a term",
      "DIFFERENT tool" in _filled or "SHORTER term" in _filled)
# Computed per request: this process runs for weeks and a date
# captured at import is wrong for every day after the first.
check("the date is computed per call, not frozen at import",
      _today() == _today())


print("\n== a stored thread goes back to the provider as messages ==")
# A user turn is stored as ONE message object; an assistant turn as
# the provider-shaped TAIL of the round, which is a LIST. Reading both
# with `append` put a list where a message belongs, and it travelled
# all the way to the provider, which answered the NEXT turn of any
# thread that had called a tool with
#
#   HTTP 400: Invalid request format: 'list' object has no attribute 'get'
#
# It was reported against a local model and is not local: the same
# thread breaks on any provider.
import json as _json  # noqa: E402

from app.routers.agent import thread_messages  # noqa: E402

# The two shapes exactly as they are found in a real thread.
_turns = [
    _json.dumps({"role": "user", "content": "are any of these secrets bad?"}),
    _json.dumps([
        {"role": "assistant", "content": [{"type": "text", "text": "Let me look."}]},
        {"role": "tool", "tool_call_id": "c1", "content": "{}"},
        {"role": "assistant", "content": "Two of them are live."},
    ]),
    _json.dumps({"role": "user", "content": "What is the current date?"}),
    _json.dumps([{"content": "It is 2026-01-22.", "role": "assistant"}]),
]
_msgs = thread_messages(_turns)
check("a tool-calling round is spread back out, not nested",
      len(_msgs) == 6, f"{len(_msgs)} messages, expected 6")
# The assertion that actually encodes the bug. Every element must be a
# message; one list among them is what the provider choked on.
check("...so every element is a message object",
      all(isinstance(m, dict) for m in _msgs),
      [type(m).__name__ for m in _msgs])
check("...in the order they were said",
      [m.get("role") for m in _msgs]
      == ["user", "assistant", "tool", "assistant", "user", "assistant"],
      [m.get("role") for m in _msgs])
check("a turn that is not JSON is dropped rather than sent",
      thread_messages(["{not json", _json.dumps({"role": "user"})])
      == [{"role": "user"}])
check("a list holding something that is not a message drops only that",
      thread_messages([_json.dumps([{"role": "assistant"}, "oops", 3])])
      == [{"role": "assistant"}])
check("an empty thread is an empty conversation", thread_messages([]) == [])


print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
