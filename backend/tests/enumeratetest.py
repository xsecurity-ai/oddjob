"""Turning finished lookups into inventory, and spotting unscanned ranges.

`/api/enumerate` derives its state rather than storing it: a pending
choice is a completed Drone lookup whose answer the target does not yet
carry. That is cheap and needs no table, but it means the behaviour is
entirely emergent — answering a choice has to make it disappear on its
own, and a stale lookup must not be able to overwrite a newer one.
Neither property is visible in the code; they only show up by driving
the endpoints.

These tests exist because this router shipped with none: it was written
in parallel under a brief that fixed the expected test count, which
discouraged adding any. A backend surface that queues scans and renames
hosts is not one to leave uncovered.
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
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    if key: r.add_header("X-Drone-Key", key)
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "ENUM", "name": "Enumerate"}, token=admin)

# An agent to own the lookups. Results are posted as a real agent would,
# because the whole point is that `pending` reads what Drone actually
# sends back rather than a shape invented for the test.
st, en = call("/api/agents?project=ENUM", "POST", {"name": "scanner"}, token=admin)
KEY, AID = en["callback_key"], en["agent"]["id"]
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True}, key=KEY)


def finish(kind, args, output):
    """Queue a task, let the agent claim it, and report a result."""
    st, t = call(f"/api/agents/{AID}/tasks?project=ENUM", "POST",
                 {"kind": kind, "args": args}, token=admin)
    tid = t["id"]
    call("/api/agents/heartbeat", "POST", {}, key=KEY)
    call(f"/api/agents/tasks/{tid}/result", "POST",
         {"status": "done", "output": json.dumps(output), "exit_code": 0},
         key=KEY)
    return tid


print("== a lookup with several answers becomes a choice ==")
call("/api/targets?project=ENUM", "POST",
     {"host": "198.51.100.10"}, token=admin)
finish("reverse_ip", {"targets": ["198.51.100.10"]},
       [{"ip": "198.51.100.10",
         "domains": ["one.acme.example", "two.acme.example"],
         "sources": ["ptr"], "partial": False}])

st, pend = call("/api/enumerate/pending?project=ENUM", token=admin)
check("pending is served", st == 200, f"status={st} {str(pend)[:120]}")
mine = [p for p in (pend or []) if p.get("subject") == "198.51.100.10"]
check("the address with two names is offered as one choice", len(mine) == 1,
      str(len(mine)))
check("and carries both candidates",
      sorted(mine[0]["options"]) == ["one.acme.example", "two.acme.example"]
      if mine else False, str(mine[0]["options"] if mine else None))

print("== a newer lookup wins ==")
# Re-running a lookup is how a stale answer gets corrected, so the older
# result must not be able to come back.
finish("reverse_ip", {"targets": ["198.51.100.10"]},
       [{"ip": "198.51.100.10",
         "domains": ["three.acme.example", "four.acme.example"],
         "sources": ["ptr"], "partial": False}])
st, pend = call("/api/enumerate/pending?project=ENUM", token=admin)
mine = [p for p in (pend or []) if p.get("subject") == "198.51.100.10"]
check("still one choice, not one per run", len(mine) == 1, str(len(mine)))
check("and it is the newer answer",
      sorted(mine[0]["options"]) == ["four.acme.example", "three.acme.example"]
      if mine else False, str(mine[0]["options"] if mine else None))

print("== applying an answer ==")
st, res = call("/api/enumerate/resolve?project=ENUM", "POST",
               {"host": "198.51.100.10", "field": "host",
                "value": "three.acme.example"}, token=admin)
check("the choice applies", st == 200, f"status={st} {str(res)[:120]}")

st, tgts = call("/api/targets?project=ENUM&page_size=100", token=admin)
rows = (tgts or {}).get("items", [])
named = [t for t in rows if t["host"] == "three.acme.example"]
check("the target is renamed", len(named) == 1, str([t["host"] for t in rows]))
check("and keeps the address it was found at",
      named[0]["ip_address"] == "198.51.100.10" if named else False,
      str(named[0].get("ip_address") if named else None))
check("the old name is gone, not duplicated",
      not any(t["host"] == "198.51.100.10" for t in rows),
      str([t["host"] for t in rows]))

st, pend = call("/api/enumerate/pending?project=ENUM", token=admin)
check("and the choice disappears without being marked done",
      not any(p.get("subject") == "198.51.100.10" for p in (pend or [])),
      str(pend)[:140])

print("== a rename is not a merge ==")
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.20"}, token=admin)
finish("reverse_ip", {"targets": ["198.51.100.20"]},
       [{"ip": "198.51.100.20", "domains": ["three.acme.example"],
         "sources": ["ptr"], "partial": False}])
st, err = call("/api/enumerate/resolve?project=ENUM", "POST",
               {"host": "198.51.100.20", "field": "host",
                "value": "three.acme.example"}, token=admin)
# Folding two targets together moves services, findings and PoCs
# between them. That is a decision, not a side effect of picking a name.
check("a name already in use is refused", st == 409, f"status={st}")
check("and the refusal names the target it would have collided with",
      "three.acme.example" in str(err), str(err)[:140])

print("== what cannot be applied ==")
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "198.51.100.20", "field": "host",
              "value": "203.0.113.9"}, token=admin)
check("an address is not a hostname", st == 422, f"status={st}")
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "198.51.100.20", "field": "host", "value": "   "},
             token=admin)
check("an empty answer is refused", st == 422, f"status={st}")
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "no-such.acme.example", "field": "host",
              "value": "x.acme.example"}, token=admin)
check("applying to a host that is not here is 404", st == 404, f"status={st}")

print("== permissions ==")
st, _ = call("/api/enumerate/pending?project=ENUM")
check("pending needs a session", st == 401, f"status={st}")
call("/api/users", "POST",
     {"username": "reader", "password": "reader-password-1"}, token=admin)
call("/api/projects/ENUM/acl", "POST",
     {"username": "reader", "role": "readonly"}, token=admin)
rtok = call("/api/auth/login", "POST",
            {"username": "reader", "password": "reader-password-1"})[1]["access_token"]
st, _ = call("/api/enumerate/pending?project=ENUM", token=rtok)
check("a reader may see pending choices", st == 200, f"status={st}")
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "198.51.100.20", "field": "host",
              "value": "ok.acme.example"}, token=rtok)
# Applying a choice edits the inventory, which readonly does not do.
check("but may not apply one", st == 403, f"status={st}")

print("== unscanned ranges ==")
st, ranges = call("/api/enumerate/ranges?project=ENUM", token=admin)
check("ranges is served", st == 200, f"status={st} {str(ranges)[:120]}")
check("with no scope defined there is nothing to report",
      ranges == [] or isinstance(ranges, list), str(ranges)[:120])


print("== the names you did not pick are still findings ==")
# An address answering to several names is usually shared hosting or a
# load balancer, and those other names are leads — frequently the most
# useful thing a reverse lookup produces. Choosing one must not discard
# the rest.
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.77"}, token=admin)
finish("reverse_ip", {"targets": ["198.51.100.77"]},
       [{"ip": "198.51.100.77",
         "domains": ["alpha.acme.example", "beta.acme.example",
                     "gamma.acme.example"],
         "sources": ["ptr"], "partial": False}])
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "198.51.100.77", "field": "host",
              "value": "alpha.acme.example",
              "also_resolved": ["alpha.acme.example", "beta.acme.example",
                                "gamma.acme.example"]}, token=admin)
check("the pick applies", st == 200, f"status={st}")

st, tl = call("/api/targets/ENUM/alpha.acme.example/timeline", token=admin)
events = tl if isinstance(tl, list) else (tl or {}).get("items", [])
blob = json.dumps(events)
check("the other names are recorded against the target",
      "beta.acme.example" in blob and "gamma.acme.example" in blob,
      f"status={st} {blob[:140]}")
check("and the one chosen is not listed as an also-ran",
      blob.count("alpha.acme.example") >= 1, blob[:80])
check("the note says what they are and are not",
      "shared hosting" in blob or "load balancer" in blob, blob[:160])

print("\n== the names not chosen can be added or refused ==")
# Picking one name does not make the others untrue. Until now they went
# on the timeline and nowhere else: findable, but not testable, and
# proposed again by domain detection a week later.
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.40"},
     token=admin)
finish("reverse_ip", {"targets": ["198.51.100.40"]},
       [{"ip": "198.51.100.40",
         "domains": ["keep.acme.example", "add-me.acme.example",
                     "deny-me.acme.example", "ignore-me.acme.example"],
         "sources": ["ptr"], "partial": False}])
st, res = call("/api/enumerate/resolve?project=ENUM", "POST",
               {"host": "198.51.100.40", "field": "host",
                "value": "keep.acme.example",
                "also_resolved": ["keep.acme.example", "add-me.acme.example",
                                  "deny-me.acme.example",
                                  "ignore-me.acme.example"],
                "add": ["add-me.acme.example"],
                "deny": ["deny-me.acme.example"]}, token=admin)
check("the choice applies with decisions attached", st == 200,
      f"status={st} {str(res)[:140]}")
check("and names what it added rather than counting it",
      (res or {}).get("added") == ["add-me.acme.example"], str(res)[:160])
check("and what it refused", (res or {}).get("denied") == ["deny-me.acme.example"],
      str(res)[:160])

st, tgts = call("/api/targets?project=ENUM&page_size=200", token=admin)
hosts = {t["host"] for t in (tgts or {}).get("items", [])}
check("the chosen name is the target", "keep.acme.example" in hosts, str(sorted(hosts))[:200])
check("the added one is a target in its own right",
      "add-me.acme.example" in hosts, str(sorted(hosts))[:200])
check("the refused one is not", "deny-me.acme.example" not in hosts,
      str(sorted(hosts))[:200])
# Silence is not a decision: untouched names stay leads on the
# timeline, exactly as before.
check("and one left alone is neither added nor refused",
      "ignore-me.acme.example" not in hosts, str(sorted(hosts))[:200])

added = next(t for t in (tgts or {}).get("items", [])
             if t["host"] == "add-me.acme.example")
check("nothing probed it, so it is not claimed to be alive",
      added["alive"] is None, str(added["alive"]))

# The refusal is remembered, or the same judgement gets asked for again.
st, cands = call("/api/domains/candidates?project=ENUM", token=admin)
by = {c["name"]: c for c in (cands or [])}
check("the refusal is recorded against the name",
      by.get("deny-me.acme.example", {}).get("state") == "rejected",
      str(by.get("deny-me.acme.example"))[:140])
check("and the acceptance too, so neither is proposed again",
      by.get("add-me.acme.example", {}).get("state") == "accepted",
      str(by.get("add-me.acme.example"))[:140])

print("-- only names the lookup actually returned --")
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.41"},
     token=admin)
finish("reverse_ip", {"targets": ["198.51.100.41"]},
       [{"ip": "198.51.100.41", "domains": ["a.acme.example", "b.acme.example"],
         "sources": ["ptr"], "partial": False}])
st, res = call("/api/enumerate/resolve?project=ENUM", "POST",
               {"host": "198.51.100.41", "field": "host",
                "value": "a.acme.example",
                "also_resolved": ["a.acme.example", "b.acme.example"],
                "add": ["smuggled.acme.example"]}, token=admin)
# This endpoint is for choosing between answers, not a door into
# creating arbitrary targets.
check("a name the lookup never returned is not created",
      (res or {}).get("added") == [], str(res)[:140])
st, tgts = call("/api/targets?project=ENUM&page_size=200&q=smuggled", token=admin)
check("and does not appear in the inventory",
      (tgts or {}).get("total") == 0, str(tgts)[:120])

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
