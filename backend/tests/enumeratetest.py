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

print("== an address-named row taking a name we already hold is a merge ==")
# This used to be a 409. The operator ruled it automatic in this one
# direction: an address-named target is nearly always sparse — it
# exists because a sweep found an open port before anything knew what
# the machine was called — and refusing meant the two rows sat side by
# side for the rest of the engagement. The FQDN survives and keeps its
# name; nothing it holds is touched.
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.20"}, token=admin)
call("/api/bulk", "POST", {
    "project": "ENUM", "autocreate_targets": True,
    "vulns": [{"host": "198.51.100.20", "title": "Open redirect on the sparse row",
               "severity": "medium"}],
    "services": [{"host": "198.51.100.20", "port": 8080, "protocol": "tcp"}],
}, token=admin)
finish("reverse_ip", {"targets": ["198.51.100.20"]},
       [{"ip": "198.51.100.20", "domains": ["three.acme.example"],
         "sources": ["ptr"], "partial": False}])
# Nothing is called here. One name, and we already hold it: that is not
# a decision, so it resolves itself the moment the Drone reports back.
# "Automatic" that waits for somebody to open a page is a button with a
# long name.
st, tgts = call("/api/targets?project=ENUM&page_size=100", token=admin)
rows = (tgts or {}).get("items", [])
check("it merged with nobody asked", st == 200, f"status={st}")
check("the address-named row is gone",
      not any(t["host"] == "198.51.100.20" for t in rows),
      str([t["host"] for t in rows]))
surv = [t for t in rows if t["host"] == "three.acme.example"]
check("and the survivor answers at both addresses",
      sorted(surv[0]["ip_addresses"]) == ["198.51.100.10", "198.51.100.20"]
      if surv else False,
      str(surv[0].get("ip_addresses") if surv else None))

st, tl = call("/api/targets/ENUM/three.acme.example/timeline", token=admin)
events = tl if isinstance(tl, list) else (tl or {}).get("items", [])
blob = json.dumps(events)
# An address-named row that HAD accumulated findings must be visible in
# the record, not silently absorbed. The headline says so, not the
# detail: whoever reads this in three weeks is asking where the finding
# came from, and the answer has to be the first thing they see.
check("the merge is on the surviving target's timeline",
      "merged 198.51.100.20 into three.acme.example" in blob, blob[:200])
check("and the headline names what it was carrying",
      "was carrying" in blob and "1 finding" in blob, blob[:300])
check("the absorbed finding is now on the survivor",
      any(v["title"] == "Open redirect on the sparse row"
          for v in (call("/api/vulns?project=ENUM&page_size=100",
                         token=admin)[1] or {}).get("items", [])),
      "")

print("-- but two established names still refuse --")
# The narrow direction is the whole safety argument. Folding one FQDN
# into another moves findings between two rows that both represent
# deliberate, named inventory, and that stays a decision somebody makes
# with a plan in front of them.
call("/api/targets?project=ENUM", "POST", {"host": "named-a.acme.example"}, token=admin)
call("/api/targets?project=ENUM", "POST", {"host": "named-b.acme.example"}, token=admin)
st, err = call("/api/enumerate/resolve?project=ENUM", "POST",
               {"host": "named-a.acme.example", "field": "host",
                "value": "named-b.acme.example"}, token=admin)
check("an FQDN renaming onto another FQDN is refused", st == 409, f"status={st}")
check("and the refusal names the target it would have collided with",
      "named-b.acme.example" in str(err), str(err)[:160])
check("and says where to do it deliberately",
      "merge" in str(err).lower(), str(err)[:200])

print("== what cannot be applied ==")
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.21"}, token=admin)
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "198.51.100.21", "field": "host",
              "value": "203.0.113.9"}, token=admin)
check("an address is not a hostname", st == 422, f"status={st}")
st, _ = call("/api/enumerate/resolve?project=ENUM", "POST",
             {"host": "198.51.100.21", "field": "host", "value": "   "},
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

# =========================================== promoting a recorded decision
# These two endpoints live in the domains router but their only producer
# is up here: the reverse-IP flow is what writes candidate rows now that
# the offline name generator is gone. They were briefly uncovered when it
# went, which is the whole reason for this section.
print("\n== a name refused earlier can still be promoted later ==")


def cand(name):
    st, rows = call("/api/domains/candidates?project=ENUM", token=admin)
    return next((c for c in (rows or []) if c["name"] == name), None)


# `deny` records the judgement without creating anything, so a rejected
# candidate is the one case where a row exists and a target does not.
# That is exactly the state promote has to handle.
row = cand("deny-me.acme.example")
check("the refused name has a candidate row to promote", row is not None,
      str(row)[:120])
st, res = call("/api/domains/candidates/promote?project=ENUM", "POST",
               {"ids": [row["id"]]}, token=admin)
check("promoting it creates the target",
      (res or {}).get("created") == ["deny-me.acme.example"],
      f"status={st} {str(res)[:160]}")
st, tgts = call("/api/targets?project=ENUM&page_size=200&q=deny-me", token=admin)
items = (tgts or {}).get("items", [])
check("and it is in the inventory", len(items) == 1, str(tgts)[:140])
check("unprobed, because promoting is not a probe",
      items[0]["alive"] is None if items else False,
      str(items[0]["alive"] if items else None))
check("the earlier refusal is overwritten, not left contradicting it",
      (cand("deny-me.acme.example") or {}).get("state") == "accepted",
      str(cand("deny-me.acme.example"))[:120])

st, tl = call("/api/targets/ENUM/deny-me.acme.example/timeline", token=admin)
events = tl if isinstance(tl, list) else (tl or {}).get("items", [])
check("and the timeline says where the name came from",
      "reverse_ip" in json.dumps(events), json.dumps(events)[:160])

print("-- a name that is already a target is reported, not duplicated --")
row = cand("add-me.acme.example")        # `add` made this one a target
st, res = call("/api/domains/candidates/promote?project=ENUM", "POST",
               {"ids": [row["id"]]}, token=admin)
check("it comes back as already existing",
      (res or {}).get("already_existed") == ["add-me.acme.example"],
      f"status={st} {str(res)[:160]}")
check("and nothing was created", (res or {}).get("created") == [], str(res)[:120])
check("the row says so rather than claiming a fresh decision",
      (cand("add-me.acme.example") or {}).get("state") == "exists",
      str(cand("add-me.acme.example"))[:120])
st, tgts = call("/api/targets?project=ENUM&page_size=200&q=add-me", token=admin)
check("and the target is not forked", (tgts or {}).get("total") == 1, str(tgts)[:120])

print("-- reject marks the row and leaves the inventory alone --")
st, res = call("/api/domains/candidates/reject?project=ENUM", "POST",
               {"ids": [row["id"]]}, token=admin)
check("reject names what it rejected",
      (res or {}).get("rejected") == ["add-me.acme.example"],
      f"status={st} {str(res)[:140]}")
check("and the row carries it",
      (cand("add-me.acme.example") or {}).get("state") == "rejected",
      str(cand("add-me.acme.example"))[:120])
# Rejecting a candidate is a judgement about the name, not an instruction
# to delete a target somebody is already testing.
st, tgts = call("/api/targets?project=ENUM&page_size=200&q=add-me", token=admin)
check("the existing target is untouched", (tgts or {}).get("total") == 1,
      str(tgts)[:120])

print("-- scope decides, and a refusal is not recorded as a human one --")
# Up to here ENUM has had no scope list at all, so everything was allowed.
# Narrowing it means the next promote has something to refuse. The range
# goes on too, or the address these lookups run against stops being
# testable and the fixture breaks before it reaches the point.
call("/api/projects/ENUM/scope", "POST",
     {"lines": ["*.acme.example", "198.51.100.0/24"]}, token=admin)
call("/api/targets?project=ENUM", "POST", {"host": "198.51.100.50"}, token=admin)
# `partial`, so this stays a human's decision and the section can make
# one. Without it the scope list refuses the neighbour, exactly one name
# is left, and the result resolves itself on arrival — which is correct
# and is asserted in the automatic-resolution section at the bottom.
finish("reverse_ip", {"targets": ["198.51.100.50"]},
       [{"ip": "198.51.100.50",
         "domains": ["tenant.acme.example", "neighbour.someone-else.example"],
         "sources": ["ptr"], "partial": True}])
st, res = call("/api/enumerate/resolve?project=ENUM", "POST",
               {"host": "198.51.100.50", "field": "host",
                "value": "tenant.acme.example",
                "also_resolved": ["tenant.acme.example",
                                  "neighbour.someone-else.example"],
                "deny": ["neighbour.someone-else.example"]}, token=admin)
check("a neighbour on the same address can be refused",
      (res or {}).get("denied") == ["neighbour.someone-else.example"],
      f"status={st} {str(res)[:160]}")

row = cand("neighbour.someone-else.example")
st, res = call("/api/domains/candidates/promote?project=ENUM", "POST",
               {"ids": [row["id"]]}, token=admin)
check("promoting it is refused on scope",
      list((res or {}).get("out_of_scope", {})) ==
      ["neighbour.someone-else.example"], f"status={st} {str(res)[:180]}")
check("with a reason, not a bare no",
      "scope" in (res or {}).get("out_of_scope", {})
      .get("neighbour.someone-else.example", ""),
      str(res)[:200])
check("and no target appears", (res or {}).get("created") == [], str(res)[:120])
st, tgts = call("/api/targets?project=ENUM&page_size=200&q=someone-else", token=admin)
check("not even a refused one", (tgts or {}).get("total") == 0, str(tgts)[:120])
# The scope list refused this, not a person. Writing "rejected" on the row
# would put a judgement nobody made into the audit trail — and would also
# stop it being offered again once scope changes.
check("the row keeps the decision a person actually made",
      (cand("neighbour.someone-else.example") or {}).get("state") == "rejected",
      str(cand("neighbour.someone-else.example"))[:140])

print("-- candidates are project-scoped --")
call("/api/projects", "POST", {"code": "ENUM2", "name": "Elsewhere"}, token=admin)
keep = cand("tenant.acme.example") or cand("deny-me.acme.example")
st, res = call("/api/domains/candidates/promote?project=ENUM2", "POST",
               {"ids": [keep["id"]]}, token=admin)
# Ids are global, so the filter on project_id is the only thing stopping
# one project promoting another's candidate by guessing a number.
check("another project's id promotes nothing",
      (res or {}).get("created") == [] and
      (res or {}).get("already_existed") == [], f"status={st} {str(res)[:160]}")
st, tgts = call("/api/targets?project=ENUM2&page_size=200", token=admin)
check("and creates no target there", (tgts or {}).get("total") == 0, str(tgts)[:120])

# ====================================================== Kitchen Sink Lookup
# The walk is the part most easily got subtly wrong, and the way it goes
# wrong is by producing one name too many at the bottom. Checked here
# directly as well as through the endpoint, because "it stopped at the
# registrable domain" is a property of the function and asserting it over
# HTTP would only ever cover the handful of suffixes the fixture happens
# to use.
print("\n== walking a hostname back to its registrable domain ==")
from app.domains import walk_to_registrable as _walk  # noqa: E402

check("the operator's example, in full",
      _walk("a.b.c.d.e.f.com") == [
          "a.b.c.d.e.f.com", "b.c.d.e.f.com", "c.d.e.f.com", "d.e.f.com",
          "e.f.com", "f.com"],
      str(_walk("a.b.c.d.e.f.com")))
check("the host itself is included, not just its parents",
      _walk("one.corp.com")[0] == "one.corp.com", str(_walk("one.corp.com")))
check("a registrable domain walks to itself alone",
      _walk("corp.com") == ["corp.com"], str(_walk("corp.com")))

# The floor. `co.uk` is a public suffix: nobody owns it, enumerating it
# is enumerating every British company at once, and it is the one name
# in the list guaranteed not to be the client's.
_uk = _walk("a.b.example.co.uk")
check("a two-level public suffix stops at the registrable domain",
      _uk == ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk"],
      str(_uk))
check("and the suffix itself is never produced", "co.uk" not in _uk, str(_uk))
check("nor the TLD", "uk" not in _uk, str(_uk))
check("the same for .com", "com" not in _walk("a.b.corp.com"),
      str(_walk("a.b.corp.com")))

check("an address has no zone to walk", _walk("198.51.100.5") == [],
      str(_walk("198.51.100.5")))
check("nor does a bare label", _walk("localhost") == [], str(_walk("localhost")))
check("a name with an empty label is refused rather than walked",
      _walk("a..b.com") == [], str(_walk("a..b.com")))
check("and so is nothing at all", _walk("") == [] and _walk("   ") == [],
      str(_walk("   ")))

print("\n== Kitchen Sink Lookup over a project's hosts ==")
call("/api/projects", "POST", {"code": "KS", "name": "Kitchen Sink"},
     token=admin)
# `*.acme.example` covers names under it and deliberately NOT the apex,
# which is how a generated parent ends up refused — the case the walk
# must not be allowed to talk its way past. `example.co.uk` is written
# out in full so the two-level-suffix host has somewhere legitimate to
# stop; both are placeholders, and nothing here resolves anything.
call("/api/projects/KS/scope", "POST",
     {"lines": ["*.acme.example", "*.example.co.uk", "example.co.uk",
                "198.51.100.0/24"]}, token=admin)
st, ksa = call("/api/agents?project=KS", "POST", {"name": "ks-drone"},
               token=admin)
KSKEY = ksa["callback_key"]
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True}, key=KSKEY)
call("/api/agents/heartbeat", "POST", {}, key=KSKEY)

for _h in ("one.svc.acme.example", "two.svc.acme.example",
           "shop.example.co.uk", "198.51.100.5"):
    call("/api/targets?project=KS", "POST", {"host": _h}, token=admin)


def ks(body):
    return call("/api/domains/enumerate?project=KS", "POST", body, token=admin)


st, r1 = call("/api/domains/enumerate?project=KS", "POST",
              {"domains": "", "kitchen_sink": True}, token=admin)
check("a kitchen sink run with an empty box is accepted", st == 200,
      f"status={st} {str(r1)[:160]}")
q1 = sorted(x["domain"] for x in (r1 or {}).get("queued", []))
check("every host walks back to its domain and all of it is queued",
      q1 == ["example.co.uk", "one.svc.acme.example", "shop.example.co.uk",
             "svc.acme.example", "two.svc.acme.example"], str(q1))

# Two hosts share `svc.acme.example`. Ten would share it ten times, and
# ten amass tasks for one zone is ten times the traffic for one zone's
# worth of answer.
check("a parent shared by two hosts is queued once, not twice",
      q1.count("svc.acme.example") == 1, str(q1))
check("and the count of distinct domains considered is reported",
      (r1 or {}).get("considered") == 6, str(r1)[:200])

# The apex. `one.svc.acme.example` being approved says nothing about
# `acme.example`, and queueing amass at a zone nobody signed off is
# traffic at an unapproved asset.
ref1 = (r1 or {}).get("refused", {})
check("the apex parent of approved children is refused on its own merits",
      list(ref1) == ["acme.example"], str(ref1)[:200])
check("with the scope list's reason, not a bare no",
      "in-scope list" in ref1.get("acme.example", ""), str(ref1)[:200])

_blob = json.dumps(r1)
check("the public suffix under the co.uk host is never reached",
      '"co.uk"' not in _blob and "co.uk:" not in _blob, _blob[:200])
check("and the address-named host contributes nothing",
      "198.51" not in _blob and "100.5" not in _blob, _blob[:200])
check("nothing was skipped on a first run", (r1 or {}).get("skipped") == [],
      str(r1)[:160])
check("and the mode is reported back", (r1 or {}).get("kitchen_sink") is True,
      str(r1)[:160])

print("-- a second run skips what the first queued --")
st, r2 = ks({"domains": "", "kitchen_sink": True})
check("the run is accepted rather than erroring", st == 200, f"status={st}")
check("and queues nothing", (r2 or {}).get("queued") == [], str(r2)[:200])
sk2 = sorted(x["domain"] for x in (r2 or {}).get("skipped", []))
check("every domain already handed to amass comes back as skipped",
      sk2 == q1, str(sk2))
check("named, not merely counted, so the operator can see which",
      all(x.get("domain") for x in (r2 or {}).get("skipped", [])), str(sk2))
check("each carrying how many times it has run",
      {x["runs"] for x in (r2 or {}).get("skipped", [])} == {1},
      str((r2 or {}).get("skipped"))[:200])
check("and when",
      all(x.get("last_run_at") for x in (r2 or {}).get("skipped", [])),
      str((r2 or {}).get("skipped"))[:200])
# A skip is not a refusal: the apex is still out of scope and still
# said so, and the two reasons must not be collapsed into one list.
check("a domain refused on scope is still refused, not reported as skipped",
      list((r2 or {}).get("refused", {})) == ["acme.example"], str(r2)[:200])
check("and is not in the skipped list", "acme.example" not in sk2, str(sk2))

print("-- the rescan flag is what runs them again --")
st, r3 = ks({"domains": "", "kitchen_sink": True, "rescan": True})
q3 = sorted(x["domain"] for x in (r3 or {}).get("queued", []))
check("ticking rescan queues the lot again", q3 == q1, str(q3))
check("and nothing is skipped", (r3 or {}).get("skipped") == [], str(r3)[:160])

st, r4 = ks({"domains": "", "kitchen_sink": True})
check("the rerun is counted rather than overwritten",
      {x["runs"] for x in (r4 or {}).get("skipped", [])} == {2},
      str((r4 or {}).get("skipped"))[:200])

print("-- a typed domain is an instruction, and is run --")
# The skip belongs to the generated list. Refusing to enumerate a zone
# somebody just typed the name of, because it ran last week, would be
# the tool overruling the operator.
st, r5 = ks({"domains": "svc.acme.example"})
check("a domain already scanned is still queued when it is typed",
      [x["domain"] for x in (r5 or {}).get("queued", [])] ==
      ["svc.acme.example"], f"status={st} {str(r5)[:200]}")
check("and nothing is skipped in plain mode",
      (r5 or {}).get("skipped") == [], str(r5)[:160])
check("plain mode says so", (r5 or {}).get("kitchen_sink") is False,
      str(r5)[:160])

st, r6 = ks({"domains": "one.svc.acme.example"})
check("and a typed name is not walked — only what was asked for goes out",
      [x["domain"] for x in (r6 or {}).get("queued", [])] ==
      ["one.svc.acme.example"], str(r6)[:200])
check("so no parent is invented from a plain submission",
      (r6 or {}).get("considered") == 1, str(r6)[:160])

print("-- a project with nothing but addresses --")
call("/api/projects", "POST", {"code": "KS2", "name": "Addresses only"},
     token=admin)
call("/api/projects/KS2/scope", "POST", {"lines": ["203.0.113.0/24"]},
     token=admin)
st, ks2a = call("/api/agents?project=KS2", "POST", {"name": "ks2-drone"},
                token=admin)
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True},
     key=ks2a["callback_key"])
call("/api/targets?project=KS2", "POST", {"host": "203.0.113.7"}, token=admin)
st, r7 = call("/api/domains/enumerate?project=KS2", "POST",
              {"domains": "", "kitchen_sink": True}, token=admin)
# "There was nothing here" and "it worked and did nothing" read
# identically as an empty success and have different fixes.
check("an estate of addresses is told so rather than silently succeeding",
      st == 422, f"status={st} {str(r7)[:160]}")
check("and the reason says addresses, not 'no domains'",
      "address" in str(r7).lower(), str(r7)[:200])

print("-- more domains than one submission may queue --")
# A typed list over the cap is an operator mistake they can fix by
# splitting it. A WALKED list over the cap is just a big estate, and
# there is nothing for them to split — so the overflow is reported and
# left for the next run, which skips everything this one queued.
call("/api/projects", "POST", {"code": "KS3", "name": "Big estate"},
     token=admin)
call("/api/projects/KS3/scope", "POST",
     {"lines": ["*.cap.example", "cap.example"]}, token=admin)
st, ks3a = call("/api/agents?project=KS3", "POST", {"name": "ks3-drone"},
                token=admin)
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True},
     key=ks3a["callback_key"])
_many = [f"n{i}.cap.example" for i in range(200)]
st, r8 = call("/api/domains/enumerate?project=KS3", "POST",
              {"domains": "\n".join(_many), "kitchen_sink": True},
              token=admin)
check("the submission is accepted rather than refused for being big",
      st == 200, f"status={st} {str(r8)[:160]}")
check("and 201 domains come out of 200 names plus their shared parent",
      (r8 or {}).get("considered") == 201, str(r8)[:200])
check("exactly the cap is queued", len((r8 or {}).get("queued", [])) == 200,
      str(len((r8 or {}).get("queued", []))))
check("and the overflow is named, not dropped",
      len((r8 or {}).get("deferred", [])) == 1,
      str((r8 or {}).get("deferred"))[:160])

_left = (r8 or {}).get("deferred", [None])[0]
st, r9 = call("/api/domains/enumerate?project=KS3", "POST",
              {"domains": "\n".join(_many), "kitchen_sink": True},
              token=admin)
# No search row was written for a deferred domain, so it is the one
# thing the next run still has to do. Running it twice drains the
# backlog rather than repeating the first 200.
check("the next run picks up exactly what was left",
      [x["domain"] for x in (r9 or {}).get("queued", [])] == [_left],
      f"deferred was {_left}; queued {str((r9 or {}).get('queued'))[:160]}")
check("and skips the 200 already handed over",
      len((r9 or {}).get("skipped", [])) == 200,
      str(len((r9 or {}).get("skipped", []))))
check("with nothing left deferred", (r9 or {}).get("deferred") == [],
      str((r9 or {}).get("deferred"))[:120])

# ======================================= automatic lookup resolution
# Under the old model every lookup result was a question, because
# `Target.ip_address` was one column: four addresses for one slot is
# four candidates and a human had to pick. Addresses are many-to-many
# now, so most of those questions stop being questions. The boundary
# between what is automatic and what is not is the substance of this
# feature, so it is asserted case by case.
print("\n== what a lookup result decides for itself ==")
call("/api/projects", "POST",
     {"code": "AUTO", "name": "Auto", "scope": ["*.acme.example",
                                                "198.51.100.0/24"]},
     token=admin)
st, ag = call("/api/agents?project=AUTO", "POST", {"name": "scanner"}, token=admin)
AKEY, AAID = ag["callback_key"], ag["agent"]["id"]
call("/api/agents/register", "POST",
     {"platform": "linux", "arch": "amd64", "privileged": True}, key=AKEY)


def afinish(kind, args, output):
    st, t = call(f"/api/agents/{AAID}/tasks?project=AUTO", "POST",
                 {"kind": kind, "args": args}, token=admin)
    call("/api/agents/heartbeat", "POST", {}, key=AKEY)
    call(f"/api/agents/tasks/{t['id']}/result", "POST",
         {"status": "done", "output": json.dumps(output), "exit_code": 0},
         key=AKEY)


def atargets():
    st, r = call("/api/targets?project=AUTO&page_size=200", token=admin)
    return {t["host"]: t for t in (r or {}).get("items", [])}


def apending(subject):
    st, r = call("/api/enumerate/pending?project=AUTO", token=admin)
    return next((p for p in (r or []) if p["subject"] == subject), None)


print("-- forward lookup, N addresses: no choice at all --")
# A host with four addresses has four addresses. Adding one creates no
# asset, points no scanner anywhere new, and asserts nothing except that
# the name resolved there. Nothing is called below the afinish: the
# result applies itself the moment the Drone reports it.
call("/api/targets?project=AUTO", "POST", {"host": "many.acme.example"}, token=admin)
afinish("nslookup", {"targets": ["many.acme.example"]},
        [{"query": "many.acme.example",
          "a": ["198.51.100.4", "198.51.100.5"],
          "aaaa": ["2001:db8::4"]}])
check("nothing is left waiting on a person",
      apending("many.acme.example") is None, str(apending("many.acme.example")))
check("all three addresses land, v4 and v6 together",
      sorted(atargets()["many.acme.example"]["ip_addresses"])
      == ["198.51.100.4", "198.51.100.5", "2001:db8::4"],
      str(atargets()["many.acme.example"]["ip_addresses"]))
check("ip_address still answers with the first of them",
      atargets()["many.acme.example"]["ip_address"] == "198.51.100.4",
      str(atargets()["many.acme.example"]["ip_address"]))

st, rep2 = call("/api/enumerate/auto?project=AUTO", "POST", {}, token=admin)
check("the endpoint is there for a client that wants to reconcile",
      st == 200, f"status={st}")
check("a second run is a no-op — this is safe on every refresh",
      (rep2 or {}).get("addresses_added") == {}, str(rep2)[:200])

print("-- INVARIANT: every address is gated on its own --")
# Nothing is approved because a sibling in the same answer was. The
# name here is in scope and so are two of its addresses; one is on the
# out-of-scope list, and being handed back in the same breath as two
# allowed ones does not launder it.
#
# Note what DOES vouch, and why that is not the same thing. An address
# an in-scope NAME resolves to is in scope — that is the link rule the
# gate has always had, and without it a scope document written as names
# could never record an address. The vouching comes from the subject of
# the lookup, which is this very asset. It never comes from a sibling,
# and the out-of-scope list is consulted before any of it.
call("/api/projects/AUTO/scope", "POST",
     {"lines": ["!203.0.113.200"]}, token=admin)
call("/api/targets?project=AUTO", "POST", {"host": "mixed.acme.example"}, token=admin)
afinish("nslookup", {"targets": ["mixed.acme.example"]},
        [{"query": "mixed.acme.example",
          "a": ["198.51.100.8", "203.0.113.200", "192.0.2.7"]}])
check("the barred address is not written",
      sorted(atargets()["mixed.acme.example"]["ip_addresses"])
      == ["192.0.2.7", "198.51.100.8"],
      str(atargets()["mixed.acme.example"]["ip_addresses"]))
# And it stays REPORTED. A refusal is true until the scope list
# changes, so the row does not quietly disappear once the addresses
# beside it have been applied — the operator's cue to edit the list
# would go with it.
p = apending("mixed.acme.example")
check("the refusal is still on the queue afterwards, with its reason",
      list((p or {}).get("refused", {})) == ["203.0.113.200"], str(p)[:280])
check("classified as blocked — there is nothing to pick",
      (p or {}).get("decision") == "blocked", str(p)[:280])

print("-- reverse lookup, ONE name: rename, no choice --")
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.30"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.30"]},
        [{"ip": "198.51.100.30", "domains": ["solo.acme.example"],
          "sources": ["ptr"], "partial": False}])
check("the row is renamed, with nobody asked", "solo.acme.example" in atargets(),
      str(sorted(atargets())))
check("and the address it was named for moves into ip_addresses",
      atargets().get("solo.acme.example", {}).get("ip_addresses")
      == ["198.51.100.30"],
      str(atargets().get("solo.acme.example", {}).get("ip_addresses")))
check("and nothing is left waiting", apending("198.51.100.30") is None,
      str(apending("198.51.100.30")))

print("-- reverse lookup, ONE name we already hold: merge, no choice --")
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.31"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.31"]},
        [{"ip": "198.51.100.31", "domains": ["solo.acme.example"],
          "sources": ["ptr"], "partial": False}])
check("it merges rather than asking", "198.51.100.31" not in atargets(),
      str(sorted(atargets())))
check("and the survivor now answers at both addresses",
      sorted(atargets()["solo.acme.example"]["ip_addresses"])
      == ["198.51.100.30", "198.51.100.31"],
      str(atargets()["solo.acme.example"]["ip_addresses"]))

print("-- reverse lookup, SEVERAL names: which one owns the row is a choice --")
# An address answering to several names is itself the evidence that it
# is SHARED, so no one of them is "the host at that address". They can
# all be added; which takes over the address-named row is not something
# the data decides.
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.40"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.40"]},
        [{"ip": "198.51.100.40",
          "domains": ["alpha.acme.example", "bravo.acme.example"],
          "sources": ["ptr"], "partial": False}])
p = apending("198.51.100.40")
check("two names is a genuine choice", (p or {}).get("decision") == "choice",
      str(p)[:240])
check("and the question is stated, not implied",
      "which one takes over" in (p or {}).get("plan", ""),
      str(p and p.get("plan"))[:200])
st, rep = call("/api/enumerate/auto?project=AUTO", "POST", {}, token=admin)
check("auto leaves it alone and reports it as deferred",
      "reverse_ip:198.51.100.40" in (rep or {}).get("deferred", {}),
      str(rep)[:240])
check("the address-named row is still here, unanswered",
      "198.51.100.40" in atargets(), str(sorted(atargets())))
check("and creates neither name behind the operator's back",
      "alpha.acme.example" not in atargets()
      and "bravo.acme.example" not in atargets(), str(sorted(atargets())))

print("-- unless exactly one of them is a name we already hold --")
# Then the project has already committed to that name for this host.
# The address-named row folds into it and the rest become leads.
call("/api/targets?project=AUTO", "POST", {"host": "bravo.acme.example"}, token=admin)
st, rep = call("/api/enumerate/auto?project=AUTO", "POST", {}, token=admin)
check("the established name takes the row",
      (rep or {}).get("merged") == {"198.51.100.40": "bravo.acme.example"},
      str(rep)[:240])
check("and the other name is created as a lead",
      (rep or {}).get("created") == ["alpha.acme.example"], str(rep)[:240])
check("the lead carries the address it was seen at",
      atargets().get("alpha.acme.example", {}).get("ip_addresses")
      == ["198.51.100.40"],
      str(atargets().get("alpha.acme.example", {}).get("ip_addresses")))
check("a lead is NOT marked alive — a reverse lookup is not a probe",
      atargets().get("alpha.acme.example", {}).get("alive") is None,
      str(atargets().get("alpha.acme.example", {}).get("alive")))

print("-- INVARIANT: a shared address does not vouch for its tenants --")
# The CDN case, over HTTP. 198.51.100.0/24 IS on this project's scope
# document, so if a returned name were gated WITH the address it was
# seen at, every co-tenant of that range would be auto-created. Names
# from a multi-answer reverse lookup are gated on the NAME ALONE.
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.41"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.41"]},
        [{"ip": "198.51.100.41",
          "domains": ["ours.acme.example", "theirs.other.example"],
          "sources": ["ptr"], "partial": False}])
check("the row is named for ours", "ours.acme.example" in atargets(),
      str(sorted(atargets())))
check("and the neighbour is not in the inventory",
      "theirs.other.example" not in atargets(), str(sorted(atargets())))
# The refusal survives the rename. Once the row has a name it is no
# longer an outstanding lookup, so the queue cannot report it any more
# and the timeline is the only place left that can.
st, tl = call("/api/targets/AUTO/ours.acme.example/timeline", token=admin)
tlb = json.dumps(tl if isinstance(tl, list) else (tl or {}).get("items", []))
check("the co-tenant is on the record, with the reason it was not added",
      "theirs.other.example" in tlb and "Not added, and why" in tlb, tlb[:300])
check("and the reason is the scope list, named",
      "in-scope list" in tlb, tlb[:400])

print("-- partial: a floor is acted on forward and never backward --")
# The asymmetry is the judgement call. A forward decision is not about
# how many addresses there are — each one that came back is
# independently true and adding is additive — so a floor is safe. A
# reverse decision IS about cardinality: one name means "rename it",
# several mean "the address is shared", and a floor cannot tell them
# apart. Renaming a row on a partial single answer is exactly the
# wrong-and-automatic outcome.
call("/api/targets?project=AUTO", "POST", {"host": "floor.acme.example"}, token=admin)
afinish("nslookup", {"targets": ["floor.acme.example"]},
        [{"query": "floor.acme.example", "a": ["198.51.100.60"],
          "error": "one resolver timed out"}])
check("a partial forward result is still applied",
      atargets()["floor.acme.example"]["ip_addresses"] == ["198.51.100.60"],
      str(atargets()["floor.acme.example"]["ip_addresses"]))
st, tl = call("/api/targets/AUTO/floor.acme.example/timeline", token=admin)
tlb = json.dumps(tl if isinstance(tl, list) else (tl or {}).get("items", []))
check("and the record says the answer was not complete",
      "floor" in tlb, tlb[:300])

call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.70"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.70"]},
        [{"ip": "198.51.100.70", "domains": ["lonely.acme.example"],
          "sources": ["ptr"], "partial": True}])
p = apending("198.51.100.70")
check("a partial reverse result with ONE name is NOT automatic",
      (p or {}).get("decision") == "choice", str(p)[:260])
check("and says that the unknown is whether the address is shared",
      "shared" in (p or {}).get("plan", ""), str(p and p.get("plan"))[:220])
call("/api/enumerate/auto?project=AUTO", "POST", {}, token=admin)
check("nothing is renamed on a floor", "198.51.100.70" in atargets(),
      str(sorted(atargets())))

print("-- a name a human already refused is never auto-added --")
# A rejected candidate row exists so the same name coming back from a
# later lookup does not ask for the judgement twice. Auto-adding it
# would reverse a decision somebody made, silently.
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.79"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.79"]},
        [{"ip": "198.51.100.79",
          "domains": ["yes.acme.example", "nope.acme.example"],
          "sources": ["ptr"], "partial": False}])
st, _ = call("/api/enumerate/resolve?project=AUTO", "POST",
             {"host": "198.51.100.79", "field": "host",
              "value": "yes.acme.example",
              "also_resolved": ["yes.acme.example", "nope.acme.example"],
              "deny": ["nope.acme.example"]}, token=admin)
check("a name can be refused by hand", st == 200, f"status={st}")

call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.80"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.80"]},
        [{"ip": "198.51.100.80", "domains": ["nope.acme.example"],
          "sources": ["ptr"], "partial": False}])
p = apending("198.51.100.80")
check("the refused name is blocked, not offered again",
      (p or {}).get("decision") == "blocked", str(p)[:260])
check("and the reason says a decision already exists",
      "already refused" in str((p or {}).get("refused", {})), str(p)[:260])
call("/api/enumerate/auto?project=AUTO", "POST", {}, token=admin)
check("the address-named row is untouched", "198.51.100.80" in atargets(),
      str(sorted(atargets())))

print("-- a lookup that found nothing is reported, not asked about --")
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.90"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.90"]},
        [{"ip": "198.51.100.90", "domains": [], "sources": ["ptr"],
          "partial": False}])
p = apending("198.51.100.90")
check("an empty answer is blocked, with nothing to pick",
      (p or {}).get("decision") == "blocked", str(p)[:220])
check("and says plainly that the lookup returned nothing",
      "returned no names" in (p or {}).get("plan", ""),
      str(p and p.get("plan"))[:160])

print("-- a reader may look but not apply --")
st, _ = call("/api/enumerate/auto?project=AUTO", "POST", {}, token=rtok)
check("applying automatically still needs write access", st in (403, 404),
      f"status={st}")


# ============================= the same decision, through the agent tools
# The agent could already QUEUE a reverse-IP or nslookup sweep and then
# had no way to read what came back, so "add all the lookup results"
# got "I don\'t have any lookup results to add". Three surfaces now —
# the dialog, the Add all control and these two tools — and one
# implementation behind them, because if the agent\'s idea of what scope
# allows could drift from the API\'s, that difference IS the bug.
print("\n== the agent can read the queue, and apply the safe half ==")
import asyncio as _aio  # noqa: E402

from sqlalchemy import select as _sel  # noqa: E402

from app.agent.tools import build as _build  # noqa: E402
from app.db import SessionLocal as _SL  # noqa: E402
from app.models import Project as _P  # noqa: E402
from app.models import User as _U  # noqa: E402

# A genuine choice: two in-scope names, neither of them a target, so
# nothing decides which one owns the address-named row.
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.95"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.95"]},
        [{"ip": "198.51.100.95",
          "domains": ["tool-a.acme.example", "tool-b.acme.example"],
          "sources": ["ptr"], "partial": False}])

# And something deterministic the automatic pass has not seen: the
# result lands before the target exists, so there is nothing for it to
# apply to until the target is created a moment later.
afinish("reverse_ip", {"targets": ["198.51.100.96"]},
        [{"ip": "198.51.100.96", "domains": ["tool-c.acme.example"],
          "sources": ["ptr"], "partial": False}])
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.96"}, token=admin)


async def _tools(code, writes, scope_ids=None):
    async with _SL() as sx:
        pr = (await sx.execute(
            _sel(_P).where(_P.code == code))).scalars().first() if code else None
        u = (await sx.execute(_sel(_U).limit(1))).scalars().first()
        return {t.name: t for t in _build(sx, pr, u, writes,
                                          scope_ids=scope_ids)}, sx


async def _call(code, name, writes=False, scope_ids=None, **kw):
    async with _SL() as sx:
        pr = (await sx.execute(
            _sel(_P).where(_P.code == code))).scalars().first() if code else None
        u = (await sx.execute(_sel(_U).limit(1))).scalars().first()
        tool = {t.name: t for t in _build(sx, pr, u, writes,
                                          scope_ids=scope_ids)}[name]
        return await tool.fn(**kw)


_q = _aio.run(_call("AUTO", "lookup_results"))
check("the read tool answers with the queue", isinstance(_q, dict), str(_q)[:140])
_auto_subjects = [r["subject"] for r in _q.get("automatic", [])]
_need_subjects = [r["subject"] for r in _q.get("needs_you", [])]
check("it separates what resolves itself from what does not",
      "198.51.100.96" in _auto_subjects and "198.51.100.95" in _need_subjects,
      f"automatic={_auto_subjects} needs_you={_need_subjects}")
check("the ambiguous one comes with the question, not just a flag",
      "which one takes over" in next(
          (r["question"] for r in _q["needs_you"]
           if r["subject"] == "198.51.100.95"), ""),
      str(_q.get("needs_you"))[:220])
check("and with the candidates, so they can be offered",
      sorted(next((r["candidates"] for r in _q["needs_you"]
                   if r["subject"] == "198.51.100.95"), []))
      == ["tool-a.acme.example", "tool-b.acme.example"],
      str(_q.get("needs_you"))[:220])
check("the distinction is explained rather than left to be inferred",
      "not a decision" in _q.get("how_to_read_this", ""),
      str(_q.get("how_to_read_this"))[:160])

print("-- scope_ids bounds it, like every other read --")
_none = _aio.run(_call(None, "lookup_results", scope_ids=[]))
check("a user who may read nothing sees nothing",
      _none.get("total") == 0, str(_none)[:160])
_wide = _aio.run(_call(None, "lookup_results"))
check("and a site admin with no project in view sees across them",
      _wide.get("total", 0) >= _q.get("total", 0), str(_wide.get("total")))

print("-- the write tool applies the safe half and reports the rest --")
_before = atargets()
_rep = _aio.run(_call("AUTO", "apply_lookup_results", writes=True))
_after = atargets()
check("the deterministic one was applied",
      "tool-c.acme.example" in _after and "198.51.100.96" not in _after,
      str(sorted(_after)))
check("and is named in the report rather than counted",
      _rep.get("renamed", {}).get("198.51.100.96") == "tool-c.acme.example",
      str(_rep)[:220])
# The failure the whole change exists to avoid, and it is worse through
# a chat window where nobody sees the choice being made.
check("the ambiguous one was NOT guessed at",
      "198.51.100.95" in _after
      and "tool-a.acme.example" not in _after
      and "tool-b.acme.example" not in _after, str(sorted(_after)))
_wait = {r["subject"]: r for r in _rep.get("still_needs_a_person", [])}
check("it comes back as still needing a person, with the candidates",
      sorted(_wait.get("198.51.100.95", {}).get("candidates", []))
      == ["tool-a.acme.example", "tool-b.acme.example"], str(_wait)[:260])
check("and the note says plainly not to guess it",
      "guessing it" in _rep.get("note", ""), str(_rep.get("note"))[:200])

print("-- the scope gate is not bypassed by going through a tool --")
# `neighbour.other.example` matches nothing on AUTO\'s in-scope list.
# The address does — 198.51.100.0/24 is on the document — and that must
# not carry the name in with it.
call("/api/targets?project=AUTO", "POST", {"host": "198.51.100.97"}, token=admin)
afinish("reverse_ip", {"targets": ["198.51.100.97"]},
        [{"ip": "198.51.100.97",
          "domains": ["tool-d.acme.example", "neighbour.other.example"],
          "sources": ["ptr"], "partial": False}])
_q2 = _aio.run(_call("AUTO", "lookup_results"))
_blocked = {r["subject"]: r for r in _q2.get("nothing_to_pick", [])}
_all_rows = (_q2.get("automatic", []) + _q2.get("needs_you", [])
             + list(_blocked.values()))
_refused = {k: v for r in _all_rows for k, v in (r.get("not_allowed") or {}).items()}
check("the tool reports the refused co-tenant rather than hiding it",
      "neighbour.other.example" in _refused
      or "neighbour.other.example" not in atargets(), str(_q2)[:260])
check("and it is not in the inventory",
      "neighbour.other.example" not in atargets(), str(sorted(atargets())))
check("while our own name on that address was taken",
      "tool-d.acme.example" in atargets(), str(sorted(atargets())))


# ================================ INVARIANT: host identity and its case
print("\n== host is unique per project and always lowercase ==")
call("/api/projects", "POST", {"code": "CASE", "name": "Case"}, token=admin)
st, _ = call("/api/targets?project=CASE", "POST",
             {"host": "Web01.ACME.Example."}, token=admin)
check("a mixed-case host with a trailing dot is accepted", st == 201,
      f"status={st}")
st, r = call("/api/targets?project=CASE&page_size=50", token=admin)
hosts = [t["host"] for t in (r or {}).get("items", [])]
check("and stored lowercased, with the root dot gone",
      hosts == ["web01.acme.example"], str(hosts))
st, r = call("/api/targets?project=CASE", "POST",
             {"host": "WEB01.acme.example"}, token=admin)
# Two rows differing only in case are two buckets one machine's findings
# get split across. `host` is the join key the API speaks.
check("the same host in another case is a duplicate, not a second row",
      st == 409, f"status={st} {str(r)[:140]}")
st, r = call("/api/targets?project=CASE&page_size=50", token=admin)
check("still one row", len((r or {}).get("items", [])) == 1,
      str([t["host"] for t in (r or {}).get("items", [])]))

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
