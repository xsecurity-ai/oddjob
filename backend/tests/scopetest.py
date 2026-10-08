"""Project scope: the two lists, and every path they are supposed to stop.

The shape under test is the one that matters in a real engagement. Scope
is not a note on the project — it decides what the tool will do, and the
expensive mistake is a check that exists on one path and not another,
because the paths that ARE checked make people believe the rest are too.

So this suite does not only assert that `scope.check()` returns the right
word. It drives each writing path over HTTP — add a target, bulk load,
import a scan, queue a Drone task, hand that task to an agent — and
asserts the refusal lands there.

Four rules are load-bearing and each has its own section:

  out beats in      a host on both lists is barred
  new, not old      the lists govern what the project ACQUIRES; what it
                    already has is removed only when someone says so
  barred vs outside two different refusals, and the second does not stop
                    work continuing on a host the project already had
  declared, never   a country is a statement the operator typed, not a
  looked up         lookup, and "undetermined" is a third answer
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


def project(code, scope=None):
    call("/api/projects", "POST",
         {"code": code, "name": code, "scope": scope or []}, token=admin)


def add_scope(code, **body):
    return call(f"/api/projects/{code}/scope", "POST", body, token=admin)


def add_target(code, host, **extra):
    return call(f"/api/targets?project={code}", "POST",
                {"host": host, **extra}, token=admin)


def hosts_in(code):
    st, r = call(f"/api/targets?project={code}&limit=500", token=admin)
    return sorted(t["host"] for t in (r or {}).get("items", []))


# ===================================================== nothing declared
print("== a project with no scope lists enforces nothing ==")
project("NOSCOPE")
st, _ = add_target("NOSCOPE", "anything.example")
check("any host can be added", st == 201, f"status={st}")
st, r = call("/api/projects/NOSCOPE/scope/violations", token=admin)
check("and nothing is in violation",
      st == 200 and r["violations"] == [] and r["scope_defined"] is False,
      str(r)[:120])


# ================================================= the allowlist is new-only
print("\n== an in-scope list governs what is NEW, not what is there ==")
project("ALLOW")
st, _ = add_target("ALLOW", "legacy.other.example", ip_address="198.51.100.9")
check("a host added before any list exists", st == 201, f"status={st}")

st, r = add_scope("ALLOW", lines=["203.0.113.0/24", "portal.acme.example"])
check("an in-scope list is accepted", st == 200, f"status={st} {str(r)[:100]}")

st, r = add_target("ALLOW", "elsewhere.example")
check("a new host outside the list is refused", st == 422, f"status={st}")
check("and the refusal names the host, not just 'out of scope'",
      "elsewhere.example" in str(r), str(r)[:160])

st, _ = add_target("ALLOW", "portal.acme.example")
check("a new host on the list is allowed", st == 201, f"status={st}")
st, _ = add_target("ALLOW", "web01.acme.example", ip_address="203.0.113.10")
check("a name is let in by its recorded address, so a CIDR-only scope works",
      st == 201, f"status={st}")

check("the host that predates the list is still here",
      "legacy.other.example" in hosts_in("ALLOW"), str(hosts_in("ALLOW")))
st, r = call("/api/projects/ALLOW/scope/violations", token=admin)
check("it is REPORTED as a violation rather than deleted",
      st == 200 and [v["host"] for v in r["violations"]] == ["legacy.other.example"],
      str(r)[:200])
check("and reported as 'outside', which is not the same as barred",
      r["violations"][0]["verdict"] == "outside", str(r["violations"][0])[:140])
check("the report says how many, and which",
      "1 host(s) currently violate" in r["detail"], r["detail"])

# Work already under way on it must not stop: the list said nothing about
# hosts the project had before it existed.
st, _ = call("/api/bulk", "POST", {"project": "ALLOW", "targets": [
    {"host": "legacy.other.example", "os": "Ubuntu 22.04"}]}, token=admin)
check("an existing outside-the-list host can still be updated", st == 200,
      f"status={st}")


# ===================================================== out trumps in
print("\n== out of scope always wins ==")
project("TRUMP")
add_scope("TRUMP", lines=["203.0.113.0/24", "portal.acme.example"])
add_scope("TRUMP", lines=["203.0.113.5", "portal.acme.example"], included=False)

st, r = add_target("TRUMP", "203.0.113.5")
check("an address barred inside an in-scope range is barred, not allowed",
      st == 403, f"status={st}")
check("and the out entry is named", "203.0.113.5" in str(r), str(r)[:160])
st, _ = add_target("TRUMP", "203.0.113.6")
check("its neighbour inside the same range is fine", st == 201, f"status={st}")

# A value lives on one list. Adding it to the other is a statement about
# the entry that is there, and the same rule applies: out wins.
st, r = add_target("TRUMP", "portal.acme.example")
check("re-adding an in-scope name to the out list MOVED it there",
      st == 403, f"status={st}")
st, r = add_scope("TRUMP", lines=["portal.acme.example"], included=True)
check("and adding it back to the in list does not silently un-bar it",
      any("out-of-scope list" in e for e in r["scope_errors"]),
      str(r["scope_errors"])[:200])
st, _ = add_target("TRUMP", "portal.acme.example")
check("so it is still barred", st == 403, f"status={st}")

# A barred host the project somehow already has is still barred.
project("WASFINE")
add_target("WASFINE", "doomed.acme.example")
add_scope("WASFINE", lines=["doomed.acme.example"], included=False)
st, r = call("/api/projects/WASFINE/scope/violations", token=admin)
check("an existing host put on the out list is reported as barred",
      st == 200 and r["violations"][0]["verdict"] == "barred",
      str(r["violations"])[:160])
check("and it is still present until someone says otherwise",
      hosts_in("WASFINE") == ["doomed.acme.example"], str(hosts_in("WASFINE")))
st, _ = call("/api/bulk", "POST", {"project": "WASFINE", "targets": [
    {"host": "doomed.acme.example", "os": "Ubuntu 22.04"}]}, token=admin)
st, r = call("/api/targets?project=WASFINE&limit=10", token=admin)
check("but nothing may write to it any more",
      (r["items"][0]["os"] or "") == "", f"os={r['items'][0]['os']!r}")


# ======================================================= wildcards
print("\n== wildcard names ==")
project("WILD")
add_scope("WILD", lines=["*.acme.example"])
for host, want in (("a.acme.example", 201),
                   ("deep.nested.acme.example", 201),
                   ("acme.example", 422),          # the apex is not covered
                   ("notacme.example", 422),
                   ("acme.example.evil.test", 422)):
    st, _ = add_target("WILD", host)
    check(f"{host} -> {want}", st == want, f"status={st}")

add_scope("WILD", lines=["*.acme.example"], included=False)
st, r = add_target("WILD", "b.acme.example")
check("moving the wildcard to the out list bars what it used to allow",
      st == 403, f"status={st}")

project("WILD2")
st, r = add_scope("WILD2", lines=["a.*.example", "*.example"])
check("a '*' that is not the first label is refused, with a reason",
      any("first label" in e for e in r["scope_errors"]), str(r["scope_errors"]))
check("and a wildcard over a whole TLD is refused",
      any("TLD" in e for e in r["scope_errors"]), str(r["scope_errors"]))


# ================================================== include subdomains
# `*.acme.example` not covering `acme.example` is correct and is also a
# trap: the operator pastes a scope document, gets the wildcard, and
# meets the rule weeks later as a refusal on the apex that reads like a
# bug. So the intent is expressible where the name is typed.
#
# One row, not two. The checks below care about three things in this
# order: that it covers what it says, that OUT still beats it, and that
# it never comes on by itself.
print("\n== an FQDN entry can bring its subdomains ==")
project("SUBS")
st, r = add_scope("SUBS", lines=["acme.example"], include_subdomains=True)
check("the entry is accepted", st == 200 and not r["scope_errors"],
      str(r.get("scope_errors"))[:160])

st, rows = call("/api/projects/SUBS/scope", token=admin)
check("it is ONE row and not a silent pair", len(rows) == 1, str(rows)[:200])
check("still kind 'fqdn', holding the name the operator typed",
      rows[0]["kind"] == "fqdn" and rows[0]["value"] == "acme.example",
      str(rows[0])[:160])
check("and the intent is stored on it, so it is one thing to undo",
      rows[0]["include_subdomains"] is True, str(rows[0])[:160])

for host, want in (("acme.example", 201),        # the apex — the whole point
                   ("a.acme.example", 201),
                   ("deep.nested.acme.example", 201),
                   # Identity-anchored, never substring. Each of these
                   # ENDS with the letters of the entry or begins with
                   # them, and none of them is under the zone.
                   ("notacme.example", 422),
                   ("xacme.example", 422),
                   ("acme.example.evil.test", 422),
                   ("example", 422)):
    st, _ = add_target("SUBS", host)
    check(f"{host} -> {want}", st == want, f"status={st}")

print("\n-- without it, a name is still only itself --")
project("NOSUBS")
add_scope("NOSUBS", lines=["corp.com"])
st, _ = add_target("NOSUBS", "corp.com")
check("the name is in scope", st == 201, f"status={st}")
st, _ = add_target("NOSUBS", "a.corp.com")
check("its subdomain is not — the default did not move", st == 422,
      f"status={st}")

print("\n-- the flag is dropped on kinds that cannot answer it --")
project("SUBKIND")
st, r = add_scope("SUBKIND",
                  lines=["203.0.113.0/24", "*.corp.com", "2001:db8::1"],
                  include_subdomains=True)
check("a mixed paste with the box ticked is not an error",
      st == 200 and not r["scope_errors"], str(r.get("scope_errors"))[:160])
st, rows = call("/api/projects/SUBKIND/scope", token=admin)
check("and no range, address or wildcard row claims a rule it has not got",
      all(e["include_subdomains"] is False for e in rows),
      str([(e["value"], e["include_subdomains"]) for e in rows])[:200])
st, _ = add_target("SUBKIND", "corp.com")
check("the wildcard still does not cover its own apex", st == 422,
      f"status={st}")

print("\n-- out of scope still wins over a zone that is in scope --")
project("SUBOUT")
add_scope("SUBOUT", lines=["acme.example"], include_subdomains=True)
add_scope("SUBOUT", lines=["secret.acme.example"], included=False)
st, r = add_target("SUBOUT", "secret.acme.example")
check("a barred name inside an in-scope zone is barred, not allowed",
      st == 403, f"status={st}")
check("and the out entry is named", "secret.acme.example" in str(r), str(r)[:170])
st, _ = add_target("SUBOUT", "other.acme.example")
check("its sibling in the same zone is fine", st == 201, f"status={st}")
st, _ = add_target("SUBOUT", "acme.example")
check("and so is the apex the entry was written as", st == 201, f"status={st}")

# The other direction: the zone on the OUT list has to bar the whole
# zone, including names an in-scope wildcard covers. A flag that
# expanded only the in-list would bar less than it allows.
project("SUBOUT2")
add_scope("SUBOUT2", lines=["*.acme.example"])
add_scope("SUBOUT2", lines=["acme.example"], included=False,
          include_subdomains=True)
st, r = add_target("SUBOUT2", "a.acme.example")
check("a zone barred by an out entry beats the in-scope wildcard over it",
      st == 403, f"status={st}")
check("and the refusal says the entry carried its subdomains",
      "+subdomains" in str(r), str(r)[:200])

print("\n-- a declared country travels with the zone --")
# Half a rule is the failure mode: if the attribution stopped at the
# apex, the apex would be barred for being in DE and every name under
# it would be unplaced and therefore NOT barred, out of one row.
project("SUBGEO")
add_scope("SUBGEO", lines=["acme.example"], country="de",
          include_subdomains=True)
add_scope("SUBGEO", countries=["de"], included=False)
st, r = add_target("SUBGEO", "acme.example")
check("the apex is barred by the country it was declared to be in",
      st == 403, f"status={st}")
st, r = add_target("SUBGEO", "a.acme.example")
check("and so is a name under it — the row is not half-enforced",
      st == 403, f"status={st}")
check("for the same stated reason", "DE" in str(r), str(r)[:170])

print("\n-- nothing widens by accident --")
# The scenario this rule exists for: 400 lines re-pasted with the box
# ticked for the sake of four new names. The other 396 are already
# enforced as single names and must not quietly become whole zones.
project("NOWIDEN")
add_scope("NOWIDEN", lines=["corp.com", "portal.corp.com"])
st, r = add_scope("NOWIDEN", lines=["corp.com", "new.example"],
                  include_subdomains=True)
check("re-adding an in-scope entry with the box ticked is REFUSED",
      any("corp.com" in e and "NOT added" in e for e in r["scope_errors"]),
      str(r["scope_errors"])[:260])
st, _ = add_target("NOWIDEN", "a.corp.com")
check("so the zone is still not in scope", st == 422, f"status={st}")
st, rows = call("/api/projects/NOWIDEN/scope", token=admin)
by_value = {e["value"]: e for e in rows}
check("the stored entry is untouched",
      by_value["corp.com"]["include_subdomains"] is False,
      str(by_value["corp.com"])[:160])
# Refusing one line must not cost the rest of the batch, same as a
# line that fails to parse.
check("but the new name in the same batch still landed, with its zone",
      by_value.get("new.example", {}).get("include_subdomains") is True,
      str(by_value.get("new.example"))[:160])
st, _ = add_target("NOWIDEN", "a.new.example")
check("and that one does cover its subdomains", st == 201, f"status={st}")

# On the OUT list the same amendment only ever refuses MORE, so it
# applies rather than being refused.
project("WIDENOUT")
add_scope("WIDENOUT", lines=["bad.example"], included=False)
st, _ = add_target("WIDENOUT", "a.bad.example")
check("a name under a barred apex starts out allowed", st == 201,
      f"status={st}")
st, r = add_scope("WIDENOUT", lines=["bad.example"], included=False,
                  include_subdomains=True)
check("adding subdomains to an OUT entry is applied, not refused",
      not r["scope_errors"], str(r["scope_errors"])[:200])
st, _ = add_target("WIDENOUT", "b.bad.example")
check("and the whole zone is barred from then on", st == 403, f"status={st}")

print("\n-- the per-entry patch is where widening is deliberate --")
st, rows = call("/api/projects/NOWIDEN/scope", token=admin)
eid = next(e["id"] for e in rows if e["value"] == "corp.com")
st, r = call(f"/api/projects/NOWIDEN/scope/{eid}", "PATCH",
             {"include_subdomains": True}, token=admin)
check("naming one entry turns it on", st == 200
      and r["include_subdomains"] is True, f"status={st} {str(r)[:140]}")
st, _ = add_target("NOWIDEN", "b.corp.com")
check("and the zone is in scope from then on", st == 201, f"status={st}")
st, r = call(f"/api/projects/NOWIDEN/scope/{eid}", "PATCH",
             {"include_subdomains": False}, token=admin)
check("turning it back off is one act on one row", st == 200
      and r["include_subdomains"] is False, f"status={st} {str(r)[:140]}")
st, _ = add_target("NOWIDEN", "c.corp.com")
check("and the zone is out again", st == 422, f"status={st}")
check("the entry that was already there is still here, not replaced",
      eid in [e["id"] for e in call("/api/projects/NOWIDEN/scope",
                                    token=admin)[1]], f"id={eid}")

cid = next((e["id"] for e in call("/api/projects/SUBKIND/scope", token=admin)[1]
            if e["kind"] == "cidr"), None)
st, r = call(f"/api/projects/SUBKIND/scope/{cid}", "PATCH",
             {"include_subdomains": True}, token=admin)
check("asking a range about its subdomains is refused, not silently ignored",
      st == 422, f"status={st} {str(r)[:140]}")

print("\n-- and it is a project-creation option too --")
st, r = call("/api/projects", "POST",
             {"code": "SUBNEW", "name": "SUBNEW",
              "scope": ["acme.example", "203.0.113.0/24"],
              "scope_include_subdomains": True}, token=admin)
check("a project can be created with it", st in (200, 201),
      f"status={st} {str(r)[:140]}")
st, _ = add_target("SUBNEW", "a.acme.example")
check("the zone is in scope from the moment it is created", st == 201,
      f"status={st}")
st, _ = add_target("SUBNEW", "acme.example")
check("so is the apex", st == 201, f"status={st}")
st, _ = add_target("SUBNEW", "notacme.example", ip_address="198.51.100.1")
check("and nothing outside it came along", st == 422, f"status={st}")

print("\n-- a Drone task is gated on it like everything else --")
st, en = call("/api/agents?project=SUBOUT", "POST", {"name": "s1"}, token=admin)
SAID = ((en or {}).get("agent") or {}).get("id")
st, r = call(f"/api/agents/{SAID}/tasks?project=SUBOUT", "POST",
             {"kind": "nmap", "args": {"targets": ["queued.acme.example"]}},
             token=admin)
check("a task against the zone is queued", st == 201, f"status={st} {str(r)[:120]}")
st, r = call(f"/api/agents/{SAID}/tasks?project=SUBOUT", "POST",
             {"kind": "nmap", "args": {"targets": ["secret.acme.example"]}},
             token=admin)
check("a task against the barred name inside it is refused", st == 403,
      f"status={st}")


# =========================================================== IPv6
print("\n== IPv6 ==")
project("V6")
add_scope("V6", lines=["2001:db8::/32", "2001:db8:dead::1"])
add_scope("V6", lines=["2001:db8:beef::/48"], included=False)
for host, want in (("2001:db8::1", 201),
                   # Same address, written long. Text comparison would
                   # have let this one through as "not in the list".
                   ("2001:0db8:0000:0000:0000:0000:0000:0002", 201),
                   ("2001:db9::1", 422),
                   ("2001:db8:beef::9", 403)):
    st, _ = add_target("V6", host)
    check(f"{host} -> {want}", st == want, f"status={st}")

st, r = call("/api/projects/V6/scope", token=admin)
kinds = {e["value"]: e["kind"] for e in r}
check("a v6 range classifies as cidr and a v6 literal as ipv6",
      kinds.get("2001:db8::/32") == "cidr"
      and kinds.get("2001:db8:dead::1") == "ipv6", str(kinds))


# ======================================================== countries
print("\n== countries are declared, never looked up ==")
project("GEO")
# The attribution and the list are two different statements: this range
# IS in DE, and DE is out of scope.
add_scope("GEO", lines=["203.0.113.0/24"], country="de")
add_scope("GEO", lines=["198.51.100.0/24"], country="jp")
add_scope("GEO", countries=["de"], included=False)

st, r = add_target("GEO", "203.0.113.7")
check("a host in a barred country is barred", st == 403, f"status={st}")
check("and the refusal says which country and that it was declared",
      "DE" in str(r), str(r)[:160])
st, _ = add_target("GEO", "198.51.100.7")
check("one in an unbarred country is not", st == 201, f"status={st}")

st, r = add_scope("GEO", countries=["zz"])
check("a country code that is not assigned is refused",
      any("zz" in e for e in r["scope_errors"]), str(r["scope_errors"]))
st, r = add_scope("GEO", countries=["Japan"])
check("and so is a country name — this is alpha-2 only",
      any("alpha-2" in e for e in r["scope_errors"]), str(r["scope_errors"]))

print("\n== an in-scope country list refuses what it cannot place ==")
project("GEOIN")
add_scope("GEOIN", lines=["203.0.113.0/24", "198.51.100.0/24"])
add_scope("GEOIN", lines=["203.0.113.0/24"], country="jp")
add_scope("GEOIN", countries=["jp"], included=True)
st, _ = add_target("GEOIN", "203.0.113.7")
check("a host declared to be in an allowed country is allowed", st == 201,
      f"status={st}")
st, r = add_target("GEOIN", "198.51.100.7")
check("one whose country nobody declared is refused, not assumed", st == 422,
      f"status={st}")
check("and the refusal says the country is undetermined, not that it is wrong",
      "no country is declared" in str(r), str(r)[:200])


# ===================================================== Drone tasking
print("\n== Drone tasking is gated, at queue time and at hand-out ==")
project("DRONEX")
add_scope("DRONEX", lines=["203.0.113.0/24"])
add_scope("DRONEX", lines=["203.0.113.5"], included=False)
st, en = call("/api/agents?project=DRONEX", "POST", {"name": "a1"}, token=admin)
AID = ((en or {}).get("agent") or {}).get("id")
KEY = (en or {}).get("callback_key")
call("/api/agents/register", "POST", {"platform": "linux"}, key=KEY)

st, r = call(f"/api/agents/{AID}/tasks?project=DRONEX", "POST",
             {"kind": "nmap", "args": {"targets": ["203.0.113.5"]}}, token=admin)
check("a task naming a barred host is refused", st == 403, f"status={st}")
check("and says which host and which entry", "203.0.113.5" in str(r), str(r)[:170])

st, r = call(f"/api/agents/{AID}/tasks?project=DRONEX", "POST",
             {"kind": "nmap",
              "args": {"targets": ["203.0.113.4", "203.0.113.5"]}}, token=admin)
check("one barred host refuses the whole task, not just that entry",
      st == 403, f"status={st}")

st, r = call(f"/api/agents/{AID}/tasks?project=DRONEX", "POST",
             {"kind": "nmap", "args": {"targets": ["198.51.100.1"]}}, token=admin)
check("a task outside the in-scope list is refused too", st == 422, f"status={st}")

st, r = call("/api/agents/tasks?project=DRONEX", "POST",
             {"kind": "masscan", "args": {"targets": ["203.0.113.5"]}}, token=admin)
check("the pooled queue is gated identically — it is the same packets",
      st == 403, f"status={st}")

st, r = call(f"/api/agents/{AID}/tasks?project=DRONEX", "POST",
             {"kind": "nmap", "args": {"targets": ["203.0.113.9"]}}, token=admin)
check("an in-scope task is queued", st == 201, f"status={st} {str(r)[:120]}")
TASK = (r or {}).get("id")

# A URL-shaped target still has to pass: httpx and gospider take them.
st, r = call(f"/api/agents/{AID}/tasks?project=DRONEX", "POST",
             {"kind": "httpx", "args": {"targets": ["https://203.0.113.5:8443/x"]}},
             token=admin)
check("a target written as a URL is still resolved to its host and barred",
      st == 403, f"status={st}")

# A range whose edges are in scope passes; one whose edges are not does not.
st, r = call(f"/api/agents/{AID}/tasks?project=DRONEX", "POST",
             {"kind": "masscan", "args": {"targets": ["198.51.100.0/24"]}},
             token=admin)
check("a CIDR argument outside the list is refused", st == 422, f"status={st}")

print("\n-- the list can move while a task is queued --")
add_scope("DRONEX", lines=["203.0.113.9"], included=False)
st, hb = call("/api/agents/heartbeat", "POST", {}, key=KEY)
check("heartbeat is answered", st == 200, f"status={st}")
check("the now-barred task is NOT handed over",
      (hb or {}).get("task") is None, str(hb)[:160])
st, tasks = call(f"/api/agents/{AID}/tasks?project=DRONEX", token=admin)
row = next((t for t in (tasks or []) if t["id"] == TASK), None)
check("it is failed with the reason, not left queued forever",
      row and row["status"] == "failed" and "scope" in (row["error"] or ""),
      str(row)[:200])


# ===================================================== scan imports
print("\n== scan imports are gated on the same lists ==")
project("IMP")
add_scope("IMP", lines=["203.0.113.0/24"])
add_scope("IMP", lines=["203.0.113.5"], included=False)
NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX -" start="1760000000" version="7.94">
<host><status state="up" reason="echo-reply"/>
<address addr="203.0.113.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
  <service name="ssh" method="table" conf="3"/></port></ports></host>
<host><status state="up" reason="echo-reply"/>
<address addr="203.0.113.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
  <service name="http" method="table" conf="3"/></port></ports></host>
<host><status state="up" reason="echo-reply"/>
<address addr="198.51.100.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
  <service name="http" method="table" conf="3"/></port></ports></host>
<runstats><finished time="1760000030" elapsed="29"/>
<hosts up="3" down="0" total="3"/></runstats></nmaprun>
"""
st, r = call("/api/scans/import?project=IMP", "POST",
             {"format": "nmap", "content": NMAP, "mode": "open"}, token=admin)
check("the import runs", st == 200, f"status={st} {str(r)[:120]}")
check("open mode still creates only the in-scope host",
      hosts_in("IMP") == ["203.0.113.9"], str(hosts_in("IMP")))
check("and the ones it would not create are NAMED, not just counted",
      set((r or {}).get("barred_hosts", {})) == {"203.0.113.5", "198.51.100.3"},
      str((r or {}).get("barred_hosts"))[:200])

st, r = call("/api/scans/import?project=IMP", "POST",
             {"format": "nmap", "content": NMAP, "mode": "strict"}, token=admin)
check("strict mode does not even offer a barred host as a decision",
      not any(u["host"] in ("203.0.113.5", "198.51.100.3")
              for u in (r or {}).get("unknown_hosts", [])),
      str((r or {}).get("unknown_hosts"))[:160])

# The decision mechanism must not be a way around the list.
st, r = call("/api/scans/import?project=IMP", "POST",
             {"format": "nmap", "content": NMAP, "mode": "strict",
              "decisions": {"203.0.113.5": {"action": "add"},
                            "198.51.100.3": {"action": "add"}}}, token=admin)
check("answering 'add' for a barred host does not create it",
      hosts_in("IMP") == ["203.0.113.9"], str(hosts_in("IMP")))

print("\n-- bulk --")
st, r = call("/api/bulk", "POST", {"project": "IMP", "targets": [
    {"host": "203.0.113.11"}, {"host": "203.0.113.5"},
    {"host": "198.51.100.4"}]}, token=admin)
check("bulk creates the allowed row only", st == 200
      and hosts_in("IMP") == ["203.0.113.11", "203.0.113.9"],
      str(hosts_in("IMP")))
check("and reports each refusal by name",
      sum(1 for e in (r or {}).get("errors", []) if e.startswith("scope:")) == 2,
      str((r or {}).get("errors"))[:200])

st, r = call("/api/bulk", "POST", {"project": "IMP",
                                   "autocreate_targets": True,
                                   "vulns": [{"host": "198.51.100.9",
                                              "title": "x", "severity": "low"}]},
             token=admin)
check("autocreate cannot smuggle a host in through a child row",
      "198.51.100.9" not in hosts_in("IMP"), str(hosts_in("IMP")))


# ===================================================== apply
print("\n== apply: named hosts, and only when asked ==")
project("APPLY")
for h in ("keep.acme.example", "drop1.other.example", "drop2.other.example"):
    add_target("APPLY", h)
add_scope("APPLY", lines=["*.acme.example"])

st, r = call("/api/projects/APPLY/scope/violations", token=admin)
check("both strays are listed, by name",
      sorted(v["host"] for v in r["violations"])
      == ["drop1.other.example", "drop2.other.example"], str(r["violations"])[:200])
check("with what would go with them if removed",
      all("services" in v and "vulns" in v for v in r["violations"]))

st, r = call("/api/projects/APPLY/scope/apply", "POST", {"action": "ignore"},
             token=admin)
check("ignore deletes nothing", st == 200 and len(hosts_in("APPLY")) == 3,
      str(hosts_in("APPLY")))
check("and says plainly that it recorded nothing",
      "reported again" in r["detail"], r["detail"])

st, r = call("/api/projects/APPLY/scope/apply", "POST", {"action": "remove"},
             token=admin)
check("remove with no hosts named is refused", st == 422, f"status={st}")
check("because 'everything currently in violation' is a list nobody read",
      "nobody read" in str(r), str(r)[:160])

st, r = call("/api/projects/APPLY/scope/apply", "POST",
             {"action": "remove", "hosts": ["keep.acme.example"]}, token=admin)
check("removing a host that is NOT in violation is refused, not ignored",
      st == 409, f"status={st} {str(r)[:120]}")

st, r = call("/api/projects/APPLY/scope/apply", "POST",
             {"action": "remove", "hosts": ["drop1.other.example"]}, token=admin)
check("removing a named violator works", st == 200
      and r["removed"] == ["drop1.other.example"], str(r)[:160])
check("only that one went",
      hosts_in("APPLY") == ["drop2.other.example", "keep.acme.example"],
      str(hosts_in("APPLY")))
check("and the one still in violation is still reported",
      [v["host"] for v in r["violations"]] == ["drop2.other.example"],
      str(r["violations"])[:140])


# ===================================================== authority
print("\n== changing the lists is an admin act ==")
call("/api/users", "POST", {"username": "bob", "password": "bob-password-1",
                            "role": "user"}, token=admin)
bob = call("/api/auth/login", "POST",
           {"username": "bob", "password": "bob-password-1"})[1]
bobtok = (bob or {}).get("access_token")
if bobtok:
    call("/api/projects/APPLY/acl", "POST", {"username": "bob", "role": "user"},
         token=admin)
    st, _ = call("/api/projects/APPLY/scope", "POST", {"lines": ["8.8.8.8"]},
                 token=bobtok)
    check("a 'user' cannot widen the scope", st == 403, f"status={st}")
    st, _ = call("/api/projects/APPLY/scope/apply", "POST",
                 {"action": "remove", "hosts": ["drop2.other.example"]},
                 token=bobtok)
    check("nor delete hosts through apply", st == 403, f"status={st}")
    st, _ = call("/api/projects/APPLY/config", token=bobtok)
    check("but can read the configuration", st == 200, f"status={st}")
else:
    check("could not create a second user to test authority with", False,
          str(bob)[:160])


print("\n== scope travels between a name and the address it was seen at ==")
# The case that prompted this: a project scoped to *.mufg.jp, a target
# www.mufg.jp recorded at 23.13.159.70, and a scan of that address
# refused as "not in this project's in-scope list". It is the same
# machine under a different label.
from app.scope import ScopeIndex  # noqa: E402


def _idx(entries, links=()):
    class E:
        def __init__(s_, k, v, i): s_.kind, s_.value, s_.included, s_.country = k, v, i, None
    ix = ScopeIndex([E(k, v, i) for k, v, i in entries])
    for h, a in links:
        ix.link(h, a)
    return ix


_i = _idx([("wildcard", "*.corp.com", True)],
          links=[("www.corp.com", "198.51.100.7")])
check("the name itself is in scope", _i.check("www.corp.com").allowed, "")
_r = _i.check("198.51.100.7")
check("and so is the address it was recorded at", _r.allowed, _r.reason)
# Provenance is the whole point of doing it this way: an address in
# scope only because something else is must never read the same as one
# written on the scope document.
check("the ruling names what it came in on",
      "via www.corp.com" in _r.reason, _r.reason)

check("an unrelated address is still refused",
      not _i.check("203.0.113.9").allowed, _i.check("203.0.113.9").reason)

# And the other direction: a CIDR scope, a name observed inside it.
_j = _idx([("cidr", "198.51.100.0/24", True)],
          links=[("host.elsewhere.test", "198.51.100.7")])
_r2 = _j.check("host.elsewhere.test")
check("a name inherits from an in-scope address too", _r2.allowed, _r2.reason)

# Out-of-scope still wins over anything inherited. A barred address
# that an in-scope name happens to resolve to is still barred —
# otherwise the deny list could be walked around by adding a CNAME.
_k = _idx([("wildcard", "*.corp.com", True), ("ipv4", "198.51.100.7", False)],
          links=[("www.corp.com", "198.51.100.7")])
check("an out-of-scope address is not rescued by an in-scope name",
      not _k.check("198.51.100.7").allowed, _k.check("198.51.100.7").reason)

# Nothing is resolved here. A name the project has never observed at
# an address inherits nothing, which is the honest answer rather than
# a guess made by a resolver at gate time.
_l = _idx([("wildcard", "*.corp.com", True)])
check("an address nothing has been observed at inherits nothing",
      not _l.check("198.51.100.7").allowed, _l.check("198.51.100.7").reason)


print("\n== the index expands an FQDN+subdomains, and only that ==")
# Below the HTTP layer, because these are claims about the matcher
# itself: an entry that covers a zone is the same two lookups a name
# and a wildcard would have been, and nothing else acquired one.
from app.scope import Entry, entry_label  # noqa: E402


def _sidx(*entries):
    return ScopeIndex(entries)


_m = _sidx(Entry("fqdn", "acme.example", True, True))
check("the apex is matched as a name",
      _m.inc.match_name("acme.example") == "acme.example",
      str(_m.inc.names))
check("the zone is matched by suffix",
      _m.inc.match_name("a.b.acme.example") is not None,
      str(_m.inc.suffixes))
for miss in ("acme.example.evil.test", "notacme.example", "example",
             "acmexexample", "b.acme.examplex"):
    check(f"{miss} is not matched by the zone",
          _m.inc.match_name(miss) is None, str(_m.inc.suffixes))

# The flag on a kind that cannot carry it must add NOTHING. A suffix
# accidentally derived from a CIDR or an address string would be a
# rule the operator never wrote.
_n = _sidx(Entry("cidr", "203.0.113.0/24", True, True),
           Entry("ipv4", "198.51.100.7", True, True),
           Entry("wildcard", "*.corp.com", True, True),
           Entry("country", "jp", True, True))
check("no suffix is derived from a range, an address or a country",
      set(_n.inc.suffixes) == {".corp.com"}, str(_n.inc.suffixes))

# Both spellings of the same coverage on one side. The verdict must be
# identical either way; only the sentence differs, and it names the
# entry the operator literally typed.
_o = _sidx(Entry("wildcard", "*.acme.example", True),
           Entry("fqdn", "acme.example", True, True))
check("a zone written both ways is still just in scope",
      _o.check("a.acme.example").allowed, _o.check("a.acme.example").reason)
# Whichever order the rows load in, the entry blamed for a match is the
# wildcard the operator typed out rather than the derived one. The
# verdict never depended on this; which rule they are sent to edit does.
for _pair in ((Entry("wildcard", "*.acme.example", True),
               Entry("fqdn", "acme.example", True, True)),
              (Entry("fqdn", "acme.example", True, True),
               Entry("wildcard", "*.acme.example", True))):
    _p = _sidx(*_pair)
    check("the named entry is the wildcard, in either row order",
          _p.inc.match_name("a.acme.example") == "*.acme.example",
          str(_p.inc.suffixes))
# On its own it names itself, labelled, so a refusal is actionable.
_q = _sidx(Entry("fqdn", "acme.example", False, True))
check("an out-of-scope zone names the entry that barred it",
      "acme.example (+subdomains)" in _q.check("a.acme.example").reason,
      _q.check("a.acme.example").reason)

check("the label says so where a person reads it back",
      entry_label("fqdn", "acme.example", True) == "acme.example (+subdomains)"
      and entry_label("wildcard", "*.acme.example", True) == "*.acme.example"
      and entry_label("cidr", "203.0.113.0/24", True) == "203.0.113.0/24",
      entry_label("fqdn", "acme.example", True))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
raise SystemExit(1 if fail else 0)
