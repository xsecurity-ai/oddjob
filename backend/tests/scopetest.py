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
# The case that prompted this: a project scoped to a zone, a target
# under it recorded at a CDN address, and a scan of that address
# refused as "not in this project's in-scope list". It is the same
# machine under a different label.
#
# Written generically on purpose. The original comment here named the
# client's zone, one of their hostnames and the address it resolved
# to. This repository is public; an engagement's scope is the client's
# information and does not stop being so because it is in a comment
# rather than a fixture.
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

# ===================================================== the shared fixture
#
# The browser classifies a pasted scope line too. It has to: a pill that
# can only say "line 217 is malformed" after a round trip is the textarea
# this replaced. frontend/src/lib/scopeEntry.ts is a port of `classify`,
# and a port that drifts is worse than no port at all — the operator
# reconciles a client's scope document against a label that was never
# what got stored.
#
# frontend/test/scope-cases.json is the record of what `classify` answers.
# This section asserts the server still agrees with it; the frontend's
# `npm run test:logic` asserts the port does. Change the rules in
# scope.py and this goes red, which is the reminder to regenerate the
# fixture and look at what moved — the diff is a diff of what a scope
# list MEANS, so it wants reading rather than accepting.
#
# Each row carries the `subs` the flag was called with, because
# `include_subdomains` changes the Entry and so has to be part of what
# the two sides agree on — this section was added when `classify` took
# one argument, and the day it took two is exactly the day a port
# silently stops covering half of it.
#
# Regenerate with:
#     cd backend && uv run python - <<'EOF'
#     import json, pathlib
#     from app.scope import classify
#     p = pathlib.Path("../frontend/test/scope-cases.json")
#     out = []
#     for c in json.loads(p.read_text()):
#         row = {"raw": c["raw"], "subs": c.get("subs", False)}
#         try:
#             e = classify(c["raw"], row["subs"])
#             row.update(ok=True, kind=e.kind, value=e.value,
#                        included=e.included,
#                        include_subdomains=e.include_subdomains)
#         except ValueError:
#             row.update(ok=False)
#         out.append(row)
#     p.write_text(json.dumps(out, indent=0) + "\n")
#     EOF
from app.scope import classify  # noqa: E402

_fixture = (_pathlib.Path(__file__).resolve().parents[2]
            / "frontend" / "test" / "scope-cases.json")
if not _fixture.exists():
    check("the shared classification fixture is present", False, str(_fixture))
else:
    _cases = json.loads(_fixture.read_text())
    _drift = []
    for _c in _cases:
        _subs = _c.get("subs", False)
        try:
            _e = classify(_c["raw"], _subs)
            _got = {"ok": True, "kind": _e.kind, "value": _e.value,
                    "included": _e.included,
                    "include_subdomains": _e.include_subdomains}
        except ValueError:
            _got = {"ok": False}
        _want = ({"ok": True, "kind": _c.get("kind"), "value": _c.get("value"),
                  "included": _c.get("included"),
                  "include_subdomains": _c.get("include_subdomains")}
                 if _c["ok"] else {"ok": False})
        if _got != _want:
            _drift.append(f"{_c['raw']!r} subs={_subs}: recorded {_want}, "
                          f"now {_got}")
    check(f"classify() still matches all {len(_cases)} recorded verdicts "
          f"the browser is held to", not _drift, "; ".join(_drift[:3]))
    check("the fixture still covers every kind classify() can return",
          all(any(c.get("kind") == k for c in _cases)
              for k in ("cidr", "ipv4", "ipv6", "fqdn", "wildcard")))
    # The flag is only ever carried on an fqdn, and the browser has to
    # drop it on the other kinds for the same reason the server does —
    # a pill that says "+subdomains" on a CIDR claims a rule the stored
    # row does not have.
    check("the fixture exercises the subdomains flag in both positions",
          any(c.get("subs") for c in _cases)
          and any(not c.get("subs") for c in _cases))
    check("and pins that only an fqdn carries it",
          any(c.get("include_subdomains") for c in _cases)
          and all(c.get("kind") == "fqdn"
                  for c in _cases if c.get("include_subdomains")))

# ============================== INVARIANT: inheritance is not transitive
print("\n== one step, and the partner must match the list itself ==")
# This is the invariant the many-to-many address model puts under real
# pressure, and it was previously true only by construction.
#
# `ScopeIndex` links a host to an address so that each can vouch for the
# other — an operator whose scope says `*.acme.example` and who scans the
# address `ours.acme.example` resolves to is not going outside it. With
# one address per target that link was a pair. Now a single CDN address
# row links to EVERY name the project has recorded at it, so if the walk
# were recursive — if a partner counted because it was itself ALLOWED
# rather than because it matches the document DIRECTLY — an in-scope name
# would vouch for its CDN address, and that address would then vouch for
# every other tenant renting space behind the same edge. A two-line scope
# document would quietly cover a hosting provider.
#
# The shape, which is the one the operator verified by hand:
#
#     ours.acme.example      ALLOWED   on the scope document
#     203.0.113.9            ALLOWED   via ours.acme.example
#     theirs.other.example   REFUSED   not in this project's in-scope list
_cdn = _idx([("wildcard", "*.acme.example", True)],
            links=[("ours.acme.example", "203.0.113.9")])
check("the name on the document is in scope",
      _cdn.check("ours.acme.example").allowed, "")
_via = _cdn.check("203.0.113.9")
check("the shared address is in scope, via that name", _via.allowed, _via.reason)
check("and the ruling says so rather than reading like a document entry",
      "via ours.acme.example" in _via.reason, _via.reason)
_theirs = _cdn.check("theirs.other.example")
check("a co-tenant at that address is REFUSED", not _theirs.allowed, _theirs.reason)

# The strong form. Above, `theirs.other.example` had no link at all, so
# it could be refused without the walk ever running. Here the project
# HAS recorded it at the same address — which really happens: a target
# added while no in-scope list existed, or added at a different address
# that later turned out to be shared. The walk now runs, finds
# `203.0.113.9`, and must ask whether that address is ON THE DOCUMENT.
# It is not. It was only ever allowed because of somebody else.
_shared = _idx([("wildcard", "*.acme.example", True)],
               links=[("ours.acme.example", "203.0.113.9"),
                      ("theirs.other.example", "203.0.113.9")])
check("ours is still in scope with a neighbour present",
      _shared.check("ours.acme.example").allowed, "")
check("the address is still in scope", _shared.check("203.0.113.9").allowed, "")
_co = _shared.check("theirs.other.example")
check("but the co-tenant sharing that very address is still REFUSED",
      not _co.allowed, _co.reason)
check("and the refusal is about the in-scope list, not about the address",
      "not in this project's in-scope list" in _co.reason, _co.reason)

# Two hops, spelled out. If scope chained, `far.other.example` would be
# allowed: it shares 198.51.100.50 with theirs.other.example, which
# shares 203.0.113.9 with ours.acme.example, which is on the document.
_chain = _idx([("wildcard", "*.acme.example", True)],
              links=[("ours.acme.example", "203.0.113.9"),
                     ("theirs.other.example", "203.0.113.9"),
                     ("theirs.other.example", "198.51.100.50"),
                     ("far.other.example", "198.51.100.50")])
check("scope does not chain across two hops",
      not _chain.check("far.other.example").allowed,
      _chain.check("far.other.example").reason)
check("nor does the second address inherit from the first",
      not _chain.check("198.51.100.50").allowed,
      _chain.check("198.51.100.50").reason)


# ====================== INVARIANT: every address is checked, separately
print("\n== a host is not laundered by one of its addresses ==")
# A target has many addresses now, so `check` takes a list. The two
# lists read it differently and both readings are the cautious one.
_multi = _idx([("cidr", "203.0.113.0/24", True), ("ipv4", "198.51.100.7", False)])
check("a host is admitted by any one of its addresses being in scope",
      _multi.check("web01.example", ["203.0.113.9", "203.0.113.10"]).allowed, "")
_barred = _multi.check("web01.example", ["203.0.113.9", "198.51.100.7"])
check("but ANY address on the out-list bars the host — a machine is "
      "not partly out of scope", not _barred.allowed, _barred.reason)
check("and the refusal names the address that caused it",
      "198.51.100.7" in _barred.reason, _barred.reason)
# The failure this replaces: `ip_address or ipv6_address` picked one,
# so a host with a clean v4 and a barred v6 passed on the strength of
# the first address looked at.
_v6 = _idx([("cidr", "203.0.113.0/24", True), ("cidr", "2001:db8::/32", False)])
check("a barred v6 address is not hidden behind a clean v4",
      not _v6.check("dual.example", ["203.0.113.9", "2001:db8::1"]).allowed, "")

print("\n== enumerating a zone is not the same question as touching a host ==")
# `*.acme.example` does not put `acme.example` in scope, deliberately:
# the apex is a different machine from the names under it. But
# "enumerate the zone acme.example" is the one operation that wildcard
# plainly DOES authorise -- every name it can return is `*.acme.example`
# -- and refusing it meant Kitchen Sink walking a known host queued
# amass for the LEAF name and never for the zone. A project scoped the
# ordinary way could not enumerate itself.
_z = ScopeIndex([classify("*.sub.acme.example", False)])
check("a name under the wildcard is in scope",
      _z.check("x.sub.acme.example").allowed)
check("the apex is still NOT a host the project may touch",
      not _z.check("sub.acme.example").allowed)
check("...but it IS a zone the project may enumerate",
      _z.check_zone("sub.acme.example").allowed,
      _z.check_zone("sub.acme.example").reason)
check("...and the ruling names the entry that authorised it",
      "*.sub.acme.example" in _z.check_zone("sub.acme.example").reason,
      _z.check_zone("sub.acme.example").reason)

# Everything the widening must NOT reach. One input changed answer and
# these say which ones did not.
check("a parent ABOVE the wildcard is not a zone either",
      not _z.check_zone("acme.example").allowed)
check("nor the grandparent", not _z.check_zone("example").allowed)
check("nor a sibling zone", not _z.check_zone("other.acme.example").allowed)
check("an unrelated zone is still refused",
      not _z.check_zone("somebody-else.example").allowed)
check("nor a name under a zone that is only enumerable",
      not _z.check("sub.acme.example").allowed)

# The out-list still wins. BARRED is a decision, not an absence, and
# only OUTSIDE may be reconsidered.
_x = ScopeIndex([classify("*.sub.acme.example", False),
                 classify("!sub.acme.example", False)])
check("an explicitly excluded apex stays excluded",
      not _x.check_zone("sub.acme.example").allowed,
      _x.check_zone("sub.acme.example").reason)
check("...and says it was the out-list that did it",
      "out-of-scope" in _x.check_zone("sub.acme.example").reason,
      _x.check_zone("sub.acme.example").reason)

# An fqdn entry is not a wildcard: what must not happen is its parent
# becoming enumerable.
_f = ScopeIndex([classify("one.host.acme.example", False)])
check("a plain fqdn does not make its parent a zone",
      not _f.check_zone("host.acme.example").allowed)
check("...and the fqdn itself is allowed, as it already was",
      _f.check_zone("one.host.acme.example").allowed)

check("a bare address never matches the wildcard-apex branch",
      not ScopeIndex([classify("*.acme.example", False)])
      .check_zone("203.0.113.5").allowed)
check("an empty zone is refused", not _z.check_zone("").allowed)

# With no allowlist the project is unrestricted; check_zone must not
# become stricter than check.
_open = ScopeIndex([])
check("no allowlist: check_zone agrees with check",
      _open.check_zone("anything.example").allowed
      == _open.check("anything.example").allowed)

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
raise SystemExit(1 if fail else 0)
