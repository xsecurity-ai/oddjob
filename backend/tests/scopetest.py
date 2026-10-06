"""Project scope: the two lists, and every path they are supposed to stop.

The shape under test is the one that matters in a real engagement. Scope
is not a note on the project — it decides what the tool will do, and the
expensive mistake is a check that exists on one path and not another,
because the paths that ARE checked make people believe the rest are too.

So this suite does not only assert that `scope.check()` returns the right
word. It drives each writing path over HTTP — add a target, bulk load,
import a scan, queue a Jaws task, hand that task to an agent — and
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


# ===================================================== Jaws tasking
print("\n== Jaws tasking is gated, at queue time and at hand-out ==")
project("JAWSX")
add_scope("JAWSX", lines=["203.0.113.0/24"])
add_scope("JAWSX", lines=["203.0.113.5"], included=False)
st, en = call("/api/agents?project=JAWSX", "POST", {"name": "a1"}, token=admin)
AID = ((en or {}).get("agent") or {}).get("id")
KEY = (en or {}).get("callback_key")
call("/api/agents/register", "POST", {"platform": "linux"}, key=KEY)

st, r = call(f"/api/agents/{AID}/tasks?project=JAWSX", "POST",
             {"kind": "nmap", "args": {"targets": ["203.0.113.5"]}}, token=admin)
check("a task naming a barred host is refused", st == 403, f"status={st}")
check("and says which host and which entry", "203.0.113.5" in str(r), str(r)[:170])

st, r = call(f"/api/agents/{AID}/tasks?project=JAWSX", "POST",
             {"kind": "nmap",
              "args": {"targets": ["203.0.113.4", "203.0.113.5"]}}, token=admin)
check("one barred host refuses the whole task, not just that entry",
      st == 403, f"status={st}")

st, r = call(f"/api/agents/{AID}/tasks?project=JAWSX", "POST",
             {"kind": "nmap", "args": {"targets": ["198.51.100.1"]}}, token=admin)
check("a task outside the in-scope list is refused too", st == 422, f"status={st}")

st, r = call("/api/agents/tasks?project=JAWSX", "POST",
             {"kind": "masscan", "args": {"targets": ["203.0.113.5"]}}, token=admin)
check("the pooled queue is gated identically — it is the same packets",
      st == 403, f"status={st}")

st, r = call(f"/api/agents/{AID}/tasks?project=JAWSX", "POST",
             {"kind": "nmap", "args": {"targets": ["203.0.113.9"]}}, token=admin)
check("an in-scope task is queued", st == 201, f"status={st} {str(r)[:120]}")
TASK = (r or {}).get("id")

# A URL-shaped target still has to pass: httpx and gospider take them.
st, r = call(f"/api/agents/{AID}/tasks?project=JAWSX", "POST",
             {"kind": "httpx", "args": {"targets": ["https://203.0.113.5:8443/x"]}},
             token=admin)
check("a target written as a URL is still resolved to its host and barred",
      st == 403, f"status={st}")

# A range whose edges are in scope passes; one whose edges are not does not.
st, r = call(f"/api/agents/{AID}/tasks?project=JAWSX", "POST",
             {"kind": "masscan", "args": {"targets": ["198.51.100.0/24"]}},
             token=admin)
check("a CIDR argument outside the list is refused", st == 422, f"status={st}")

print("\n-- the list can move while a task is queued --")
add_scope("JAWSX", lines=["203.0.113.9"], included=False)
st, hb = call("/api/agents/heartbeat", "POST", {}, key=KEY)
check("heartbeat is answered", st == 200, f"status={st}")
check("the now-barred task is NOT handed over",
      (hb or {}).get("task") is None, str(hb)[:160])
st, tasks = call(f"/api/agents/{AID}/tasks?project=JAWSX", token=admin)
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


print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
raise SystemExit(1 if fail else 0)
