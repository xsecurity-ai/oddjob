"""Combining two targets that turned out to be one host.

This happens constantly: an address gets scanned, a name gets scanned,
and a reverse lookup later shows they were always the same machine.

Merging is the most destructive thing this application does — it moves
services, findings, proof-of-concepts, web exchanges and a timeline
between rows and then deletes one. So the tests are mostly about what
must NOT disappear. A merge that loses a finding is worse than a merge
that refuses, because the finding is gone and nothing says so.
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


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "MRG", "name": "Merge"}, token=admin)
call("/api/projects", "POST", {"code": "OTHER", "name": "Other"}, token=admin)

# One host, found twice: once by address, once by name. 443 is on both
# — the collision the merge has to resolve without dropping a banner.
NMAP_IP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 198.51.100.50" start="1760000000" version="7.94">
<host><status state="up" reason="echo-reply"/>
<address addr="198.51.100.50" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
  <service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
  <service name="https" product="nginx"/></port>
</ports></host>
<runstats><finished time="1760000030"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""
NMAP_NAME = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - web.acme.example" start="1760000100" version="7.94">
<host><status state="up" reason="echo-reply"/>
<address addr="198.51.100.50" addrtype="ipv4"/>
<hostnames><hostname name="web.acme.example" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
  <service name="https" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
  <service name="http-proxy"/></port>
</ports></host>
<runstats><finished time="1760000130"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

for xml in (NMAP_IP, NMAP_NAME):
    call("/api/scans/nmap?project=MRG&mode=open", "POST", {"xml": xml}, token=admin)

st, tg = call("/api/targets?project=MRG&page_size=100", token=admin)
hosts = sorted(t["host"] for t in (tg or {}).get("items", []))
check("both turned up as separate targets",
      "198.51.100.50" in hosts and "web.acme.example" in hosts, str(hosts))

# A finding and a PoC on the address, so there is something whose loss
# would matter.
st, mkv = call("/api/vulns?project=MRG", "POST",
               {"host": "198.51.100.50", "title": "Weak SSH ciphers",
                "severity": "medium"}, token=admin)
check("a finding exists on the address, so its loss would matter",
      st == 201, f"status={st} {str(mkv)[:110]}")

print("== the plan, before anything is touched ==")
st, p = call("/api/enumerate/merge-plan?project=MRG"
             "&host=198.51.100.50&into=web.acme.example", token=admin)
check("a plan is produced", st == 200, f"status={st} {str(p)[:120]}")
check("it names the port seen on both", p.get("service_conflicts") == ["443/tcp"],
      str(p.get("service_conflicts")))
check("and the services that simply move", p.get("services_moved") == 1,
      f"{p.get('services_moved')} (22/tcp)")
check("and the finding", p.get("vulns_moved") == 1, str(p.get("vulns_moved")))

st, before = call("/api/targets?project=MRG&page_size=100", token=admin)
n_before = len((before or {}).get("items", []))
st, sbefore = call("/api/services?project=MRG&page_size=100", token=admin)
check("planning changed nothing",
      len((before or {}).get("items", [])) == n_before, str(n_before))

print("== it refuses without being confirmed ==")
st, err = call("/api/enumerate/merge?project=MRG&host=198.51.100.50", "POST",
               {"into": "web.acme.example"}, token=admin)
# Approving a verb is not approving a list of consequences.
check("an unconfirmed merge is refused", st == 428, f"status={st}")
check("and says how to see what it would do",
      "merge-plan" in str(err), str(err)[:140])

print("== what it must refuse outright ==")
st, _ = call("/api/enumerate/merge?project=MRG&host=198.51.100.50", "POST",
             {"into": "198.51.100.50", "confirm": True}, token=admin)
check("a target cannot be merged into itself", st == 409, f"status={st}")
call("/api/targets?project=OTHER", "POST", {"host": "elsewhere.acme.example"},
     token=admin)
st, _ = call("/api/enumerate/merge?project=MRG&host=198.51.100.50", "POST",
             {"into": "elsewhere.acme.example", "confirm": True}, token=admin)
# Moving findings between engagements puts one client's data in
# another client's report.
check("a target in another engagement is not even found", st == 404,
      f"status={st}")

print("== the merge ==")
st, done = call("/api/enumerate/merge?project=MRG&host=198.51.100.50", "POST",
                {"into": "web.acme.example", "confirm": True}, token=admin)
check("it goes through", st == 200, f"status={st} {str(done)[:140]}")
check("the name chosen survives", (done or {}).get("surviving") == "web.acme.example",
      str((done or {}).get("surviving")))

st, after = call("/api/targets?project=MRG&page_size=100", token=admin)
rows = (after or {}).get("items", [])
check("there is one target where there were two", len(rows) == 1, str(len(rows)))
check("and it is the named one",
      rows and rows[0]["host"] == "web.acme.example", str(rows)[:90])
check("which kept the address it was found at",
      rows and rows[0]["ip_address"] == "198.51.100.50",
      str(rows[0].get("ip_address") if rows else None))

print("== nothing was lost ==")
st, svc = call("/api/services?project=MRG&page_size=100", token=admin)
ports = sorted(s["port"] for s in (svc or {}).get("items", []))
# 22 moved, 8080 was already there, 443 was on both and must appear
# once — not twice, and not zero times.
check("every port from both scans is present once", ports == [22, 443, 8080],
      str(ports))

four43 = next((s for s in (svc or {}).get("items", []) if s["port"] == 443), {})
check("the surviving 443 kept the version only one scan saw",
      four43.get("version") == "1.24.0", str(four43.get("version")))
check("and the product both agreed on", four43.get("product") == "nginx",
      str(four43.get("product")))

st, v = call("/api/vulns?project=MRG&page_size=100", token=admin)
titles = [x["title"] for x in (v or {}).get("items", [])]
check("the finding came with it", "Weak SSH ciphers" in titles, str(titles))

st, tl = call("/api/targets/MRG/web.acme.example/timeline", token=admin)
events = tl if isinstance(tl, list) else (tl or {}).get("items", [])
blob = json.dumps(events)
check("the merge is on the timeline", "merged 198.51.100.50" in blob,
      blob[:160])
check("and says what moved, not just that it happened",
      "service" in blob and "443/tcp" in blob, blob[:200])

print("== a merge nobody asked for cannot happen by accident ==")
st, _ = call("/api/enumerate/merge?project=MRG&host=nope.acme.example", "POST",
             {"into": "web.acme.example", "confirm": True}, token=admin)
check("an unknown source is 404", st == 404, f"status={st}")
call("/api/users", "POST", {"username": "r2", "password": "r2-password-123"},
     token=admin)
call("/api/projects/MRG/acl", "POST", {"username": "r2", "role": "readonly"},
     token=admin)
rtok = call("/api/auth/login", "POST",
            {"username": "r2", "password": "r2-password-123"})[1]["access_token"]
call("/api/targets?project=MRG", "POST", {"host": "spare.acme.example"},
     token=admin)
st, _ = call("/api/enumerate/merge?project=MRG&host=spare.acme.example", "POST",
             {"into": "web.acme.example", "confirm": True}, token=rtok)
check("a reader cannot merge", st == 403, f"status={st}")
st, _ = call("/api/enumerate/merge-plan?project=MRG"
             "&host=spare.acme.example&into=web.acme.example", token=rtok)
check("but may look at what it would do", st == 200, f"status={st}")

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
