"""Which scans a port still needs, given what has already been run.

The rules under test are the operator's, stated as they were given:

    do -sS then -sT  ->  the -sT still has to run
    do -sT then -sV  ->  the -sV still has to run
    already did -sT  ->  do not do a -sS
    already did -sV  ->  do not do a -sS or a -sT
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.portcoverage import (  # noqa: E402
    Range,
    covered,
    expand,
    merge,
    needed,
    parse_ports,
    rank,
    subsumes,
    technique_from_scan,
)

passed = failed = 0


def check(label, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" {got}" if got is not None else ""))


# =====================================================================
# Part 1 — the operator's four rules, verbatim
# =====================================================================
print("\n--- the stated rules ---")

check("did -sS, still need -sT", not subsumes("syn", "connect"))
check("did -sT, still need -sV", not subsumes("connect", "version"))
check("did -sT, so no -sS", subsumes("connect", "syn"))
check("did -sV, so no -sS", subsumes("version", "syn"))
check("did -sV, so no -sT", subsumes("version", "connect"))
check("did -sS, so no second -sS", subsumes("syn", "syn"))

# An unknown technique must not suppress anything. An nmap that invents
# a scan type would otherwise silently cancel future real scans.
check("an unrecognised technique subsumes nothing",
      not subsumes("xmas", "syn") and not subsumes("syn", "xmas"))
check("unknown ranks 0", rank("nonsense") == 0)

# =====================================================================
# Part 2 — technique comes from what nmap DID, not what we asked for
# =====================================================================
print("\n--- the technique is read off the scan, not the request ---")

check("syn scan", technique_from_scan("syn", "nmap -sS -oX /t 10.0.0.1") == "syn")
check("connect scan", technique_from_scan("connect", "nmap -sT -oX /t 10.0.0.1")
      == "connect")
# The one that matters: -sS without raw sockets silently becomes a
# connect scan, and nmap says so in scaninfo. Recording the REQUEST
# would record a syn scan that never happened.
check("asked -sS, nmap did connect -> recorded as connect",
      technique_from_scan("connect", "nmap -sS -oX /t 10.0.0.1") == "connect",
      technique_from_scan("connect", "nmap -sS -oX /t 10.0.0.1"))
check("-sV promotes a syn scan to version",
      technique_from_scan("syn", "nmap -sS -sV -oX /t 10.0.0.1") == "version")
check("-sV promotes a connect scan to version",
      technique_from_scan("connect", "nmap -sT -sV -oX /t 10.0.0.1") == "version")

# ACK and window scans map firewall rules, not services. Letting one
# count as coverage would suppress a real -sS forever.
check("an ack scan is not coverage", technique_from_scan("ack", "nmap -sA") is None)
check("a window scan is not coverage",
      technique_from_scan("window", "nmap -sW") is None)
check("no scaninfo at all is not coverage", technique_from_scan(None, "nmap -sV")
      is None)

# -sV must be a whole token. A path containing it would otherwise
# record a version scan that never ran and suppress the real one.
check("-sV inside a path is not a -sV flag",
      technique_from_scan("syn", "nmap -oX /tmp/out-sV.xml 10.0.0.1") == "syn",
      technique_from_scan("syn", "nmap -oX /tmp/out-sV.xml 10.0.0.1"))

# =====================================================================
# Part 3 — the port list nmap says it covered
# =====================================================================
print("\n--- port specs ---")

check("single", parse_ports("80") == [(80, 80)])
check("list", parse_ports("22,80,443") == [(22, 22), (80, 80), (443, 443)])
check("range", parse_ports("8000-8100") == [(8000, 8100)])
check("mixed", parse_ports("22,80,8000-8100")
      == [(22, 22), (80, 80), (8000, 8100)])
check("overlapping ranges merge", parse_ports("1-100,50-200") == [(1, 200)])
# Touching ranges must join, or "is 1-100 covered" answers no.
check("adjacent ranges join", merge([(1, 79), (80, 100)]) == [(1, 100)])
check("backwards range is repaired", parse_ports("100-1") == [(1, 100)])
check("out-of-band values are clamped", parse_ports("0-70000") == [(1, 65535)])
check("junk is skipped, not fatal", parse_ports("80,abc,443")
      == [(80, 80), (443, 443)])
check("empty", parse_ports("") == [] and parse_ports(None) == [])

# =====================================================================
# Part 4 — the question actually asked at scan time
# =====================================================================
print("\n--- what still needs running ---")

# A full TCP syn sweep has happened.
full_syn = [Range("syn", 1, 65535)]
check("a -sS everywhere does not satisfy a -sT",
      needed([22, 80, 443], full_syn, "connect") == [22, 80, 443])
check("...and does satisfy another -sS",
      needed([22, 80, 443], full_syn, "syn") == [])

# A -sV was run, but only against the web ports.
mixed = [Range("syn", 1, 1024), Range("version", 80, 80), Range("version", 443, 443)]
check("-sV on 80 means no -sS and no -sT there",
      needed([80], mixed, "syn") == [] and needed([80], mixed, "connect") == [])
check("22 had only a -sS, so a -sT is still owed",
      needed([22], mixed, "connect") == [22])
check("8080 was never looked at by anything",
      needed([8080], mixed, "syn") == [8080])
check("a mixed request returns only the uncovered",
      needed([80, 443, 22, 8080], mixed, "connect") == [22, 8080],
      needed([80, 443, 22, 8080], mixed, "connect"))

# Coverage is about what was ATTEMPTED. A port scanned and found
# closed is covered; it must not be rescanned forever just because no
# service row exists for it.
check("a port scanned and found closed is still covered",
      covered([Range("connect", 1, 1024)], 139, "syn"))

check("nothing known means everything is needed",
      needed([1, 2, 3], [], "syn") == [1, 2, 3])

# =====================================================================
# Part 5 — expand is bounded
# =====================================================================
print("\n--- expansion is bounded ---")

check("a full range expands to the cap, not past it",
      len(expand([(1, 65535)])) == 65535)
check("an explicit cap is honoured", len(expand([(1, 65535)], cap=10)) == 10)
check("expansion is correct for small ranges",
      expand([(80, 82), (443, 443)]) == [80, 81, 82, 443])

# =====================================================================
# Part 6 — against real nmap XML, not just the helper
# =====================================================================
print("\n--- read off actual nmap output ---")

from app.importers.nmap import parse  # noqa: E402

# The operator asked for -sS; nmap had no raw sockets, did a connect
# scan, and recorded that. Coverage must follow what happened.
got = parse('''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sS -oX /tmp/o.xml -p 1-1024 10.0.0.1" start="1760000000">
<scaninfo type="connect" protocol="tcp" numservices="1024" services="1-1024"/>
<host><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>''').coverage
check("asked -sS, nmap did connect -> recorded as connect",
      got == [("connect", "tcp", "1-1024")], got)

# One run, two techniques, two <scaninfo> elements. -sV promotes the
# TCP one; the UDP scan is a different protocol and not TCP coverage.
got = parse('''<?xml version="1.0"?><nmaprun args="nmap -sS -sU -sV -oX /t h">
<scaninfo type="syn" protocol="tcp" services="1-100"/>
<scaninfo type="udp" protocol="udp" services="53,161"/>
<runstats><finished summary="done"/></runstats></nmaprun>''').coverage
check("-sV promotes tcp, and udp is not tcp coverage",
      got == [("version", "tcp", "1-100")], got)

got = parse('''<?xml version="1.0"?><nmaprun args="nmap -sA -oX /t h">
<scaninfo type="ack" protocol="tcp" services="1-1024"/>
<runstats><finished summary="done"/></runstats></nmaprun>''').coverage
check("an ack scan records no coverage", got == [], got)

got = parse('''<?xml version="1.0"?><nmaprun args="nmap -oX /t h">
<runstats><finished summary="done"/></runstats></nmaprun>''').coverage
check("no scaninfo parses cleanly and records nothing", got == [], got)

# =====================================================================
# Part 7 — end to end: import a scan, ask what is still owed
# =====================================================================
print("\n--- against a live server ---")

import json  # noqa: E402
import os  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "COV", "name": "COV"}, token=admin)

# A syn sweep of 1-1024 against one host.
SYN = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sS -oX /t -p 1-1024 10.9.9.1" start="1760000000">
<scaninfo type="syn" protocol="tcp" numservices="1024" services="1-1024"/>
<host><address addr="10.9.9.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
st, _ = call("/api/scans/import?project=COV", "POST",
             {"content": SYN, "format": "auto", "mode": "open"}, token=admin)
check("the syn scan imported", st == 200, st)

st, r = call("/api/targets/unscanned?project=COV&technique=syn&ports=80,443", token=admin)
check("after a -sS of 1-1024, 80 needs no further -sS",
      st == 200 and "10.9.9.1" not in r["hosts"]
      # Not vacuous: the host must have been looked at and allowed,
      # or an empty list would pass for the wrong reason.
      and r["considered"] == 1 and r["out_of_scope"] == 0,
      f"hosts={r.get('hosts')} considered={r.get('considered')} "
      f"refused={r.get('out_of_scope')}")

st, r = call("/api/targets/unscanned?project=COV&technique=connect&ports=80,443", token=admin)
by_host = {h["host"]: h for h in r.get("gaps", [])}
check("...but a -sT is still owed on both",
      "10.9.9.1" in by_host and by_host["10.9.9.1"]["ports"] == "80,443",
      by_host.get("10.9.9.1"))

# Now a -sV, but only on 80.
VER = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sT -sV -oX /t -p 80 10.9.9.1" start="1760000100">
<scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>
<host><address addr="10.9.9.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
st, _ = call("/api/scans/import?project=COV", "POST",
             {"content": VER, "format": "auto", "mode": "open"}, token=admin)
check("the version scan imported", st == 200, st)

st, r = call("/api/targets/unscanned?project=COV&technique=connect&ports=80,443", token=admin)
by_host = {h["host"]: h for h in r.get("gaps", [])}
check("-sV on 80 clears the -sT there, leaving only 443",
      by_host.get("10.9.9.1", {}).get("ports") == "443",
      by_host.get("10.9.9.1"))

st, r = call("/api/targets/unscanned?project=COV&technique=version&ports=80,443", token=admin)
by_host = {h["host"]: h for h in r.get("gaps", [])}
check("a -sV is still owed on 443", by_host.get("10.9.9.1", {}).get("ports") == "443",
      by_host.get("10.9.9.1"))

# A run of ports comes back as a range, not 998 comma-separated numbers.
st, r = call("/api/targets/unscanned?project=COV&technique=version&ports=1-1024", token=admin)
by_host = {h["host"]: h for h in r.get("gaps", [])}
check("the gap is returned as a collapsed spec",
      by_host.get("10.9.9.1", {}).get("ports", "").startswith("1-79,81-"),
      by_host.get("10.9.9.1", {}).get("ports", "")[:24])

st, r = call("/api/targets/unscanned?project=COV&technique=nonsense", token=admin)
check("an unknown technique is refused, not silently ignored", st == 400, st)

# The original behaviour is untouched when no technique is named.
st, r = call("/api/targets/unscanned?project=COV", token=admin)
check("without a technique it still answers the old question",
      st == 200 and "gaps" not in r, sorted(r) if st == 200 else st)


# =====================================================================
# Part 8 — an open port belongs to the address, not to the name
# =====================================================================
print("\n--- ports reach every name at the same address ---")

call("/api/projects", "POST", {"code": "COT", "name": "COT"}, token=admin)
# Scope: two names in, one deliberately out. The out-of-scope one is
# the case that matters -- it is somebody else's host that happens to
# share an IP, and nothing may be written about it.
call("/api/projects/COT/scope", "POST",
     {"lines": ["a.cot.example", "b.cot.example"]}, token=admin)
# The two in-scope names, at one shared address. Addresses live on
# the target, not behind a route of their own.
for h in ("a.cot.example", "b.cot.example"):
    call("/api/targets?project=COT", "POST",
         {"host": h, "ip_address": "198.51.100.7"}, token=admin)

# The out-of-scope neighbour has to be inserted DIRECTLY. The API
# refuses to create it -- 422, because the scope does not cover it --
# and an absent target would make the assertion below pass without
# testing anything: nothing propagates to a host that does not exist.
# Checked by removing the co-tenancy scope gate and watching the whole
# suite still pass, which is what sent me here.
#
# A target that exists and is out of scope is a real state: scope gets
# narrowed after hosts are added, and co-tenants arrive from DNS.
import asyncio  # noqa: E402

from sqlalchemy import select as _select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import Project as _Project  # noqa: E402
from app.models import Target as _Target  # noqa: E402
from app.models import TargetAddress as _Addr  # noqa: E402


async def _plant_stranger():
    async with SessionLocal() as db:
        pr = (await db.execute(
            _select(_Project).where(_Project.code == "COT"))).scalar_one()
        addr = (await db.execute(
            _select(_Addr).where(_Addr.project_id == pr.id,
                                 _Addr.address == "198.51.100.7"))).scalar_one()
        t = _Target(project_id=pr.id, host="stranger.example", kind="host")
        t.addresses.append(addr)
        db.add(t)
        await db.commit()


asyncio.run(_plant_stranger())

SHARED = '''<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"
 args="nmap -sT -sV -oX /t -p 443 a.cot.example" start="1760000200">
<scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
<host><address addr="198.51.100.7" addrtype="ipv4"/>
<hostnames><hostname name="a.cot.example" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.25"/></port></ports></host>
<runstats><finished summary="done"/></runstats></nmaprun>'''
st, r = call("/api/scans/import?project=COT", "POST",
             {"content": SHARED, "format": "auto", "mode": "open"}, token=admin)
check("the shared-address scan imported", st == 200, st)


def ports_of(host):
    st, d = call(f"/api/targets/COT/{host}/detail", token=admin)
    return {s["port"]: s for s in (d or {}).get("services", [])}


a_ports = ports_of("a.cot.example")
b_ports = ports_of("b.cot.example")
stranger = ports_of("stranger.example")

check("the scanned host has 443", 443 in a_ports, sorted(a_ports))
check("the other in-scope name at that address has it too",
      443 in b_ports, sorted(b_ports))

# The out-of-scope neighbour must get nothing. Sharing an address with
# an in-scope name is not inheritance.
check("an out-of-scope co-tenant is left alone",
      443 not in stranger, sorted(stranger))

# What was copied, and what was not. The product came from a request
# for ONE virtual host; claiming it for every name at the address
# would be inventing evidence.
check("the copy carries the port's service type",
      b_ports.get(443, {}).get("name") == "https", b_ports.get(443))
check("...but not the product the scanned vhost returned",
      not b_ports.get(443, {}).get("product"), b_ports.get(443))
check("...and says it was not scanned by name",
      "not scanned by name" in (b_ports.get(443, {}).get("notes") or ""),
      b_ports.get(443, {}).get("notes"))
# The directly-scanned host keeps its full detail.
check("the scanned host keeps the product",
      a_ports.get(443, {}).get("product") == "nginx", a_ports.get(443))

# Coverage must NOT travel. It is what stops a future scan running,
# and claiming a name was covered because its neighbour was would
# suppress a real scan for ever.
st, r = call("/api/targets/unscanned?project=COT&technique=connect&ports=443",
             token=admin)
owed = {h["host"] for h in r.get("gaps", [])}
check("the neighbour still owes its own -sT", "b.cot.example" in owed,
      sorted(owed))
check("...while the scanned host does not", "a.cot.example" not in owed,
      sorted(owed))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
