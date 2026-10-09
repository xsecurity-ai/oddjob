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

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
