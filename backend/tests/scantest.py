"""nmap -sV -O -A ingestion, and the target timeline it writes.

The fixture is a trimmed but structurally faithful `nmap -oX` document: OS
matches with competing accuracies, service/version detection, a port that
resisted identification, a script with only structured output, host-level
NSE, MAC, uptime and traceroute.
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


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode(); r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -O -A -oX - 10.0.0.5" start="1760000000" version="7.95">
<host starttime="1760000001">
<status state="up" reason="echo-reply"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<address addr="00:0C:29:AB:CD:EF" addrtype="mac" vendor="VMware"/>
<hostnames>
  <hostname name="web01.example.com" type="PTR"/>
  <hostname name="www.example.com" type="user"/>
</hostnames>
<ports>
<extraports state="closed" count="994"><extrareasons reason="resets" count="994"/></extraports>
<port protocol="tcp" portid="22">
  <state state="open" reason="syn-ack" reason_ttl="64"/>
  <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu 3ubuntu13"
           method="probed" conf="10">
    <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>
  </service>
  <script id="ssh-hostkey" output="  3072 SHA256:abc (RSA)"/>
</port>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack" reason_ttl="64"/>
  <service name="http" product="nginx" version="1.27.1" tunnel="ssl"
           method="probed" conf="10">
    <cpe>cpe:/a:igor_sysoev:nginx:1.27.1</cpe>
  </service>
  <script id="http-title" output="Welcome"/>
  <script id="ssl-cert">
    <table key="subject"><elem key="commonName">web01.example.com</elem></table>
    <elem key="validity">2026-01-01</elem>
  </script>
</port>
<port protocol="tcp" portid="8081">
  <state state="open" reason="syn-ack" reason_ttl="64"/>
  <service name="unknown" method="table" conf="3"/>
</port>
<port protocol="tcp" portid="9999">
  <state state="open" reason="syn-ack" reason_ttl="64"/>
</port>
<port protocol="udp" portid="161">
  <state state="open|filtered" reason="no-response"/>
  <service name="snmp" method="table" conf="3"/>
</port>
</ports>
<os>
  <portused state="open" proto="tcp" portid="22"/>
  <osmatch name="Linux 5.15 - 6.8" accuracy="96">
    <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96">
      <cpe>cpe:/o:linux:linux_kernel:5</cpe>
    </osclass>
  </osmatch>
  <osmatch name="Linux 4.15" accuracy="92"/>
</os>
<uptime seconds="1209600" lastboot="Mon Sep 21 09:00:00 2026"/>
<distance value="3"/>
<tcpsequence index="261" difficulty="Good luck!"/>
<hostscript>
  <script id="smb-os-discovery" output="OS: Windows 10"/>
</hostscript>
<trace port="443" proto="tcp">
  <hop ttl="1" ipaddr="10.0.0.1" rtt="0.21"/>
  <hop ttl="3" ipaddr="10.0.0.5" rtt="1.10" host="web01.example.com"/>
</trace>
</host>
<host>
<status state="down" reason="no-response"/>
<address addr="10.0.0.9" addrtype="ipv4"/>
</host>
<runstats><finished summary="Nmap done; 2 IP addresses scanned"/></runstats>
</nmaprun>
"""

admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "SCAN", "name": "Scan test"}, token=admin)

print("== importing nmap -sV -O -A ==")
st, r = call("/api/scans/nmap?project=SCAN", "POST", {"xml": XML}, token=admin)
check("import accepted", st == 200, f"status={st} {str(r)[:120]}")
check("tool and command recorded", r["tool"].startswith("nmap 7.95")
      and "-sV -O -A" in (r["command"] or ""), f"{r['tool']} / {r['command']}")
check("both hosts seen", r["hosts_seen"] == 2, str(r["hosts_seen"]))
check("two targets created", r["targets_created"] == 2, str(r["targets_created"]))
# Four, not five: the fixture's 161/udp is open|filtered, and only
# open ports are recorded now.
check("four services created", r["services_created"] == 4, str(r["services_created"]))
check("unidentified open ports counted", r["services_unknown"] == 2,
      f"{r['services_unknown']} (8081 named 'unknown', 9999 with no service element)")
check("NSE output captured", r["scripts_captured"] == 3, str(r["scripts_captured"]))

print("\n== the target ==")
st, d = call("/api/targets/SCAN/web01.example.com/detail", token=admin)
check("keyed on the hostname, not the IP", st == 200, f"status={st}")
t = d["target"]
check("ip recorded", t["ip_address"] == "10.0.0.5", str(t["ip_address"]))
check("alive from the status element", t["alive"] is True)
check("best OS match wins", t["os"] == "Linux 5.15 - 6.8", str(t["os"]))
check("with its accuracy, not just the name", t["os_accuracy"] == 96, str(t["os_accuracy"]))
check("MAC and vendor", t["mac_address"] == "00:0C:29:AB:CD:EF" and t["mac_vendor"] == "VMware")
check("every hostname kept", t["hostnames"] == ["web01.example.com", "www.example.com"],
      str(t["hostnames"]))
x = t["extra"]
check("the losing OS match is kept too", len(x["os_matches"]) == 2, str(len(x.get("os_matches", []))))
check("uptime", x["uptime"]["seconds"] == 1209600)
check("distance", x["distance"] == 3)
check("tcp sequence analysis", x["tcp_sequence"]["difficulty"] == "Good luck!")
check("traceroute hops", len(x["traceroute"]["hops"]) == 2)
check("extraports summary", x["extraports"][0]["count"] == 994)
check("host-level NSE", "smb-os-discovery" in x["hostscripts"])
check("a host that was down is recorded as not alive",
      call("/api/targets/SCAN/10.0.0.9", token=admin)[1]["alive"] is False)

print("\n== services ==")
svc = {f"{s['port']}/{s['protocol']}": s for s in d["services"]}
check("all four open ports", len(svc) == 4, str(sorted(svc)))
s22 = svc["22/tcp"]
check("version detection", s22["product"] == "OpenSSH" and s22["version"] == "9.6p1")
check("extrainfo", s22["extrainfo"] == "Ubuntu 3ubuntu13")
check("banner reads like nmap's VERSION column",
      s22["banner"] == "OpenSSH 9.6p1 (Ubuntu 3ubuntu13)", s22["banner"])
check("cpe", s22["cpe"] == ["cpe:/a:openbsd:openssh:9.6p1"], str(s22["cpe"]))
check("confidence and method", s22["confidence"] == 10 and s22["method"] == "probed")
check("state reason", s22["reason"] == "syn-ack")
check("per-port NSE", s22["scripts"]["ssh-hostkey"].startswith("3072 SHA256"),
      str(s22["scripts"])[:60])

s443 = svc["443/tcp"]
check("tls tunnel noted", s443["tunnel"] == "ssl")
check("banner carries the tunnel", s443["banner"] == "ssl/nginx 1.27.1", s443["banner"])
check("a script with no @output is still captured",
      "commonName" in s443["scripts"]["ssl-cert"], str(s443["scripts"].get("ssl-cert"))[:80])

check("nmap's own 'unknown' becomes UNKNOWN", svc["8081/tcp"]["name"] == "UNKNOWN",
      str(svc["8081/tcp"]["name"]))
check("a port with no service element becomes UNKNOWN too",
      svc["9999/tcp"]["name"] == "UNKNOWN", str(svc["9999/tcp"]["name"]))
# Only open ports are recorded. A UDP probe with no reply is
# indistinguishable from one a firewall dropped — nmap says so with
# "open|filtered" — and a closed TCP port is a reply saying nothing is
# there. Neither is a service. One real -sU sweep of 2,051 hosts
# produced 42,890 open|filtered rows against 13 genuinely open ports,
# which made every port count in the UI meaningless.
check("an open|filtered udp port is NOT recorded as a service",
      "161/udp" not in svc, str([k for k in svc if k.endswith("/udp")]))
check("every service recorded is open",
      all(v["state"] == "open" for v in svc.values()),
      str({k: v["state"] for k, v in svc.items() if v["state"] != "open"}))

from app.importers import nmap as _nm

_probe = """<?xml version="1.0"?><nmaprun scanner="nmap" args="x">
<host><status state="up"/><address addr="10.9.9.9" addrtype="ipv4"/><ports>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
<port protocol="udp" portid="161"><state state="open|filtered"/></port>
<port protocol="udp" portid="123"><state state="closed"/></port>
<port protocol="tcp" portid="80"><state state="open"/></port>
<port protocol="tcp" portid="81"><state state="closed"/></port>
<port protocol="tcp" portid="82"><state state="filtered"/></port>
</ports></host></nmaprun>"""
_got = {(x.protocol, x.port) for x in _nm.parse(_probe).hosts[0].services}
check("the parser keeps open udp", ("udp", 53) in _got)
check("drops open|filtered udp", ("udp", 161) not in _got)
check("drops closed udp", ("udp", 123) not in _got)
check("keeps open tcp", ("tcp", 80) in _got)
check("drops closed tcp", ("tcp", 81) not in _got)
check("drops filtered tcp", ("tcp", 82) not in _got)
check("so the host is left with exactly the open ports", _got == {("udp", 53), ("tcp", 80)},
      str(sorted(_got)))

from app.importers import masscan as _ms

_mp = """<?xml version="1.0"?><!-- masscan --><nmaprun scanner="masscan">
<host><address addr="10.9.9.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/></port>
<port protocol="tcp" portid="444"><state state="closed"/></port>
</ports></host></nmaprun>"""
check("masscan XML drops closed too",
      {(x.protocol, x.port) for x in _ms.parse(_mp).hosts[0].services} == {("tcp", 443)})
check("masscan list format drops closed",
      {(x.protocol, x.port) for x in _ms.parse(
          "open tcp 443 10.0.0.1 1699999999\nclosed tcp 25 10.0.0.1 1699999999"
      ).hosts[0].services} == {("tcp", 443)})

print("\n== timeline ==")
st, tl = call("/api/targets/SCAN/web01.example.com/timeline", token=admin)
check("timeline readable", st == 200, f"status={st}")
kinds = [e["kind"] for e in tl["items"]]
summaries = " | ".join(e["summary"] for e in tl["items"])
check("discovery recorded", "discovered" in kinds, str(kinds))
check("says which tool found it", "nmap" in summaries, summaries[:100])
check("OS fingerprint recorded", "OS fingerprint: Linux 5.15 - 6.8 (96% confidence)" in summaries,
      summaries[:160])
check("services recorded", any(k == "service" for k in kinds), str(kinds))
check("NSE recorded with its output",
      any(e["kind"] == "scan" and "ssl-cert" in (e["summary"] + (e["detail"] or ""))
          for e in tl["items"]))
check("every entry attributed", all(e["actor"] for e in tl["items"]))
check("provenance kept", all(e["source"] in (None, "nmap:inline") for e in tl["items"]))

print("\n== a note is part of the narrative ==")
st, _ = call("/api/targets/SCAN/web01.example.com", "PATCH",
             {"notes": "Checked manually.\nAdmin panel behind basic auth."}, token=admin)
st, tl = call("/api/targets/SCAN/web01.example.com/timeline?kind=note", token=admin)
check("the note appears as its own entry", tl["total"] == 1, str(tl["total"]))
check("first line is the summary", tl["items"][0]["summary"] == "Checked manually.",
      tl["items"][0]["summary"])
check("full text in the detail", "basic auth" in tl["items"][0]["detail"])

st, _ = call("/api/targets/SCAN/web01.example.com", "PATCH", {"hacked": True}, token=admin)
st, tl = call("/api/targets/SCAN/web01.example.com/timeline?kind=status", token=admin)
check("compromise is recorded", tl["total"] == 1 and "compromised" in tl["items"][0]["summary"],
      str(tl["items"][0]["summary"] if tl["total"] else tl))

st, e = call("/api/targets/SCAN/web01.example.com/timeline", "POST",
             {"kind": "note", "summary": "Reported to client"}, token=admin)
check("a note can be added directly", st == 201, f"status={st}")
check("attributed to the person", e["actor"] == "root", str(e.get("actor")))
st, e = call("/api/targets/SCAN/web01.example.com/timeline", "POST",
             {"kind": "vuln", "summary": "forged"}, token=admin)
check("automatic kinds cannot be written by hand", st == 422, f"status={st}")

print("\n== re-importing the same scan ==")
st, r2 = call("/api/scans/nmap?project=SCAN", "POST", {"xml": XML}, token=admin)
check("creates nothing new", r2["targets_created"] == 0 and r2["services_created"] == 0,
      f"{r2['targets_created']}/{r2['services_created']}")
check("and reports no service changes", r2["services_updated"] == 0, str(r2["services_updated"]))

CHANGED = XML.replace('version="9.6p1"', 'version="9.7p1"')
st, r3 = call("/api/scans/nmap?project=SCAN", "POST", {"xml": CHANGED}, token=admin)
check("a changed version is an update, not a duplicate",
      r3["services_updated"] == 1 and r3["services_created"] == 0,
      f"{r3['services_updated']}/{r3['services_created']}")
st, tl = call("/api/targets/SCAN/web01.example.com/timeline?kind=service", token=admin)
check("and the change is in the timeline",
      any("9.6p1 → 9.7p1" in (e["detail"] or "") for e in tl["items"]),
      str([e["detail"] for e in tl["items"]])[:140])

print("\n== bad input ==")
st, r = call("/api/scans/nmap?project=SCAN", "POST", {"xml": "<not-nmap/>"}, token=admin)
check("a non-nmap document is refused with a usable message",
      st == 422 and "-oX" in str(r), f"status={st} {str(r)[:90]}")
st, r = call("/api/scans/nmap?project=SCAN", "POST", {"xml": "<nmaprun>"}, token=admin)
check("malformed XML is refused", st == 422, f"status={st}")
st, r = call("/api/scans/nmap?project=NOSUCH", "POST", {"xml": XML}, token=admin)
check("an unknown project is refused", st == 404, f"status={st}")

call("/api/users", "POST", {"username": "viewer", "password": "viewer-password-1"}, token=admin)
v = call("/api/auth/login", "POST",
         {"username": "viewer", "password": "viewer-password-1"})[1]["access_token"]
call("/api/projects/SCAN/acl", "POST", {"username": "viewer", "role": "readonly"}, token=admin)
st, _ = call("/api/scans/nmap?project=SCAN", "POST", {"xml": XML}, token=v)
check("a readonly member cannot import", st == 403, f"status={st}")
st, _ = call("/api/targets/SCAN/web01.example.com/timeline", token=v)
check("but can read the timeline", st == 200, f"status={st}")

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
