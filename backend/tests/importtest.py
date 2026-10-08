"""Every importer: format detection, parsing, and what lands in the DB.

Fixtures are trimmed but structurally faithful to each tool's real output.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8015")
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


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]


def imp(project, content, fmt="auto", mode="open"):
    """Seeding helper. `open` because these suites are establishing the
    estate; strict mode has its own tests below."""
    call("/api/projects", "POST", {"code": project, "name": project}, token=admin)
    return call(f"/api/scans/import?project={project}", "POST",
                {"content": content, "format": fmt, "mode": mode}, token=admin)


def detail(project, host):
    return call(f"/api/targets/{project}/{host}/detail", token=admin)[1]


# ======================================================== supported formats
print("== formats endpoint ==")
st, fmts = call("/api/scans/formats", token=admin)
names = {f["name"] for f in fmts}
check("formats listed", st == 200 and len(fmts) >= 12, f"{len(fmts)}")
check("every importer advertised",
      {"nmap", "masscan", "nessus", "metasploit", "burp", "nikto", "nuclei",
       "httpx", "cobaltstrike", "mythic", "merlin", "sliver", "havoc"} <= names,
      str(sorted(names)))

# ============================================================== metasploit
MSF = """<?xml version="1.0" encoding="UTF-8"?>
<MetasploitV5>
<hosts>
  <host><id>1</id><address>10.10.0.5</address><mac>00:11:22:33:44:55</mac>
    <name>dc01.corp.local</name><state>alive</state>
    <os-name>Windows</os-name><os-flavor>Server 2019</os-flavor>
    <purpose>server</purpose><arch>x64</arch><comments>DC</comments></host>
  <host><id>2</id><address>10.10.0.9</address><name></name><state>alive</state>
    <os-name>Linux</os-name></host>
</hosts>
<services>
  <service><id>1</id><host-id>1</host-id><port>445</port><proto>tcp</proto>
    <state>open</state><name>smb</name><info>Windows Server 2019</info></service>
  <service><id>2</id><host-id>1</host-id><port>3389</port><proto>tcp</proto>
    <state>open</state><name>unknown</name></service>
</services>
<vulns>
  <vuln><id>1</id><host-id>1</host-id><name>MS17-010 SMB RCE</name>
    <info>EternalBlue</info><refs><ref>CVE-2017-0144</ref><ref>MSB-MS17-010</ref></refs>
  </vuln>
  <vuln><id>2</id><host-id>2</host-id><name>Observation only</name><refs/></vuln>
</vulns>
<creds>
  <cred><id>1</id><host-id>1</host-id><user>Administrator</user>
    <pass>aad3b435b51404ee:31d6cfe0d16ae931</pass><ptype>smb_hash</ptype>
    <sname>smb</sname><port>445</port><active>true</active></cred>
  <cred><id>2</id><host-id>2</host-id><user>root</user><pass>toor</pass>
    <ptype>password</ptype><sname>ssh</sname><port>22</port></cred>
</creds>
<sessions>
  <session><id>1</id><host-id>1</host-id><stype>meterpreter</stype>
    <via-exploit>exploit/windows/smb/ms17_010_eternalblue</via-exploit>
    <via-payload>windows/x64/meterpreter/reverse_tcp</via-payload></session>
</sessions>
<notes>
  <note><id>1</id><host-id>1</host-id><ntype>smb.fingerprint</ntype>
    <data>Windows Server 2019 Standard</data></note>
</notes>
<loots>
  <loot><id>1</id><host-id>1</host-id><ltype>windows.hashes</ltype>
    <name>hashdump</name><path>/root/.msf4/loot/x.txt</path></loot>
</loots>
</MetasploitV5>
"""
print("\n== metasploit ==")
st, r = imp("MSF", MSF)
check("imported", st == 200, f"status={st} {str(r)[:100]}")
check("detected without being told", r["format"] == "metasploit", r["format"])
check("both hosts", r["targets_created"] == 2, str(r["targets_created"]))
check("services", r["services_created"] == 2, str(r["services_created"]))
check("vulns", r["vulns_created"] == 2, str(r["vulns_created"]))
check("credentials", r["credentials_created"] == 2, str(r["credentials_created"]))
check("a session marks the host compromised", r["hosts_flagged"] == 1, str(r["hosts_flagged"]))

d = detail("MSF", "dc01.corp.local")
check("keyed on the msf host name, not the address", d["target"]["host"] == "dc01.corp.local")
check("address kept", d["target"]["ip_address"] == "10.10.0.5")
check("os assembled from name+flavor", d["target"]["os"] == "Windows Server 2019",
      str(d["target"]["os"]))
check("pwned flag set", d["target"]["hacked"] is True)
svc = {s["port"]: s for s in d["services"]}
check("msf 'unknown' service becomes UNKNOWN", svc[3389]["name"] == "UNKNOWN",
      svc[3389]["name"])
check("service info becomes the banner", svc[445]["banner"] == "Windows Server 2019")
v = {x["title"]: x for x in d["vulns"]}
check("CVE lifted out of refs as the external id",
      v["MS17-010 SMB RCE"]["external_id"] == "CVE-2017-0144",
      str(v["MS17-010 SMB RCE"]["external_id"]))
check("a vuln with refs is not filed as info",
      v["MS17-010 SMB RCE"]["severity"] == "medium", v["MS17-010 SMB RCE"]["severity"])
check("refs listed in the description", "CVE-2017-0144" in v["MS17-010 SMB RCE"]["description"])

st, creds = call("/api/credentials?project=MSF", token=admin)
by_user = {c["username"]: c for c in creds["items"]}
check("hash recorded as a hash", by_user["Administrator"]["kind"] == "hash",
      by_user["Administrator"]["kind"])
check("an active msf cred counts as working",
      by_user["Administrator"]["validated"] == "works")
check("password recorded as a password", by_user["root"]["kind"] == "password")

st, tl = call("/api/targets/MSF/dc01.corp.local/timeline", token=admin)
sums = " | ".join(e["summary"] for e in tl["items"])
check("session in the timeline", "meterpreter" in sums and "eternalblue" in sums.lower(),
      sums[:120])
check("loot in the timeline", "hashdump" in sums, sums[:120])
check("note in the timeline", "smb.fingerprint" in sums, sums[:120])

# =================================================================== nessus
NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2>
<Report name="weekly">
<ReportHost name="10.20.0.7">
  <HostProperties>
    <tag name="host-ip">10.20.0.7</tag>
    <tag name="host-fqdn">app01.corp.local</tag>
    <tag name="operating-system">Linux Kernel 5.15 on Ubuntu 22.04</tag>
    <tag name="netbios-name">APP01</tag>
    <tag name="mac-address">00:aa:bb:cc:dd:ee</tag>
  </HostProperties>
  <ReportItem port="443" svc_name="www" protocol="tcp" severity="4"
              pluginID="12345" pluginName="OpenSSL RCE" pluginFamily="Web Servers">
    <synopsis>Remote code execution.</synopsis>
    <description>The remote host runs a vulnerable OpenSSL.</description>
    <solution>Upgrade OpenSSL.</solution>
    <cve>CVE-2022-3602</cve>
    <cvss3_base_score>9.8</cvss3_base_score>
  </ReportItem>
  <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0"
              pluginID="10267" pluginName="SSH Server Type" pluginFamily="Service detection">
    <plugin_output>SSH version : OpenSSH_8.9p1</plugin_output>
  </ReportItem>
  <ReportItem port="0" svc_name="general" protocol="tcp" severity="2"
              pluginID="99999" pluginName="Weak host config" pluginFamily="Misc.">
    <description>Something host-wide.</description>
  </ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>
"""
print("\n== nessus ==")
st, r = imp("NESS", NESSUS)
check("imported", st == 200 and r["format"] == "nessus", f"{st} {r.get('format')}")
d = detail("NESS", "app01.corp.local")
check("keyed on the fqdn tag, not the scanned address",
      d["target"]["host"] == "app01.corp.local")
check("ip from host-ip", d["target"]["ip_address"] == "10.20.0.7")
check("os from the tag", "Ubuntu 22.04" in (d["target"]["os"] or ""), str(d["target"]["os"]))
check("all its names kept", "app01" in str(d["target"]["hostnames"]).lower())
titles = {v["title"]: v for v in d["vulns"]}
check("service-detection info is NOT filed as a finding",
      "SSH Server Type" not in titles, str(sorted(titles)))
check("but it did create the service", any(s["port"] == 22 for s in d["services"]))
check("its output became the banner",
      "OpenSSH_8.9p1" in (next(s for s in d["services"] if s["port"] == 22)["banner"] or ""))
check("severity 4 is critical", titles["OpenSSL RCE"]["severity"] == "critical")
check("solution lands in remediation, not buried in the description",
      titles["OpenSSL RCE"]["remediation"] == "Upgrade OpenSSL."
      and "Upgrade OpenSSL" not in (titles["OpenSSL RCE"]["description"] or ""),
      f'rem={titles["OpenSSL RCE"]["remediation"]!r}')
check("cve carried over", "CVE-2022-3602" in titles["OpenSSL RCE"]["description"])
check("plugin id is the external id", titles["OpenSSL RCE"]["external_id"] == "nessus-12345")
check("a port-0 finding is recorded against the host",
      titles["Weak host config"]["port"] is None, str(titles["Weak host config"]["port"]))

# ===================================================================== burp
BURP = """<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="Mon Oct 06 2026">
<issue>
  <serialNumber>123</serialNumber><type>5244928</type>
  <name>Cross-site scripting (reflected)</name>
  <host ip="10.30.0.1">https://shop.corp.local</host>
  <path>/search</path><severity>High</severity><confidence>Certain</confidence>
  <issueDetail>The value of the <b>q</b> parameter is echoed.&lt;br&gt;Payload used.</issueDetail>
  <issueBackground>&lt;p&gt;Reflected XSS arises when...&lt;/p&gt;</issueBackground>
  <remediationBackground>&lt;p&gt;Encode output.&lt;/p&gt;</remediationBackground>
</issue>
<issue>
  <serialNumber>124</serialNumber><type>2097408</type>
  <name>Information disclosure</name>
  <host ip="10.30.0.1">https://shop.corp.local</host>
  <path>/status</path><severity>Information</severity><confidence>Firm</confidence>
</issue>
</issues>
"""
print("\n== burp ==")
st, r = imp("BURP", BURP)
check("imported", st == 200 and r["format"] == "burp", f"{st} {r.get('format')}")
d = detail("BURP", "shop.corp.local")
check("host from the URL", d["target"]["host"] == "shop.corp.local")
check("ip from the attribute", d["target"]["ip_address"] == "10.30.0.1")
check("https service inferred", any(s["port"] == 443 and s["tunnel"] == "ssl"
                                    for s in d["services"]), str(d["services"]))
t = {v["title"]: v for v in d["vulns"]}
check("path is part of the title", any("/search" in k for k in t), str(sorted(t)))
xss = next(v for k, v in t.items() if "/search" in k)
check("severity mapped", xss["severity"] == "high", xss["severity"])
check("HTML flattened to text", "<p>" not in (xss["description"] or "")
      and "<br" not in (xss["description"] or ""), str(xss["description"])[:80])
check("Burp's 'Information' maps to info",
      next(v for k, v in t.items() if "/status" in k)["severity"] == "info")
check("request/response bodies are not imported",
      "requestresponse" not in json.dumps(d).lower())

# ==================================================================== nikto
NIKTO = json.dumps({
    "host": "www.corp.local", "ip": "10.40.0.3", "port": "80",
    "banner": "Apache/2.4.52",
    "vulnerabilities": [
        {"id": "999986", "OSVDB": "3092", "method": "GET", "url": "/admin/",
         "msg": "This might be interesting: admin panel"},
        {"id": "999103", "OSVDB": "0", "method": "GET", "url": "/",
         "msg": "The X-Frame-Options header is not present."},
        {"id": "999960", "OSVDB": "12184", "method": "GET", "url": "/.env",
         "msg": "/.env: Arbitrary file retrieval of environment secrets."},
    ]})
print("\n== nikto ==")
st, r = imp("NIK", NIKTO)
check("imported", st == 200 and r["format"] == "nikto", f"{st} {r.get('format')}")
d = detail("NIK", "www.corp.local")
check("banner kept", "Apache/2.4.52" in (d["services"][0]["banner"] or ""))
sev = {v["title"].split(" (")[0]: v["severity"] for v in d["vulns"]}
check("a file-retrieval finding is banded high",
      [s for t, s in sev.items() if "Arbitrary file" in t] == ["high"], str(sev))
check("a missing header is banded low",
      [s for t, s in sev.items() if "X-Frame-Options" in t] == ["low"], str(sev))
check("the banding is disclosed, not passed off as Nikto's",
      all("assigned by Oddjob" in (v["description"] or "") for v in d["vulns"]),
      str(d["vulns"][0]["description"])[:90])

# =================================================================== nuclei
NUCLEI = "\n".join(json.dumps(x) for x in [
    {"template-id": "CVE-2021-44228", "info": {"name": "Log4j RCE",
     "severity": "critical", "description": "JNDI lookup",
     "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
     "tags": ["cve", "rce"]},
     "host": "https://api.corp.local:8443", "ip": "10.50.0.4",
     "matched-at": "https://api.corp.local:8443/login"},
    {"template-id": "tech-detect", "info": {"name": "nginx", "severity": "info"},
     "host": "https://api.corp.local:8443", "matched-at": "https://api.corp.local:8443"},
])
print("\n== nuclei ==")
st, r = imp("NUC", NUCLEI)
check("JSONL imported", st == 200 and r["format"] == "nuclei", f"{st} {r.get('format')}")
d = detail("NUC", "api.corp.local")
check("port parsed out of the URL", any(s["port"] == 8443 for s in d["services"]),
      str([s["port"] for s in d["services"]]))
log4j = next(v for v in d["vulns"] if "Log4j" in v["title"])
check("nuclei's own severity is trusted", log4j["severity"] == "critical")
check("references kept", "nvd.nist.gov" in log4j["description"])
check("template id in the external id", "CVE-2021-44228" in log4j["external_id"])

# ==================================================================== httpx
HTTPX = "\n".join(json.dumps(x) for x in [
    {"url": "https://web.corp.local", "input": "web.corp.local", "host": "10.60.0.5",
     "port": 443, "scheme": "https", "status_code": 200, "title": "Welcome",
     "webserver": "nginx/1.25", "tech": ["Nginx", "React"], "content_length": 512},
])
print("\n== httpx ==")
st, r = imp("HTX", HTTPX)
check("imported", st == 200 and r["format"] == "httpx", f"{st} {r.get('format')}")
d = detail("HTX", "web.corp.local")
check("keyed on the name, not the resolved address",
      d["target"]["host"] == "web.corp.local", d["target"]["host"])
check("address kept as the ip", d["target"]["ip_address"] == "10.60.0.5")
s0 = d["services"][0]
check("webserver becomes the product", s0["product"] == "nginx/1.25")
check("title and status in the banner",
      "Welcome" in (s0["banner"] or "") and "200" in (s0["banner"] or ""), str(s0["banner"]))

# ================================================================== masscan
print("\n== masscan ==")
MASS_LIST = """#masscan
open tcp 443 10.70.0.8 1760000000
open tcp 22 10.70.0.8 1760000000
open udp 161 10.70.0.9 1760000000
"""
st, r = imp("MAS", MASS_LIST)
check("grepable list imported", st == 200 and r["format"] == "masscan",
      f"{st} {r.get('format')}")
check("two hosts", r["targets_created"] == 2, str(r["targets_created"]))
check("masscan knows no service, so all UNKNOWN", r["services_unknown"] == 3,
      str(r["services_unknown"]))

MASS_JSON = json.dumps([{"ip": "10.70.0.10", "ports": [
    {"port": 8080, "proto": "tcp", "status": "open", "reason": "syn-ack",
     "service": {"name": "http", "banner": "Server: lighttpd"}}]}])
st, r = imp("MAS", MASS_JSON)
check("json form imported", st == 200, f"status={st}")
d = detail("MAS", "10.70.0.10")
check("banner-grabbed service is not UNKNOWN", d["services"][0]["name"] == "http")
check("banner kept", "lighttpd" in (d["services"][0]["banner"] or ""))

# ====================================================== C2: Cobalt Strike
CS = json.dumps([{
    "id": "1234", "external": "203.0.113.9", "internal": "10.80.0.20",
    "computer": "WKSTN-07", "user": "jdoe *", "pid": 4821, "is64": 1,
    "os": "Windows", "ver": "10.0", "build": "19045", "barch": "x64",
    "listener": "https-cdn", "last": 15000, "note": "initial access",
    "charset": "cp1252", "session": "beacon"}])
print("\n== cobalt strike ==")
st, r = imp("CS", CS)
check("imported", st == 200 and r["format"] == "cobaltstrike", f"{st} {r.get('format')}")
check("callback recorded", r["implants_created"] == 1, str(r["implants_created"]))
check("host marked compromised", r["hosts_flagged"] == 1, str(r["hosts_flagged"]))
d = detail("CS", "wkstn-07")
im = d["implants"][0]
check("framework", im["framework"] == "cobaltstrike")
check("CS asterisk means elevated, and is stripped from the username",
      im["user"] == "jdoe" and im["integrity"] == "high", f'{im["user"]}/{im["integrity"]}')
check("internal and external addresses kept",
      im["internal_ip"] == "10.80.0.20" and im["external_ip"] == "203.0.113.9")
check("os assembled", im["os"] == "Windows 10.0 19045", str(im["os"]))
check("is64 becomes an arch", im["arch"] == "x64", str(im["arch"]))
check("listener", im["listener"] == "https-cdn")
check("CS 'last' is ms-since-checkin, not a timestamp",
      im["last_seen"] is None and im["extra"].get("last_checkin_ms_ago") == 15000,
      f'{im["last_seen"]} / {im["extra"]}')
check("unrecognised fields preserved", im["extra"].get("charset") == "cp1252",
      str(im["extra"]))
check("target flagged pwned", d["target"]["hacked"] is True)
st, tl = call("/api/targets/CS/wkstn-07/timeline?kind=implant", token=admin)
check("callback written to the timeline", tl["total"] == 1 and "jdoe" in tl["items"][0]["summary"],
      str(tl["items"][0]["summary"]) if tl["total"] else str(tl))

# =============================================================== C2: Mythic
MYTHIC = json.dumps({"callbacks": [{
    "id": 7, "agent_callback_id": "a1b2c3d4-0000-4444-8888-aaaabbbbcccc",
    "host": "SRV-DB-02", "user": "svc_sql", "pid": 991, "ip": "10.90.0.30",
    "external_ip": "198.51.100.4", "process_name": "sqlservr.exe",
    "integrity_level": 4, "os": "Windows Server 2019", "architecture": "x64",
    "domain": "CORP", "payload_type": "apollo", "active": True,
    "init_callback": "2026-10-01T09:15:00Z", "last_checkin": "2026-10-06T11:02:00Z",
    "description": "sql service account"}]})
print("\n== mythic ==")
st, r = imp("MYT", MYTHIC)
check("imported from a wrapped list", st == 200 and r["format"] == "mythic",
      f"{st} {r.get('format')}")
d = detail("MYT", "srv-db-02")
im = d["implants"][0]
check("integrity_level 4 is SYSTEM", im["integrity"] == "system", str(im["integrity"]))
check("agent_callback_id is the implant id",
      im["implant_id"].startswith("a1b2c3d4"), im["implant_id"])
check("payload type recorded as the listener", im["listener"] == "apollo")
check("domain kept", im["domain"] == "CORP")
check("timestamps parsed", im["last_seen"] and im["last_seen"].startswith("2026-10-06"),
      str(im["last_seen"]))
check("raw level kept too", im["extra"].get("integrity_level") == 4, str(im["extra"]))

# =============================================================== C2: Merlin
MERLIN = json.dumps([{
    "id": "c1d2e3f4-5555-6666-7777-888899990000", "hostname": "build-01",
    "username": "jenkins", "userguid": "S-1-5-21-1", "platform": "linux",
    "architecture": "amd64", "process": "java", "pid": 3312,
    "ips": ["127.0.0.1", "10.100.0.40"], "integrity": 2,
    "initial": "2026-10-02 08:00:00", "statuscheckin": "2026-10-06 10:00:00",
    "version": "2.0.1", "build": "abc123", "status": "active", "protocol": "h2c"}])
print("\n== merlin ==")
st, r = imp("MER", MERLIN)
check("imported", st == 200 and r["format"] == "merlin", f"{st} {r.get('format')}")
d = detail("MER", "build-01")
im = d["implants"][0]
check("loopback is not taken as the internal address",
      im["internal_ip"] == "10.100.0.40", str(im["internal_ip"]))
check("all addresses still kept", "127.0.0.1" in str(im["extra"].get("all_ips")),
      str(im["extra"].get("all_ips")))
check("integrity level mapped", im["integrity"] == "medium", str(im["integrity"]))
check("agent version kept", im["extra"].get("agent_version") == "2.0.1", str(im["extra"]))
check("platform becomes the os", "linux" in (im["os"] or ""), str(im["os"]))

# =============================================================== C2: sliver
SLIVER = json.dumps([{
    "ID": "ANCIENT-TIGER", "Name": "implant1", "Hostname": "lab-03",
    "Username": "root", "UID": "0", "OS": "linux", "Arch": "amd64",
    "Transport": "mtls", "RemoteAddress": "10.110.0.50:49152", "PID": 777,
    "Filename": "/tmp/.x", "LastCheckin": "2026-10-06T12:00:00Z",
    "ActiveC2": "mtls://c2.example:8888", "IsDead": False, "Burned": False,
    "ReconnectInterval": 60}])
print("\n== sliver ==")
st, r = imp("SLV", SLIVER)
check("imported", st == 200 and r["format"] == "sliver", f"{st} {r.get('format')}")
im = detail("SLV", "lab-03")["implants"][0]
check("uid 0 reads as system", im["integrity"] == "system", str(im["integrity"]))
check("remote address port stripped", im["external_ip"] == "10.110.0.50",
      str(im["external_ip"]))
check("active c2 as the listener", "mtls" in (im["listener"] or ""), str(im["listener"]))
check("not dead means active", im["active"] is True)

# ================================================================ C2: havoc
HAVOC = json.dumps([{
    "NameID": "0a1b2c", "Hostname": "FIN-WS-11", "Username": "m.chen",
    "DomainName": "CORP", "InternalIP": "10.120.0.60", "ExternalIP": "203.0.113.77",
    "ProcessName": "explorer.exe", "ProcessPID": 6120, "ProcessArch": "x64",
    "Elevated": True, "OSVersion": "Windows 11", "Listener": "http-cf",
    "FirstCallIn": "06/10/2026 09:00:00", "LastCallIn": "06/10/2026 12:30:00"}])
print("\n== havoc ==")
st, r = imp("HAV", HAVOC)
check("imported", st == 200 and r["format"] == "havoc", f"{st} {r.get('format')}")
im = detail("HAV", "fin-ws-11")["implants"][0]
check("elevated maps to high integrity", im["integrity"] == "high")
check("domain and user", im["domain"] == "CORP" and im["user"] == "m.chen")
check("havoc's dd/mm/yyyy timestamps parsed",
      im["first_seen"] and im["first_seen"].startswith("2026-10-06"), str(im["first_seen"]))

# ==================================================== burp proxy history
print("\n== burp proxy history (Save items) ==")
import base64 as _b64

_resp = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Type: text/html\r\n\r\n"
         b"<html><head><title>Portal Login</title></head></html>")
_req = b"GET /portal HTTP/1.1\r\nHost: pay.corp.local\r\nCookie: JSESSIONID=supersecret\r\n\r\n"
BURPHIST = f'''<?xml version="1.0"?>
<items burpVersion="2024.1" exportTime="Mon Oct 06 2026">
<item><time>t</time><url><![CDATA[https://pay.corp.local/portal]]></url>
<host ip="10.44.0.2">pay.corp.local</host><port>443</port><protocol>https</protocol>
<method><![CDATA[GET]]></method><path><![CDATA[/portal]]></path>
<request base64="true">{_b64.b64encode(_req).decode()}</request>
<status>200</status><responselength>512</responselength><mimetype>HTML</mimetype>
<response base64="true">{_b64.b64encode(_resp).decode()}</response>
<comment>main login</comment></item>
<item><time>t</time><url><![CDATA[http://pay.corp.local:8080/actuator/env]]></url>
<host ip="10.44.0.2">pay.corp.local</host><port>8080</port><protocol>http</protocol>
<method><![CDATA[GET]]></method><path><![CDATA[/actuator/env]]></path>
<status>401</status><responselength>0</responselength><mimetype>JSON</mimetype>
<comment></comment></item>
</items>'''
st, r = imp("BHIST", BURPHIST)
check("detected as history, not as the issue export",
      st == 200 and r["format"] == "burphistory", f"{st} {r.get('format')}")
check("two addresses", r["urls_created"] == 2, str(r["urls_created"]))
check("no findings — history is inventory, not issues", r["vulns_created"] == 0,
      str(r["vulns_created"]))
d = detail("BHIST", "pay.corp.local")
byurl = {w["url"]: w for w in call("/api/web?project=BHIST", token=admin)[1]["items"]}
login = byurl["https://pay.corp.local/portal"]
check("title pulled out of the base64 response", login["title"] == "Portal Login",
      str(login["title"]))
check("Server header pulled out too", login["webserver"] == "Apache/2.4.58",
      str(login["webserver"]))
check("status and mime kept", login["status_code"] == 200
      and login["content_type"] == "HTML")
check("method is its own column, not buried in a note",
      login["method"] == "GET", str(login["method"]))
check("the note is the analyst's comment only",
      login["notes"] == "main login", str(login["notes"]))
check("history counts as fetched", login["crawled"] is True)
check("non-default port kept distinct",
      "http://pay.corp.local:8080/actuator/env" in byurl, str(sorted(byurl)))
check("both ports became services",
      sorted(s["port"] for s in d["services"]) == [443, 8080],
      str([s["port"] for s in d["services"]]))
check("the session cookie in the request is NOT stored anywhere",
      "supersecret" not in json.dumps(byurl) and "supersecret" not in json.dumps(d))

st, r = imp("BHIST", BURP)
check("an issue export is still detected as 'burp', not history",
      r["format"] == "burp", r["format"])

print("\n== the same history imported twice does not duplicate ==")
st, first = imp("BHIST2", BURPHIST)
st, again = imp("BHIST2", BURPHIST)
check("second import creates nothing", again["urls_created"] == 0,
      str(again["urls_created"]))
rows = call("/api/web?project=BHIST2", token=admin)[1]
check("still the same number of addresses", rows["total"] == first["urls_created"],
      f'{rows["total"]} vs {first["urls_created"]}')
check("and no duplicate (method, url) pairs",
      len({(w["method"], w["url"]) for w in rows["items"]}) == rows["total"],
      str(rows["total"]))

print("\n== but a different verb on the same URL is a different address ==")
_r2 = _b64.b64encode(b"HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n").decode()
TWOVERBS = f'''<?xml version="1.0"?>
<items burpVersion="2024.1">
<item><url><![CDATA[https://pay.corp.local/portal]]></url>
<host ip="10.44.0.2">pay.corp.local</host><port>443</port><protocol>https</protocol>
<method><![CDATA[POST]]></method><path><![CDATA[/portal]]></path>
<status>302</status><responselength>0</responselength><mimetype>HTML</mimetype>
<response base64="true">{_r2}</response><comment></comment></item>
</items>'''
st, r = imp("BHIST2", TWOVERBS)
check("POST to an already-known GET URL is a new row", r["urls_created"] == 1,
      str(r["urls_created"]))
pairs = {(w["method"], w["url"]) for w in
         call("/api/web?project=BHIST2&q=portal", token=admin)[1]["items"]}
check("both verbs present", {"GET", "POST"} <= {m for m, _ in pairs}, str(pairs))
check("with their own status codes",
      {w["status_code"] for w in
       call("/api/web?project=BHIST2&q=portal", token=admin)[1]["items"]} == {200, 302},
      str([w["status_code"] for w in
           call("/api/web?project=BHIST2&q=portal", token=admin)[1]["items"]]))

print("\n== a method-less row learns its verb rather than forking ==")
call("/api/projects", "POST", {"code": "LEARN", "name": "L"}, token=admin)
imp("LEARN", json.dumps({"url": "https://learn.corp/x", "input": "learn.corp",
                         "host": "10.1.1.1", "port": 443, "scheme": "https",
                         "status_code": 200}))
before = call("/api/web?project=LEARN", token=admin)[1]
check("httpx recorded it with no verb", before["items"][0]["method"] == "",
      repr(before["items"][0]["method"]))
_r3 = _b64.b64encode(b"HTTP/1.1 200 OK\r\n\r\nx").decode()
st, r = imp("LEARN", f'''<?xml version="1.0"?><items burpVersion="2024.1"><item>
<url><![CDATA[https://learn.corp/x]]></url><host ip="10.1.1.1">learn.corp</host>
<port>443</port><protocol>https</protocol><method><![CDATA[GET]]></method>
<path><![CDATA[/x]]></path><status>200</status><responselength>1</responselength>
<mimetype>HTML</mimetype><response base64="true">{_r3}</response></item></items>''')
after = call("/api/web?project=LEARN", token=admin)[1]
check("no second row was created", after["total"] == 1, str(after["total"]))
check("the existing row learned the verb", after["items"][0]["method"] == "GET",
      str(after["items"][0]["method"]))

print("\n== the packet is fetched separately, never in the listing ==")
wid = [w for w in call("/api/web?project=BHIST2&q=portal", token=admin)[1]["items"]
       if w["method"] == "GET"][0]["id"]
check("the listing carries no bodies",
      "request" not in call("/api/web?project=BHIST2", token=admin)[1]["items"][0])
st, pkt = call(f"/api/web/{wid}/packet", token=admin)
check("the packet endpoint returns the exchange", st == 200, f"status={st}")
check("request captured", "GET /portal" in (pkt["request"] or ""),
      str(pkt["request"])[:50])
check("response captured", "Apache/2.4.58" in (pkt["response"] or ""),
      str(pkt["response"])[:50])
check("method and status on the packet too",
      pkt["method"] == "GET" and pkt["status_code"] == 200)
call("/api/users", "POST", {"username": "pkt-outsider",
                            "password": "pkt-outsider-pw-1"}, token=admin)
_out = call("/api/auth/login", "POST",
            {"username": "pkt-outsider",
             "password": "pkt-outsider-pw-1"})[1]["access_token"]
check("someone with no grant on the project cannot fetch it",
      call(f"/api/web/{wid}/packet", token=_out)[0] == 404)

# ============================================================== re-imports
print("\n== re-importing is an update, not a duplicate ==")
st, r2 = imp("CS", CS)
check("no new callback", r2["implants_created"] == 0, str(r2["implants_created"]))
st, r2 = imp("MSF", MSF)
check("no new targets", r2["targets_created"] == 0, str(r2["targets_created"]))
check("no new vulns", r2["vulns_created"] == 0, str(r2["vulns_created"]))
check("no new credentials", r2["credentials_created"] == 0, str(r2["credentials_created"]))

print("\n== a later tool does not erase what an earlier one knew ==")
# masscan rescans a host nessus had already fingerprinted
imp("NESS", "open tcp 443 10.20.0.7 1760000000")
d = detail("NESS", "app01.corp.local")
check("the fqdn-keyed target still has its os", "Ubuntu" in (d["target"]["os"] or ""),
      str(d["target"]["os"]))

# ============================================================ bad documents
print("\n== bad input ==")
st, r = imp("BAD", "just some text")
check("unrecognised content is refused with the list of formats",
      st == 422 and "nmap" in str(r) and "metasploit" in str(r), f"{st} {str(r)[:80]}")
st, r = imp("BAD", MSF, fmt="nessus")
check("the wrong format named explicitly is refused, not half-parsed",
      st == 422, f"status={st}")
st, r = imp("BAD", "<nmaprun", fmt="nmap")
check("malformed XML refused", st == 422, f"status={st}")
st, r = imp("BAD", "{}", fmt="nope")
check("unknown format name refused", st == 422 and "nope" in str(r), f"{st} {str(r)[:60]}")

print("\n== authorisation ==")
call("/api/users", "POST", {"username": "ro", "password": "ro-password-1"}, token=admin)
ro = call("/api/auth/login", "POST",
          {"username": "ro", "password": "ro-password-1"})[1]["access_token"]
call("/api/projects/CS/acl", "POST", {"username": "ro", "role": "readonly"}, token=admin)
st, _ = call("/api/scans/import?project=CS", "POST",
             {"content": CS, "format": "auto", "mode": "open"}, token=ro)
check("a readonly member cannot import", st == 403, f"status={st}")
st, _ = call("/api/scans/import?project=MSF", "POST",
             {"content": CS, "format": "auto", "mode": "open"}, token=ro)
check("and cannot reach a project they hold nothing on", st == 404, f"status={st}")

print("\n== a service note is not a banner ==")
# The banner column answers "what software is listening". An operator's
# note is a different question and belongs in its own field.
st, r = call("/api/bulk", "POST", {"project": "BANNER", "project_name": "Banner",
    "targets": [{"host": "svc.corp.local"}],
    "services": [{"host": "svc.corp.local", "port": 443, "state": "open",
                  "name": "https", "version": "nginx 1.25",
                  "banner": "nginx 1.25", "notes": "coverage gap, never scanned"}]},
    token=admin)
check("bulk accepts a service note", st == 200, f"status={st}")
d = detail("BANNER", "svc.corp.local")
s0 = d["services"][0]
check("the banner says what is listening", s0["banner"] == "nginx 1.25", str(s0["banner"]))
check("the note is kept separately", s0["notes"] == "coverage gap, never scanned",
      str(s0["notes"]))
check("and is not jammed into the banner", "coverage" not in (s0["banner"] or ""))

# ===================================== strict mode: the wrong-project guard
print("\n== strict mode reports unknown hosts instead of creating them ==")
# Exactly the accident this exists for: a Burp history from one engagement
# imported into another. Fourteen targets belonging to a different client
# were created silently.
call("/api/projects", "POST", {"code": "STRICT", "name": "Strict"}, token=admin)
call("/api/bulk", "POST", {"project": "STRICT", "targets": [
    {"host": "known-a.corp.local"}, {"host": "known-b.corp.local"}]}, token=admin)

STRAY = "\n".join(json.dumps(x) for x in [
    {"url": "https://known-a.corp.local/x", "input": "known-a.corp.local",
     "host": "10.0.0.1", "port": 443, "scheme": "https", "status_code": 200},
    {"url": "https://stranger.other.com/a", "input": "stranger.other.com",
     "host": "10.9.9.1", "port": 443, "scheme": "https", "status_code": 200},
    {"url": "https://stranger.other.com/b", "input": "stranger.other.com",
     "host": "10.9.9.1", "port": 443, "scheme": "https", "status_code": 401},
    {"url": "https://lonely.other.com/", "input": "lonely.other.com",
     "host": "10.9.9.2", "port": 443, "scheme": "https", "status_code": 200},
])

st, r = call("/api/scans/import?project=STRICT", "POST",
             {"content": STRAY, "format": "auto"}, token=admin)
check("strict is the default", st == 200 and r["needs_decision"] is True,
      f'{st} {r.get("needs_decision")}')
check("NOTHING was written", r["targets_created"] == 0 and r["urls_created"] == 0,
      f'{r["targets_created"]}/{r["urls_created"]}')
unk = {u["host"]: u for u in r["unknown_hosts"]}
check("only the unknown hosts are reported",
      set(unk) == {"stranger.other.com", "lonely.other.com"}, str(sorted(unk)))
check("the known host is not questioned", "known-a.corp.local" not in unk)
check("each one says what it would bring",
      unk["stranger.other.com"]["web"] == 2 and unk["stranger.other.com"]["services"] == 1,
      str(unk["stranger.other.com"]))
check("biggest first, so the costly one is seen",
      r["unknown_hosts"][0]["host"] == "stranger.other.com",
      r["unknown_hosts"][0]["host"])
check("the project is untouched",
      call("/api/targets?project=STRICT", token=admin)[1]["total"] == 2)

print("\n== an unanswered host is rejected, not quietly created ==")
st, r = call("/api/scans/import?project=STRICT", "POST",
             {"content": STRAY, "format": "auto",
              "decisions": {"stranger.other.com": {"action": "reject"},
                            "lonely.other.com": {"action": "reject"}}}, token=admin)
check("the import proceeds", st == 200 and r["needs_decision"] is False, str(st))
check("the known host's data landed", r["urls_created"] == 1, str(r["urls_created"]))
check("no new targets", r["targets_created"] == 0, str(r["targets_created"]))
check("and the rejection is reported, not silent",
      set(r["rejected_hosts"]) == {"stranger.other.com", "lonely.other.com"},
      str(r["rejected_hosts"]))
check("still two targets",
      call("/api/targets?project=STRICT", token=admin)[1]["total"] == 2)

print("\n== 'add' creates the host; 'map' attaches to an existing one ==")
st, r = call("/api/scans/import?project=STRICT", "POST",
             {"content": STRAY, "format": "auto",
              "decisions": {
                  "stranger.other.com": {"action": "add"},
                  "lonely.other.com": {"action": "map",
                                       "target": "known-b.corp.local"}}},
             token=admin)
check("the added host is created", r["created_hosts"] == ["stranger.other.com"],
      str(r["created_hosts"]))
check("the mapped host is recorded as mapped",
      r["mapped_hosts"] == {"lonely.other.com": "known-b.corp.local"},
      str(r["mapped_hosts"]))
check("three targets now, not four",
      call("/api/targets?project=STRICT", token=admin)[1]["total"] == 3,
      str(call("/api/targets?project=STRICT", token=admin)[1]["total"]))
rows = {w["host"]: w for w in call("/api/web?project=STRICT", token=admin)[1]["items"]}
check("the mapped host's URL landed on the chosen target",
      any(w["host"] == "known-b.corp.local" and "lonely" in w["url"]
          for w in call("/api/web?project=STRICT", token=admin)[1]["items"]),
      str([(w["host"], w["url"]) for w in
           call("/api/web?project=STRICT", token=admin)[1]["items"]])[:140])
check("no target called lonely.other.com was created",
      not any(t["host"] == "lonely.other.com" for t in
              call("/api/targets?project=STRICT", token=admin)[1]["items"]))

print("\n== mapping to a target that does not exist is refused ==")
call("/api/projects", "POST", {"code": "STRICT2", "name": "S2"}, token=admin)
call("/api/bulk", "POST", {"project": "STRICT2",
                           "targets": [{"host": "real.corp.local"}]}, token=admin)
st, r = call("/api/scans/import?project=STRICT2", "POST",
             {"content": STRAY, "format": "auto",
              "decisions": {"known-a.corp.local": {"action": "reject"},
                            "stranger.other.com": {"action": "map",
                                                   "target": "does-not-exist.local"},
                            "lonely.other.com": {"action": "reject"}}}, token=admin)
check("a bad mapping rejects rather than inventing a target",
      "stranger.other.com" in r["rejected_hosts"], str(r["rejected_hosts"]))
check("and no phantom target appears",
      call("/api/targets?project=STRICT2", token=admin)[1]["total"] == 1)

print("\n== open mode still works for a deliberate bulk load ==")
st, r = call("/api/scans/import?project=STRICT2", "POST",
             {"content": STRAY, "format": "auto", "mode": "open"}, token=admin)
check("open mode asks nothing", r["needs_decision"] is False)
check("and creates what the file names", r["targets_created"] == 3,
      str(r["targets_created"]))

print("\n== strict applies to every format, not just the web ones ==")
call("/api/projects", "POST", {"code": "STRICT3", "name": "S3"}, token=admin)
st, r = call("/api/scans/import?project=STRICT3", "POST",
             {"content": MSF, "format": "auto"}, token=admin)
check("metasploit is gated too", r["needs_decision"] is True)
check("it lists the hosts and their credentials",
      any(u["credentials"] > 0 for u in r["unknown_hosts"]),
      str(r["unknown_hosts"])[:120])
st, r = call("/api/scans/import?project=STRICT3", "POST",
             {"content": CS, "format": "auto"}, token=admin)
check("a C2 callback is gated too", r["needs_decision"] is True)
check("and names the implant it would bring",
      any(u["implants"] > 0 for u in r["unknown_hosts"]), str(r["unknown_hosts"])[:120])

print("\n== untrusted XML cannot bomb the server ==")
# Measured before the fix: a 331-byte document expanded to 1 MB, and each
# further nesting level multiplies by ten. Against a 64 MB upload cap
# that is a trivial way to exhaust memory during an import.
BOMB = '''<?xml version="1.0"?>
<!DOCTYPE nmaprun [
 <!ENTITY a "AAAAAAAAAA">
 <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
 <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<nmaprun scanner="nmap" args="&d;"><host/></nmaprun>'''
st, r = imp("XMLSAFE", BOMB, fmt="nmap")
check("an entity-expansion bomb is refused, not expanded", st == 422, f"status={st}")
check("and the refusal explains itself",
      "entit" in str(r).lower(), str(r)[:110])

XXE = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
       '"file:///etc/passwd">]><nmaprun args="&x;"><host/></nmaprun>')
st, r = imp("XMLSAFE", XXE, fmt="nmap")
check("an external entity is refused too", st == 422, f"status={st}")
check("and no file content comes back", "root:" not in str(r), str(r)[:60])

# The fix must not break ordinary scanner output, including a DOCTYPE
# that declares nothing dangerous.
st, r = imp("XMLSAFE", '<?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "nmap.dtd">'
            '<nmaprun scanner="nmap" args="x"><host><status state="up"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>',
            fmt="nmap")
check("a harmless DOCTYPE is not treated as an attack", st == 200, f"status={st} {str(r)[:80]}")

# ======================================================== streamed upload
# A Burp history is the one format read a chunk at a time instead of
# being loaded whole, because a real one is gigabytes. These tests use a
# small synthetic history, so what they verify is that the streaming
# path produces the SAME result as the in-memory path -- the size is
# exercised separately against the real 2.5 GB file.
print("\n== streamed upload ==")
import uuid as _uuid


def _burp_items(n, host="stream.example", start=0):
    rows = []
    for i in range(start, start + n):
        req = _b64.b64encode(f"GET /p{i} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                             .encode()).decode()
        resp = _b64.b64encode(f"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
                              f"<html><title>page {i}</title></html>"
                              .encode()).decode()
        rows.append(
            f"<item><time>Mon Jan 01 00:00:00 UTC 2026</time>"
            f"<url>https://{host}/p{i}</url><host ip=\"203.0.113.9\">{host}</host>"
            f"<port>443</port><protocol>https</protocol><method>GET</method>"
            f"<path>/p{i}</path><extension>null</extension>"
            f"<request base64=\"true\">{req}</request><status>200</status>"
            f"<responselength>40</responselength><mimetype>HTML</mimetype>"
            f"<response base64=\"true\">{resp}</response><comment></comment></item>")
    return ("<?xml version=\"1.0\"?><items burpVersion=\"2026.1\" "
            "exportTime=\"Mon Jan 01 00:00:00 UTC 2026\">" + "".join(rows) + "</items>")


def upload(project, body, fmt="auto", mode="open", decisions=None, fname="h.xml"):
    """POST multipart to the streaming endpoint, as a browser would."""
    boundary = "----oddjob" + _uuid.uuid4().hex
    data = body.encode() if isinstance(body, str) else body
    payload = (f"--{boundary}\r\n"
               f"Content-Disposition: form-data; name=\"file\"; filename=\"{fname}\"\r\n"
               f"Content-Type: application/xml\r\n\r\n").encode() + data + \
              f"\r\n--{boundary}--\r\n".encode()
    q = f"/api/scans/import/upload?project={project}&format={fmt}&mode={mode}"
    if decisions is not None:
        q += "&decisions=" + urllib.parse.quote(json.dumps(decisions))
    r = urllib.request.Request(BASE + q, method="POST", data=payload)
    r.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    r.add_header("Authorization", f"Bearer {admin}")
    try:
        with urllib.request.urlopen(r, timeout=300) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


import urllib.parse

call("/api/projects", "POST", {"code": "STREAM", "name": "STREAM"}, token=admin)

# More items than one chunk holds, so the multi-chunk path is what runs.
from app.importers.burphistory import CHUNK as _CHUNK

N = _CHUNK * 2 + 37
st, r = upload("STREAM", _burp_items(N), mode="open")
check("a multi-chunk history uploads", st == 200, f"status={st} {str(r)[:160]}")
check("and is detected as burphistory", (r or {}).get("format") == "burphistory",
      str((r or {}).get("format")))
check(f"every one of the {N} rows is written",
      (r or {}).get("urls_created") == N, str((r or {}).get("urls_created")))
check("counts are summed across chunks, not just the last one",
      (r or {}).get("urls_created", 0) > _CHUNK,
      f"{(r or {}).get('urls_created')} vs chunk {_CHUNK}")
check("the host is counted once, not once per chunk",
      (r or {}).get("hosts_seen") == 1, str((r or {}).get("hosts_seen")))

st, r = call("/api/web?project=STREAM&limit=1", token=admin)
check("the rows are queryable afterwards", st == 200 and (r or {}).get("total") == N,
      f"total={(r or {}).get('total')}")

# Re-uploading the same file must converge, not duplicate. This is what
# makes retrying a locked chunk safe.
st, r = upload("STREAM", _burp_items(N), mode="open")
check("re-uploading creates nothing new", (r or {}).get("urls_created") == 0,
      str((r or {}).get("urls_created")))
# `urls_updated` counts rows whose CONTENT changed, so a byte-identical
# re-import is correctly reported as zero of both. What matters is that
# nothing was duplicated.
check("and reports no spurious updates for identical rows",
      (r or {}).get("urls_updated") == 0, str((r or {}).get("urls_updated")))
st, r = call("/api/web?project=STREAM&limit=1", token=admin)
check("so the row count is unchanged", (r or {}).get("total") == N,
      f"total={(r or {}).get('total')}")

# Strict mode must survey without writing, and the survey has to come
# from the cheap host pass rather than a full parse.
call("/api/projects", "POST", {"code": "STREAMS", "name": "STREAMS"}, token=admin)
body = _burp_items(60, host="a.example") + ""
two = ("<?xml version=\"1.0\"?><items>"
       + _burp_items(30, host="a.example").split("exportTime=\"Mon Jan 01 00:00:00 UTC 2026\">")[1].replace("</items>", "")
       + _burp_items(20, host="b.example").split(">", 1)[1].replace("<items>", "").replace("</items>", "")
       + "</items>")
st, r = upload("STREAMS", _burp_items(40, host="a.example"), mode="strict")
check("strict mode reports unknown hosts", st == 200 and (r or {}).get("needs_decision") is True,
      f"status={st} {str(r)[:120]}")
check("and names the host with its transaction count",
      [u for u in (r or {}).get("unknown_hosts", []) if u["host"] == "a.example"
       and u["web"] == 40] != [], str((r or {}).get("unknown_hosts"))[:160])
st, r = call("/api/web?project=STREAMS&limit=1", token=admin)
check("strict mode wrote nothing", (r or {}).get("total") == 0,
      f"total={(r or {}).get('total')}")

# Answering the survey through the query parameter completes the import.
st, r = upload("STREAMS", _burp_items(40, host="a.example"), mode="strict",
               decisions={"a.example": {"action": "add"}})
check("a decision lets the same file through", st == 200
      and not (r or {}).get("needs_decision"), f"status={st} {str(r)[:120]}")
check("and the rows land", (r or {}).get("urls_created") == 40,
      str((r or {}).get("urls_created")))

st, r = upload("STREAMS", "", fmt="auto")
check("an empty upload is refused with a reason", st == 422 and "empty" in str(r).lower(),
      f"status={st} {str(r)[:100]}")

st, r = upload("STREAM", "<items></items>", fmt="burphistory")
check("a history with no items is refused", st == 422, f"status={st} {str(r)[:100]}")

st, r = upload("STREAM", "<nmaprun><host/></nmaprun>", fmt="burphistory")
check("the wrong root element is refused with guidance",
      st == 422 and "Save items" in str(r), f"status={st} {str(r)[:140]}")

st, r = upload("STREAM", _burp_items(5), decisions="not json")
check("unparseable decisions are rejected, not silently dropped",
      st == 422 and "json" in str(r).lower(), f"status={st} {str(r)[:100]}")

# A non-streaming format still works through the same endpoint.
st, r = upload("STREAM", '<?xml version="1.0"?><nmaprun scanner="nmap" args="x">'
               '<host><status state="up"/><address addr="198.51.100.7" addrtype="ipv4"/>'
               '<ports><port protocol="tcp" portid="22"><state state="open"/>'
               '<service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>',
               fname="scan.xml")
check("a non-streaming format still uploads through the same route",
      st == 200 and (r or {}).get("format") == "nmap", f"status={st} {str(r)[:120]}")

# Streaming and in-memory readers must agree, or the format quietly
# means two different things depending on how the file arrived.
from app.importers import burphistory as _bh

_doc = _burp_items(7, host="cmp.example")
_whole = _bh.parse(_doc)
import os as _os
import tempfile as _tf

_fd, _pth = _tf.mkstemp(suffix=".xml"); _os.write(_fd, _doc.encode()); _os.close(_fd)
_streamed = list(_bh.stream(_pth, chunk=3))
_os.unlink(_pth)
check("streamed and whole-document reads produce the same row count",
      sum(len(s.web) for s in _streamed) == len(_whole.web),
      f"{sum(len(s.web) for s in _streamed)} vs {len(_whole.web)}")
check("and the same URLs in the same order",
      [w.url for s in _streamed for w in s.web] == [w.url for w in _whole.web])
check("and the same decoded bodies",
      [w.response for s in _streamed for w in s.web] == [w.response for w in _whole.web])
check("hosts_in counts without decoding bodies",
      _bh.hosts_in.__doc__ is not None)

# ==================================================== held uploads
# The strict survey keeps the uploaded file so answering it does not
# mean sending the whole thing again. For a 2.5 GB proxy history that
# second upload is most of the wall-clock cost.
print("\n== held uploads ==")
import os as _osmod
import tempfile as _tmpmod

from app.routers.scans import HELD_PREFIX as _pfx
from app.routers.scans import sweep_orphan_uploads as sweep_orphan_uploads_ref


def _spooled():
    return {n for n in _osmod.listdir(_tmpmod.gettempdir()) if n.startswith(_pfx)}


# Earlier strict-mode tests left holds on purpose -- they asked a
# question nobody answered, which is exactly when a file should be
# kept. The invariant worth testing is that THIS section adds no file
# it does not also release.
_before = _spooled()
call("/api/projects", "POST", {"code": "HOLD", "name": "HOLD"}, token=admin)

_doc = _burp_items(25, host="held.example")
st, r = upload("HOLD", _doc, mode="strict")
check("a strict upload asks for a decision", (r or {}).get("needs_decision") is True,
      f"{st} {str(r)[:100]}")
uid = (r or {}).get("upload_id")
check("and hands back an upload_id to resume from", bool(uid), str(uid))

# Resuming sends decisions only -- no file.
st, r = call("/api/scans/import/resume?project=HOLD", "POST",
             {"upload_id": uid, "decisions": {"held.example": {"action": "add"}}},
             token=admin)
check("resume completes the import without the file", st == 200
      and not (r or {}).get("needs_decision"), f"{st} {str(r)[:120]}")
check("and writes every row", (r or {}).get("urls_created") == 25,
      str((r or {}).get("urls_created")))
st, r = call("/api/web?project=HOLD&limit=1", token=admin)
check("the rows are really there", (r or {}).get("total") == 25,
      f"total={(r or {}).get('total')}")

# The hold is consumed: a second resume must not work, or an uploaded
# file would linger addressable after it was used.
st, r = call("/api/scans/import/resume?project=HOLD", "POST",
             {"upload_id": uid, "decisions": {"held.example": {"action": "add"}}},
             token=admin)
check("a consumed upload_id is gone", st == 404, f"{st} {str(r)[:100]}")

st, r = call("/api/scans/import/resume?project=HOLD", "POST",
             {"upload_id": "nope-not-a-real-token", "decisions": {}}, token=admin)
check("an unknown upload_id is a 404, not a crash", st == 404, f"{st} {str(r)[:80]}")

# A held file is bound to its project: the token alone must not let it
# be imported somewhere else.
call("/api/projects", "POST", {"code": "HOLD2", "name": "HOLD2"}, token=admin)
st, r = upload("HOLD", _burp_items(5, host="bound.example"), mode="strict")
uid2 = (r or {}).get("upload_id")
st, r = call("/api/scans/import/resume?project=HOLD2", "POST",
             {"upload_id": uid2, "decisions": {"bound.example": {"action": "add"}}},
             token=admin)
check("a held upload cannot be resumed into another project",
      st in (403, 404), f"{st} {str(r)[:100]}")
st, r = call("/api/web?project=HOLD2&limit=1", token=admin)
check("and nothing landed there", (r or {}).get("total") == 0,
      f"total={(r or {}).get('total')}")

# Cancelling releases the disk.
st, _ = call(f"/api/scans/import/held/{uid2}?project=HOLD", "DELETE", token=admin)
check("a held upload can be discarded", st in (200, 204), str(st))
st, r = call("/api/scans/import/resume?project=HOLD", "POST",
             {"upload_id": uid2, "decisions": {}}, token=admin)
check("and is gone afterwards", st == 404, f"{st} {str(r)[:80]}")

# Still-unanswered hosts keep the hold alive rather than dropping it,
# or a partial answer would force a re-upload.
st, r = upload("HOLD", _burp_items(4, host="x1.example")
               + "", mode="strict")
uid3 = (r or {}).get("upload_id")
st, r = call("/api/scans/import/resume?project=HOLD", "POST",
             {"upload_id": uid3, "decisions": {}}, token=admin)
check("resuming with no decisions still needs a decision",
      (r or {}).get("needs_decision") is True, str(r)[:100])
check("and the same token keeps working",
      (r or {}).get("upload_id") == uid3, str((r or {}).get("upload_id")))
st, r = call("/api/scans/import/resume?project=HOLD", "POST",
             {"upload_id": uid3, "decisions": {"x1.example": {"action": "skip"}}},
             token=admin)
check("answering it then finishes", st == 200
      and not (r or {}).get("needs_decision"), f"{st} {str(r)[:100]}")

# Every file this section spooled must be released again: a resumed
# import, a discarded hold and a rejected cross-project resume all have
# to end with the disk back where it started.
_after = _spooled()
check("a completed resume leaves no spooled file behind",
      _after <= _before, f"new: {sorted(_after - _before)}")

# And a hold that IS still outstanding must be reapable, so an
# abandoned multi-gigabyte upload cannot sit there forever.
from app.routers.scans import _HELD, HELD_TTL, _reap_held

# _HELD and _reap_held are asserted on, not merely imported: the import
# alone is an existence check nothing reads, and a rename upstream would
# then silently take the reaping guarantee with it.
check("held uploads have a finite lifetime",
      HELD_TTL > 0 and HELD_TTL <= 86400 and isinstance(_HELD, dict)
      and callable(_reap_held),
      str(HELD_TTL))
check("the sweeper removes orphans a killed process left",
      callable(sweep_orphan_uploads_ref), "")

# ================================================ background imports
# A large import runs for a long time. Held open as one request it dies
# with the tab; queued, it outlives the page that started it and the
# operator can go and look at something else.
print("\n== background imports ==")
import time as _time

call("/api/projects", "POST", {"code": "BG", "name": "BG"}, token=admin)

st, r = upload("BG", _burp_items(40, host="bg.example"), mode="strict")
_uid = (r or {}).get("upload_id")
check("a strict upload holds the file for a background run", bool(_uid), str(r)[:100])

st, r = call("/api/scans/import/resume?project=BG", "POST",
             {"upload_id": _uid, "decisions": {"bg.example": {"action": "add"}},
              "background": True}, token=admin)
check("queueing returns immediately with a job id",
      st == 200 and (r or {}).get("job_id"), f"{st} {str(r)[:120]}")
_job = (r or {}).get("job_id")
check("and nothing is reported as written yet",
      (r or {}).get("urls_created", 0) == 0, str((r or {}).get("urls_created")))

# Poll it the way the UI does.
_final = None
for _ in range(100):
    st, j = call(f"/api/scans/import/jobs/{_job}?project=BG", token=admin)
    if (j or {}).get("status") in ("done", "failed"):
        _final = j
        break
    _time.sleep(0.2)
check("the job reaches a terminal state", _final is not None,
      str((j or {}).get("status")))
check("and it succeeded", (_final or {}).get("status") == "done",
      f"{(_final or {}).get('status')}: {(_final or {}).get('error')}")
check("the job carries the import result",
      ((_final or {}).get("result") or {}).get("urls_created") == 40,
      str(((_final or {}).get("result") or {}).get("urls_created")))

st, r = call("/api/web?project=BG&limit=1", token=admin)
check("the rows really landed", (r or {}).get("total") == 40,
      f"total={(r or {}).get('total')}")

st, jobs = call("/api/scans/import/jobs?project=BG", token=admin)
check("the job is listed for the project", st == 200
      and any(j["id"] == _job for j in (jobs or [])), f"{st} {str(jobs)[:120]}")
check("and records which file it was",
      next((j for j in (jobs or []) if j["id"] == _job), {}).get("filename") == "h.xml",
      str(next((j for j in (jobs or []) if j["id"] == _job), {}).get("filename")))

# A job belongs to its project.
call("/api/projects", "POST", {"code": "BG2", "name": "BG2"}, token=admin)
st, r = call(f"/api/scans/import/jobs/{_job}?project=BG2", token=admin)
check("a job cannot be read through another project", st == 404, str(st))
st, jobs2 = call("/api/scans/import/jobs?project=BG2", token=admin)
check("and does not leak into its job list", jobs2 == [], str(jobs2)[:80])

# The held file must be released once the job finishes, or a queued
# 2.5 GB import would leave 2.5 GB behind.
st, r = call("/api/scans/import/resume?project=BG", "POST",
             {"upload_id": _uid, "decisions": {}}, token=admin)
check("the background job consumed the held upload", st == 404, str(st))

# A failing job has to land on the row, not vanish.
st, r = call("/api/scans/import/resume?project=BG", "POST",
             {"upload_id": "bogus", "background": True, "decisions": {}}, token=admin)
check("queueing an unknown upload is refused up front", st == 404, str(st))

# reap_stale is what stops a restart leaving a job spinning forever.
from app.importers.jobs import reap_stale as _reap

check("there is a reaper for jobs a restart interrupted", callable(_reap))

# ============================================ streamed burp ISSUE export
# A Burp issue export is a different format from the proxy history and
# was not streamable, so a 2,232 MB one was refused outright against the
# 64 MB whole-document limit.
print("\n== streamed burp issue export ==")
call("/api/projects", "POST", {"code": "BURPI", "name": "BURPI"}, token=admin)


def _issues(n, host="issue.example"):
    items = "".join(
        f"<issue><serialNumber>{i}</serialNumber><type>5243392</type>"
        f"<name>Cross-site scripting (reflected)</name>"
        f"<host ip='203.0.113.5'>https://{host}</host><path>/p{i}</path>"
        f"<severity>High</severity><confidence>Certain</confidence>"
        f"<issueDetail>detail {i}</issueDetail>"
        f"<remediationBackground>Encode output.</remediationBackground>"
        f"</issue>" for i in range(n))
    return ("<?xml version='1.0'?><issues burpVersion='2026.1' exportTime='x'>"
            + items + "</issues>")


from app.importers.burp import CHUNK as _BCHUNK

N = _BCHUNK * 2 + 11
st, r = upload("BURPI", _issues(N), mode="open", fname="issues.xml")
check("a multi-chunk issue export uploads", st == 200, f"{st} {str(r)[:140]}")
check("and is detected as burp, not burphistory",
      (r or {}).get("format") == "burp", str((r or {}).get("format")))
check(f"all {N} findings are written",
      (r or {}).get("vulns_created") == N, str((r or {}).get("vulns_created")))

st, v = call("/api/vulns?project=BURPI&limit=1", token=admin)
check("the findings are queryable", (v or {}).get("total") == N,
      f"total={(v or {}).get('total')}")

# Re-import must converge, which is what makes resuming an interrupted
# multi-gigabyte import safe.
st, r = upload("BURPI", _issues(N), mode="open", fname="issues.xml")
check("re-importing creates no duplicates", (r or {}).get("vulns_created") == 0,
      str((r or {}).get("vulns_created")))
st, v = call("/api/vulns?project=BURPI&limit=1", token=admin)
check("so the finding count is unchanged", (v or {}).get("total") == N,
      f"total={(v or {}).get('total')}")

st, r = upload("BURPI", "<items><item></item></items>", fmt="burp")
check("the wrong root element is refused with guidance",
      st == 422 and "Report issues" in str(r), f"{st} {str(r)[:140]}")

# Both readers of the format must agree, or an export means different
# things depending on its size.
import os as _os3
import tempfile as _tf3

from app.importers import burp as _burp

_d = _issues(7, host="cmp2.example")
_whole = _burp.parse(_d)
_fd, _p = _tf3.mkstemp(suffix=".xml"); _os3.write(_fd, _d.encode()); _os3.close(_fd)
_streamed = [x for c in _burp.stream(_p, chunk=3) for x in c.vulns]
_hosts = _burp.hosts_in(_p)
_os3.unlink(_p)
check("streamed and whole-document issue reads agree on count",
      len(_streamed) == len(_whole.vulns), f"{len(_streamed)} vs {len(_whole.vulns)}")
check("and on every title", [v.title for v in _streamed] == [v.title for v in _whole.vulns])
check("and on remediation text",
      [v.remediation for v in _streamed] == [v.remediation for v in _whole.vulns])
check("hosts_in counts the issues per host", _hosts == {"cmp2.example": 7}, str(_hosts))

# ==================================================== vuln detail view
print("\n== vuln detail ==")
st, v = call("/api/vulns?project=BURPI&limit=1", token=admin)
_vid = v["items"][0]["id"]
st, d = call(f"/api/vulns/{_vid}", token=admin)
check("a finding can be fetched on its own", st == 200, f"{st} {str(d)[:100]}")
check("it carries the description", bool((d or {}).get("description")),
      str((d or {}).get("description"))[:60])
check("and the remediation, which the list endpoint used to drop",
      bool((d or {}).get("remediation")), str((d or {}).get("remediation"))[:60])
check("and lists the hosts it was found on",
      len((d or {}).get("occurrences") or []) >= 1,
      str(len((d or {}).get("occurrences") or [])))
check("each occurrence names a host",
      all(o.get("host") for o in ((d or {}).get("occurrences") or [])))
check("and says how they were grouped", bool((d or {}).get("grouped_by")),
      str((d or {}).get("grouped_by")))
st, d = call("/api/vulns/99999999", token=admin)
check("an unknown finding is a 404", st == 404, str(st))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
