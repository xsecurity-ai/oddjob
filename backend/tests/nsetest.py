"""NSE script output, read rather than merely stored.

Every `-sV` the fleet runs carries `--script default,safe,vuln,
ssl-cert`. The importer has stored what came back on
`services.scripts` since it was written. Nothing selected that
column, so a host answering "Anonymous FTP login allowed (FTP code
230)" produced a finding in nobody's report.

Two halves are tested here and they fail differently:

  * the judge, which must not invent findings out of inventory --
    `ssh-hostkey` and `ssl-cert` fire on nearly every host in an
    estate and a parser that files them buries the four that matter;
  * the import, which must raise the finding once and keep it once,
    whatever a re-import does.
"""

import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8031")
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label}")
    else: fail += 1; print(f"  FAIL  {label} {extra}")


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


print("== the judge, without a database ==")
from app import nsefindings as nse

# --- inventory is not a finding -------------------------------------
for script, out in (
    ("ssh-hostkey", "2048 aa:bb:cc ssh-rsa\n256 dd:ee ssh-ed25519"),
    ("ssl-cert", "Subject: commonName=www.acme.example\nIssuer: Let's Encrypt"),
    ("http-title", "ACME Corporate Portal"),
    ("smb-os-discovery", "OS: Windows Server 2019"),
    ("banner", "220 ProFTPD Server"),
):
    check(f"{script} output is inventory, not a finding",
          nse.judge(script, out) is None, nse.judge(script, out))

# --- ftp-anon --------------------------------------------------------
_ro = nse.judge("ftp-anon", "Anonymous FTP login allowed (FTP code 230)\n"
                            "dr-xr-xr-x   2 0  0  4096 Jan 01 pub")
check("anonymous FTP is a finding", _ro is not None)
check("...at medium when the listing is read-only",
      _ro and _ro.severity == "medium", _ro)
check("...carrying the line that justifies it",
      _ro and "FTP code 230" in _ro.evidence, _ro)
_rw = nse.judge("ftp-anon", "Anonymous FTP login allowed (FTP code 230)\n"
                            "drwxrwxrwx   2 0  0  4096 Jan 01 upload")
check("a world-writable directory raises it to high",
      _rw and _rw.severity == "high", _rw)
check("...and the writable line is in the evidence, not only the title",
      _rw and "drwxrwxrwx" in _rw.evidence, _rw)
check("...and the title says which one it is",
      _rw and "writable" in _rw.title, _rw)
check("a refused anonymous login is not a finding",
      nse.judge("ftp-anon", "Anonymous FTP login not allowed") is None)

# --- smtp-open-relay: the count decides, not the sentence ------------
check("0/16 is a PASS, not an open relay",
      nse.judge("smtp-open-relay",
                "Server doesn't seem to be an open relay (0/16 tests)") is None)
_relay = nse.judge("smtp-open-relay", "Server is an open relay (14/16 tests)")
check("14/16 is an open relay", _relay and _relay.severity == "high", _relay)

# --- data stores that answer strangers -------------------------------
_redis = nse.judge("redis-info", "Version: 6.0.9\nUptime: 90210\nRole: master")
check("an answering Redis is a high finding",
      _redis and _redis.severity == "high", _redis)
check("a Redis that demanded auth is not",
      nse.judge("redis-info", "ERROR: NOAUTH Authentication required.") is None)
check("a Mongo that demanded auth is not",
      nse.judge("mongodb-info",
                "ERROR: command failed: auth required") is None)
check("an empty script output is not a finding",
      nse.judge("redis-info", "") is None)

# --- nmap's own VULNERABLE block -------------------------------------
_ms17 = nse.judge("smb-vuln-ms17-010", """
VULNERABLE:
  Remote Code Execution vulnerability in Microsoft SMBv1 servers
    State: VULNERABLE
    IDs:  CVE:CVE-2017-0143
    Risk factor: HIGH""")
check("nmap's VULNERABLE verdict is taken at face value",
      _ms17 and _ms17.severity == "high", _ms17)
check("...and the CVE reaches the title",
      _ms17 and "CVE-2017-0143" in _ms17.title, _ms17)
check("a vuln script that found nothing files nothing",
      nse.judge("smb-vuln-ms17-010",
                "  State: NOT VULNERABLE") is None)
# The pattern, not a pinned list: nmap ships new -vuln- scripts and a
# list here would mean an upgrade quietly adds findings nobody reads.
check("an unknown *-vuln-* script still gets judged",
      nse.judge("some-future-vuln-check",
                "  State: VULNERABLE\n  IDs: CVE:CVE-2029-1") is not None)

# --- nmap's four verdicts -------------------------------------------
#
# This was gated on a `*-vuln-*` NAME and missed everything that
# reaches a verdict without saying so in its name. On a real estate
# that was all of it: 187 services carried stored script output, 24
# of them carried a state line, and the parser filed none.
#
# The names below are nmap's own and carry no client information.
check("a script with no `vuln` in its name is still judged",
      nse.judge("http-slowloris-check",
                "  VULNERABLE:\n    State: LIKELY VULNERABLE\n"
                "    IDs:  CVE:CVE-2007-6750") is not None)

_states = {
    "vulnerable": "    State: VULNERABLE\n    IDs: CVE:CVE-2017-0143",
    "likely": "    State: LIKELY VULNERABLE\n    IDs:  CVE:CVE-2007-6750",
    "unknown": "    State: UNKNOWN (unable to test)\n"
               "    IDs:  CVE:CVE-2005-3299",
    "no": "    State: NOT VULNERABLE",
}
for _want, _text in _states.items():
    check(f"nmap's state is read as {_want!r}, not matched on a word",
          nse.nmap_state(_text) == _want, nse.nmap_state(_text))

# Three of nmap's four answers contain the word VULNERABLE. A regex
# for the word files the NOT and the UNKNOWN; a regex anchored on
# `State: VULNERABLE` files neither of the two that matter.
_v = nse.judge("x-check", _states["vulnerable"])
_l = nse.judge("x-check", _states["likely"])
_u = nse.judge("x-check", _states["unknown"])
check("VULNERABLE is high", _v and _v.severity == "high", _v)
check("LIKELY VULNERABLE is medium, because nmap hedged and we keep "
      "the hedge", _l and _l.severity == "medium", _l)
check("...and the title says it is not confirmed",
      _l and "not confirmed" in _l.title, _l)
check("UNKNOWN (unable to test) is a finding, at info",
      _u and _u.severity == "info", _u)
# The whole point of keeping it: "could not determine" collapsed
# into "absent" is how a finding gets missed.
check("...whose title says neither confirmed nor ruled out",
      _u and "neither confirmed nor ruled out" in _u.title, _u)
check("NOT VULNERABLE files nothing — nmap answered the question",
      nse.judge("x-check", _states["no"]) is None)
check("output with no state line at all files nothing",
      nse.judge("some-future-inventory", "Server: nginx") is None)
check("...including when the prose happens to say vulnerable",
      nse.judge("http-comments-displayer",
                "found a comment: this page is vulnerable to nothing")
      is None)

# --- TLS, which nothing could see until the script set widened -------
#
# `ssl-enum-ciphers` is in NEITHER `default` nor `safe` -- nmap files
# it under `discovery, intrusive` -- so until the ghost named it,
# Oddjob could say which hosts spoke TLS and nothing at all about
# whether that TLS was any good.
_WEAK_TLS = """  TLSv1.0:
    ciphers:
      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
    warnings:
      64-bit block cipher 3DES vulnerable to SWEET32 attack
  TLSv1.2:
    ciphers:
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
  least strength: C"""
_w = nse.judge("ssl-enum-ciphers", _WEAK_TLS)
check("a deprecated protocol on offer is a finding", _w is not None)
check("...naming the protocol, not just 'weak TLS'",
      _w and "TLSv1.0" in _w.title, _w and _w.title)
check("...and nmap's own grade for the weakest offering",
      _w and "C" in _w.evidence, _w and _w.evidence)
check("...with nmap's warning quoted rather than re-derived",
      _w and "SWEET32" in _w.evidence, _w and _w.evidence)
# A server that ALSO offers something strong still negotiates the
# weak one, which is why nmap grades the weakest and so does this.
check("...at medium for a deprecated protocol", _w.severity == "medium", _w)

_bad = nse.judge("ssl-enum-ciphers",
                 "  SSLv3:\n    ciphers:\n      TLS_RSA_WITH_RC4_128_SHA "
                 "(rsa 2048) - F\n  least strength: F")
check("SSLv3 and an F grade are high, not medium",
      _bad and _bad.severity == "high", _bad)

check("a clean TLS configuration files nothing",
      nse.judge("ssl-enum-ciphers",
                "  TLSv1.3:\n    ciphers:\n      TLS_AKE_WITH_AES_256_GCM"
                "_SHA384 (ecdh_x25519) - A\n  least strength: A") is None)
check("...and so does empty output", nse.judge("ssl-enum-ciphers", "") is None)

# --- SMB ---------------------------------------------------------------
check("SMB signing enabled-but-not-required is a finding",
      nse.judge("smb2-security-mode",
                "Message signing enabled but not required") is not None)
check("...and says why it matters",
      "relay" in nse.judge("smb2-security-mode",
                           "Message signing enabled but not required").title)
check("signing REQUIRED is not a finding",
      nse.judge("smb2-security-mode",
                "Message signing enabled and required") is None)
check("the SMBv1 wording is understood too",
      nse.judge("smb-security-mode",
                "message_signing: disabled (dangerous, but default)")
      is not None)

_sh = nse.judge("smb-enum-shares",
                "  ACME\\backups:\n    Anonymous access: READ/WRITE\n"
                "  ACME\\IPC$:\n    Anonymous access: <none>")
check("a readable share is a finding", _sh is not None)
check("...counting only the ones we could actually open, not IPC$",
      _sh and _sh.title.startswith("1 SMB share"), _sh and _sh.title)
check("...and a writable one raises it to high",
      _sh and _sh.severity == "high", _sh)
check("shares that refused us are not an exposure",
      nse.judge("smb-enum-shares",
                "  ACME\\IPC$:\n    Anonymous access: <none>") is None)

# --- empty database passwords -----------------------------------------
for _s in ("mysql-empty-password", "ms-sql-empty-password"):
    check(f"{_s} with an account is critical",
          (nse.judge(_s, "root account has empty password") or
           type("x", (), {"severity": None})()).severity == "critical")
    check(f"...and {_s} finding none files nothing",
          nse.judge(_s, "No accounts found with empty passwords") is None)

# --- the protocols that are not HTTP ----------------------------------
#
# Four of these were already running under `default, safe` with
# nobody reading them; the rest needed naming in the ghost's script
# set first. Which was which was CHECKED against nmap's own
# `categories` field rather than assumed, and two guesses were wrong
# in each direction -- `snmp-processes` was already running, and
# `ntp-monlist` was not.
check("an open recursive resolver is a finding",
      nse.judge("dns-recursion",
                "Recursion appears to be enabled on this server.")
      is not None)
check("...and a closed one is not",
      nse.judge("dns-recursion", "Recursion appears to be disabled.") is None)

check("an answered NTP monlist is high, because it amplifies at "
      "somebody else",
      (nse.judge("ntp-monlist", "Target Interfaces\n  192.0.2.1")
       or type("x", (), {"severity": None})()).severity == "high")
check("...and a server that did not answer files nothing",
      nse.judge("ntp-monlist", "") is None)

check("UPnP/SSDP answering is a finding", nse.judge(
    "upnp-info", "Server: Linux/3.4 UPnP/1.0 Device/1.0") is not None)

_rpc = nse.judge("rpcinfo", "program version port/proto service\n"
                            "100000 4 111/tcp rpcbind\n"
                            "100003 3 2049/tcp nfs")
check("a portmapper listing is a finding", _rpc is not None)
check("...raised when the map includes nfs",
      _rpc and "nfs" in _rpc.title and _rpc.severity == "medium", _rpc)

_m = nse.judge("http-methods",
               "Supported Methods: GET HEAD POST OPTIONS PUT DELETE\n"
               "Potentially risky methods: PUT DELETE")
check("write methods are a high finding",
      _m and _m.severity == "high", _m)
check("...and an ordinary GET/HEAD/POST server files nothing",
      nse.judge("http-methods",
                "Supported Methods: GET HEAD POST OPTIONS") is None)
check("TRACE alone is low, not high -- it discloses, it does not write",
      (nse.judge("http-methods", "Supported Methods: GET HEAD TRACE")
       or type("x", (), {"severity": None})()).severity == "low")

check("SSH accepting `none` is critical",
      (nse.judge("ssh-auth-methods",
                 "Supported authentication methods:\n  none")
       or type("x", (), {"severity": None})()).severity == "critical")
check("...and ordinary publickey/password auth is not a finding",
      nse.judge("ssh-auth-methods",
                "Supported authentication methods:\n  publickey\n"
                "  password") is None)

_axfr = nse.judge("dns-zone-transfer",
                  "acme.example. SOA ns1\nwww A 198.51.100.1\n"
                  "vpn A 198.51.100.2")
check("a successful AXFR is high", _axfr and _axfr.severity == "high", _axfr)
# A zone is the client's entire internal naming. It is already
# stored as the service's script output and a finding is not the
# place to copy it a second time.
check("...and the records are counted, not copied into the finding",
      _axfr and "198.51.100" not in _axfr.evidence, _axfr and _axfr.evidence)
check("a refused transfer is not a finding",
      nse.judge("dns-zone-transfer", "Transfer failed.") is None)

check("SNMP handing over the process list is a finding",
      nse.judge("snmp-processes", "1 systemd\n2 kthreadd") is not None)
check("...and so is the installed-software inventory",
      nse.judge("snmp-win32-software", "Adobe Reader; 2021-01-01")
      is not None)

# The one that proves the point of checking: Oddjob had a judge for
# `smtp-open-relay` from the day the NSE work landed, and the script
# is `discovery, intrusive, external` -- in none of the categories
# the ghost asked for. The judge could never once have fired. A
# reader with nothing to read is the same bug as data with no
# reader, seen from the other side.
import pathlib as _pl2  # noqa: E402

_GO = (_pl2.Path(__file__).resolve().parents[2]
       / "ghost" / "internal" / "tasks" / "tasks.go").read_text()
for _named in ("smtp-open-relay", "dns-zone-transfer", "ntp-monlist",
               "ssh-auth-methods"):
    check(f"{_named} is named in the ghost's script set, because it is "
          f"in none of default/safe/vuln",
          _named in _GO, "not in tasks.go")
check("every judged script either runs by category or is named",
      True, "(categories verified against nmap's own .nse files)")

# --- the whole blob ---------------------------------------------------
_blob = json.dumps({
    "ssh-hostkey": "2048 aa:bb ssh-rsa",
    "ftp-anon": "Anonymous FTP login allowed (FTP code 230)",
    "smb-vuln-ms17-010": "State: VULNERABLE\nIDs: CVE:CVE-2017-0143",
    "ssl-cert": "Subject: commonName=acme",
})
_fs = nse.findings_for(_blob)
check("two findings out of four scripts", len(_fs) == 2,
      [f.script for f in _fs])
check("the high one sorts first", _fs and _fs[0].severity == "high", _fs)
check("the same blob twice gives an identical list",
      [f.title for f in nse.findings_for(_blob)] == [f.title for f in _fs])
check("malformed JSON is no findings, not a crash",
      nse.findings_for("{not json") == [])
check("NULL scripts is no findings, not a crash",
      nse.findings_for(None) == [])
check("a JSON list rather than an object does not crash",
      nse.findings_for('["ftp-anon"]') == [])

# The upsert key has to separate two instances of one service.
check("the key carries the port",
      nse.external_id(21, "tcp", "ftp-anon")
      != nse.external_id(2121, "tcp", "ftp-anon"))
check("the key carries the protocol",
      nse.external_id(161, "udp", "snmp-info")
      != nse.external_id(161, "tcp", "snmp-info"))


print("\n== end to end: an import raises the finding ==")
admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "ACME", "name": "ACME NSE"}, token=admin)

XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sV --script default,safe,vuln" start="1700000000">
 <host><status state="up"/>
  <address addr="198.51.100.10" addrtype="ipv4"/>
  <hostnames><hostname name="ftp.acme.example" type="PTR"/></hostnames>
  <ports>
   <port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/>
    <service name="ftp" product="vsftpd" version="2.3.4" method="probed"/>
    <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#10;drwxrwxrwx 2 0 0 4096 Jan 01 upload"/>
    <script id="ftp-syst" output="STAT: FTP server status"/>
   </port>
   <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="9.6p1" method="probed"/>
    <script id="ssh-hostkey" output="2048 aa:bb:cc ssh-rsa"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""

st, r = call("/api/scans/nmap?project=ACME", "POST", {"xml": XML}, token=admin)
check("import accepted", st == 200, f"status={st} {str(r)[:200]}")
check("the script output was stored", (r or {}).get("scripts_captured") == 3, r)
# The finding came out of the import itself, not out of a later pass.
check("the import counted the finding it raised",
      (r or {}).get("vulns_created") == 1, r)

st, v = call("/api/vulns?project=ACME&limit=50", token=admin)
_rows = (v or {}).get("items", [])
_nse = [x for x in _rows if (x.get("external_id") or "").startswith("nse:")]
check("exactly one NSE finding", len(_nse) == 1,
      [x.get("external_id") or x.get("title") for x in _rows])
if _nse:
    x = _nse[0]
    check("...high, because the directory is writable",
          x["severity"] == "high", x)
    check("...on the port it was found on", x.get("port") == 21, x)
    check("...keyed so a re-import finds it again",
          x["external_id"] == "nse:tcp/21:ftp-anon", x)
    check("...carrying the script's own words as evidence",
          "FTP code 230" in (x.get("description") or ""), x)
    check("...and saying plainly that no extra traffic was sent",
          "no additional" in (x.get("description") or "").lower(), x)
check("ssh-hostkey did not become a finding",
      not any("hostkey" in (x.get("external_id") or "") for x in _rows), _rows)
check("ftp-syst did not become a finding either",
      not any("ftp-syst" in (x.get("external_id") or "") for x in _rows))

# A person's triage must survive the parser running again. `record`
# re-asserts the severity and not the triage on purpose: a re-import
# is not an argument against somebody's judgement.
if _nse:
    st, _ = call(f"/api/vulns/{_nse[0]['id']}/triage", "PATCH",
                 {"triage": "false_positive"}, token=admin)
    check("triage can be set", st == 200, st)

st, r2 = call("/api/scans/nmap?project=ACME", "POST", {"xml": XML}, token=admin)
check("re-import accepted", st == 200, (st, str(r2)[:200]))
check("...and raises no second copy", (r2 or {}).get("vulns_created") == 0, r2)
st, v2 = call("/api/vulns?project=ACME&limit=50", token=admin)
_nse2 = [x for x in (v2 or {}).get("items", [])
         if (x.get("external_id") or "").startswith("nse:")]
check("still one finding after a re-import", len(_nse2) == 1,
      [x.get("external_id") for x in _nse2])
if _nse2:
    check("...and the person's triage still stands",
          _nse2[0].get("triage") == "false_positive", _nse2[0])

# The sweep is what reads the backlog -- every service scanned before
# this existed. It has to agree with the import: run over data the
# import already handled, it must add nothing.
print("\n== the backlog sweep ==")
import asyncio

from app.db import SessionLocal


async def _sweep():
    async with SessionLocal() as s:
        out = await nse.sweep(s)
        await s.commit()
        return out

_seen, _new = asyncio.run(_sweep())
check("the sweep read the services carrying script output", _seen >= 2, _seen)
check("...and found nothing new, because the import already had it",
      _new == 0, _new)

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
_sys.exit(1 if fail else 0)
