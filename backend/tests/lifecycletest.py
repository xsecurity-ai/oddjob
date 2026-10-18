"""Is it still there.

Oddjob could say a finding existed. It could never say one had gone
away: a row written in March sat at `open` for ever, through
re-scans that no longer saw it, because nothing recorded that
anybody had looked again.

The rule everything here is built around:

    A finding missing from a new scan is not evidence it was fixed.

It is evidence of nothing unless the new scan COULD have found it.
A narrower template set, a scan that errored half way, a host that
was down -- each produces an absence and none of them is a
remediation. So the tests that matter most are the ones that prove
`resolved` is NOT said: the four-way split exists so that "we do
not know" has somewhere to go.
"""

import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8035")
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


print("== the verdict, without a database ==")
from app import lifecycle as lc

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
T1 = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)
T2 = datetime(2026, 5, 1, 9, 0, tzinfo=UTC)

# --- the three everybody asks for ------------------------------------
_new = lc.verdict("nuclei", first_seen=T2, last_seen=T2, last_looked=T2)
check("first seen by the latest scan is NEW", _new.state == lc.NEW, _new)
_still = lc.verdict("nuclei", first_seen=T0, last_seen=T2, last_looked=T2)
check("seen before and seen again is PRESENT", _still.state == lc.PRESENT,
      _still)
_gone = lc.verdict("nuclei", first_seen=T0, last_seen=T1, last_looked=T2)
check("a later look that did not report it is RESOLVED",
      _gone.state == lc.RESOLVED, _gone)

# --- and the fourth, which is the point ------------------------------
_quiet = lc.verdict("nuclei", first_seen=T0, last_seen=T1, last_looked=None)
check("nobody has looked since -> UNCONFIRMED, not resolved",
      _quiet.state == lc.UNCONFIRMED, _quiet)
check("...and it says so in words", "no nuclei scan" in _quiet.why, _quiet.why)
_stale = lc.verdict("nuclei", first_seen=T0, last_seen=T1, last_looked=T1)
check("a look at the same moment it was seen is PRESENT, not resolved",
      _stale.state == lc.PRESENT, _stale)
_older = lc.verdict("nuclei", first_seen=T0, last_seen=T2, last_looked=T1)
check("a look OLDER than the last sighting does not resolve anything",
      _older.state == lc.PRESENT, _older)

# --- a finding nobody's tool is responsible for ----------------------
_manual = lc.verdict(None, first_seen=T0, last_seen=T0, last_looked=T2)
check("a finding with no scanner is never resolved by a sweep",
      _manual.state == lc.UNCONFIRMED, _manual)
check("...and says why: nothing is responsible for re-checking it",
      "without a scanner" in _manual.why, _manual.why)

# --- the claim always carries its sentence ---------------------------
check("every verdict explains itself",
      all(lc.verdict(s, T0, T1, t).why
          for s in ("nmap", None) for t in (None, T0, T2)))
check("a RESOLVED names both dates",
      "2026-05-01" in _gone.why and "2026-04-01" in _gone.why, _gone.why)

# --- naive timestamps, which is what SQLite hands back ---------------
check("a naive last_looked is read as UTC",
      lc.verdict("nmap", T0, T1, datetime(2026, 5, 1, 9, 0)).state
      == lc.RESOLVED)
check("...and a naive last_seen too",
      lc.verdict("nmap", T0, datetime(2026, 5, 1, 9, 0), T1).state
      == lc.PRESENT)

# --- the summary -----------------------------------------------------
_sum = lc.summarise([_new, _still, _gone, _quiet])
check("the summary counts each state", _sum == {"new": 1, "present": 1,
                                                "resolved": 1,
                                                "unconfirmed": 1}, _sum)
# A summary that omitted `resolved` because nothing was resolved
# would read as a tool that cannot answer the question.
check("every state appears even at zero",
      set(lc.summarise([]).keys()) == set(lc.STATES), lc.summarise([]))
check("every state has a stated meaning",
      all(s in lc.MEANING and lc.MEANING[s] for s in lc.STATES))


print("\n== end to end ==")
admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "LIFE", "name": "Lifecycle"},
     token=admin)

# Two findings on one host from one scanner, via a nuclei import.
def _nuclei(ids):
    return "\n".join(json.dumps({
        "template-id": i, "host": "app.acme.example",
        "matched-at": f"https://app.acme.example/{i}",
        "info": {"name": f"finding {i}", "severity": "high"},
    }) for i in ids)

st, r = call("/api/scans/import?project=LIFE", "POST",
             {"format": "nuclei", "mode": "open", "content": _nuclei(["cve-a", "cve-b"])}, token=admin)
check("first scan imported", st == 200, (st, r))
check("...and raised two findings", (r or {}).get("vulns_created") == 2, r)

st, v = call("/api/vulns?project=LIFE&limit=50", token=admin)
_items = (v or {}).get("items") or []
check("both findings are NEW after the first scan",
      sorted(x["lifecycle"] for x in _items) == ["new", "new"],
      [(x["title"], x["lifecycle"]) for x in _items])
check("...attributed to the scanner that found them",
      all(x["scanner"] == "nuclei" for x in _items),
      [x["scanner"] for x in _items])
check("...with a first_seen and a last_seen of their own",
      all(x["first_seen_at"] and x["last_seen_at"] for x in _items), _items[:1])

# The second scan reports only one of them. The other was LOOKED FOR
# by a tool that reports this kind of finding, and not reported.
st, r = call("/api/scans/import?project=LIFE", "POST",
             {"format": "nuclei", "mode": "open", "content": _nuclei(["cve-a"])}, token=admin)
check("second scan imported", st == 200, (st, r))
check("...creating nothing new", (r or {}).get("vulns_created") == 0, r)

st, v = call("/api/vulns?project=LIFE&limit=50", token=admin)
_by = {x["title"]: x for x in ((v or {}).get("items") or [])}
check("the finding reported again is PRESENT",
      _by.get("finding cve-a", {}).get("lifecycle") == "present",
      _by.get("finding cve-a"))
check("...and no longer NEW, because it was seen before",
      _by.get("finding cve-a", {}).get("lifecycle") != "new")
check("the one that was looked for and not found is RESOLVED",
      _by.get("finding cve-b", {}).get("lifecycle") == "resolved",
      _by.get("finding cve-b"))
check("...and the resolution says which scan cleared it",
      "nuclei" in (_by.get("finding cve-b", {}).get("lifecycle_why") or ""),
      _by.get("finding cve-b", {}).get("lifecycle_why"))
check("...and carries when the host was last looked at",
      bool(_by.get("finding cve-b", {}).get("last_looked_at")),
      _by.get("finding cve-b"))

# The rule, stated as a test. A DIFFERENT tool sweeping the same host
# must not resolve a nuclei finding: an nmap run says nothing about
# whether a web vulnerability is still there.
print("\n-- a different scanner does not close another's findings --")
NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1700000000">
 <host><status state="up"/>
  <address addr="198.51.100.77" addrtype="ipv4"/>
  <hostnames><hostname name="app.acme.example" type="PTR"/></hostnames>
  <ports><port protocol="tcp" portid="443"><state state="open"/>
   <service name="https"/></port></ports>
 </host>
</nmaprun>
"""
st, r = call("/api/scans/import?project=LIFE", "POST",
             {"format": "nmap", "mode": "open", "content": NMAP}, token=admin)
check("an nmap scan of the same host imports", st == 200, (st, r))
st, v = call("/api/vulns?project=LIFE&limit=50", token=admin)
_by = {x["title"]: x for x in ((v or {}).get("items") or [])}
check("the nuclei finding is still PRESENT after an nmap sweep",
      _by.get("finding cve-a", {}).get("lifecycle") == "present",
      _by.get("finding cve-a"))

print("\n-- a finding somebody typed in --")
st, mv = call("/api/vulns?project=LIFE", "POST",
              {"host": "app.acme.example",
               "title": "Reviewer found this by hand",
               "severity": "medium"}, token=admin)
check("a manual finding can be created", st == 201, (st, mv))
check("...and has no scanner", (mv or {}).get("scanner") is None, mv)
st, r = call("/api/scans/import?project=LIFE", "POST",
             {"format": "nuclei", "mode": "open", "content": _nuclei(["cve-a"])}, token=admin)
st, v = call("/api/vulns?project=LIFE&limit=50", token=admin)
_by = {x["title"]: x for x in ((v or {}).get("items") or [])}
_hand = _by.get("Reviewer found this by hand", {})
check("a scan does not resolve a person's finding",
      _hand.get("lifecycle") == "unconfirmed", _hand)

print("\n-- filtering, and the summary --")
st, v = call("/api/vulns?project=LIFE&state=resolved&limit=50", token=admin)
_res = (v or {}).get("items") or []
check("the listing can be filtered to what was resolved",
      [x["title"] for x in _res] == ["finding cve-b"],
      [x["title"] for x in _res])
st, v = call("/api/vulns?project=LIFE&state=present&limit=50", token=admin)
check("...and to what is still there",
      [x["title"] for x in ((v or {}).get("items") or [])] == ["finding cve-a"])

st, s = call("/api/vulns/lifecycle?project=LIFE", token=admin)
check("the summary reads", st == 200, (st, s))
_c = (s or {}).get("counts") or {}
check("one resolved", _c.get("resolved") == 1, _c)
check("one still present", _c.get("present") == 1, _c)
check("one unconfirmed -- the hand-written one", _c.get("unconfirmed") == 1, _c)
check("every state is in the summary even at zero",
      set(_c) == set(lc.STATES), _c)
check("the summary carries what each word means, so a report can "
      "print the definition next to the number",
      set((s or {}).get("meaning") or {}) == set(lc.STATES))
# "0 resolved" from a tool that has not run in six weeks is not good
# news, and the summary has to make that readable.
_sc = {x["scanner"]: x for x in ((s or {}).get("scanners") or [])}
check("the summary says when each scanner last looked",
      "nuclei" in _sc and _sc["nuclei"]["last_looked_at"], _sc)
check("...including the other tool that swept the host",
      "nmap" in _sc, sorted(_sc))
check("the host with an unconfirmed finding is named, not just counted",
      "app.acme.example" in ((s or {}).get("unconfirmed_hosts") or []), s)

print("\n-- a re-scan revives rather than fights a stored column --")
# The state is derived per request, so a finding that comes back
# needs nothing cleared first.
st, r = call("/api/scans/import?project=LIFE", "POST",
             {"format": "nuclei", "mode": "open", "content": _nuclei(["cve-a", "cve-b"])}, token=admin)
check("the third scan sees cve-b again", st == 200, (st, r))
st, v = call("/api/vulns?project=LIFE&limit=50", token=admin)
_by = {x["title"]: x for x in ((v or {}).get("items") or [])}
check("the resolved finding is PRESENT again with nothing to undo",
      _by.get("finding cve-b", {}).get("lifecycle") == "present",
      _by.get("finding cve-b"))
check("...and is not called NEW, because it was seen in March",
      _by.get("finding cve-b", {}).get("lifecycle") != "new",
      _by.get("finding cve-b"))
check("...and no second row was forked for it",
      len([x for x in ((v or {}).get("items") or [])
           if x["title"] == "finding cve-b"]) == 1)

print("\n-- the target page agrees with the listing --")
st, d = call("/api/targets/LIFE/app.acme.example/detail", token=admin)
check("the target detail reads", st == 200, st)
_tv = {x["title"]: x for x in ((d or {}).get("vulns") or [])}
check("...and carries the same verdicts",
      _tv.get("finding cve-a", {}).get("lifecycle") == "present", _tv.keys())
check("...including for the hand-written finding",
      _tv.get("Reviewer found this by hand", {}).get("lifecycle")
      == "unconfirmed")

# ============================================================
# The hole in `resolved`, and the manifest that closes it
# ============================================================
#
#     nuclei -severity critical,high   found CVE-2021-44228
#     nuclei -severity critical        did not
#
# Same tool, same host, later timestamp. Nothing about any of those
# says the second run was configured not to look, and before the
# manifest the tool said `resolved` out loud.

print("\n== what a run was configured to look for ==")
from app import manifest as mf

_a = mf.build("nuclei", "-severity critical,high -rate 150 -c 25")
_b = mf.build("nuclei", "-severity high,critical -rate 900 -timeout 30")
_c = mf.build("nuclei", "-severity critical")
check("pacing is not part of a run's identity", _a[0] == _b[0], (_a, _b))
check("...nor is the order a filter was written in", _a[0] == _b[0])
check("a narrower template filter IS a different run", _a[0] != _c[0])
check("the detail says what went into the hash",
      _a[1] == {"tool": "nuclei", "-severity": "critical,high"}, _a[1])
check("...and the difference is reportable in words",
      mf.differences(_a[1], _c[1]) == ["-severity: 'critical,high' -> "
                                       "'critical'"],
      mf.differences(_a[1], _c[1]))

# nmap: the things that change what a scan can FIND.
_n1 = mf.build("nmap", "nmap -sV -p 1-1024 -T4 --script default,safe")
_n2 = mf.build("nmap", "nmap -sV -p 1-1024 -T2 --script default,safe")
_n3 = mf.build("nmap", "nmap -sV -p 1-65535 --script default,safe")
_n4 = mf.build("nmap", "nmap -sV -sU -p 1-1024 --script default,safe")
check("nmap timing template is not part of the identity", _n1[0] == _n2[0])
check("a wider port range is a different run", _n1[0] != _n3[0])
check("adding UDP is a different run", _n1[0] != _n4[0])
check("a positional target is not part of what was looked FOR",
      mf.build("nmap", "nmap -sV 198.51.100.1")[0]
      == mf.build("nmap", "nmap -sV 203.0.113.9")[0])
check("an unknown flag is dropped rather than guessed at",
      mf.build("nmap", "nmap -sV --some-future-flag x")[0]
      == mf.build("nmap", "nmap -sV")[0])
check("`-severity=high` and `-severity high` are one run",
      mf.build("nuclei", "-severity=high")[0]
      == mf.build("nuclei", "-severity high")[0])
check("an unbalanced quote does not lose the configuration",
      mf.build("nuclei", "-severity high -tags \"unclosed")[1].get("-severity")
      == "high")
check("a tool nothing is known about yields its name and no more",
      mf.build("some-future-tool", "-whatever x")[1] == {
          "tool": "some-future-tool"})

print("\n== a sweep that was configured not to look ==")
_T0 = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
_T1 = datetime(2026, 4, 1, 9, 0, tzinfo=UTC)
_T2 = datetime(2026, 5, 1, 9, 0, tzinfo=UTC)

_same = lc.verdict("nuclei", _T0, _T1, _T2, "abc", "abc")
check("a later sweep with the SAME configuration resolves it",
      _same.state == lc.RESOLVED, _same)
check("...and says the configurations matched",
      "same configuration" in _same.why, _same.why)

_diff = lc.verdict("nuclei", _T0, _T1, _T2, "abc", "xyz")
check("a later sweep configured DIFFERENTLY resolves nothing",
      _diff.state == lc.UNCONFIRMED, _diff)
check("...and says why: it was not looking for this",
      "configured differently" in _diff.why
      and "proves nothing" in _diff.why, _diff.why)
check("...while still reporting that a scan did happen",
      _diff.last_looked == _T2, _diff)
check("...and carrying both manifests, so a UI can name the change",
      (_diff.found_by, _diff.looked_with) == ("abc", "xyz"), _diff)

# Not recorded is NOT the same as configured differently, and the
# weaker claim has to read as the weaker claim.
_unknown = lc.verdict("nuclei", _T0, _T1, _T2, None, None)
check("an unrecorded configuration still resolves",
      _unknown.state == lc.RESOLVED, _unknown)
check("...but says it cannot show the two runs were comparable",
      "not recorded" in _unknown.why, _unknown.why)
check("...which reads differently from a matched configuration",
      _unknown.why != _same.why)
for _one_side in (("abc", None), (None, "abc")):
    _v = lc.verdict("nuclei", _T0, _T1, _T2, *_one_side)
    check(f"one side unrecorded {_one_side} is still the weaker resolve",
          _v.state == lc.RESOLVED and "not recorded" in _v.why, _v)

print("\n== end to end: narrowing the scan does not close findings ==")
call("/api/projects", "POST", {"code": "MANI", "name": "Manifest"},
     token=admin)


def _nuc(ids, args):
    return "\n".join(json.dumps({
        "template-id": i, "host": "shop.acme.example",
        "matched-at": f"https://shop.acme.example/{i}",
        "info": {"name": f"m {i}", "severity": "high"},
        # nuclei records the command line it ran under.
        "cmd": args,
    }) for i in ids)


# The importer reads the command line off the scan where the format
# carries one. For nuclei JSONL it does not, so the manifest is the
# tool name -- which is the unrecorded case, and is covered above.
# Here the shape is proved with nmap, whose XML DOES carry `args`.
def _nmap(ports, scripts):
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" args="nmap -sV -p {ports} --script {scripts}" start="1700000000">
 <host><status state="up"/>
  <address addr="198.51.100.21" addrtype="ipv4"/>
  <hostnames><hostname name="ftp.acme.example" type="PTR"/></hostnames>
  <ports><port protocol="tcp" portid="21"><state state="open"/>
   <service name="ftp" product="vsftpd" version="2.3.4"/>
   <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
  </port></ports>
 </host>
</nmaprun>
"""


st, r = call("/api/scans/import?project=MANI", "POST",
             {"format": "nmap", "mode": "open",
              "content": _nmap("1-1024", "default,safe,vuln")}, token=admin)
check("the full scan imported", st == 200, (st, r))
st, v = call("/api/vulns?project=MANI&limit=20", token=admin)
_items = (v or {}).get("items") or []
check("the NSE finding was raised", len(_items) == 1,
      [x["title"] for x in _items])
check("...and is NEW", _items and _items[0]["lifecycle"] == "new", _items[:1])

# Now a scan of the same host with a NARROWER script set. Scripts
# DID run -- so a sweep is genuinely recorded -- and ftp-anon is not
# among what they reported, because `default` does not include it.
# That is the exact shape that used to say `resolved`.
_NARROW = _nmap("1-1024", "default").replace(
    '<script id="ftp-anon" output="Anonymous FTP login allowed '
    '(FTP code 230)"/>',
    '<script id="ftp-syst" output="STAT: FTP server status"/>')
st, r = call("/api/scans/import?project=MANI", "POST",
             {"format": "nmap", "mode": "open", "content": _NARROW},
             token=admin)
check("the narrower scan imported", st == 200, (st, r))

st, v = call("/api/vulns?project=MANI&limit=20", token=admin)
_items = (v or {}).get("items") or []
check("a scan that was configured not to look does NOT resolve it",
      _items and _items[0]["lifecycle"] == "unconfirmed",
      [(x["title"], x["lifecycle"]) for x in _items])
check("...and says the configuration differed",
      _items and "configured differently" in (_items[0]["lifecycle_why"] or ""),
      _items[0]["lifecycle_why"] if _items else None)

# "The configuration changed" on its own is a dead end for whoever
# reads it. The detail is stored so this list can exist.
st, _d = call(f"/api/vulns/{_items[0]['id']}", token=admin)
_ch = (_d or {}).get("configuration_changed") or []
check("the detail names WHICH part of the configuration changed",
      any("--script" in c for c in _ch), _ch)
check("...showing both sides of it",
      any("vuln" in c and "default" in c for c in _ch), _ch)

# And the control: the SAME script set, with the finding gone, does
# resolve it. Otherwise the above proves only that nothing resolves.
st, r = call("/api/scans/import?project=MANI", "POST",
             {"format": "nmap", "mode": "open",
              "content": _nmap("1-1024", "default,safe,vuln").replace(
                  '<script id="ftp-anon" output="Anonymous FTP login '
                  'allowed (FTP code 230)"/>',
                  '<script id="ftp-syst" output="STAT: ok"/>')}, token=admin)
check("the comparable scan imported", st == 200, (st, r))
st, v = call("/api/vulns?project=MANI&limit=20", token=admin)
_items = (v or {}).get("items") or []
check("the SAME configuration, with the finding gone, DOES resolve it",
      _items and _items[0]["lifecycle"] == "resolved",
      [(x["title"], x["lifecycle"]) for x in _items])
check("...and says the configurations matched",
      _items and "same configuration" in (_items[0]["lifecycle_why"] or ""),
      _items[0]["lifecycle_why"] if _items else None)
st, _d = call(f"/api/vulns/{_items[0]['id']}", token=admin)
check("...with nothing to report as changed, because nothing did",
      ((_d or {}).get("configuration_changed") or []) == [],
      (_d or {}).get("configuration_changed"))


print("\n== a caller with no configuration does not erase one ==")
# The backlog sweep reads a stored column, not a command line, so it
# has no manifest to report -- and it runs at every start. When the
# overwrite was unconditional, one restart wiped the manifest off
# every finding an import had established and quietly downgraded
# every later `resolved` to the weaker kind.
import asyncio as _aio3  # noqa: E402
import inspect as _in3  # noqa: E402

from app import nsefindings as _nf  # noqa: E402
from app.db import SessionLocal as _Sess3  # noqa: E402
from app.models import Target as _T3  # noqa: E402

check("the NSE recorder only sets a manifest it was given",
      "if run_manifest:" in _in3.getsource(_nf.record),
      "record() overwrites found_by_manifest unconditionally")
check("...and so does the sweep recorder",
      "if manifest:" in _in3.getsource(lc.record_sweep),
      "record_sweep() overwrites manifest unconditionally")


async def _manifest_survives():
    """An import establishes a manifest; a sweep must not remove it."""
    from sqlalchemy import select as _s3
    async with _Sess3() as s:
        t = (await s.execute(_s3(_T3))).scalars().first()
        if t is None:
            return None
        await lc.record_sweep(s, t.project_id, t.id, "probe",
                              datetime(2026, 5, 1, tzinfo=UTC), "known-mf")
        await s.commit()
        # The shape of the backlog sweep: a LATER look, with no
        # manifest to report.
        await lc.record_sweep(s, t.project_id, t.id, "probe",
                              datetime(2026, 6, 1, tzinfo=UTC), None)
        await s.commit()
        return (await lc.sweeps_for_targets(s, [t.id])).get((t.id, "probe"))


_sv = _aio3.run(_manifest_survives())
check("a later manifest-less sweep still moves the timestamp",
      bool(_sv) and _sv[0].month == 6, _sv)
check("...but leaves the manifest an import established",
      bool(_sv) and _sv[1] == "known-mf", _sv)


print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
_sys.exit(1 if fail else 0)
