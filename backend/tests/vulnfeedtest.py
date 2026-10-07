"""Exploit and CVE feeds, and the boundary they exist to keep.

The point of holding this data locally is not performance. It is that
the question "is anything known about Apache 2.4.49" becomes "this
client runs Apache 2.4.49" the moment it is asked of somebody else, and
over a 4,000-host engagement that is the client's whole software
inventory handed to a third party.

So the tests that matter most here are the ones about what a stale or
empty feed is allowed to claim. "No known exploits" from a table that
has never synced is a lie with a reassuring shape.
"""

import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json, os, urllib.error, urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8019")
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


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]

print("== parsing, without touching the network ==")
from app.vulnfeed import (_parse_exploits, parse_cve, product_terms,
                          version_matches)

CSV = ("id,file,description,date_published,author,type,platform,port,codes,verified\n"
       "50383,exploits/multiple/webapps/50383.sh,Apache HTTP Server 2.4.49 - "
       "Path Traversal,2021-10-05,Lucas,webapps,multiple,80,"
       "CVE-2021-41773;CVE-2021-42013,1\n"
       "9999,exploits/linux/local/9999.c,Some Local Thing,2020-01-01,x,local,"
       "linux,,,0\n"
       "not-a-number,x,y,z,a,b,c,,,\n")
rows = _parse_exploits(CSV)
check("usable rows are parsed", len(rows) == 2, str(len(rows)))
check("and a malformed id is skipped, not crashed on",
      all(isinstance(r["id"], int) for r in rows), str(rows)[:120])
first = rows[0]
check("CVEs are pulled out of the codes column",
      first["cves"] == "CVE-2021-41773,CVE-2021-42013", str(first["cves"]))
check("verified is a boolean, not the string '1'",
      first["verified"] is True, str(first["verified"]))
check("an empty port is None rather than 0", rows[1]["port"] is None,
      str(rows[1]["port"]))

# The published CSV really does repeat ids. A straight insert finds out
# as a primary key violation, AFTER it has deleted the old table — so
# the first live sync wiped the data and then failed to replace it.
DUPES = ("id,file,description,date_published,author,type,platform,port,codes,verified\n"
         "16929,a,First copy,2020-01-01,x,remote,aix,,,0\n"
         "16929,a2,Second copy,2021-01-01,y,remote,aix,,,1\n")
dup = _parse_exploits(DUPES)
check("a repeated id collapses to one row", len(dup) == 1, str(len(dup)))
check("keeping the later entry, as a republished one supersedes it",
      dup[0]["title"] == "Second copy", str(dup[0]["title"]))

NVD = {"cve": {
    "id": "CVE-2021-41773",
    "published": "2021-10-05T07:15:07.000",
    "lastModified": "2023-11-07T03:38:29.297",
    "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 7.5, "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}],
}}
rec = parse_cve(NVD)
check("a CVE record is flattened", rec["id"] == "CVE-2021-41773", str(rec)[:90])
check("with its score and severity",
      rec["cvss_score"] == 7.5 and rec["severity"] == "high", str(rec)[:120])
check("and a product index for the cheap first pass",
      "apache http server" in (rec["products"] or ""), str(rec["products"]))
check("a record with no id is refused rather than stored as null",
      parse_cve({"cve": {}}) is None)

print("\n== matching is approximate, and errs toward showing you more ==")
check("noise words are not searched on",
      "server" not in product_terms("Apache HTTP Server"),
      str(product_terms("Apache HTTP Server")))
check("the product name survives",
      "apache" in product_terms("Apache HTTP Server"),
      str(product_terms("Apache HTTP Server")))
check("an exact version matches",
      version_matches("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "2.4.49"))
check("a different version does not",
      not version_matches("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "2.4.50"))
# Over-matching is the right way round for something producing leads a
# person will check; under-matching hides the one that mattered.
check("a wildcard CPE covers everything, rather than nothing",
      version_matches("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "9.9.9"))

print("\n== an unsynced feed does not get to say 'nothing found' ==")
st, s = call("/api/vulnfeeds/status", token=admin)
check("status is readable", st == 200, f"status={st}")
check("and says the feeds have never run",
      s.get("usable") is False, str(s)[:160])
check("in words that distinguish 'not held' from 'does not exist'",
      any("not 'nothing exists'" in w for w in s.get("warnings", [])),
      str(s.get("warnings"))[:200])

st, r = call("/api/vulnfeeds/search?q=apache", token=admin)
check("a search works against an empty table", st == 200, f"status={st}")
check("returns nothing", r.get("results") == [], str(r)[:100])
# The caveat has to travel WITH the result. A caller that only reads
# `results` must still be handed the reason it is empty.
check("but carries the feed state with it, so the emptiness is explained",
      r.get("feeds", {}).get("usable") is False, str(r.get("feeds"))[:140])

st, r = call("/api/vulnfeeds/cve/CVE-2021-41773", token=admin)
check("an unknown CVE is a 404", st == 404, f"status={st}")
check("that says the feed has never synced rather than implying it is fake",
      "never synced" in str(r), str(r)[:180])

print("\n== the lookup takes software, never a host ==")
st, r = call("/api/vulnfeeds/leads?product=Apache%20httpd&version=2.4.49",
             token=admin)
check("leads are looked up by product and version", st == 200, f"status={st}")
check("and say what they searched on", r.get("terms"), str(r)[:140])
check("with the caveat attached",
      "not findings" in (r.get("caveat") or ""), str(r.get("caveat"))[:120])
st, r = call("/api/vulnfeeds/leads", token=admin)
check("asking for nothing in particular is refused", st == 422, f"status={st}")

print("\n== who may make it reach the internet ==")
call("/api/users", "POST", {"username": "plain", "password": "plain-password-1"},
     token=admin)
plain = call("/api/auth/login", "POST",
             {"username": "plain", "password": "plain-password-1"})[1]["access_token"]
st, _ = call("/api/vulnfeeds/sync?source=exploitdb", "POST", {}, token=plain)
check("an ordinary user cannot start a sync", st == 403, f"status={st}")
st, _ = call("/api/vulnfeeds/status", token=plain)
check("but can read how current the data is", st == 200, f"status={st}")
st, _ = call("/api/vulnfeeds/status")
check("and anonymous cannot", st in (401, 403), f"status={st}")

st, r = call("/api/vulnfeeds/stats", token=admin)
check("stats report what is held", st == 200 and r.get("exploits") == 0,
      str(r)[:120])

print("\n== NVD date windows stay inside what NVD accepts ==")
# NVD refuses a range wider than 120 days. The resume path is where
# this bites: a backfill that runs out of page budget parks the cursor
# years in the past, and asking for (cursor, now) as one span would
# wedge every sync after it.
from datetime import datetime, timedelta, timezone          # noqa: E402
from app.vulnfeed import _nvd_windows, NVD_EPOCH            # noqa: E402

now = datetime(2026, 10, 7, tzinfo=timezone.utc)
full = _nvd_windows(NVD_EPOCH, now)
check("a full backfill splits into many windows", len(full) > 70, str(len(full)))
check("none of them exceeds NVD's 120-day limit",
      all((b - a) <= timedelta(days=120) for a, b in full),
      str(max((b - a).days for a, b in full)))
check("they cover the whole span without a gap",
      full[0][0] == NVD_EPOCH and full[-1][1] == now
      and all(full[i][1] == full[i + 1][0] for i in range(len(full) - 1)),
      f"{full[0][0]}..{full[-1][1]}")

stale = _nvd_windows(datetime(2009, 3, 1, tzinfo=timezone.utc), now)
check("resuming from a years-old cursor also chunks, rather than "
      "asking for one illegal 17-year range",
      len(stale) > 50 and all((b - a) <= timedelta(days=120) for a, b in stale),
      str(len(stale)))

fresh = _nvd_windows(now - timedelta(hours=2), now)
check("an ordinary daily run is still a single request", len(fresh) == 1,
      str(len(fresh)))
check("a zero-width span still yields one window rather than none",
      len(_nvd_windows(now, now)) == 1, str(_nvd_windows(now, now)))

print("\n== a wildcard CPE is not evidence about a version ==")
from app.vulnfeed import match_kind, version_matches                # noqa: E402

exact = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
anyver = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
check("a CPE naming the version is exact",
      match_kind(exact, "2.4.49") == "exact", str(match_kind(exact, "2.4.49")))
check("a wildcard CPE is reported as any-version, not as a match on it",
      match_kind(anyver, "2.4.49") == "any-version",
      str(match_kind(anyver, "2.4.49")))
check("a different version does not match", match_kind(exact, "2.4.50") is None,
      str(match_kind(exact, "2.4.50")))
# The over-match is deliberate: a wildcard still passes the boolean, so
# leads surface rather than being filtered away. Only the label differs.
check("but a wildcard still counts as a match, so the lead is not dropped",
      version_matches(anyver, "2.4.50") is True, "")
check("a malformed CPE matches nothing", match_kind("cpe:2.3:a", "1.0") is None,
      str(match_kind("cpe:2.3:a", "1.0")))

print("\n== a failed sync keeps the ground it covered ==")
# A first NVD sync is hours long. Losing all of it to one dropped DNS
# lookup means that on a flaky connection it never finishes at all --
# which is how this was found: a real sync died at 21,545 records and
# parked no cursor, so the next run would have started again at 2002.
import asyncio as _aio                                           # noqa: E402
from datetime import datetime as _dt, timezone as _tz            # noqa: E402
import app.vulnfeed as _vf                                       # noqa: E402
from app.db import SessionLocal as _SL                           # noqa: E402


async def _failing_sync():
    """Let three windows land, then fail the way a dropped link does."""
    calls = {"n": 0}

    class _Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"vulnerabilities": [], "totalResults": 0}

    class _Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, params=None):
            calls["n"] += 1
            if calls["n"] > 3:
                raise ConnectionError("nodename nor servname provided")
            return _Resp()

    # Patch the delay constant, not asyncio.sleep: _vf.asyncio is the
    # one shared module object, so replacing its sleep replaces it for
    # everything in the process -- including the replacement, which then
    # calls itself.
    real_client, real_delay = _vf.httpx.AsyncClient, _vf.NVD_DELAY_NO_KEY
    _vf.httpx.AsyncClient = lambda *a, **k: _Client()
    _vf.NVD_DELAY_NO_KEY = 0
    try:
        async with _SL() as s:
            st = await _vf._state(s, "nvd")
            st.cursor = None
            st.error = None
            await s.commit()
            r = await _vf.sync_nvd(s, api_key="")
            st = await _vf._state(s, "nvd")
            return r, st.cursor, st.error, st.running
    finally:
        _vf.httpx.AsyncClient, _vf.NVD_DELAY_NO_KEY = real_client, real_delay


_res, _cursor, _err, _running = _aio.run(_failing_sync())
check("a sync that dies reports failure rather than success",
      _res.get("ok") is False, str(_res)[:120])
check("and records why", "nodename" in (_err or ""), str(_err)[:120])
check("and clears the running flag, so the next run is not locked out",
      _running is False, str(_running))
check("and parks a cursor past the epoch, so the work already done "
      "is not repeated",
      _cursor is not None and _dt.fromisoformat(_cursor) > _vf.NVD_EPOCH,
      f"cursor={_cursor}")
# The resume point must be a window boundary that completed, never the
# one that was in flight when the connection dropped -- resuming inside
# a half-read window silently loses whatever it had not reached.
check("at a boundary that actually completed",
      _cursor is not None
      and _dt.fromisoformat(_cursor) <= _dt.now(_tz.utc),
      f"cursor={_cursor}")

print("\n== a banner and a CPE spell a version differently ==")
# OpenSSH reports 8.2p1; NVD records the patch level in the CPE's
# separate `update` segment, as cpe:...:openssh:8.2:p1:*. Comparing the
# banner string to the version segment therefore never matched, and
# every OpenSSH lookup silently returned product-level hits only --
# which reads as "nothing specific is known", the most reassuring
# possible way to be wrong.
from app.vulnfeed import version_candidates as _vc                  # noqa: E402

check("a patch-suffixed version also tries its base",
      _vc("8.2p1") == ["8.2p1", "8.2"], str(_vc("8.2p1")))
check("a packager's suffix is trimmed",
      "1.18.0" in _vc("1.18.0-6ubuntu14"), str(_vc("1.18.0-6ubuntu14")))
check("a lettered release tries its base too",
      "1.0.2" in _vc("1.0.2k"), str(_vc("1.0.2k")))
check("an ordinary version is left alone",
      _vc("2.4.49") == ["2.4.49"], str(_vc("2.4.49")))
check("and nothing in means nothing out", _vc("") == [], str(_vc("")))

_openssh = "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*"
check("so the CPE NVD actually publishes matches the banner",
      match_kind(_openssh, "8.2p1") == "exact",
      str(match_kind(_openssh, "8.2p1")))
check("without making every version match",
      match_kind(_openssh, "9.1p1") is None,
      str(match_kind(_openssh, "9.1p1")))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
_sys.exit(1 if fail else 0)
