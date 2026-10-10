"""MaxMind GeoLite2: configuration, lookup, and the status entry.

No network. The download path is exercised against a real MaxMind
account by hand (and was, before this was written); what is asserted
here is everything that can go wrong without one — which is most of
it, and all of the parts that fail quietly.
"""
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
passed = failed = 0


def check(label, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" {got}" if got is not None else ""))


def call(p, m="GET", b=None, token=None, key=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    if key:
        # A ghost authenticates with its callback key, not a bearer
        # token. Without this the register call below is a TypeError.
        r.add_header("X-Ghost-Key", key)
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


from app import geoip  # noqa: E402

# =====================================================================
# Part 1 — the edition list
# =====================================================================
print("\n--- EditionIDs ---")

# The exact line from MaxMind's own GeoIP.conf, which is how an
# operator will paste it.
check("a GeoIP.conf EditionIDs line parses",
      geoip.parse_editions("GeoLite2-ASN GeoLite2-City GeoLite2-Country")
      == ["GeoLite2-ASN", "GeoLite2-City", "GeoLite2-Country"])
check("commas work too, because a web form invites them",
      geoip.parse_editions("GeoLite2-ASN,GeoLite2-City")
      == ["GeoLite2-ASN", "GeoLite2-City"])
check("empty falls back to the default set",
      geoip.parse_editions("") == geoip.parse_editions(None)
      == ["GeoLite2-ASN", "GeoLite2-City", "GeoLite2-Country"])
# A typo must not stop the editions that ARE valid from downloading.
check("an unknown edition is dropped, not fatal",
      geoip.parse_editions("GeoLite2-City GeoLite-Typo") == ["GeoLite2-City"])
check("duplicates collapse",
      geoip.parse_editions("GeoLite2-ASN GeoLite2-ASN") == ["GeoLite2-ASN"])
check("the default constant matches MaxMind's own config",
      geoip.DEFAULT_EDITIONS == "GeoLite2-ASN GeoLite2-City GeoLite2-Country")

# =====================================================================
# Part 2 — lookup with no databases present
# =====================================================================
print("\n--- lookup degrades, it does not raise ---")

geoip.DB_DIR = pathlib.Path("/nonexistent/geoip-for-test")
for bad in ("8.8.8.8", "192.168.1.1", "not-an-ip", "", "::1"):
    loc = geoip.lookup(bad)
    check(f"{bad!r} with no database returns an empty answer",
          loc.known is False and loc.address == bad, loc.country)
check("installed() on a missing directory is empty, not an error",
      geoip.installed() == {})

# A malformed address must never reach the reader.
check("a hostname is refused before any lookup",
      geoip.lookup("example.com").sources == [])

# =====================================================================
# Part 3 — the status entry
# =====================================================================
print("\n--- it appears on the status page ---")

admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
st, h = call("/api/health/site", token=admin)
check("status is served", st == 200, st)
mm = (h or {}).get("maxmind")
check("maxmind has an entry", isinstance(mm, dict), type(mm).__name__)
if isinstance(mm, dict):
    check("it reports as unconfigured before a key is set",
          mm.get("configured") is False, mm.get("configured"))
    check("...and says so rather than looking broken",
          "licence key" in (mm.get("note") or ""), mm.get("note"))
    check("it lists the editions it would fetch",
          mm.get("editions") == ["GeoLite2-ASN", "GeoLite2-City",
                                 "GeoLite2-Country"], mm.get("editions"))
    check("and which databases are on disk", "databases" in mm, sorted(mm))

# Setting a key changes `configured` but not `state`: a key that has
# never successfully downloaded anything is the common
# misconfiguration, and one boolean cannot show it.
st, _ = call("/api/settings", "PATCH",
             {"values": {"geoip.account_id": "123456",
                         "geoip.license_key": "not-a-real-key",
                         "geoip.enabled": True}}, token=admin)
check("the settings were accepted", st == 200, st)
st, h = call("/api/health/site", token=admin)
mm = (h or {}).get("maxmind") or {}
check("a key makes it configured", mm.get("configured") is True,
      mm.get("configured"))
check("...but it still has no database and says which",
      "no database has been downloaded" in (mm.get("note") or ""),
      mm.get("note"))

# The key must never come back out of the status page.
check("the licence key is not echoed anywhere in status",
      "not-a-real-key" not in json.dumps(h or {}), "LEAKED")

# =====================================================================
# Part 4 — the metadata is tagged onto the ADDRESS
# =====================================================================
print("\n--- tagged onto the address, not the name ---")

# A real lookup needs real databases, which this suite does not
# download. What is asserted without them: that a lookup still stamps
# `geo_at`, so "nothing known" is distinguishable from "never asked"
# and a private range is not re-queried on every pass for ever.
import asyncio  # noqa: E402

from sqlalchemy import select as _sel  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import Project as _P  # noqa: E402
from app.models import TargetAddress as _A  # noqa: E402

call("/api/projects", "POST", {"code": "GEO", "name": "GEO"}, token=admin)
call("/api/projects/GEO/scope", "POST", {"lines": ["geo.example"]}, token=admin)
call("/api/targets?project=GEO", "POST",
     {"host": "geo.example", "ip_address": "8.8.8.8"}, token=admin)


async def _tag():
    async with SessionLocal() as db:
        pr = (await db.execute(_sel(_P).where(_P.code == "GEO"))).scalar_one()
        addr = (await db.execute(_sel(_A).where(
            _A.project_id == pr.id, _A.address == "8.8.8.8"))).scalar_one()
        check("an address starts un-looked-up", addr.geo_at is None, addr.geo_at)
        await geoip.tag(db, addr)
        await db.commit()
        return addr.geo_at, addr.geo_country


when, country = asyncio.run(_tag())
check("a lookup stamps when it happened, found or not", when is not None, when)
# With no databases present nothing is known, and that is recorded as
# nothing rather than as a guess.
check("...and invents nothing when there is no database",
      country is None, country)

# positioned() is the guard that stops a country centroid being shown
# as a place. Asserted on the dataclass, since it needs no database.
near = geoip.Location(address="1.2.3.4", latitude=1.0, longitude=2.0,
                      accuracy_km=20, city="Somewhere")
far = geoip.Location(address="8.8.8.8", latitude=37.751, longitude=-97.822,
                     accuracy_km=1000)
check("a 20 km answer is a position", near.positioned is True)
check("a 1000 km country centroid is NOT a position",
      far.positioned is False, far.accuracy_km)
check("...though the country is still known from it",
      geoip.Location(country="US").known is True)

# =====================================================================
# Part 5 — it reaches targets and ghosts
# =====================================================================
print("\n--- wired to targets and to ghosts ---")

# A ghost carries its located address on the fleet listing. With no
# database installed that is None, which is the honest answer and is
# what the field means -- not an error, and not a guess.
st, g = call("/api/ghosts?project=GEO", "POST", {"name": "geo-ghost"},
             token=admin)
GKEY = (g or {}).get("callback_key")
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "version": "t",
      "hostname": "geo-box", "privileged": False,
      "outbound_ip": "8.8.8.8"}, key=GKEY)
st, rows = call("/api/ghosts?project=GEO", token=admin)
ghost = next((a for a in (rows or []) if a.get("name", "").startswith("geo-ghost")), None)
check("a ghost reports its outbound address", ghost is not None
      and ghost.get("outbound_ip") == "8.8.8.8", (ghost or {}).get("outbound_ip"))
check("...and carries a geo field, null until a database is installed",
      ghost is not None and "geo" in ghost, sorted(ghost or {}))

# A private address is never located, database or not, and that is
# not an error -- it is what RFC1918 means.
from app import geoip as _g  # noqa: E402

check("a private address is not located",
      _g.lookup("10.0.0.1").known is False)

# The standing-order cycle is where target addresses get tagged. With
# geolocation off it must do nothing at all rather than looking up
# every address on every pass.
import asyncio as _a  # noqa: E402

from app.db import SessionLocal as _S  # noqa: E402


async def _off():
    async with _S() as db:
        from sqlalchemy import select as _sel

        from app.models import Project as _Pr
        pr = (await db.execute(_sel(_Pr).where(_Pr.code == "GEO"))).scalar_one()
        return await _g.tag_missing(db, pr.id)


check("with geolocation off, nothing is tagged", _a.run(_off()) == 0)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
