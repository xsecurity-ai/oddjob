"""MaxMind GeoLite2: configuration, lookup, and the status entry.

No network. The download path is exercised against a real MaxMind
account by hand (and was, before this was written); what is asserted
here is everything that can go wrong without one — which is most of
it, and all of the parts that fail quietly.
"""
import json
import os
import pathlib
import re
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

# =====================================================================
# Part 6 — Location.summary(), which is what a report prints
# =====================================================================
print("\n--- the one-line summary ---")

check("place then network",
      geoip.Location(city="Tokyo", country_name="Japan", asn=2497,
                     organisation="Internet Initiative Japan").summary()
      == "Tokyo, Japan (AS2497 Internet Initiative Japan)")
# MaxMind answers Tokyo with a subdivision also called Tokyo. "Tokyo,
# Tokyo, Japan" reads as a bug in us rather than a quirk of the data.
check("a repeated part is collapsed",
      geoip.Location(city="Tokyo", subdivision="Tokyo",
                     country_name="Japan").summary() == "Tokyo, Japan")
check("the ASN alone is still an answer",
      geoip.Location(asn=64500).summary() == "AS64500")
check("knowing nothing says nothing", geoip.Location().summary() == "")
check("a country code stands in when there is no long name",
      geoip.Location(country="JP").summary() == "JP")

# The batch path opens the databases once instead of once per address.
# It has to agree with the single lookup exactly, or a sweep and a
# one-off would disagree about the same address.
_batch = geoip.lookup_many(["8.8.8.8", "10.0.0.1", "not-an-ip"])
check("the batch answers every address it was given",
      sorted(_batch) == ["10.0.0.1", "8.8.8.8", "not-an-ip"], sorted(_batch))
check("...each carrying its own address back",
      all(k == v.address for k, v in _batch.items()))
check("...and agreeing with the single lookup",
      all(geoip.lookup(k).known == v.known for k, v in _batch.items()))
check("an empty batch is empty, not an error", geoip.lookup_many([]) == {})

# =====================================================================
# Part 7 — the enumerate routes
# =====================================================================
print("\n--- Enumerate: locate addresses ---")

# Three addresses on two targets, so the counts below are not 1.
call("/api/projects/GEO/scope", "POST",
     {"lines": ["geo2.example", "geo3.example"]}, token=admin)
call("/api/targets?project=GEO", "POST",
     {"host": "geo2.example", "ip_addresses": ["198.51.100.7", "198.51.100.8"]},
     token=admin)
call("/api/targets?project=GEO", "POST",
     {"host": "geo3.example", "ip_address": "203.0.113.9"}, token=admin)

st, g = call("/api/enumerate/geolocation?project=GEO", token=admin)
check("the state is readable", st == 200, st)
# 8.8.8.8 was tagged by hand in part 4, so it is not in the backlog.
check("...and counts only what has never been asked",
      (g or {}).get("remaining") == 3, (g or {}).get("remaining"))
check("with no database it reports itself unusable",
      (g or {}).get("usable") is False, (g or {}).get("usable"))
# The note has to name BOTH halves. "Disabled" alone sends half the
# people who read it to the wrong page.
check("...and the note names the switch and the database",
      "Settings" in ((g or {}).get("note") or "")
      and "database" in ((g or {}).get("note") or ""), (g or {}).get("note"))

st, r = call("/api/enumerate/geolocate?project=GEO", "POST", {}, token=admin)
check("locating with it switched off is a 200 and a note, not an error",
      st == 200 and (r or {}).get("usable") is False, st)
check("...and it wrote nothing",
      (r or {}).get("located") == {} and (r or {}).get("unknown") == [],
      (r or {}).get("located"))

# A GET must never be the thing that does the work.
st, g2 = call("/api/enumerate/geolocation?project=GEO", token=admin)
check("asking twice changed nothing",
      (g2 or {}).get("remaining") == 3, (g2 or {}).get("remaining"))

# Now switch it on with a database present. The file is not a real
# GeoLite2 database -- they are not redistributable and this repo is
# public -- so every lookup comes back knowing nothing. That is the
# case worth asserting anyway: it proves "asked and nothing known" is
# recorded AS asked, which is the whole reason `geo_at` exists.
import os as _os  # noqa: E402

_dir = pathlib.Path(_os.environ.get("ODDJOB_GEOIP_DIR",
                                    "/tmp/ms-geoip-unset"))
_dir.mkdir(parents=True, exist_ok=True)
(_dir / "GeoLite2-City.mmdb").write_bytes(b"not a real mmdb")

st, g = call("/api/enumerate/geolocation?project=GEO", token=admin)
check("a database on disk makes it usable", (g or {}).get("usable") is True,
      (g or {}).get("usable"))
# The GET must not be the thing that does the work, and this is the
# only place that can prove it: with geolocation off it could not have
# done any. Asked twice while it is fully able to, the backlog must be
# untouched, because a menu opening is not an operation on inventory.
check("...and reading the state still locates nothing",
      (g or {}).get("remaining") == 3, (g or {}).get("remaining"))
st, g = call("/api/enumerate/geolocation?project=GEO", token=admin)
check("...however many times it is asked",
      (g or {}).get("remaining") == 3, (g or {}).get("remaining"))

st, r = call("/api/enumerate/geolocate?project=GEO", "POST", {}, token=admin)
check("the run is accepted", st == 200, st)
check("an unreadable database locates nothing rather than raising",
      (r or {}).get("located") == {}, (r or {}).get("located"))
# The distinction the whole report exists for.
check("...and the addresses land in 'no data', not in 'never asked'",
      sorted((r or {}).get("unknown") or [])
      == ["198.51.100.7", "198.51.100.8", "203.0.113.9"],
      (r or {}).get("unknown"))
check("nothing is left unasked afterwards",
      (r or {}).get("remaining") == 0, (r or {}).get("remaining"))

# Asked-and-unknown must not be re-asked. Without `geo_at` this would
# go round for ever on every private range in the estate.
st, g = call("/api/enumerate/geolocation?project=GEO", token=admin)
check("an address that answered nothing is not asked again",
      (g or {}).get("remaining") == 0, (g or {}).get("remaining"))
st, r = call("/api/enumerate/geolocate?project=GEO", "POST", {}, token=admin)
check("...so a second run has nothing to do",
      (r or {}).get("unknown") == [] and (r or {}).get("located") == {},
      (r or {}).get("unknown"))

# Readonly may look; writing is a user action.
st, _ = call("/api/enumerate/geolocation?project=GEO")
check("anonymous cannot read the state", st in (401, 403), st)
st, _ = call("/api/enumerate/geolocate?project=GEO", "POST", {})
check("anonymous cannot run it", st in (401, 403), st)

# =====================================================================
# Part 7b — the download, which nothing used to be able to trigger
# =====================================================================
print("\n--- the databases can be fetched ---")

# No network here, so what is asserted is everything around the
# download: who may ask, that a failure is reported per edition rather
# than as one boolean, and that the licence key does not come back out
# in the answer or go into the audit trail. The download itself is
# exercised by hand against a real MaxMind account.
st, _ = call("/api/settings/geoip/refresh", "POST", {})
check("anonymous cannot trigger a download", st in (401, 403), st)

st, r = call("/api/settings/geoip/refresh", "POST", {}, token=admin)
check("a site admin can", st == 200, st)
check("...and the key it was configured with is a bad one, so it fails",
      (r or {}).get("ok") is False, (r or {}).get("ok"))
# Per edition. "2 of 3 worked" cannot say which one to go and fix.
_eds = (r or {}).get("editions") or {}
check("every configured edition is reported on",
      sorted(_eds) == ["GeoLite2-ASN", "GeoLite2-City", "GeoLite2-Country"],
      sorted(_eds))
# A 401 against a download URL reads like the database is missing
# rather than the key being wrong, so it has to say which.
check("...and a rejected key says so in words",
      any("account id and licence key" in v for v in _eds.values()),
      list(_eds.values())[:1])
check("the licence key is not echoed in the result",
      "not-a-real-key" not in json.dumps(r or {}), "LEAKED")

from app.models import AuditEvent as _AE  # noqa: E402


async def _audit_rows():
    async with SessionLocal() as db:
        return [(r.action, r.detail or "") for r in (await db.execute(
            _sel(_AE).where(_AE.action == "geoip.refresh"))).scalars()]


_rows = asyncio.run(_audit_rows())
check("the attempt is in the audit trail", len(_rows) == 1, len(_rows))
# The request this made carried the licence key. The record of it
# must not.
check("...and the licence key is not in it",
      all("not-a-real-key" not in d for _, d in _rows), "LEAKED")
check("...while the per-edition outcome is",
      any("GeoLite2-City" in d for _, d in _rows), _rows[:1])

# The health page already diagnosed this state; now it is actionable.
st, hh = call("/api/health/site", token=admin)
_mm = (hh or {}).get("maxmind") or {}
check("health still names the editions it would fetch",
      _mm.get("editions") == ["GeoLite2-ASN", "GeoLite2-City",
                              "GeoLite2-Country"], _mm.get("editions"))

# =====================================================================
# Part 8 — the country reaches the target row
# =====================================================================
print("\n--- the Targets grid can show it ---")

st, rows = call("/api/targets?project=GEO", token=admin)
items = (rows or {}).get("items") or []
g2row = next((t for t in items if t.get("host") == "geo2.example"), None)
check("a target carries the geo roll-up", g2row is not None
      and "geo_country" in g2row, sorted(g2row or {}))
if g2row:
    check("no country is known from an unreadable database",
          g2row.get("geo_country") is None, g2row.get("geo_country"))
    # The field that stops a blank cell being read as a fact about
    # the host rather than a gap in our coverage.
    check("...and it reports nothing left unasked",
          g2row.get("geo_pending") == 0, g2row.get("geo_pending"))
    check("the country list is empty, not absent",
          g2row.get("geo_countries") == [], g2row.get("geo_countries"))

# Provider is gone from the grid but NOT from the API: a cloud target
# is still named as its provider names it, and the Type chip shows it.
check("provider is still on the target payload",
      g2row is not None and "provider" in g2row, sorted(g2row or {}))


# A target whose addresses span two countries must report both. Written
# straight onto the address rows, because an unreadable database cannot
# produce this and it is the case the column exists to show.
async def _two_countries():
    async with SessionLocal() as db:
        pr = (await db.execute(_sel(_P).where(_P.code == "GEO"))).scalar_one()
        for a, c, n in (("198.51.100.7", "JP", "Japan"),
                        ("198.51.100.8", "SG", "Singapore")):
            row = (await db.execute(_sel(_A).where(
                _A.project_id == pr.id, _A.address == a))).scalar_one()
            row.geo_country, row.geo_country_name = c, n
        await db.commit()


asyncio.run(_two_countries())
st, rows = call("/api/targets?project=GEO", token=admin)
g2row = next((t for t in ((rows or {}).get("items") or [])
              if t.get("host") == "geo2.example"), None)
check("a CDN-fronted host reports every country it answers in",
      (g2row or {}).get("geo_countries") == ["JP", "SG"],
      (g2row or {}).get("geo_countries"))
check("...and the single-value field is the first of them",
      (g2row or {}).get("geo_country") == "JP", (g2row or {}).get("geo_country"))
check("...with its long name alongside",
      (g2row or {}).get("geo_country_name") == "Japan",
      (g2row or {}).get("geo_country_name"))


# --- the databases have to outlive the container ---------------------
#
# A download that lands in the writable layer is thrown away by the
# next deploy, and watchtower deploys on every push to main. The
# failure is quiet in the worst way: the Country column goes back to
# "not looked yet", which is a true statement about the data and a
# false one about why. So the volume is asserted, not remembered.
# Not `geoip.DB_DIR` -- the suite runs with ODDJOB_GEOIP_DIR pointed
# at a scratch directory, so the live value is the test's, not the
# one a container uses. What has to agree with the compose file is
# the fallback, so that is what gets read.
_root = pathlib.Path(__file__).resolve().parents[2]
_compose = (_root / "docker-compose.yml").read_text()
_dockerfile = (_root / "Dockerfile").read_text()
_m = re.search(r'ODDJOB_GEOIP_DIR",\s*"([^"]+)"',
               (_root / "backend/app/geoip.py").read_text())
check("geoip.py still has a default path to anchor this to", bool(_m))
DB_DIR = _m.group(1) if _m else "\0"

check("the geoip directory is a named volume, not the writable layer",
      f":{DB_DIR}" in _compose, str(DB_DIR))
check("...and that volume is declared",
      "\n  geoip:\n" in _compose)
# Docker seeds a new named volume from the image's directory, owner
# included. Without the directory in the image the volume arrives
# owned by root, the app runs as 10001, and the first download dies
# on EACCES -- with the volume correctly in place the whole time.
check("...and the image creates it owned by the uid that writes to it",
      f"--chown=10001:10001 /empty {DB_DIR}" in _dockerfile)


# ================================================== netblock expansion
# Both assertions below exist because the first version of this code
# got them wrong against the real engagement, not in theory.
from app.geoip import ENUMERABLE_V4_PREFIX, Netblock  # noqa: E402

print("\n== IPv6 prefixes are never 'enumerable' ==")
v6 = Netblock(network="2001:db8::/32", asn=64500, organisation="ACME",
              known=3, size=2 ** 96, version=6)
check("a v6 /32 is not enumerable", v6.enumerable is False)
check("...and reports unseen as None, not as a count", v6.unseen is None, v6.unseen)
# Sorting by raw `unseen` put v6 prefixes above every v4 one: a /32
# holds 7.9e28 addresses, so "unseen opportunity" was true, useless
# and misleading next to a /24 holding 256.
v4 = Netblock(network="203.0.113.0/24", asn=64500, organisation="ACME",
              known=10, size=256, version=4)
check("a v4 /24 is enumerable", v4.enumerable is True)
check("...and reports a real remainder", v4.unseen == 246, v4.unseen)

print("\n== an allocation is not a client block ==")
big = Netblock(network="10.0.0.0/8", asn=64500, organisation="ACME",
               known=1, size=2 ** 24, version=4)
check(f"a v4 prefix larger than /{ENUMERABLE_V4_PREFIX} is not enumerable",
      big.enumerable is False)
check("...so it offers no remainder to go and sweep", big.unseen is None)
edge = Netblock(network="198.51.0.0/16", asn=64500, organisation="ACME",
                known=4, size=65536, version=4)
check(f"a /{ENUMERABLE_V4_PREFIX} itself is still enumerable",
      edge.enumerable is True)

print("\n== density decides the order, not the size of the remainder ==")
# Measured against a real engagement: sorting by `unseen` put eight
# provider /16s holding ONE address apiece at the top. "65,535
# addresses you have not looked at" is true of every allocation we
# ever touched once, and acting on it means scanning somebody else's
# network.
sparse = Netblock(network="192.0.0.0/16", asn=1, organisation="A provider",
                  known=1, size=65536, version=4)
dense = Netblock(network="203.0.113.0/24", asn=2, organisation="ACME",
                 known=70, size=256, version=4)
ordered = sorted([sparse, dense],
                 key=lambda n: (0 if n.enumerable else 1,
                                -n.known, -(n.unseen or 0), n.network))
check("the prefix we hold 70 addresses in sorts above the one we hold 1 in",
      ordered[0].network == dense.network,
      [n.network for n in ordered])
check("...even though the sparse one has far more unseen",
      (sparse.unseen or 0) > (dense.unseen or 0),
      (sparse.unseen, dense.unseen))


print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
