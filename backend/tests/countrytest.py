"""The country gates: where an engagement may test, and where a ghost will.

Two independent lists, both empty by default, and both have to say
yes. The part worth testing hardest is not that a wrong country is
refused -- it is what happens when the country is NOT KNOWN, because
that is the case a geographic restriction quietly stops meaning
anything if it is got wrong.
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


from app import countrygate as cg  # noqa: E402

print("== parsing ==")
check("codes are upper-cased and trimmed",
      cg.parse(" jp , GB,us ") == {"JP", "GB", "US"}, cg.parse(" jp , GB,us "))
# A trailing comma is how people type lists. If the empty segment
# became an entry the set would contain "" and match nothing, which
# narrows the list rather than leaving it alone -- a silent tightening
# is as bad as a silent widening.
check("a trailing comma does not become an empty code",
      cg.parse("JP,") == {"JP"}, cg.parse("JP,"))
check("empty is empty, not a set containing nothing useful",
      cg.parse("") == set() and cg.parse(None) == set())
check("render is the inverse and sorts", cg.render(["us", "GB"]) == "GB,US")
check("render of nothing is NULL, not an empty string",
      cg.render([]) is None and cg.render(None) is None)

print("\n== the three outcomes ==")
# The whole module exists for this distinction.
r = cg.check(set(), None)
check("no restriction: anything passes, including an unknown country",
      r.allowed and r.state == "OFF", r.state)
r = cg.check({"GB"}, "GB")
check("a permitted country is allowed", r.allowed and r.state == "ALLOWED")
r = cg.check({"GB"}, "jp")
check("an excluded country is refused",
      not r.allowed and r.state == "REFUSED", r.reason)
r = cg.check({"GB"}, None)
check("an UNKNOWN country does not pass",
      not r.allowed and r.state == "UNKNOWN", r.state)
# And it must not be reported as though it were adjudicated: "we have
# not located this" is a gap someone can close, "this is in Japan" is
# a finished answer, and a log that says the same thing for both sends
# people to the wrong work.
check("...and says so, rather than claiming it was excluded",
      "no known country" in cg.check({"GB"}, None).reason,
      cg.check({"GB"}, None).reason)
check("case does not matter on the way in", cg.check({"GB"}, "gb").allowed)


class _A:
    def __init__(self, c):
        self.geo_country = c


class _T:
    def __init__(self, host, countries):
        self.host = host
        self.addresses = [_A(c) for c in countries]


print("\n== a target with several addresses ==")
# EVERY country it answers in has to be allowed. A CDN-fronted or
# anycast host really is being scanned in each of them, so "one
# address matched" would authorise exactly the traffic the list was
# drawn up to prevent.
r = cg.check_target({"GB"}, _T("cdn.example", ["GB", "JP"]))
check("a host answering in GB and JP is refused by a GB-only list",
      not r.allowed and r.state == "REFUSED", r.reason)
check("...and names the country that did it", "JP" in r.reason, r.reason)
r = cg.check_target({"GB", "JP"}, _T("cdn.example", ["GB", "JP"]))
check("allowed once both are permitted", r.allowed, r.reason)
r = cg.check_target({"GB"}, _T("half.example", ["GB", None]))
check("one unlocated address makes the whole target unknown",
      not r.allowed and r.state == "UNKNOWN", r.reason)
r = cg.check_target({"GB"}, _T("bare.example", []))
check("a target with no address at all is unknown, not allowed",
      not r.allowed and r.state == "UNKNOWN", r.reason)
r = cg.check_target(set(), _T("bare.example", []))
check("...unless nothing is restricted", r.allowed and r.state == "OFF")

print("\n== the API ==")
admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "CGATE", "name": "CGATE"}, token=admin)

st, r = call("/api/ghosts/routing?project=CGATE", token=admin)
check("routing reports the country list", st == 200, st)
check("which starts empty — every project is global until told",
      (r or {}).get("scan_countries") == [], (r or {}).get("scan_countries"))
# The flag the UI greys out on. False in the suite: geolocation is off
# by default and no database is installed.
check("and reports whether geolocation can answer at all",
      (r or {}).get("geoip_available") is False, (r or {}).get("geoip_available"))

st, r = call("/api/ghosts/routing?project=CGATE", "PUT",
             {"scan_countries": ["gb", "JP"]}, token=admin)
check("a list can be set", st == 200, st)
check("...stored normalised and sorted",
      (r or {}).get("scan_countries") == ["GB", "JP"],
      (r or {}).get("scan_countries"))
# Settable with geolocation off on purpose: where an engagement is
# authorised is a fact about the engagement, not about whether we
# happen to have a licence key yet. It simply does not bite until
# there is a database.
check("...even though geolocation is off", st == 200)

st, _ = call("/api/ghosts/routing?project=CGATE", "PUT",
             {"scan_countries": ["GBR"]}, token=admin)
check("a three-letter code is refused", st == 422, st)
st, _ = call("/api/ghosts/routing?project=CGATE", "PUT",
             {"scan_countries": ["england"]}, token=admin)
check("so is a country name", st == 422, st)

st, r = call("/api/ghosts/routing?project=CGATE", "PUT",
             {"max_parallel": 3}, token=admin)
check("omitting the field leaves the list alone",
      (r or {}).get("scan_countries") == ["GB", "JP"],
      (r or {}).get("scan_countries"))
st, r = call("/api/ghosts/routing?project=CGATE", "PUT",
             {"scan_countries": []}, token=admin)
check("an empty list clears it — which is not the same request",
      (r or {}).get("scan_countries") == [], (r or {}).get("scan_countries"))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
