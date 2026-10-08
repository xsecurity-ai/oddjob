"""Web addresses, and the domain roots they group under."""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8017")
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
call("/api/projects", "POST", {"code": "WEB", "name": "Web"}, token=admin)


def imp(content, fmt="auto", project="WEB", mode="open"):
    return call(f"/api/scans/import?project={project}", "POST",
                {"content": content, "format": fmt, "mode": mode}, token=admin)


# ===================================================== web address capture
HTTPX = "\n".join(json.dumps(x) for x in [
    {"url": "https://shop.corp.com", "input": "shop.corp.com", "host": "10.0.0.1",
     "port": 443, "scheme": "https", "status_code": 200, "title": "Shop",
     "webserver": "nginx", "tech": ["Nginx"], "content_length": 900},
    {"url": "http://shop.corp.com:8080/admin", "input": "shop.corp.com",
     "host": "10.0.0.1", "port": 8080, "scheme": "http", "status_code": 401,
     "title": "Admin"},
])
NUCLEI = json.dumps({
    "template-id": "exposed-env", "info": {"name": "Exposed .env", "severity": "high"},
    "host": "https://shop.corp.com", "matched-at": "https://shop.corp.com/.env"})
BURP = """<?xml version="1.0"?>
<issues burpVersion="2024.1">
<issue><serialNumber>1</serialNumber><type>5244928</type><name>Reflected XSS</name>
<host ip="10.0.0.1">https://shop.corp.com</host><path>/search</path>
<severity>High</severity></issue>
</issues>"""

print("== web addresses are captured by every web tool ==")
st, r = imp(HTTPX)
check("httpx creates addresses", r["urls_created"] == 2, str(r["urls_created"]))
st, r = imp(NUCLEI)
check("nuclei's matched-at is an address", r["urls_created"] == 1, str(r["urls_created"]))
st, r = imp(BURP)
check("burp's issue path is an address", r["urls_created"] == 1, str(r["urls_created"]))

st, page = call("/api/web?project=WEB", token=admin)
urls = sorted(w["url"] for w in page["items"])
check("all four kept distinct", len(urls) == 4, str(urls))
check("default port dropped from the canonical url",
      "https://shop.corp.com/" in urls, str(urls))
check("non-default port kept", any(":8080" in u for u in urls), str(urls))

by_url = {w["url"]: w for w in page["items"]}
root = by_url["https://shop.corp.com/"]
check("status captured", root["status_code"] == 200)
check("title captured", root["title"] == "Shop")
check("webserver captured", root["webserver"] == "nginx")
check("tech captured", root["tech"] == ["Nginx"], str(root["tech"]))
check("crawled flag set by a tool that fetched it", root["crawled"] is True)
check("linked to the right host", root["host"] == "shop.corp.com")
check("linked to its service", root["service_id"] is not None)

print("\n== the same page found twice is one row with two sources ==")
st, r = imp(json.dumps({
    "template-id": "tech-detect", "info": {"name": "nginx", "severity": "info"},
    "host": "https://shop.corp.com", "matched-at": "https://shop.corp.com"}))
check("no new row", r["urls_created"] == 0, str(r["urls_created"]))
st, page = call("/api/web?project=WEB&q=shop.corp.com", token=admin)
root = next(w for w in page["items"] if w["url"] == "https://shop.corp.com/")
check("both tools recorded against it",
      "httpx" in root["sources"] and "nuclei" in root["sources"], root["sources"])

print("\n== search and filter ==")
check("search by path", call("/api/web?project=WEB&q=admin", token=admin)[1]["total"] == 1)
check("search by title", call("/api/web?project=WEB&q=Shop", token=admin)[1]["total"] >= 1)
check("filter by status", call("/api/web?project=WEB&status_code=401",
                               token=admin)[1]["total"] == 1)
check("filter by scheme",
      all(w["scheme"] == "https"
          for w in call("/api/web?project=WEB&scheme=https", token=admin)[1]["items"]))
check("filter to crawled only",
      call("/api/web?project=WEB&crawled=true", token=admin)[1]["total"] == 4)
st, stats = call("/api/web/stats?project=WEB", token=admin)
check("stats count hosts and statuses",
      stats["total"] == 4 and stats["hosts"] == 1 and stats["crawled"] == 4, str(stats))

print("\n== adding one by hand ==")
st, tg = call("/api/targets?project=WEB", token=admin)
tid = tg["items"][0]["id"]
st, w = call("/api/web", "POST",
             {"target_id": tid, "url": "/manual-find", "notes": "found in a browser"},
             token=admin)
check("a bare path resolves against its host", st == 201
      and w["url"].endswith("/manual-find"), f'{st} {w.get("url")}')
check("not marked crawled unless said so", w["crawled"] is False)
st, _ = call(f"/api/web/{w['id']}", "PATCH", {"status_code": 200, "crawled": True},
             token=admin)
check("can be updated", call("/api/web?project=WEB&q=manual-find",
                             token=admin)[1]["items"][0]["status_code"] == 200)
st, _ = call(f"/api/web/{w['id']}", "DELETE", token=admin)
check("can be deleted", st == 204 and
      call("/api/web?project=WEB&q=manual-find", token=admin)[1]["total"] == 0)

st, r = call("/api/web", "POST", {"target_id": tid, "url": "ftp://x/y"}, token=admin)
check("a non-http scheme is refused", st == 422, f"status={st}")

print("\n== a timeline entry records the discovery ==")
st, tl = call("/api/targets/WEB/shop.corp.com/timeline?kind=web", token=admin)
check("web discoveries land on the timeline", tl["total"] >= 1, str(tl["total"]))

# ======================================================= domain discovery
print("\n== a service that answered means the host is alive ==")
call("/api/projects", "POST", {"code": "ALIVE", "name": "Alive"}, token=admin)
st, r = call("/api/bulk", "POST", {"project": "ALIVE", "targets": [
    {"host": "answers.corp.com"}, {"host": "silent.corp.com"},
    {"host": "filtered.corp.com"}],
    "services": [
      {"host": "answers.corp.com", "port": 443, "state": "open", "name": "https"},
      {"host": "filtered.corp.com", "port": 80, "state": "filtered", "name": "http"},
    ]}, token=admin)
check("bulk import ok", st == 200, f"status={st}")
by = {t["host"]: t for t in call("/api/targets?project=ALIVE", token=admin)[1]["items"]}
check("an open service marks the host alive",
      by["answers.corp.com"]["alive"] is True, str(by["answers.corp.com"]["alive"]))
check("a filtered port proves nothing and leaves it unprobed",
      by["filtered.corp.com"]["alive"] is None, str(by["filtered.corp.com"]["alive"]))
check("a host with no services at all stays unprobed",
      by["silent.corp.com"]["alive"] is None, str(by["silent.corp.com"]["alive"]))

# A later payload that mentions no open ports must not undo it.
call("/api/bulk", "POST", {"project": "ALIVE", "services": [
    {"host": "answers.corp.com", "port": 8080, "state": "closed", "name": "x"}]},
    token=admin)
by = {t["host"]: t for t in call("/api/targets?project=ALIVE", token=admin)[1]["items"]}
check("liveness is never revoked by a later import",
      by["answers.corp.com"]["alive"] is True)

# and through the scan importer
imp("\n".join([json.dumps({"url": "https://scanned.corp.com", "input": "scanned.corp.com",
                           "host": "10.3.3.3", "port": 443, "scheme": "https",
                           "status_code": 200})]), project="ALIVE")
by = {t["host"]: t for t in call("/api/targets?project=ALIVE", token=admin)[1]["items"]}
check("the scan importer applies the same rule",
      by["scanned.corp.com"]["alive"] is True, str(by["scanned.corp.com"]["alive"]))

# ================================================== chained filters
# A table that pages in SQL cannot filter in the browser: the browser
# holds one page, so filtering there would hide rows from that page and
# leave the total describing something else.
print("\n== chained column filters ==")
import json as _json
import urllib.parse as _up


def _f(items, logic="and"):
    return "&filters=" + _up.quote(_json.dumps(items)) + f"&logic={logic}"


_P = "FILT"
call("/api/projects", "POST", {"code": _P, "name": _P}, token=admin)
_seed = [
    ("https://a.filt.example/admin", "a.filt.example", 500, "https", "GET"),
    ("https://a.filt.example/login", "a.filt.example", 200, "https", "GET"),
    ("https://b.filt.example/admin", "b.filt.example", 200, "https", "POST"),
    ("http://c.filt.example/admin",  "c.filt.example", 503, "http",  "GET"),
    ("http://c.filt.example/health", "c.filt.example", 200, "http",  "GET"),
]
for url, host, code, _scheme, method in _seed:
    call(f"/api/targets?project={_P}", "POST", {"host": host}, token=admin)
    t = call(f"/api/targets?project={_P}&q={host}&limit=1", token=admin)[1]["items"][0]
    call("/api/web", "POST", {"target_id": t["id"], "url": url,
                              "status_code": code, "method": method}, token=admin)

_base = f"/api/web?project={_P}&limit=1"
def _total(extra=""):
    return (call(_base + extra, token=admin)[1] or {}).get("total")

check("unfiltered sees every row", _total() == 5, str(_total()))
check("one filter: url contains admin",
      _total(_f([{"field": "url", "op": "contains", "value": "admin"}])) == 3,
      str(_total(_f([{"field": "url", "op": "contains", "value": "admin"}]))))
check("one filter: status_code >= 500",
      _total(_f([{"field": "status_code", "op": ">=", "value": 500}])) == 2)

_and = _f([{"field": "url", "op": "contains", "value": "admin"},
           {"field": "status_code", "op": ">=", "value": 500}])
check("CHAINED with and: both must hold", _total(_and) == 2, str(_total(_and)))

_or = _f([{"field": "url", "op": "contains", "value": "admin"},
          {"field": "status_code", "op": ">=", "value": 500}], "or")
check("CHAINED with or: either may hold", _total(_or) == 3, str(_total(_or)))

_three = _f([{"field": "scheme", "op": "equals", "value": "https"},
             {"field": "url", "op": "contains", "value": "admin"},
             {"field": "status_code", "op": "=", "value": 200}])
check("three filters chain", _total(_three) == 1, str(_total(_three)))

check("startsWith", _total(_f([{"field": "url", "op": "startsWith",
                               "value": "http://c."}])) == 2)
check("endsWith", _total(_f([{"field": "url", "op": "endsWith",
                             "value": "/health"}])) == 1)
check("doesNotContain", _total(_f([{"field": "url", "op": "doesNotContain",
                                    "value": "admin"}])) == 2)
check("isAnyOf on a number",
      _total(_f([{"field": "status_code", "op": "isAnyOf",
                  "value": [500, 503]}])) == 2)
check("host is filterable through the join",
      _total(_f([{"field": "host", "op": "equals", "value": "c.filt.example"}])) == 2)

# The total has to describe the FILTERED set, or a filtered page sits
# next to a row count for something else.
st, r = call(_base.replace("limit=1", "limit=100") + _and, token=admin)
check("the total matches the rows returned",
      r["total"] == len(r["items"]) == 2, f"total={r['total']} items={len(r['items'])}")

# A filter we cannot honour must be an error, never a silent pass: a
# table that looks filtered but is not is how a finding gets missed.
st, r = call(_base + _f([{"field": "password_hash", "op": "contains", "value": "x"}]),
             token=admin)
check("an unfilterable column is refused", st == 400 and "cannot filter" in str(r),
      f"{st} {str(r)[:80]}")
st, r = call(_base + _f([{"field": "url", "op": "nope", "value": "x"}]), token=admin)
check("an unknown operator is refused", st == 400, f"{st} {str(r)[:60]}")
st, r = call(_base + _f([{"field": "status_code", "op": ">", "value": "abc"}]), token=admin)
check("a non-numeric value on a number column is refused", st == 400,
      f"{st} {str(r)[:70]}")
st, r = call(_base + "&filters=" + _up.quote("{nope}"), token=admin)
check("malformed filter JSON is refused", st == 400, f"{st} {str(r)[:60]}")

# A half-typed filter row must not empty the table.
check("a filter with no value yet is ignored",
      _total(_f([{"field": "url", "op": "contains", "value": ""}])) == 5)

# A LIKE metacharacter is data, not syntax.
call("/api/web", "POST", {"target_id": t["id"], "url": "http://c.filt.example/100%off",
                          "status_code": 200, "method": "GET"}, token=admin)
check("a percent sign in a filter value is literal",
      _total(_f([{"field": "url", "op": "contains", "value": "100%off"}])) == 1,
      str(_total(_f([{"field": "url", "op": "contains", "value": "100%off"}]))))
check("and does not act as a wildcard",
      _total(_f([{"field": "url", "op": "contains", "value": "%%%"}])) == 0,
      str(_total(_f([{"field": "url", "op": "contains", "value": "%%%"}]))))

# ======================================= identity is the exchange
# Identity used to be (target, method, url), so every hit of a URL
# collapsed into one row keeping only the last response. For a proxy
# history that is the wrong unit: the same endpoint probed ten ways is
# ten pieces of evidence, and the differences are usually the finding.
import base64 as _b64

print("\n== one row per exchange ==")
_X = "EXCH"
call("/api/projects", "POST", {"code": _X, "name": _X}, token=admin)
call(f"/api/targets?project={_X}", "POST", {"host": "x.exch.example"}, token=admin)
_t = call(f"/api/targets?project={_X}&limit=1", token=admin)[1]["items"][0]


def _hist(pairs, host="x.exch.example"):
    rows = ""
    for method, path, req, resp in pairs:
        rb = _b64.b64encode(req.encode()).decode()
        sb = _b64.b64encode(resp.encode()).decode()
        rows += (f"<item><time>t</time><url>https://{host}{path}</url>"
                 f"<host ip='203.0.113.9'>{host}</host><port>443</port>"
                 f"<protocol>https</protocol><method>{method}</method>"
                 f"<path>{path}</path><extension>null</extension>"
                 f"<request base64='true'>{rb}</request><status>200</status>"
                 f"<responselength>9</responselength><mimetype>HTML</mimetype>"
                 f"<response base64='true'>{sb}</response><comment></comment></item>")
    return f"<?xml version='1.0'?><items>{rows}</items>"


# Same URL and verb, different request and response: two exchanges.
st, r = imp(_hist([
    ("GET", "/a", "GET /a HTTP/1.1\r\nX: 1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\none"),
    ("GET", "/a", "GET /a HTTP/1.1\r\nX: 2\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\ntwo"),
]), fmt="burphistory", project=_X)
check("two different exchanges for one URL are two rows",
      (r or {}).get("urls_created") == 2, str((r or {}).get("urls_created")))

# Byte-identical: still one.
st, r = imp(_hist([
    ("GET", "/a", "GET /a HTTP/1.1\r\nX: 1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\none"),
]), fmt="burphistory", project=_X)
check("an identical exchange does not duplicate",
      (r or {}).get("urls_created") == 0, str((r or {}).get("urls_created")))

st, w = call(f"/api/web?project={_X}&limit=50", token=admin)
check("the flat listing shows every exchange", (w or {}).get("total") == 2,
      str((w or {}).get("total")))

# ... and the grouped listing shows one row per URL.
st, g = call(f"/api/web/grouped?project={_X}&limit=50", token=admin)
check("the grouped listing collapses them to one URL",
      (g or {}).get("total") == 1, str((g or {}).get("total")))
_grp = (g or {}).get("items", [{}])[0]
check("and reports how many exchanges it stands for", _grp.get("hits") == 2,
      str(_grp.get("hits")))
check("and the verbs seen", _grp.get("methods") == ["GET"], str(_grp.get("methods")))
check("and the status codes seen", _grp.get("statuses") == [200],
      str(_grp.get("statuses")))

st, byu = call(f"/api/web/by-url?target_id={_t['id']}&url="
               + _up.quote(_grp["url"]), token=admin)
check("expanding the URL returns each exchange",
      (byu or {}).get("total") == 2, str((byu or {}).get("total")))
check("the expansion agrees with the group's count",
      (byu or {}).get("total") == _grp.get("hits"))

# Grouping must respect the same filters as the flat listing, or the
# count and the rows it expands to describe different sets.
st, g2 = call(f"/api/web/grouped?project={_X}&q=zzzznope&limit=5", token=admin)
check("a search applies to the grouped listing too", (g2 or {}).get("total") == 0,
      str((g2 or {}).get("total")))

# ================================================== replay a request
# Editing a captured request and sending it again has to produce a NEW
# row: the original and the edited one sitting side by side under the
# same URL is the entire point.
print("\n== replay ==")
_hostport = BASE.split("//", 1)[1]
_h, _, _p = _hostport.partition(":")
call(f"/api/targets?project={_X}", "POST", {"host": _h}, token=admin)
_self = [t for t in call(f"/api/targets?project={_X}&limit=50", token=admin)[1]["items"]
         if t["host"] == _h][0]
st, seed = call("/api/web", "POST",
                {"target_id": _self["id"], "url": f"http://{_hostport}/api/auth/methods",
                 "method": "GET"}, token=admin)
check("a seed row exists to replay from", st in (200, 201), f"{st} {str(seed)[:80]}")

_raw = (f"GET /api/auth/methods HTTP/1.1\r\nHost: {_hostport}\r\n"
        f"Accept: application/json\r\n\r\n")
st, rep = call(f"/api/web/{seed['id']}/replay", "POST", {"raw": _raw}, token=admin)
check("the request is sent and the result recorded", st == 200, f"{st} {str(rep)[:140]}")
check("it reached the server", (rep or {}).get("status_code") == 200,
      f"{(rep or {}).get('status_code')} err={(rep or {}).get('error')}")
check("and produced a NEW row, not an edit of the original",
      (rep or {}).get("web", {}).get("id") != seed["id"],
      f"{(rep or {}).get('web', {}).get('id')} vs {seed['id']}")
# The listing deliberately carries no request/response — captured
# traffic holds session cookies, and a list endpoint is the wrong place
# to hand it out. The packet endpoint is where it lives.
_nid = (rep or {}).get("web", {}).get("id")
check("the listing does not leak the captured traffic",
      (rep or {}).get("web", {}).get("request") in (None, ""),
      str((rep or {}).get("web", {}).get("request"))[:40])
st, _pk = call(f"/api/web/{_nid}/packet", token=admin)
check("the new row records what was sent",
      st == 200 and "Accept: application/json" in str((_pk or {}).get("request")),
      f"{st} {str((_pk or {}).get('request'))[:70]}")
check("and what came back", bool((_pk or {}).get("response")),
      str((_pk or {}).get("response"))[:60])
check("and attributes it to the replay", "replay" in
      str((rep or {}).get("web", {}).get("sources")),
      str((rep or {}).get("web", {}).get("sources")))

st, g3 = call(f"/api/web/grouped?project={_X}&q=auth/methods&limit=5", token=admin)
check("the replay groups under the same URL as the original",
      (g3 or {}).get("items", [{}])[0].get("hits") == 2,
      str((g3 or {}).get("items")))

# An edited request that differs is another row; an identical one is not.
#
# This check used to pass by luck. The identity of an exchange is hashed
# over the response text, and that text is the status line plus EVERY
# response header plus the body — including `Date`, which has one-second
# resolution and changes on its own. Both replays landing inside the same
# second was the only thing making them equal, which a fast machine
# arranges and a loaded CI runner does not: it failed there with
# "16 vs 15" and passed on a re-run.
#
# So force the condition instead of hoping to avoid it. Wait until the
# wall clock second has actually ticked over before replaying. The first
# replay's `Date` was stamped at or before `_sec`, the second is stamped
# strictly after it, so the two responses are guaranteed to differ — no
# fixed sleep, no probability, and the wait is bounded by one second
# (half of one on average).
import time as _time

_pk_resp = str((_pk or {}).get("response") or "")
check("the replayed response really does carry a volatile Date header",
      any(ln[:5].lower() == "date:" for ln in _pk_resp.splitlines()),
      _pk_resp[:120])
_sec = int(_time.time())
while int(_time.time()) == _sec:
    _time.sleep(0.02)
st, rep2 = call(f"/api/web/{seed['id']}/replay", "POST", {"raw": _raw}, token=admin)
check("replaying the identical request twice does not duplicate",
      (rep2 or {}).get("web", {}).get("id") == (rep or {}).get("web", {}).get("id"),
      f"{(rep2 or {}).get('web', {}).get('id')} vs {(rep or {}).get('web', {}).get('id')}")
_raw2 = _raw.replace("Accept: application/json", "Accept: text/html\r\nX-Test: 1")
st, rep3 = call(f"/api/web/{seed['id']}/replay", "POST", {"raw": _raw2}, token=admin)
check("an edited request is a new row",
      (rep3 or {}).get("web", {}).get("id") not in
      (seed["id"], (rep or {}).get("web", {}).get("id")),
      str((rep3 or {}).get("web", {}).get("id")))

# The end-to-end checks above prove the route is wired to the right rule.
# These prove the rule, directly and without a clock: which differences
# between two responses are the same exchange and which are new evidence.
# The second one is the line that was NOT crossed — the cheap fix for the
# Date bug is to hash only the status code and the body, and it would
# make a header-only change invisible, which in this tool is frequently
# the whole finding.
print("-- what counts as the same answer --")
from app.weburl import exchange_key as _xk  # noqa: E402
from app.weburl import stable_response as _sr  # noqa: E402


def _resp(*headers, body="hello"):
    return ("HTTP/1.1 200 OK\r\n" + "".join(f"{h}\r\n" for h in headers)
            + "\r\n" + body)


def _same(a, b):
    return _xk("GET", "https://h.example/x", "GET /x HTTP/1.1\r\n\r\n", _sr(a)) == \
           _xk("GET", "https://h.example/x", "GET /x HTTP/1.1\r\n\r\n", _sr(b))


_d1 = _resp("Date: Thu, 08 Oct 2026 12:00:00 GMT", "Server: nginx")
_d2 = _resp("Date: Thu, 08 Oct 2026 12:00:01 GMT", "Server: nginx")
check("two responses differing only in Date are the same exchange", _same(_d1, _d2))
check("a raw hash of those two is NOT the same, which is the bug",
      _xk("GET", "u", None, _d1) != _xk("GET", "u", None, _d2))
check("a changed Server banner is still a different exchange",
      not _same(_d1, _resp("Date: Thu, 08 Oct 2026 12:00:00 GMT", "Server: apache")))
check("a changed body is still a different exchange",
      not _same(_d1, _resp("Date: Thu, 08 Oct 2026 12:00:00 GMT", "Server: nginx",
                           body="goodbye")))
check("a rotating session cookie value is not a new exchange",
      _same(_resp("Set-Cookie: sid=aaaa; Path=/; HttpOnly"),
            _resp("Set-Cookie: sid=bbbb; Path=/; HttpOnly")))
check("but losing HttpOnly on that cookie is",
      not _same(_resp("Set-Cookie: sid=aaaa; Path=/; HttpOnly"),
                _resp("Set-Cookie: sid=aaaa; Path=/")))
check("a per-request id header is not a new exchange",
      _same(_resp("X-Amzn-RequestId: 1111", "Cf-Ray: aaa-LHR"),
            _resp("X-Amzn-RequestId: 2222", "Cf-Ray: bbb-LHR")))
check("a changed Cache-Control is, because that is a policy not a clock",
      not _same(_resp("Cache-Control: no-store"), _resp("Cache-Control: max-age=60")))
check("a response capped mid-headers is still normalised",
      _same("HTTP/1.1 200 OK\r\nDate: Thu, 08 Oct 2026 12:00:00 GMT\r\nServer: ng",
            "HTTP/1.1 200 OK\r\nDate: Thu, 08 Oct 2026 12:00:09 GMT\r\nServer: ng"))
check("an empty response is left alone rather than invented",
      _sr("") == "" and _sr(None) is None)

# Without this guard the endpoint is an authenticated open proxy.
st, bad = call(f"/api/web/{seed['id']}/replay", "POST",
               {"raw": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}, token=admin)
check("replay refuses a host the engagement does not have",
      st == 400 and "not a target" in str(bad), f"{st} {str(bad)[:110]}")

st, bad = call(f"/api/web/{seed['id']}/replay", "POST", {"raw": "nonsense"}, token=admin)
check("an unparseable request line is refused with a reason",
      st == 422 and "request line" in str(bad), f"{st} {str(bad)[:110]}")

# The host check used to be `host.split(":")[0]`, which is a complete
# bypass of itself: everything after the colon is userinfo to a URL
# parser, so the validated name becomes a username and the request
# goes wherever follows the `@`. CodeQL called it py/partial-ssrf and
# was right.
#
#   Host: <in-scope>:80@evil.example.net
#     validated as : <in-scope>     passes the target lookup AND the
#                                   scope gate
#     actually hits: evil.example.net
#
# Worse here than a plain open proxy: it puts live traffic on a host
# the scope gate just approved, during someone's engagement, and
# writes the wrong name into the audit trail.
print("-- the Host header cannot smuggle a second destination --")
for smuggle, why in [
    (f"{_hostport}@evil.example.net", "userinfo with no port"),
    (f"{_hostport}:80@evil.example.net", "userinfo with a port"),
    (f"{_hostport}:@evil.example.net", "userinfo with an empty port"),
    (f"{_hostport}/evil.example.net", "a path in the host"),
    (f"{_hostport}\\evil.example.net", "a backslash"),
    (f"{_hostport}#evil.example.net", "a fragment"),
    (f"{_hostport} evil.example.net", "whitespace"),
]:
    st, out = call(f"/api/web/{seed['id']}/replay", "POST",
                   {"raw": f"GET /api/auth/methods HTTP/1.1\r\n"
                           f"Host: {smuggle}\r\n\r\n"}, token=admin)
    # 400 is the shape refusal, 422 is the raw-request parser getting
    # there first. Either is a refusal; what must not happen is a 200
    # with a response fetched from somewhere else.
    check(f"refused: {why}", st in (400, 422), f"{st} {str(out)[:90]}")

st, bad = call(f"/api/web/{seed['id']}/replay", "POST", {"raw": ""}, token=admin)
check("an empty request is refused", st == 422, f"{st} {str(bad)[:80]}")

# A connection that fails is a result worth keeping, not a 500.
call(f"/api/targets?project={_X}", "POST", {"host": "127.0.0.2"}, token=admin)
_dead = [t for t in call(f"/api/targets?project={_X}&limit=50", token=admin)[1]["items"]
         if t["host"] == "127.0.0.2"][0]
st, seed2 = call("/api/web", "POST",
                 {"target_id": _dead["id"], "url": "http://127.0.0.2:9/x",
                  "method": "GET"}, token=admin)
st, dead = call(f"/api/web/{seed2['id']}/replay", "POST",
                {"raw": "GET /x HTTP/1.1\r\nHost: 127.0.0.2:9\r\n\r\n",
                 "timeout": 2}, token=admin)
check("a failed connection is recorded rather than raising",
      st == 200 and (dead or {}).get("error"), f"{st} {str(dead)[:120]}")

print("\n== roots do not require targets ==")
# A fresh engagement has scope and no targets, which is exactly when
# somebody wants to enumerate. Reporting "no root domains" then is
# reporting on the wrong thing.
call("/api/projects", "POST", {"code": "FRESH", "name": "Fresh"}, token=admin)
st, roots = call("/api/domains/roots?project=FRESH", token=admin)
check("a project with nothing in it has no roots", roots == [], str(roots))
call("/api/projects/FRESH/scope", "POST",
     {"lines": ["*.scoped.example", "portal.other-scoped.example"]},
     token=admin)
st, roots = call("/api/domains/roots?project=FRESH", token=admin)
got = {r["domain"] for r in roots}
check("scope alone produces roots", {"scoped.example", "other-scoped.example"} <= got,
      str(got))
check("marked as coming from scope, not invented from targets",
      all(r["source"] == "scope" for r in roots), str(roots)[:200])
check("and counted honestly as zero known hosts",
      all(r["known_hosts"] == 0 for r in roots), str(roots)[:160])

st, _ = call("/api/projects/FRESH/scope", "POST",
             {"lines": ["!excluded.example"]}, token=admin)
st, roots = call("/api/domains/roots?project=FRESH", token=admin)
check("an excluded domain is never offered",
      "excluded.example" not in {r["domain"] for r in roots}, str(roots)[:200])

# The project used to be created by the generation section above,
# which tested a feature that no longer exists. The agent-handoff
# tests below still need it.
call("/api/projects", "POST", {"code": "DOM", "name": "Domains"}, token=admin)
call("/api/projects/DOM/acl", "POST", {"username": "ro", "role": "readonly"},
     token=admin)

print("\n== handing domains to an agent ==")
# Refused rather than queued when nothing can run it: work accepted
# with no agent sits looking submitted, which reads as a broken scan.
st, e = call("/api/domains/enumerate?project=DOM", "POST",
             {"domains": "corp.com"}, token=admin)
check("with no agent online it is refused, not silently queued",
      st == 409, f"status={st} {str(e)[:120]}")
check("and says what to do about it",
      "online" in str(e).lower(), str(e)[:140])

st, e = call("/api/domains/enumerate?project=DOM", "POST",
             {"domains": ""}, token=admin)
check("an empty submission is 422", st == 422, f"status={st}")

print("\n== every page the app routes is a page the server will serve ==")
# Two copies of one list: SPA_ROUTES in app/main.py and GLOBAL ∪ SCOPED
# in frontend/src/lib/route.ts. They drifted — `drone` and `settings`
# were added to the app and not to the server, so those pages worked
# when navigated to and 404'd on refresh or from a pasted link. Checked
# here because the next view will be added in one place too.
import re as _re

_root = _pathlib.Path(__file__).resolve().parents[2]
_route_ts = _root / "frontend" / "src" / "lib" / "route.ts"
if _route_ts.exists():
    _src = _route_ts.read_text()
    _views = set()
    for _name in ("GLOBAL", "SCOPED"):
        _m = _re.search(_name + r"\s*=\s*new Set\(\[(.*?)\]\)", _src, _re.S)
        if _m:
            _views |= set(_re.findall(r"'([a-z-]+)'", _m.group(1)))
    from app.main import app as _app
    _spa = None
    for _r in _app.routes:
        if getattr(_r, "path", "") == "/{full_path:path}":
            _spa = _r
    # The tuple is a local inside the closure, so it is read from the
    # source rather than imported: a constant that cannot be reached
    # from outside is still a constant that has to be right.
    _main = (_root / "backend" / "app" / "main.py").read_text()
    _mm = _re.search(r"SPA_ROUTES = \((.*?)\)", _main, _re.S)
    _server = set(_re.findall(r'"([a-z-]+)"', _mm.group(1))) if _mm else set()

    check("the frontend's view list could be read", bool(_views), str(_views))
    check("and the server's", bool(_server), str(_server))
    _missing = _views - _server
    check("every view the app routes is served on a deep link",
          not _missing, f"server will 404 on: {sorted(_missing)}")
    _extra = _server - _views
    check("and the server claims no page the app cannot render",
          not _extra, f"server serves the app for: {sorted(_extra)}")

    # The one that was actually reported.
    _req = urllib.request.Request(BASE + "/drones")
    _req.add_header("Accept", "text/html")
    _req.add_header("Authorization", f"Bearer {admin}")
    try:
        with urllib.request.urlopen(_req, timeout=30) as _x:
            _st = _x.status
    except urllib.error.HTTPError as _e:
        _st = _e.code
    check("/drones is served rather than 404", _st == 200, f"status={_st}")
else:
    check("route.ts was found to compare against", False, str(_route_ts))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
