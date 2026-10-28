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


def call(p, m="GET", b=None, token=None, key=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode(); r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    # A ghost authenticates with its own key, not as a person. The
    # replay section below needs both in the same suite, because the
    # route is an operator asking and an agent answering.
    if key: r.add_header("X-Ghost-Key", key)
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
#
# **The packet leaves from a ghost, not from this server.** So this
# suite has to be one. `_ghost_send` below is the whole of an agent's
# replay loop — beat, take the task, write the bytes to a socket, post
# the answer — which is what makes these assertions about the route
# rather than about a mock: the bytes under test really do go over TCP
# and really do come back off it.
print("\n== replay ==")
import socket as _socket  # noqa: E402

_hostport = BASE.split("//", 1)[1]
_h, _, _p = _hostport.partition(":")
call(f"/api/targets?project={_X}", "POST", {"host": _h}, token=admin)
_self = [t for t in call(f"/api/targets?project={_X}&limit=50", token=admin)[1]["items"]
         if t["host"] == _h][0]

st, _en = call(f"/api/ghosts?project={_X}", "POST",
               {"name": "replay-ghost"}, token=admin)
GKEY = (_en or {}).get("callback_key")
GID = ((_en or {}).get("agent") or {}).get("id")
# Not "replay-ghost": enrollment appends a suffix so that a container
# restarted under the same name does not become two agents sharing
# one row. Read back rather than assumed.
GNAME = ((_en or {}).get("agent") or {}).get("name")
check("a ghost is enrolled to send from", st == 201 and bool(GKEY),
      f"{st} {str(_en)[:90]}")
call("/api/ghosts/register", "POST",
     {"platform": "linux", "arch": "amd64", "version": "test",
      "hostname": "ghost", "privileged": False, "tools": {}}, key=GKEY)


def _beat(ready=True, running=None):
    return call("/api/ghosts/heartbeat", "POST",
                {"ready": ready, "running_tasks": running or []}, key=GKEY)[1] or {}


def _take(task_id, beat=None):
    """The task with this id out of a heartbeat's hand-out, or None."""
    for t in (beat if beat is not None else _beat()).get("tasks") or []:
        if t.get("id") == task_id:
            return t
    return None


def _wire(task):
    """Do what the Go runner does: write the bytes, read the answer.

    A raw socket and not urllib, deliberately. The point of this whole
    path is that the request goes out exactly as it was typed, and an
    HTTP client would rebuild it from parsed fields — which is the
    thing that must not happen.
    """
    a = task["args"]
    raw = _b64.b64decode(a["raw_b64"])
    s = _socket.create_connection((a["host"], a["port"]), timeout=10)
    s.settimeout(10)
    chunks: list[bytes] = []
    try:
        s.sendall(raw)
        while sum(len(c) for c in chunks) < a.get("resp_cap", 48 * 1024):
            got = s.recv(8192)
            if not got:
                break
            chunks.append(got)
    finally:
        s.close()
    blob = b"".join(chunks)
    status = None
    if blob[:5] == b"HTTP/":
        try:
            status = int(blob.split(b" ", 2)[1])
        except (IndexError, ValueError):
            status = None
    return {"status": status, "elapsed_ms": 7,
            "response_b64": _b64.b64encode(blob).decode()}


def _ghost_send(task_id, payload=None):
    """Carry one replay task through. -> (what the ghost was given, result)."""
    task = _take(task_id)
    if task is None:
        return None, {"error": "the ghost was never handed the task"}
    out = payload if payload is not None else _wire(task)
    call(f"/api/ghosts/tasks/{task_id}/result", "POST",
         {"status": "done", "output": json.dumps(out), "stderr": "",
          "summary": "replay", "exit_code": 0}, key=GKEY)
    return task, call(f"/api/web/replays/{task_id}", token=admin)[1] or {}


def replay(seed_id, raw, **opts):
    """POST a replay and run it to completion. -> (status, ReplayOut)."""
    st, q = call(f"/api/web/{seed_id}/replay", "POST",
                 {"raw": raw, **opts}, token=admin)
    if st != 200:
        return st, q
    _task, done = _ghost_send(q["task_id"])
    return st, done


st, seed = call("/api/web", "POST",
                {"target_id": _self["id"], "url": f"http://{_hostport}/api/auth/methods",
                 "method": "GET"}, token=admin)
check("a seed row exists to replay from", st in (200, 201), f"{st} {str(seed)[:80]}")

# Read before, compared after. The seed was created through the API
# and carries no captured traffic, which is itself worth pinning:
# "unchanged" has to mean unchanged, including staying empty.
_st0, _seed_pkt = call(f"/api/web/{seed['id']}/packet", token=admin)
_seed_request = (_seed_pkt or {}).get("request")
_seed_response = (_seed_pkt or {}).get("response")

_raw = (f"GET /api/auth/methods HTTP/1.1\r\nHost: {_hostport}\r\n"
        f"Accept: application/json\r\n\r\n")

# The POST answers "where is it going", not "what did it say". Pinned
# on its own before the end-to-end run, because an endpoint that
# silently sent the packet from this server would still satisfy every
# assertion below it.
st, _q = call(f"/api/web/{seed['id']}/replay", "POST", {"raw": _raw}, token=admin)
check("the POST queues rather than sending", st == 200 and _q.get("task_id"),
      f"{st} {str(_q)[:140]}")
check("and names the ghost it will leave from",
      _q.get("agent") == GNAME and _q.get("agent_id") == GID,
      str(_q)[:140])
check("an idle ghost is reported as idle", _q.get("dispatch") == "idle",
      str(_q.get("dispatch")))
st, _qt = call(f"/api/ghosts/tasks?project={_X}&limit=50", token=admin)
_qrow = next((t for t in (_qt or []) if t.get("id") == _q["task_id"]), {})
check("the replay is an agent task like any other work",
      _qrow.get("kind") == "replay", str(_qrow)[:120])
check("and nothing has been sent yet",
      (call(f"/api/web/replays/{_q['task_id']}", token=admin)[1] or {})
      .get("state") == "queued")

# The bytes the ghost is handed are the bytes the operator typed.
_handed = _take(_q["task_id"])
check("the ghost is handed the request verbatim, base64'd",
      _handed is not None
      and _b64.b64decode(_handed["args"]["raw_b64"]).decode() == _raw,
      str(_handed)[:160] if _handed else "never handed over")
check("and told where to dial out of the target row, not the Host header",
      _handed and _handed["args"]["host"] == _h
      and _handed["args"]["port"] == int(_p),
      str((_handed or {}).get("args", {}))[:120])
_out = _wire(_handed)
call(f"/api/ghosts/tasks/{_q['task_id']}/result", "POST",
     {"status": "done", "output": json.dumps(_out), "stderr": "",
      "summary": "replay", "exit_code": 0}, key=GKEY)
st, rep = call(f"/api/web/replays/{_q['task_id']}", token=admin)
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

# THE ORIGINAL IS NOT TOUCHED. Asserted on its bytes rather than
# only on the new row having a different id: an endpoint that
# created a new row AND overwrote the old one would pass that check
# and lose the evidence the replay was being compared against.
st, _orig = call(f"/api/web/{seed['id']}/packet", token=admin)
check("the original packet still reads exactly as captured",
      st == 200 and (_orig or {}).get("request") == _seed_request
      and (_orig or {}).get("response") == _seed_response,
      f"{st} request-changed="
      f"{(_orig or {}).get('request') != _seed_request} response-changed="
      f"{(_orig or {}).get('response') != _seed_response}")

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
st, rep2 = replay(seed["id"], _raw)
check("replaying the identical request twice does not duplicate",
      (rep2 or {}).get("web", {}).get("id") == (rep or {}).get("web", {}).get("id"),
      f"{(rep2 or {}).get('web', {}).get('id')} vs {(rep or {}).get('web', {}).get('id')}")
_raw2 = _raw.replace("Accept: application/json", "Accept: text/html\r\nX-Test: 1")
st, rep3 = replay(seed["id"], _raw2)
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

# A connection that fails is a result worth keeping, not a 500 and not
# a failed task. "This host now refuses the connection" is a finding,
# and a row is filed for it beside the original so the two can be
# compared. The ghost reports `done` with the failure in its payload,
# which is exactly what the Go runner does.
call(f"/api/targets?project={_X}", "POST", {"host": "127.0.0.2"}, token=admin)
_dead = [t for t in call(f"/api/targets?project={_X}&limit=50", token=admin)[1]["items"]
         if t["host"] == "127.0.0.2"][0]
st, seed2 = call("/api/web", "POST",
                 {"target_id": _dead["id"], "url": "http://127.0.0.2:9/x",
                  "method": "GET"}, token=admin)
st, _dq = call(f"/api/web/{seed2['id']}/replay", "POST",
               {"raw": "GET /x HTTP/1.1\r\nHost: 127.0.0.2:9\r\n\r\n",
                "timeout": 2}, token=admin)
_, dead = _ghost_send(_dq["task_id"],
                      {"error": "dial tcp 127.0.0.2:9: connection refused",
                       "elapsed_ms": 1, "response_b64": ""})
check("a failed connection is recorded rather than raising",
      st == 200 and (dead or {}).get("error"), f"{st} {str(dead)[:120]}")
check("and it is a row, not just a task error",
      (dead or {}).get("web", {}).get("id") not in (None, seed2["id"]),
      str((dead or {}).get("web"))[:90])
check("whose status is absent rather than invented",
      (dead or {}).get("status_code") is None
      and (dead or {}).get("web", {}).get("crawled") is False,
      str((dead or {}).get("web"))[:120])

# ---------------------------------------------- the dispatch rule
# "Skip the line and go to the first available; if none are available
# then choose one and task anyone; if there is no ghost at all, say
# so." Three cases, three different answers.
print("-- which ghost, and how far ahead of the queue --")

# A deep backlog on the same ghost, of a kind that would otherwise be
# taken first. Four thousand would be the real case; forty proves the
# same thing in a suite, because the hand-out window is 100 and the
# ordering is what decides, not the depth.
for _i in range(40):
    call(f"/api/ghosts/{GID}/tasks?project={_X}", "POST",
         {"kind": "nslookup", "args": {"targets": [f"q{_i}.acme.example"]}},
         token=admin)
st, _jump = call(f"/api/web/{seed['id']}/replay", "POST",
                 {"raw": _raw.replace("Accept: application/json",
                                      "Accept: application/jump")}, token=admin)
check("a replay is queued behind a backlog", st == 200, f"{st} {str(_jump)[:90]}")
_first = (_beat().get("tasks") or [{}])[0]
check("and is handed over FIRST, ahead of all of it",
      _first.get("id") == _jump["task_id"],
      f"got {_first.get('kind')} #{_first.get('id')}, "
      f"wanted replay #{_jump['task_id']}")
# Mutation check on the assertion above: without the priority ordering
# the oldest nslookup is what comes back, so pin that the backlog is
# genuinely in front of it by age.
check("the backlog really was older than the replay",
      all(t["id"] < _jump["task_id"]
          for t in (call(f"/api/ghosts/tasks?project={_X}&limit=200",
                         token=admin)[1] or [])
          if t.get("kind") == "nslookup"))
call(f"/api/ghosts/tasks/{_jump['task_id']}/result", "POST",
     {"status": "done", "output": json.dumps(_wire(_first)), "stderr": "",
      "summary": "replay", "exit_code": 0}, key=GKEY)

# No idle ghost: it is queued against one anyway rather than refused.
# The ghost is made busy by telling the server it is holding work,
# which is the only thing "busy" has ever meant here.
_holding = [t["id"] for t in (_beat().get("tasks") or [])]
_bz = _beat(ready=False, running=_holding)
st, _busy = call(f"/api/web/{seed['id']}/replay", "POST",
                 {"raw": _raw.replace("application/json", "application/busy")},
                 token=admin)
check("a busy fleet still takes the work rather than refusing",
      st == 200 and _busy.get("agent_id") == GID, f"{st} {str(_busy)[:110]}")
check("and says plainly that it is waiting for a slot",
      _busy.get("dispatch") == "busy" and "mid-scan" in (_busy.get("note") or ""),
      str(_busy)[:160])
# Drain, so the suite leaves the ghost idle for anything after it —
# the work it was holding, and then the replay that was waiting behind
# it, which is itself the proof that "queued on a busy ghost" really
# does arrive rather than merely being accepted.
for _tid in _holding:
    call(f"/api/ghosts/tasks/{_tid}/result", "POST",
         {"status": "done", "output": "[]", "stderr": "", "summary": "done",
          "exit_code": 0}, key=GKEY)
_was_busy = _take(_busy["task_id"])
check("and the queued replay is handed over once the slot frees",
      _was_busy is not None, str(_busy)[:110])
if _was_busy is not None:
    call(f"/api/ghosts/tasks/{_busy['task_id']}/result", "POST",
         {"status": "done", "output": json.dumps(_wire(_was_busy)),
          "stderr": "", "summary": "replay", "exit_code": 0}, key=GKEY)

# No ghost at all. A real answer about the engagement, not an error to
# swallow and not a quiet fallback to sending it from this server --
# which is the whole thing this change exists to stop.
call("/api/projects", "POST", {"code": "NOGHOST", "name": "No ghost"}, token=admin)
call("/api/targets?project=NOGHOST", "POST", {"host": _h}, token=admin)
_ng_t = [t for t in call("/api/targets?project=NOGHOST&limit=50",
                         token=admin)[1]["items"] if t["host"] == _h][0]
st, _ng_seed = call("/api/web", "POST",
                    {"target_id": _ng_t["id"],
                     "url": f"http://{_hostport}/api/auth/methods",
                     "method": "GET"}, token=admin)
st, _ng = call(f"/api/web/{_ng_seed['id']}/replay", "POST",
               {"raw": _raw}, token=admin)
check("an engagement with no ghost is told so, plainly",
      st == 409 and "no ghost" in str(_ng), f"{st} {str(_ng)[:140]}")
_ng_rows = call("/api/web?project=NOGHOST&limit=50", token=admin)[1] or {}
check("and nothing was sent from the server instead — the seed row and "
      "no second one", _ng_rows.get("total") == 1, str(_ng_rows.get("total")))

# The one transformation `wire_form` makes, and the one it does not.
print("-- what goes on the wire --")
from app.routers.web import wire_form as _wf  # noqa: E402

check("bare LF line endings become CRLF, because a textarea cannot type one",
      _wf("GET / HTTP/1.1\nHost: a.acme.example\n\n")
      == "GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\n")
check("a request already in CRLF is left exactly as it is",
      _wf("GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\nx=1")
      == "GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\nx=1")
check("the body is bytes and is not rewritten",
      _wf("POST / HTTP/1.1\nHost: a.acme.example\n\na\nb\r\nc")
      == "POST / HTTP/1.1\r\nHost: a.acme.example\r\n\r\na\nb\r\nc")
check("header order, casing and duplicates all survive",
      _wf("get /X HTTP/1.1\nhOsT: a.acme.example\nA: 1\nA: 2\nZ: 3\n\n")
      == "get /X HTTP/1.1\r\nhOsT: a.acme.example\r\nA: 1\r\nA: 2\r\nZ: 3\r\n\r\n")
check("a deliberately malformed request line is not repaired",
      _wf("GET  HTTP/9.9 /x\n\n") == "GET  HTTP/9.9 /x\r\n\r\n")
check("a request with no blank line still gets a terminator",
      _wf("GET / HTTP/1.1\nHost: a.acme.example")
      == "GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\n")

# What the dispatch-time scope gate is offered out of a replay's
# arguments. The gate reads EVERY argument looking for hosts, which is
# right, and it is the reason two of those arguments are shaped the way
# they are:
#
#   the request is base64, or the gate would find the Referer, the
#   Origin and every cookie domain in it and refuse the task because
#   one of them is not in the engagement
#
#   the destination is `dest_url` and not `url`, because `url` is one
#   of the keys under which every comma-separated token counts as a
#   host whatever it looks like -- and `/report/a,b` is a path, not a
#   request to send something to `b`
print("-- what the scope gate sees of a replay --")
from app.scopegate import task_hosts as _th  # noqa: E402

st, _comma = call(f"/api/web/{seed['id']}/replay", "POST",
                  {"raw": f"GET /api/auth/methods?x=a,b HTTP/1.1\r\n"
                          f"Host: {_hostport}\r\n"
                          f"Referer: https://out-of-scope.example/p\r\n"
                          f"Cookie: s=1; Domain=another.example\r\n\r\n"},
                  token=admin)
check("a replay carrying out-of-scope header values is queued, not refused",
      st == 200, f"{st} {str(_comma)[:110]}")
_ch = _take(_comma["task_id"])
_seen = set(_th((_ch or {}).get("args") or {}))
check("and the gate is offered the destination",
      any(_h in s for s in _seen), str(sorted(_seen))[:160])
check("and nothing out of the request body or headers",
      not any("out-of-scope.example" in s or "another.example" in s
              for s in _seen), str(sorted(_seen))[:200])
check("and no stray token out of the query string",
      "b" not in _seen, str(sorted(_seen))[:200])
# Finished off, so the suite does not leave the ghost holding work.
if _ch is not None:
    call(f"/api/ghosts/tasks/{_comma['task_id']}/result", "POST",
         {"status": "done", "output": json.dumps(_wire(_ch)), "stderr": "",
          "summary": "replay", "exit_code": 0}, key=GKEY)

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
# Only the wildcard's zone. `portal.other-scoped.example` is one
# host, and a host does not authorise enumerating the zone above it —
# /enumerate would refuse `other-scoped.example`, so offering it here
# was offering work that could never run. The list is gated now.
check("scope alone produces roots", "scoped.example" in got,
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
# Two copies of one list: SPA_ROUTES in app/main.py and
# GLOBAL_VIEWS ∪ SCOPED_VIEWS in frontend/src/lib/route.ts. They
# drifted — `ghost` and `settings` were added to the app and not to
# the server, so those pages worked when navigated to and 404'd on
# refresh or from a pasted link. Checked here because the next view
# will be added in one place too.
#
# And it was, twice more. `ghost-debug` went missing from BOTH lists,
# so they agreed and this passed while the page could not be
# reloaded. The frontend's two copies are now coupled by the `View`
# type and cannot disagree; this one is Python, so it stays a test.
#
# Which makes "the list could be read" load-bearing rather than
# defensive: when route.ts changed shape, the regex quietly returned
# an empty set, and an empty set is a subset of everything. Without
# that first check the whole comparison would have passed by
# answering no question at all.
import re as _re

_root = _pathlib.Path(__file__).resolve().parents[2]
_route_ts = _root / "frontend" / "src" / "lib" / "route.ts"
if _route_ts.exists():
    _src = _route_ts.read_text()
    _views = set()
    for _name in ("GLOBAL_VIEWS", "SCOPED_VIEWS"):
        _m = _re.search(_name + r"\s*=\s*\[(.*?)\]\s*as const", _src, _re.S)
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
    _req = urllib.request.Request(BASE + "/ghosts")
    _req.add_header("Accept", "text/html")
    _req.add_header("Authorization", f"Bearer {admin}")
    try:
        with urllib.request.urlopen(_req, timeout=30) as _x:
            _st = _x.status
    except urllib.error.HTTPError as _e:
        _st = _e.code
    check("/ghosts is served rather than 404", _st == 200, f"status={_st}")
else:
    check("route.ts was found to compare against", False, str(_route_ts))

print("\n== found_by: who discovered the URL, not whether we fetched it ==")
#
# The feature this replaced: "once a crawl has run, delete the
# content-discovery rows as clutter." There is no clutter to delete.
# The importer merges a URL two tools found into ONE row naming both,
# so crawl rows and discovery-only rows are disjoint by construction,
# and the rule would have removed 45,163 live addresses that no crawl
# ever saw -- 29,032 of them 401 or 403, paths that exist and are
# protected and that nothing links to.
# Real imports, not hand-made rows: `sources` is written by the
# importer from the tool name and is not settable over the API, which
# is the right way round -- it is a record of what found the URL, not
# a field anyone gets to assert.
imp(json.dumps({"sites": ["https://src.corp.com/"], "by_type": {},
                "urls": ["https://src.corp.com/by-crawl",
                         "https://src.corp.com/by-both"]}))
# Both `found` and `hits`, which is what the agent actually sends
# (ghost/internal/tasks/gobuster.go) and what format detection needs:
# `looks_like` keys on "found" plus one of "wordlist"/"hits".
imp(json.dumps({"url": "https://src.corp.com/", "wordlist": "w",
                "found": ["by-both", "by-disco", "by-disco2"],
                "hits": [{"path": "by-both", "status": 200},
                         {"path": "by-disco", "status": 403},
                         {"path": "by-disco2", "status": 401}]}))


def _urls(query):
    return {w["url"].rsplit("/", 1)[-1]
            for w in call(f"/api/web?project=WEB&{query}",
                          token=admin)[1]["items"]}


_crawl = _urls("found_by=crawl&q=by-")
_disco = _urls("found_by=discovery&q=by-")
_all = _urls("q=by-")

check("crawl-confirmed includes what a crawler reached",
      "by-crawl" in _crawl, _crawl)
check("...including a URL two tools found", "by-both" in _crawl, _crawl)
check("discovery-only is what no crawler reached",
      _disco == {"by-disco", "by-disco2"}, _disco)
# The property the whole filter rests on. If a row could appear in
# both or neither, the counts would not add up and the operator would
# be quietly missing addresses.
check("the two partition the set exactly",
      _crawl | _disco == _all and not (_crawl & _disco),
      f"crawl={_crawl} disco={_disco} all={_all}")

st, counts = call("/api/web/source-counts?project=WEB", token=admin)
check("the counts endpoint answers", st == 200, f"{st} {counts}")
# The number the chooser puts next to each option must be the number
# of rows that option then shows, or it is worse than no number.
check("each count agrees with the listing it describes",
      counts["crawl"] == call("/api/web?project=WEB&found_by=crawl",
                              token=admin)[1]["total"]
      and counts["discovery"] == call("/api/web?project=WEB&found_by=discovery",
                                      token=admin)[1]["total"]
      and counts["all"] == call("/api/web?project=WEB", token=admin)[1]["total"],
      str(counts))
# Disjoint, but NOT a partition, and the distinction is real: this
# project also holds rows found only by httpx and nuclei, which were
# probed directly rather than crawled to or guessed at. They belong
# to neither slice and must not be forced into one.
check("the two slices never overlap and never exceed the whole",
      counts["crawl"] + counts["discovery"] <= counts["all"], str(counts))
check("...and this project really does exercise the gap",
      counts["crawl"] + counts["discovery"] < counts["all"], str(counts))
# Scoped to the rows this section made, which come only from a crawl
# and content discovery — there, they do account for everything.
st, scoped = call("/api/web/source-counts?project=WEB&q=by-", token=admin)
check("over crawl+discovery rows alone the counts do add up",
      scoped["crawl"] + scoped["discovery"] == scoped["all"], str(scoped))
# The counts must follow the filters in force, or they describe a
# different table from the one on screen.
check("the counts honour the other filters",
      scoped["all"] < counts["all"], f"{scoped} vs {counts}")

# found_by is not `crawled`. A path gobuster guessed and we then
# fetched is crawled=true AND discovery-only; folding the two
# together would make that combination unaskable.
check("found_by composes with the other filters rather than replacing them",
      call("/api/web?project=WEB&found_by=discovery&crawled=true",
           token=admin)[0] == 200)
check("an unknown found_by is refused, not silently ignored",
      call("/api/web?project=WEB&found_by=nonsense", token=admin)[0] == 422)
check("omitting it shows everything",
      call("/api/web?project=WEB&q=by-", token=admin)[1]["total"] == 4)


# ================================================= subdomain takeovers
# The matching is a pure function, so most of this is about the three
# verdicts being three different claims rather than degrees of one.
from app import takeover as _tk  # noqa: E402

print("\n== which provider a CNAME lands on ==")
check("an S3 bucket is recognised",
      (_tk.provider_for("x.s3.amazonaws.com") or _tk.Provider("", ())).name == "AWS S3")
check("...including the region-infix website form, which is not a suffix match",
      (_tk.provider_for("b.s3-website-eu-west-1.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS S3")
check("a trailing dot is the same name, because resolvers disagree about it",
      _tk.provider_for("page.github.io.") is not None)
check("case is not a different provider",
      _tk.provider_for("PAGE.GITHUB.IO") is not None)
check("something nobody hands out is not a provider",
      _tk.provider_for("www.corp.com") is None)
check("an empty cname is not a provider", _tk.provider_for("") is None)

print("\n== the three verdicts are three different claims ==")
d = _tk.decide("a.corp.com", ["a.herokuapp.com"],
               unresolved={"a.herokuapp.com"})
check("a chain reaching a name that does not resolve is `dangling`",
      d is not None and d.verdict == "dangling", d and d.verdict)
check("...and says which name it was",
      d is not None and "a.herokuapp.com" in (d.evidence or ""), d and d.evidence)

d = _tk.decide("b.corp.com", ["b.herokuapp.com"], bodies=["<h1>No such app</h1>"])
check("a provider's own unclaimed page is `fingerprint`",
      d is not None and d.verdict == "fingerprint", d and d.verdict)
check("...and quotes the marker, so nobody has to refetch the page to know why",
      d is not None and d.evidence == "No such app", d and d.evidence)

d = _tk.decide("c.corp.com", ["c.myshopify.com"], bodies=["a perfectly live store"])
check("a provider with neither piece of evidence is `candidate`, not a finding",
      d is not None and d.verdict == "candidate", d and d.verdict)
# It carries no evidence FOR a takeover -- that is what `candidate`
# means -- but it does now say why neither check could convict. A
# bare "could not determine" tells a reader a conclusion is absent
# without telling them what is absent.
check("...carrying no proof of a takeover",
      d is not None and d.verdict == "candidate", d and d.verdict)
check("...but saying why it could not be settled",
      d is not None and d.evidence and "not proven either way" in d.evidence,
      d and d.evidence)

check("a host pointing nowhere interesting is not a row at all",
      _tk.decide("d.corp.com", ["d.corp.com.cdn.internal"]) is None)
check("no cname at all is not a row", _tk.decide("e.corp.com", []) is None)
check("dangling outranks a fingerprint when both could apply",
      (_tk.decide("f.corp.com", ["f.herokuapp.com"],
                  bodies=["No such app"],
                  unresolved={"f.herokuapp.com"}) or _tk.Candidate(
                      "", "", [], "", True, "", None)).verdict == "dangling")

print("\n== AWS puts the region where a suffix cannot see it ==")
# Found by running the detector against a live engagement: the first
# real CNAME chain collected ended at
# `...elb.ap-southeast-1.amazonaws.com`, matched nothing, and the
# table reported zero takeovers on an estate that had them. A suffix
# match cannot see a region in the middle of a name.
check("the ELB spelling that was actually observed matches",
      (_tk.provider_for("zpath-prod-exporter-28195a8e3048929a"
                        ".elb.ap-southeast-1.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS ELB")
check("...as does the other spelling AWS uses",
      (_tk.provider_for("x-123.eu-west-1.elb.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS ELB")
check("...and the regionless one",
      (_tk.provider_for("x-123.elb.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS ELB")
check("an ELB name is NOT claimable — the suffix is AWS-assigned, so "
      "nobody can re-register it",
      (_tk.provider_for("x-123.elb.amazonaws.com")
       or _tk.Provider("", ("",), claimable=True)).claimable is False)

# The same infix problem for S3, which used to be three hardcoded
# startswith checks inside the matcher.
check("an S3 website endpoint with a region still matches",
      (_tk.provider_for("b.s3-website-eu-west-1.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS S3")
check("...and the dualstack spelling",
      (_tk.provider_for("b.s3.dualstack.us-east-1.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS S3")
check("...and the external-1 spelling",
      (_tk.provider_for("b.s3-external-1.amazonaws.com")
       or _tk.Provider("", ())).name == "AWS S3")
check("...while a plain bucket is still claimable, unlike an ELB",
      (_tk.provider_for("b.s3.amazonaws.com")
       or _tk.Provider("", ())).claimable is True)

print("\n== an undetermined row says WHAT is missing ==")
# "Could not determine" on its own tells a reader a conclusion is
# absent without telling them what is absent, which is the one thing
# they need to go and settle it. Three genuinely different
# situations hide behind that phrase and each implies a different
# next action.
_elb = _tk.decide("a.corp.com", ["x.elb.eu-west-1.amazonaws.com"])
check("a provider with no unclaimed page says so",
      "no distinctive unclaimed page" in (_elb.evidence or ""), _elb.evidence)
check("...and names the lookup that would settle it",
      "Run a DNS lookup" in (_elb.evidence or ""), _elb.evidence)

_none = _tk.decide("b.corp.com", ["b.s3.amazonaws.com"])
check("nothing fetched says nothing was fetched",
      "nothing has been fetched" in (_none.evidence or ""), _none.evidence)
check("...and says what to run", "httpx" in (_none.evidence or ""),
      _none.evidence)

_live = _tk.decide("c.corp.com", ["c.s3.amazonaws.com"],
                   bodies=["<html>a perfectly live bucket</html>"])
check("a page that is NOT the unclaimed one says the resource looks live",
      "suggests the resource is live" in (_live.evidence or ""), _live.evidence)
check("...while still not claiming it is proven either way",
      "not proven either way" in (_live.evidence or ""), _live.evidence)

check("the three reasons are actually different",
      len({_elb.evidence, _none.evidence, _live.evidence}) == 3)
# The finding carries it too: a vuln that says "could not determine"
# with no reason gives its reader nothing to act on.
check("the finding description carries the reason",
      "Not confirmed:" in _tk.vuln_description(_elb),
      _tk.vuln_description(_elb)[:80])

print("\n== what CloudFront actually says, and what it means ==")
# This section exists because the detector was wrong on live data and
# said so with confidence. Its CloudFront fingerprint was the string
# "ERROR: The request could not be satisfied", which CloudFront
# returns for at least four unrelated reasons. Thirteen hostnames
# matched it on one engagement. Reading the captured bodies back, all
# thirteen were live distributions.
#
# The bodies below are the four real shapes, with the client's names
# taken out.
_CF = ('<HTML><HEAD><TITLE>ERROR: The request could not be satisfied'
       '</TITLE></HEAD><BODY><H1>403 ERROR</H1>'
       '<H2>The request could not be satisfied.</H2>'
       '<HR noshade size="1px">{}'
       '<BR clear="all"><HR noshade size="1px">'
       '<PRE>Generated by cloudfront (CloudFront) HTTP3 Server</PRE>'
       '</BODY></HTML>')
_CF_UNCLAIMED = _CF.format("Bad request.")
_CF_WAF = _CF.format("Request blocked.")
_CF_METHOD = _CF.format(
    "This distribution is not configured to allow the HTTP request method "
    "that was used for this request.")
_CF_GEO = _CF.format(
    "The Amazon CloudFront distribution is configured to block access "
    "from your country.")

_tls = lambda b: _tk.Capture(b, secure=True)      # noqa: E731
_plain = lambda b: _tk.Capture(b, secure=False)   # noqa: E731

# The measured fact: every `Bad request.` on that engagement came
# over http, and the SAME hostname over https returned the WAF page.
# CloudFront routes on the TLS name, so a plaintext answer from it
# says nothing about whether the name is claimed.
d = _tk.decide("a.corp.com", ["a.cloudfront.net"],
               bodies=[_plain(_CF_UNCLAIMED)])
check("a plaintext CloudFront 'Bad request.' does NOT convict",
      d is not None and d.verdict == "candidate", d and d.verdict)
check("...and says it was the scheme that stopped it",
      d is not None and "came over http" in (d.evidence or ""), d and d.evidence)

d = _tk.decide("b.corp.com", ["b.cloudfront.net"],
               bodies=[_tls(_CF_UNCLAIMED)])
check("the same page over https DOES convict",
      d is not None and d.verdict == "fingerprint", d and d.verdict)

# The three that are served BY a distribution, so they prove the
# opposite of a takeover. Each was counted as evidence FOR one.
for _label, _body in (("a WAF block", _CF_WAF),
                      ("a 405", _CF_METHOD),
                      ("a geo block", _CF_GEO)):
    d = _tk.decide("c.corp.com", ["c.cloudfront.net"], bodies=[_tls(_body)])
    check(f"{_label} from CloudFront is `live`, not a takeover",
          d is not None and d.verdict == "live", d and d.verdict)
    check(f"...and {_label} says why the name is claimed",
          d is not None and "claimed" in (d.evidence or ""), d and d.evidence)

# `Bad request.` is four words that appear on a thousand error pages.
# Without the guard the fingerprint matches a page CloudFront did not
# serve at all.
d = _tk.decide("e.corp.com", ["e.cloudfront.net"],
               bodies=[_tls("<html><body>Bad request.</body></html>")])
check("'Bad request.' on a page CloudFront did not generate is not a hit",
      d is not None and d.verdict == "candidate", d and d.verdict)

# Both at once is not a verdict. It is two observations that cannot
# both describe the same moment, and picking the louder one is how
# the thirteen false positives were written.
d = _tk.decide("f.corp.com", ["f.cloudfront.net"],
               bodies=[_tls(_CF_UNCLAIMED), _tls(_CF_WAF)])
check("evidence that disagrees with itself is not a finding",
      d is not None and d.verdict == "candidate", d and d.verdict)
check("...and says so, rather than picking one",
      d is not None and "disagrees with itself" in (d.evidence or ""),
      d and d.evidence)

# A dangling chain still outranks everything, including a live page:
# a resolver reporting the hop empty is a fact about DNS, and the
# page may simply be older.
d = _tk.decide("g.corp.com", ["g.cloudfront.net"], bodies=[_tls(_CF_WAF)],
               unresolved={"g.cloudfront.net"})
check("a chain that does not resolve still outranks a live page",
      d is not None and d.verdict == "dangling", d and d.verdict)

# A plain string is still a body, for every provider that does not
# route on SNI. Changing the shape must not quietly disarm the rest
# of the table.
check("a bare string body still works for a provider without tls_only",
      (_tk.decide("h.corp.com", ["h.herokuapp.com"],
                  bodies=["No such app"]) or
       _tk.Candidate("", "", [], "", True, "", None)).verdict == "fingerprint")

print("\n== `live` is an answer, not a finding ==")
check("`live` is a verdict the detector can reach",
      "live" in _tk.VERDICTS)
check("...and it is NOT raised as a finding",
      "live" not in _tk.RAISE_VERDICTS, _tk.RAISE_VERDICTS)
# The other three are. A row that could not be settled is still
# worth somebody's eyes; a row that was settled in the "nothing here"
# direction is a finished question.
check("...while the other three still are",
      set(_tk.RAISE_VERDICTS) == {"dangling", "fingerprint", "candidate"},
      _tk.RAISE_VERDICTS)
check("a live row still has a severity, so the table has no hole",
      _tk.severity_for(_tk.Candidate("x", "y", [], "AWS CloudFront",
                                     False, "live", "served x")) == "low")


print("\n== 'nobody looked' and 'it resolves' are different answers ==")
# The gap this closes, found by actually running the lookups: 35 hops
# were resolved on the live engagement and every row still read "no
# lookup has reported this as empty" -- which is true of a name
# nobody has looked up AND of one that answered an hour ago. A reader
# told the first when the second is true is being told the check has
# not happened when it has.
_never = _tk.decide("a.corp.com", ["x.elb.eu-west-1.amazonaws.com"])
_does = _tk.decide("b.corp.com", ["x.elb.eu-west-1.amazonaws.com"],
                   resolved={"x.elb.eu-west-1.amazonaws.com"})
check("with no lookup, it asks for one",
      "Run a DNS lookup" in (_never.evidence or ""), _never.evidence)
check("once it has resolved, it says so instead",
      "answered with addresses" in (_does.evidence or ""), _does.evidence)
check("...and stops asking for a lookup that has happened",
      "Run a DNS lookup" not in (_does.evidence or ""), _does.evidence)
check("the two are genuinely different sentences",
      _never.evidence != _does.evidence)

# A resolving hop does NOT prove the resource is claimed. Several of
# these providers answer for names nobody has taken -- that is the
# entire reason subdomain takeover works -- so the text must not
# upgrade an observation into a conclusion.
check("a resolving hop is not claimed to prove anything more",
      _does.verdict == "candidate", _does.verdict)
_live = _tk.decide("c.corp.com", ["c.s3.amazonaws.com"],
                   bodies=["<html>a perfectly live bucket</html>"],
                   resolved={"c.s3.amazonaws.com"})
check("...and with a live-looking page too, it still says 'without proving'",
      "without proving" in (_live.evidence or ""), _live.evidence)

# An EMPTY answer still outranks everything: that is the one case
# where the record is provably pointing at nothing.
_gone = _tk.decide("d.corp.com", ["d.herokuapp.com"],
                   unresolved={"d.herokuapp.com"},
                   resolved={"d.herokuapp.com"})
check("an empty answer still wins over a stale resolving one",
      _gone.verdict == "dangling", _gone.verdict)


print("\n== not every dangling record is an exploitable takeover ==")
d = _tk.decide("g.corp.com", ["g.elasticbeanstalk.com"],
               unresolved={"g.elasticbeanstalk.com"})
check("beanstalk still dangles and is still reported",
      d is not None and d.verdict == "dangling", d and d.verdict)
check("...but is marked unclaimable, so a report does not overstate it",
      d is not None and d.claimable is False, d and d.claimable)
check("an S3 bucket by contrast is claimable",
      (_tk.decide("h.corp.com", ["h.s3.amazonaws.com"]) or
       _tk.Candidate("", "", [], "", False, "", None)).claimable is True)

print("\n== the chain is kept, not just the hop that matched ==")
d = _tk.decide("i.corp.com", ["edge.corp.com", "i.github.io"])
check("an intermediate hop does not hide the provider behind it",
      d is not None and d.provider == "GitHub Pages", d and d.provider)
check("...and the cname recorded is the hop that landed on it",
      d is not None and d.cname == "i.github.io", d and d.cname)
check("...while the whole chain survives for a reader",
      d is not None and d.chain == ["edge.corp.com", "i.github.io"], d and d.chain)

print("\n== a takeover becomes a finding ==")
def _sev(verdict, claimable):
    return _tk.severity_for(_tk.Candidate(
        "h", "cn", ["cn"], "P", claimable, verdict,
        None if verdict == "candidate" else "evidence"))

check("a record nobody can re-register is Low",
      _sev("fingerprint", False) == "low")
check("...and one anybody can is not",
      _sev("fingerprint", True) == "high")

# The inversion this table exists to prevent, measured on a live
# engagement: keyed on `claimable` alone, an EVIDENCED CloudFront
# finding ranked Low while an UNEVIDENCED Heroku name would have
# ranked High. A report where a proven misconfiguration sits below a
# guess teaches its reader to distrust the severities.
print("\n== a guess never outranks evidence ==")
_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_evidenced = [_sev(v, c) for v in ("dangling", "fingerprint")
              for c in (False, True)]
_guesses = [_sev("candidate", c) for c in (False, True)]
check("the worst unevidenced row does not outrank the best evidenced one",
      max(_rank[x] for x in _guesses) <= min(_rank[x] for x in _evidenced),
      (_guesses, _evidenced))
check("an unevidenced claimable row no longer borrows High",
      _sev("candidate", True) == "low", _sev("candidate", True))
check("evidence on a claimable provider is still the top of the table",
      _sev("dangling", True) == "high")
check("claimable=False is Low throughout, as specified",
      all(_sev(v, False) == "low"
          for v in ("dangling", "fingerprint", "candidate")))
check("a verdict the table has never met falls to the floor, not the top",
      _tk.severity_for(_tk.Candidate("h", "c", ["c"], "P", True,
                                     "something-new", None)) == "low")
_c = _tk.Candidate("x.corp.com", "y.elb.eu-west-1.amazonaws.com",
                   ["y.elb.eu-west-1.amazonaws.com"], "AWS ELB",
                   False, "candidate", None)
_d = _tk.vuln_description(_c)
check("the description says the verdict could not be determined, rather "
      "than asserting the record dangles",
      "Neither check could be run" in _d, _d[:80])
check("...and says plainly that it is not an exploitable takeover",
      "not an exploitable takeover" in _d, _d[:80])
_c2 = _tk.Candidate("y.corp.com", "b.s3.amazonaws.com",
                    ["b.s3.amazonaws.com"], "AWS S3", True,
                    "fingerprint", "NoSuchBucket")
_d2 = _tk.vuln_description(_c2)
check("a claimable one says somebody else can serve content on the name",
      "somebody else can serve content" in _d2, _d2[:80])
check("...and quotes the evidence that convicted it",
      "NoSuchBucket" in _d2, _d2[:120])

print("\n== the endpoint ==")
TAKEOVER_HTTPX = "\n".join(json.dumps(x) for x in [
    {"url": "https://dead.corp.com", "input": "dead.corp.com",
     "host": "10.0.0.77", "port": 443, "scheme": "https", "status_code": 404,
     "cname": ["dead.herokuapp.com"]},
    {"url": "https://live.corp.com", "input": "live.corp.com",
     "host": "10.0.0.78", "port": 443, "scheme": "https", "status_code": 200,
     "cname": ["live.corp.com.edge.internal"]},
])
imp(TAKEOVER_HTTPX)
st, r = call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
check("refresh runs and reports what it decided", st == 200, f"{st} {r}")
# `total` counts TAKEOVERS. The findings raised are a separate number:
# folding them into the same dict made `sum(counts.values())` report
# eight rows for four, which is the sort of wrong a findings page
# should not be able to show.
check("total is the takeover count, not takeovers plus findings",
      (r or {}).get("total") == sum((r or {}).get("counts", {}).values()),
      r)
check("...and the findings raised are reported separately",
      "findings_open" in (r or {}), r)
check("no verdict key is an internal one",
      not any(k.startswith("_") for k in (r or {}).get("counts", {})), r)
st, r = call("/api/web/takeovers?project=WEB", token=admin)
check("the endpoint answers", st == 200, st)
hosts = {i["hostname"]: i for i in (r or {}).get("items", [])}
check("the host pointing at heroku is listed",
      "dead.corp.com" in hosts, list(hosts))
check("...as a candidate, because nothing here proved it dangles",
      hosts.get("dead.corp.com", {}).get("verdict") == "candidate",
      hosts.get("dead.corp.com"))
check("...naming the provider", hosts.get("dead.corp.com", {}).get("provider") == "Heroku",
      hosts.get("dead.corp.com"))
check("the host pointing at internal infrastructure is NOT listed",
      "live.corp.com" not in hosts, list(hosts))

tid = hosts.get("dead.corp.com", {}).get("id")
st, r = call(f"/api/web/takeovers/{tid}?project=WEB", "PATCH",
             {"state": "false_positive", "note": "client owns it"}, token=admin)
check("an operator can triage a row", st == 200 and r["state"] == "false_positive",
      f"{st} {r}")

# The whole point of re-deriving rather than accumulating: DNS facts
# are rebuilt, operator decisions are not thrown away with them.
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
st, r = call("/api/web/takeovers?project=WEB", token=admin)
again = {i["hostname"]: i for i in (r or {}).get("items", [])}
check("a refresh keeps the triage an operator already did",
      again.get("dead.corp.com", {}).get("state") == "false_positive",
      again.get("dead.corp.com"))

# The finding side of the same pass.
print("\n== the finding is raised, once, and tracks the record ==")
st, vs = call("/api/vulns?project=WEB&limit=500", token=admin)
tv = [v for v in (vs or {}).get("items", [])
      if (v.get("external_id") or "").startswith("takeover:")]
check("a finding was raised for the takeover", len(tv) >= 1, len(tv))
# dead.corp.com points at Heroku, which IS first-come -- but nothing
# here showed the name to be unclaimed, so the verdict is `candidate`
# and the severity is Low. Claimable says how bad IF TRUE; the
# verdict says whether we know it is true, and it caps the answer.
# This assertion read High until the severity table grew its second
# input, which is the inversion it was written to catch.
check("...at Low: first-come, but nothing showed it was unclaimed",
      all(v["severity"] == "low" for v in tv), [v["severity"] for v in tv])
check("...keyed on external_id so it can be found again",
      all(v["external_id"].startswith("takeover:") for v in tv), tv[:1])

# Run the detector twice more. A detector that re-derives on every
# pass and forks a finding each time produces a pile, not a list.
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
st, vs2 = call("/api/vulns?project=WEB&limit=500", token=admin)
tv2 = [v for v in (vs2 or {}).get("items", [])
       if (v.get("external_id") or "").startswith("takeover:")]
check("three refreshes do not make three findings",
      len(tv2) == len(tv), f"{len(tv)} then {len(tv2)}")

# The Low half of the pair: a provider surface nobody can re-register.
ELB_HTTPX = json.dumps(
    {"url": "https://lb.corp.com", "input": "lb.corp.com",
     "host": "10.0.0.90", "port": 443, "scheme": "https",
     "status_code": 200,
     "cname": ["lb-9f2.elb.ap-southeast-1.amazonaws.com"]})
imp(ELB_HTTPX)
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
st, vs3 = call("/api/vulns?project=WEB&limit=500", token=admin)
elb = [v for v in (vs3 or {}).get("items", [])
       if (v.get("external_id") or "") == "takeover:lb.corp.com"]
check("an ELB-backed record is raised too", len(elb) == 1, len(elb))
check("...at Low, because the name is AWS-assigned and not re-registerable",
      elb and elb[0]["severity"] == "low", elb and elb[0]["severity"])

# The High case end to end: a first-come provider AND evidence. This
# is the only shape that reaches the top of the table, and without a
# test for it the severity column could be stuck on Low and nothing
# would say so.
S3_HTTPX = json.dumps(
    {"url": "https://gone.corp.com", "input": "gone.corp.com",
     "host": "10.0.0.91", "port": 443, "scheme": "https",
     "status_code": 404, "cname": ["gone-assets.s3.amazonaws.com"],
     "response": "HTTP/1.1 404\r\n\r\n<Error><Code>NoSuchBucket</Code>"
                 "<Message>The specified bucket does not exist</Message>"
                 "</Error>"})
imp(S3_HTTPX)
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
st, vs4 = call("/api/vulns?project=WEB&limit=500", token=admin)
s3 = [v for v in (vs4 or {}).get("items", [])
      if (v.get("external_id") or "") == "takeover:gone.corp.com"]
check("an evidenced takeover on a first-come provider is raised",
      len(s3) == 1, len(s3))
check("...at High — the one shape that reaches the top of the table",
      s3 and s3[0]["severity"] == "high", s3 and s3[0]["severity"])

check("...and the note with it",
      again.get("dead.corp.com", {}).get("note") == "client owns it",
      again.get("dead.corp.com"))


print("\n== a row that is serving raises nothing ==")
# The half of the CloudFront fix that decides whether a client's
# report gets cleaner. Thirteen findings were raised by the old
# detector against hosts that were live all along. The new detector
# decides those `live`, which is NOT in RAISE_VERDICTS -- so no
# finding is raised, and `_sync_vulns` closes any that already
# exists because it is no longer wanted.
#
# Closed rather than deleted, deliberately: "we found this and it
# was not real" is a thing a report should be able to say.
LIVE_ONLY = json.dumps(
    {"url": "https://cdn.corp.com", "input": "cdn.corp.com",
     "host": "10.0.0.92", "port": 443, "scheme": "https",
     "status_code": 403, "cname": ["d111111abcdef8.cloudfront.net"],
     "response": "HTTP/1.1 403\r\n\r\n<HTML><H1>403 ERROR</H1>"
                 "<H2>The request could not be satisfied.</H2>"
                 "Request blocked.<PRE>Generated by cloudfront (CloudFront)"
                 "</PRE></HTML>"})
imp(LIVE_ONLY)
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)

st, tks = call("/api/web/takeovers?project=WEB&verdict=live", token=admin)
rows = [t for t in (tks or {}).get("items", [])
        if t["hostname"] == "cdn.corp.com"]
check("a WAF page from CloudFront decides the row `live`", len(rows) == 1,
      [t["hostname"] for t in (tks or {}).get("items", [])])
check("...and says what it saw, not that it could not tell",
      rows and "claimed" in (rows[0]["evidence"] or ""),
      rows and rows[0]["evidence"])

st, vs5 = call("/api/vulns?project=WEB&limit=500", token=admin)
cdn = [v for v in (vs5 or {}).get("items", [])
       if (v.get("external_id") or "") == "takeover:cdn.corp.com"]
# This is the number that was 13 on the live engagement.
check("NO finding is raised for it", len(cdn) == 0,
      [v["title"] for v in cdn])
# The row still exists, so the work is visible even though nothing
# was filed. A sweep that examined a host and found nothing must not
# look like a sweep that never ran.
check("...while the row stays in the table, so the check is visible",
      len(rows) == 1)

print("\n== plaintext cannot convict a provider that routes on SNI ==")
# The production shape, which is the one that mattered: an http
# "Bad request." on the same host as an https WAF page. The http
# body is an artefact of asking port 80 -- CloudFront routes on the
# TLS name -- so it must not create a contradiction with the https
# answer, or every one of the thirteen would come back as
# `candidate` instead of being settled.
PLAINTEXT_BAD = json.dumps(
    {"url": "http://cdn.corp.com", "input": "cdn.corp.com",
     "host": "10.0.0.92", "port": 80, "scheme": "http",
     "status_code": 403, "cname": ["d111111abcdef8.cloudfront.net"],
     "response": "HTTP/1.1 403\r\n\r\n<HTML><H1>403 ERROR</H1>"
                 "<H2>The request could not be satisfied.</H2>"
                 "Bad request.<PRE>Generated by cloudfront (CloudFront)"
                 "</PRE></HTML>"})
imp(PLAINTEXT_BAD)
call("/api/web/takeovers/refresh?project=WEB", "POST", {}, token=admin)
st, tks2 = call("/api/web/takeovers?project=WEB", token=admin)
row2 = [t for t in (tks2 or {}).get("items", [])
        if t["hostname"] == "cdn.corp.com"]
check("the http page does not argue with the https one",
      row2 and row2[0]["verdict"] == "live",
      row2 and (row2[0]["verdict"], row2[0]["evidence"]))
st, vs6 = call("/api/vulns?project=WEB&limit=500", token=admin)
cdn2 = [v for v in (vs6 or {}).get("items", [])
        if (v.get("external_id") or "") == "takeover:cdn.corp.com"]
check("...and still raises nothing", len(cdn2) == 0,
      [v["title"] for v in cdn2])


# ======================================================== screenshots
print("== a ghost's screenshot lands, and can be read back ==")
# The picture is the only artefact here that answers "what IS this"
# rather than "what did it say", and it travels as base64 because the
# agent's result is one JSON document in a text column -- a PNG
# contains NUL bytes, which Postgres refuses in text outright. So the
# round trip worth testing is: base64 in, bytes out, served as an
# image.
import struct as _struct  # noqa: E402
import zlib as _zlib  # noqa: E402

# `_b64` is already imported further up this file, where the exchange
# capture needed it.


def _png(w=4, h=3):
    """A real, valid PNG. Built rather than pasted, so the test says
    what makes it valid instead of carrying an opaque blob."""
    def chunk(tag, data):
        c = tag + data
        return (_struct.pack(">I", len(data)) + c
                + _struct.pack(">I", _zlib.crc32(c) & 0xFFFFFFFF))
    raw = b"".join(b"\x00" + b"\xff\x00\x80" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", _struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", _zlib.compress(raw))
            + chunk(b"IEND", b""))


SHOT_URL = "https://portal.acme.example/login"
SHOT = json.dumps({
    "browser": "/usr/bin/chromium",
    "viewport": {"width": 1280, "height": 800},
    "shots": [{
        "url": SHOT_URL,
        "final_url": "https://sso.acme.example/login?rd=portal",
        "status": 200, "title": "ACME portal",
        "server": "acme-httpd/1.0", "page_content_type": "text/html",
        "width": 1280, "height": 800,
        "bytes": len(_png()), "sha256": "0" * 64,
        "png_base64": _b64.b64encode(_png()).decode(),
    }],
    "failed": [{"url": "https://dead.acme.example/",
                "error": "net::ERR_CONNECTION_REFUSED"}],
})

st, rep = imp(SHOT)
check("a screenshot result is recognised without being told",
      st == 200 and (rep or {}).get("format") == "screenshot", (st, rep))
check("the picture is stored", (rep or {}).get("screenshots_created") == 1,
      (rep or {}).get("screenshots_created"))
# The page that could not be photographed is NAMED. "1 of 2" with no
# account of the other is the substitution this codebase treats as a
# bug rather than a rounding error.
check("...and the page that failed is reported rather than dropped",
      any("dead.acme.example" in e for e in (rep or {}).get("errors") or []),
      (rep or {}).get("errors"))
# A photographed URL is a FETCHED URL: a browser asked for it and drew
# the answer. That is stronger evidence than a crawl's "something
# linked to this", and it gives the picture a row to be shown on.
st, rows = call("/api/web?project=WEB&q=portal.acme.example&limit=50",
                token=admin)
shot_row = [r for r in (rows or {}).get("items", [])
            if r["url"] == SHOT_URL]
check("the URL itself reaches the inventory", len(shot_row) == 1,
      [r["url"] for r in (rows or {}).get("items", [])])
check("...recorded as fetched, not merely linked to",
      shot_row and shot_row[0]["crawled"] is True)
check("...carrying what the browser saw",
      shot_row and shot_row[0]["status_code"] == 200
      and shot_row[0]["title"] == "ACME portal",
      shot_row and (shot_row[0]["status_code"], shot_row[0]["title"]))

st, pk = call(f"/api/web/{shot_row[0]['id']}/packet", token=admin)
shot = (pk or {}).get("screenshot")
check("the packet view knows the picture exists", st == 200 and bool(shot),
      (st, pk))
check("...and says when it was taken, because a picture carries no date",
      bool((shot or {}).get("captured_at")), shot)
check("...and where the browser ended up, which the image cannot show",
      ((shot or {}).get("final_url") or "").startswith("https://sso.acme.example"),
      (shot or {}).get("final_url"))
# The image itself is bytes from its own endpoint. An <img> cannot
# send an Authorization header, and nothing base64-encodes a megabyte
# into JSON to get a picture onto a page.
_req = urllib.request.Request(
    f"{BASE}/api/web/screenshots/{shot['id']}/image")
_req.add_header("Authorization", f"Bearer {admin}")
with urllib.request.urlopen(_req, timeout=60) as _r:
    _body = _r.read()
    _ctype = _r.headers.get("Content-Type", "")
check("the image comes back as a PNG",
      _body.startswith(b"\x89PNG\r\n\x1a\n") and _ctype == "image/png",
      (_ctype, _body[:8]))
check("...byte for byte what the agent sent", _body == _png(),
      (len(_body), len(_png())))

# A second capture REPLACES. Ten pictures of one URL are ten copies of
# one page, and across an estate that has reached 51,000 URLs that is
# the difference between a database and a problem.
AGAIN = json.loads(SHOT)
AGAIN["shots"][0]["title"] = "ACME portal (maintenance)"
st, rep2 = imp(json.dumps(AGAIN))
check("a re-shoot replaces rather than accumulating",
      (rep2 or {}).get("screenshots_updated") == 1
      and (rep2 or {}).get("screenshots_created") == 0, rep2)
st, pk2 = call(f"/api/web/{shot_row[0]['id']}/packet", token=admin)
check("...and the metadata describes THIS picture, not the last one",
      ((pk2 or {}).get("screenshot") or {}).get("title")
      == "ACME portal (maintenance)",
      ((pk2 or {}).get("screenshot") or {}).get("title"))

# A field called png_base64 holding something else is not a picture,
# and the one thing worse than no screenshot is one that renders as
# nothing and explains itself to nobody.
NOTPNG = json.dumps({
    "browser": "/usr/bin/chromium", "viewport": {"width": 800, "height": 600},
    "shots": [{"url": "https://fake.acme.example/",
               "png_base64": _b64.b64encode(b"GIF89a not a png").decode()}],
})
st, rep3 = imp(NOTPNG)
check("something that is not a PNG is refused, with a reason",
      st != 200 or (rep3 or {}).get("screenshots_created") == 0,
      (st, rep3))

# An operator reading the task afterwards must still be able to see
# what it did -- but not a second copy of every image.
from app.importers import screenshot as _shotmod  # noqa: E402

_stripped = json.loads(_shotmod.without_images(SHOT))
check("the stored result keeps everything but the payload",
      "png_base64" not in _stripped["shots"][0]
      and _stripped["shots"][0]["url"] == SHOT_URL
      and _stripped["shots"][0]["sha256"] == "0" * 64
      and _stripped["failed"][0]["url"] == "https://dead.acme.example/",
      _stripped["shots"][0])
check("...and says where the bytes went",
      _stripped["shots"][0].get("stored_in_database") is True)
check("stripping something that is not a screenshot result changes nothing",
      _shotmod.without_images("not json at all") == "not json at all")


print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
