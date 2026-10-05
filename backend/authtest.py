"""Auth + ACL verification for Oddjob."""
import json, urllib.request, urllib.error

import os
BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8000")
ok = fail = 0

def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label} {extra}")
    else:    fail += 1; print(f"  FAIL  {label} {extra}")

def call(path, method="GET", body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:200]

print("== first run ==")
st, r = call("/api/auth/setup-required")
check("setup required on empty db", st == 200 and r["setup_required"] is True, str(r))
st, r = call("/api/targets")
check("unauthenticated read is 401", st == 401, f"status={st}")

st, r = call("/api/auth/setup", "POST",
             {"username": "brandon", "password": "correct-horse-battery", "email": "b@x.io"})
check("setup creates first user", st == 201, f"status={st}")
admin = r["access_token"]
check("first user is site admin", r["user"]["is_site_admin"] is True)
check("first user is in site-admins group",
      any(g["name"] == "site-admins" for g in r["user"]["groups"]),
      str([g["name"] for g in r["user"]["groups"]]))

st, r = call("/api/auth/setup-required")
check("setup no longer required", r["setup_required"] is False)
st, r = call("/api/auth/setup", "POST", {"username": "sneak", "password": "password123"})
check("second setup attempt is 409", st == 409, f"status={st}")

print("\n== login ==")
st, r = call("/api/auth/login", "POST", {"username": "brandon", "password": "wrong"})
check("wrong password 401", st == 401)
st, r = call("/api/auth/login", "POST", {"username": "nobody", "password": "wrong"})
check("unknown user 401 with same message", st == 401 and "invalid username or password" in str(r))
st, r = call("/api/auth/login", "POST", {"username": "brandon", "password": "correct-horse-battery"})
check("correct login 200", st == 200)
admin = r["access_token"]

print("\n== projects + data ==")
st, r = call("/api/projects", "POST", {"code": "falcon-1", "name": "ACME External"}, token=admin)
check("site admin creates project", st == 201, f"status={st}")
# POST /api/projects returns a ProjectCreated envelope, not a bare project:
# it has to be able to report scope lines and members it could not apply.
check("code normalised to upper", r["project"]["code"] == "FALCON-1", str(r.get("project")))
st, r = call("/api/projects", "POST", {"code": "OTHER", "name": "Other Engagement"}, token=admin)
check("second project", st == 201)

st, r = call("/api/bulk", "POST", {
    "project": "FALCON-1",
    "targets": [{"host": "web01.acme.example", "ip_address": "10.1.1.1", "alive": True, "hacked": True},
                {"host": "db01.acme.example", "alive": False},
                {"host": "*.acme.example"},                       # wildcard: must be skipped
                {"host": "bad host.acme.example"}],               # space: must be skipped
    "services": [{"host": "web01.acme.example", "port": 443, "protocol": "tcp", "name": "https",
                  "banner": "nginx"},
                 {"host": "web01.acme.example", "port": 25, "state": "closed", "name": "smtp"}],
    "vulns": [{"host": "web01.acme.example", "title": "RCE", "severity": "critical", "external_id": "A1"}],
    "pocs": [{"host": "web01.acme.example", "title": "poc-rce", "status": "confirmed"}],
}, token=admin)
check("bulk succeeds despite bad hosts", st == 200, f"status={st}")
check("2 good targets created", r["created"]["targets"] == 2, str(r["created"]))
check("2 bad hosts skipped not fatal", r["skipped"]["targets"] == 2, str(r["skipped"]))
check("wildcard named in errors", any("*" in e for e in r["errors"]), str(r["errors"])[:160])

st, r = call("/api/targets?project=FALCON-1", token=admin)
check("targets listed", r["total"] == 2, f"total={r['total']}")
w = next(t for t in r["items"] if t["host"] == "web01.acme.example")
check("alive true recorded", w["alive"] is True)
check("alive false distinct from null",
      next(t for t in r["items"] if t["host"] == "db01.acme.example")["alive"] is False)
check("counts derived", (w["total_vulns"], w["total_criticals"], w["total_pocs"],
                         w["total_ports"]) == (1, 1, 1, 1),
      f"{w['total_vulns']}/{w['total_criticals']}/{w['total_pocs']}/{w['total_ports']}")
check("project_code on row", w["project_code"] == "FALCON-1")

print("\n== per-project ACL ==")
st, _ = call("/api/users", "POST", {"username": "reader", "password": "reader-password-1"}, token=admin)
check("admin creates user", st == 201, f"status={st}")
st, r = call("/api/auth/login", "POST", {"username": "reader", "password": "reader-password-1"})
reader = r["access_token"]
check("new user is NOT site admin", r["user"]["is_site_admin"] is False)

st, r = call("/api/targets", token=reader)
check("no grant -> sees nothing", r["total"] == 0, f"total={r['total']}")
st, r = call("/api/projects/FALCON-1", token=reader)
check("no grant -> project is 404 not 403", st == 404, f"status={st}")

st, r = call("/api/projects/FALCON-1/acl", "POST",
             {"username": "reader", "role": "readonly"}, token=admin)
check("grant readonly", st == 201, f"status={st}")
st, r = call("/api/targets", token=reader)
check("readonly now sees the 2 targets", r["total"] == 2, f"total={r['total']}")
st, r = call("/api/targets/FALCON-1/web01.acme.example", "PATCH", {"hacked": False}, token=reader)
check("readonly cannot write", st == 403, f"status={st}")
st, r = call("/api/bulk", "POST", {"project": "FALCON-1",
                                   "targets": [{"host": "new.acme.example"}]}, token=reader)
check("readonly cannot bulk import", st == 403, f"status={st}")

st, _ = call("/api/projects/FALCON-1/acl", "POST",
             {"username": "reader", "role": "user"}, token=admin)
st, r = call("/api/targets/FALCON-1/web01.acme.example", "PATCH", {"hacked": False}, token=reader)
check("re-grant to user allows write", st == 200, f"status={st}")

st, r = call("/api/targets?project=OTHER", token=reader)
check("still cannot see the other project", st == 404, f"status={st}")
st, r = call("/api/stats", token=reader)
check("stats scoped to granted project", r["targets"] == 2 and r["projects"] == 1, str(r)[:120])

print("\n== group-based grant ==")
st, _ = call("/api/groups", "POST", {"name": "redteam"}, token=admin)
check("create group", st == 201, f"status={st}")
st, _ = call("/api/groups/redteam/members/reader", "POST", token=admin)
check("add member", st == 200, f"status={st}")
st, _ = call("/api/projects/OTHER/acl", "POST", {"group": "redteam", "role": "readonly"}, token=admin)
check("grant to group", st == 201, f"status={st}")
st, r = call("/api/projects", token=reader)
check("group grant opens the second project", r["total"] == 2, f"total={r['total']}")

print("\n== by-id routes respect the ACL ==")
st, r = call("/api/services?project=FALCON-1", token=admin)
sid = r["items"][0]["id"]
st, _ = call("/api/projects/FALCON-1/acl", "POST",
             {"username": "reader", "role": "readonly"}, token=admin)
st, r = call(f"/api/services/{sid}", "DELETE", token=reader)
check("readonly cannot delete a service by id", st == 403, f"status={st}")

print("\n== api keys ==")
st, r = call("/api/auth/keys?name=mcp", "POST", token=admin)
check("key created", st == 201, f"status={st}")
key = r["key"]
check("key has msk_ prefix", key.startswith("msk_"))
st, r = call("/api/targets", token=key)
check("api key authenticates", st == 200 and r["total"] == 2, f"status={st}")
st, r = call("/api/auth/keys", token=admin)
check("key list never returns plaintext", all("key" not in k for k in r), str(r)[:120])
st, _ = call(f"/api/auth/keys/{r[0]['id']}", "DELETE", token=admin)
st, r = call("/api/targets", token=key)
check("revoked key rejected", st == 401, f"status={st}")

print("\n== lockout protection ==")
st, r = call("/api/groups/site-admins/members/brandon", "DELETE", token=admin)
check("cannot empty site-admins", st == 409, f"status={st}")
st, r = call("/api/groups/site-admins", "DELETE", token=admin)
check("cannot delete site-admins group", st == 409, f"status={st}")
st, r = call("/api/users/brandon", "DELETE", token=admin)
check("cannot delete own account", st == 409, f"status={st}")
st, r = call("/api/users", token=reader)
check("non-admin cannot list users", st == 403, f"status={st}")

# --- the gate: nothing answers without a credential ---------------------
print("\n== the gate ==")
import urllib.request as _u

class _NoRedirect(_u.HTTPRedirectHandler):
    """Follow nothing: the redirect IS the behaviour under test."""
    def redirect_request(self, *a, **k): return None


def raw(path, hdrs=None, method="GET"):
    op = _u.build_opener(_NoRedirect)
    r = _u.Request(BASE + path, method=method)
    for k, v in (hdrs or {}).items(): r.add_header(k, v)
    try:
        with op.open(r, timeout=20) as x: return x.status, x.read(), dict(x.headers)
    except urllib.error.HTTPError as e: return e.code, e.read(), dict(e.headers)

BROWSER = {"Accept": "text/html,application/xhtml+xml", "Sec-Fetch-Mode": "navigate"}

st, body, _ = raw("/api/targets")
check("an API call with no credential is 401", st == 401, f"status={st}")
st, body, hd = raw("/projects/ACME/vulns", BROWSER)
check("a browser that is not signed in is sent to sign in, not walled",
      st == 302, f"status={st}")
check("and the page it wanted is remembered",
      "next=%2Fprojects%2FACME%2Fvulns" in hd.get("location", ""), hd.get("location"))

# A path that does not exist and one that does must still be
# indistinguishable to a stranger — the redirect is identical either way.
a = raw("/api/targets", BROWSER)[2].get("location")
b = raw("/api/definitely-not-a-route", BROWSER)[2].get("location")
check("a real path and a made-up one still differ only in the echoed path",
      a.split("next=")[0] == b.split("next=")[0], f"{a} vs {b}")
st, _, hd = raw("/wp-admin", BROWSER)
check("so does an obvious probe", st == 302, f"status={st}")

st, _, hd = raw("/projects/ACME//evil.com", BROWSER)
check("a crafted next cannot become an open redirect",
      "//evil.com" not in hd.get("location", "").split("next=")[-1],
      hd.get("location"))

st, _, _ = raw("/openapi.json")
check("the API schema is not public", st in (401, 403), f"status={st}")
st, _, hd = raw("/docs", BROWSER)
check("the docs UI is not public", st == 302, f"status={st}")

st, _, _ = raw("/api/auth/setup-required")
check("but first-run setup stays reachable", st == 200, f"status={st}")
st, _, _ = raw("/", BROWSER)
check("and so does the sign-in page", st == 200, f"status={st}")

st, _, _ = raw("/api/targets", {"Authorization": "Bearer not.a.real.jwt"})
check("a forged bearer token does not get past the gate", st == 401, f"status={st}")
st, _, _ = raw("/api/targets", {"Authorization": f"Bearer {admin}"})
check("a real token does", st == 200, f"status={st}")

print("\n== once signed in, a missing page is simply missing ==")
AUTH = {**BROWSER, "Authorization": f"Bearer {admin}"}
st, body, _ = raw("/does-not-exist", AUTH)
check("an authenticated browser gets 404, not 403", st == 404, f"status={st}")
check("and the styled page says so",
      b"404" in body and b"No Such Page" in body, f"{len(body)} bytes")
st, _, _ = raw("/api/not-a-route", {"Authorization": f"Bearer {admin}"})
check("an authenticated API call gets 404 too", st == 404, f"status={st}")
st, _, _ = raw("/projects/ANY/targets", AUTH)
check("a real app path still serves the app", st == 200, f"status={st}")

print("\n== security headers ==")
# Every response, not just the happy path: a gate refusal, a redirect and
# a 404 need the same protection as a 200.
for label, path, hdrs in [
    ("app shell", "/", BROWSER),
    ("unauthenticated API", "/api/targets", {}),
    ("unauthenticated browse", "/projects", BROWSER),
    ("authenticated 404", "/nope", {**BROWSER, "Authorization": f"Bearer {admin}"}),
    ("API JSON", "/api/stats", {"Authorization": f"Bearer {admin}"}),
]:
    _st, _b, h = raw(path, hdrs)
    present = all(h.get(k) for k in ("content-security-policy",
                                     "x-content-type-options",
                                     "referrer-policy", "x-frame-options"))
    check(f"{label} carries the headers", present,
          "" if present else str(sorted(h))[:90])

_st, _b, h = raw("/", BROWSER)
csp = h.get("content-security-policy", "")
check("default-src is self", "default-src 'self'" in csp)
check("no inline script is permitted",
      "script-src 'self'" in csp and "unsafe-eval" not in csp, csp[:80])
check("nothing may frame it",
      "frame-ancestors 'none'" in csp and h.get("x-frame-options") == "DENY")
check("a <base> tag cannot re-point relative URLs", "base-uri 'none'" in csp)
check("forms cannot post off-site", "form-action 'self'" in csp)
check("no referrer leaks to an engagement target",
      h.get("referrer-policy") == "no-referrer")
check("sniffing is off", h.get("x-content-type-options") == "nosniff")

# HSTS must NOT be sent from a plain-http deployment: a browser that sees
# it refuses http to this host for a year, which would brick a dev server.
check("no HSTS over http", h.get("strict-transport-security") is None,
      str(h.get("strict-transport-security")))

from app.headers import build as _build, origins as _origins
s = _build("https://oddjob.corp.example", "", 365, "")
check("HSTS appears once the base URL is https",
      s["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains",
      s.get("Strict-Transport-Security"))
check("and requests are upgraded",
      "upgrade-insecure-requests" in s["Content-Security-Policy"])
check("max-age of 0 disables it",
      "Strict-Transport-Security" not in _build("https://x.example", "", 0, ""))
e = _build("https://x.example", "https://ui.example, https://alt.example")
check("extra origins reach connect-src",
      "connect-src 'self' https://ui.example https://alt.example"
      in e["Content-Security-Policy"],
      [p for p in e["Content-Security-Policy"].split("; ") if "connect" in p])
check("a garbage origin is dropped rather than injected",
      _origins("not-a-url, javascript:alert(1), https://ok.example")
      == ["https://ok.example"],
      str(_origins("not-a-url, javascript:alert(1), https://ok.example")))
f = _build("https://x.example", "", 365, "https://portal.example")
check("framing can be permitted explicitly",
      "frame-ancestors https://portal.example" in f["Content-Security-Policy"]
      and f["X-Frame-Options"] == "SAMEORIGIN")

from app.headers import cookies_secure
check("cookies are not Secure on an http deployment", cookies_secure() is False)

_st, _b, h = raw("/api/stats", {"Authorization": f"Bearer {admin}"})
check("API responses are not cached",
      "no-store" in h.get("cache-control", ""), h.get("cache-control"))

# ---------------------------------------------------------------------
# Directory traversal out of the built-SPA static fallback.
#
# The SPA catch-all serves any real file it finds under frontend/dist so
# that /favicon.svg and friends work. It used to do that with a bare
# `_DIST / full_path`, which is not containment: an absolute right-hand
# side replaces the base outright and ".." walks out of it. Signed in as
# an ordinary user this returned app/main.py and the entire SQLite
# database -- password hashes, stored credentials and API keys.
#
# Browsers collapse ".." before sending, so these have to go out on a raw
# socket; urllib and requests would both "helpfully" normalise them away
# and the test would pass against a vulnerable server.
import socket as _sock
from urllib.parse import urlsplit as _usplit


def wire(path, hdrs=None):
    """Send `path` byte-for-byte, with no normalisation anywhere."""
    u = _usplit(BASE)
    s = _sock.create_connection((u.hostname, u.port or 80), timeout=20)
    lines = [f"GET {path} HTTP/1.1", f"Host: {u.hostname}:{u.port or 80}",
             "Connection: close", "Accept: */*"]
    lines += [f"{k}: {v}" for k, v in (hdrs or {}).items()]
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    buf = b""
    while chunk := s.recv(65536):
        buf += chunk
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


_auth = {"Authorization": f"Bearer {admin}"}

check("the raw-socket helper reaches the app at all",
      wire("/favicon.svg", _auth)[0] == 200)

ESCAPES = [
    "/../package.json",
    "/../../backend/app/main.py",
    "/../../backend/app/security.py",
    "/../../backend/oddjob.db",
    "/./../../backend/app/main.py",
    "/%2e%2e/package.json",
    "/%2e%2e%2f%2e%2e%2fbackend/app/main.py",
    "/..%2f..%2fbackend/app/main.py",
    "/../../../../../../etc/passwd",
    "//etc/passwd",
    "/dist/../../backend/app/main.py",
]
for _p in ESCAPES:
    _st, _body = wire(_p, _auth)
    # 404 is the only acceptable answer. Assert on the body too: a 200
    # carrying source would be the actual breach, and a status check
    # alone would miss a future handler that 200s an error page.
    check(f"authenticated traversal refused: {_p}",
          _st == 404 and b"_DIST" not in _body and b"password_hash" not in _body
          and b"SQLite format" not in _body,
          f"status {_st}, {len(_body)}b")

# Unauthenticated it must not even reach the static handler.
for _p in ("/../../backend/oddjob.db", "/../package.json"):
    check(f"unauthenticated traversal refused: {_p}", wire(_p)[0] in (401, 404))

# The assets the fallback exists to serve must keep working, including
# without a session -- the sign-in page renders them.
for _p, _ct in (("/favicon.svg", b"svg"), ("/favicon.ico", b"icon"),
                ("/favicon-32.png", b"png"), ("/apple-touch-icon.png", b"png")):
    _st, _body = wire(_p)
    check(f"{_p} serves to a signed-out browser", _st == 200 and len(_body) > 100,
          f"status {_st}, {len(_body)}b")

# ---------------------------------------------------------------------
# Cache-Control. The SPA shell is the only thing that names the hashed
# bundle, so a cached shell pins the browser to old JavaScript. This
# actually happened: a fixed build was deployed and the browser kept
# running the broken one, which was indistinguishable from the bug not
# being fixed. Chrome invents a lifetime from Last-Modified when no
# Cache-Control is sent, so "we send nothing" is not a safe default.
for _p in ("/", "/index.html", "/projects"):
    _st, _b, _h = raw(_p, {"Accept": "text/html",
                           "Authorization": f"Bearer {admin}"})
    _cc = _h.get("cache-control", "")
    check(f"the SPA shell at {_p} is not cacheable",
          "no-cache" in _cc or "no-store" in _cc, f"{_st} {_cc!r}")

import re as _re
_st, _body, _ = raw("/index.html", {"Accept": "text/html",
                                    "Authorization": f"Bearer {admin}"})
_m = _re.search(rb'assets/[A-Za-z0-9_.-]+\.js', _body or b"")
check("the shell references a hashed bundle", _m is not None, str(_body)[:120])
if _m:
    _st, _b2, _h2 = raw("/" + _m.group(0).decode(),
                        {"Authorization": f"Bearer {admin}"})
    _cc = _h2.get("cache-control", "")
    check("a content-hashed asset is cached hard",
          _st == 200 and "immutable" in _cc, f"{_st} {_cc!r}")

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
