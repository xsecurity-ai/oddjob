"""Credentials, bulk edit/delete, profile and Google-status checks."""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json, urllib.request, urllib.error

import os
BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8003")
ok = fail = 0

def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label} {extra}")
    else:    fail += 1; print(f"  FAIL  {label} {extra}")

def call(path, method="GET", body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.data = json.dumps(body).encode(); req.add_header("Content-Type", "application/json")
    if token: req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read(); return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:200]

st, r = call("/api/auth/setup", "POST", {"username": "root", "password": "root-password-1"})
admin = r["access_token"]
call("/api/projects", "POST", {"code": "ALPHA", "name": "Alpha"}, token=admin)
call("/api/projects", "POST", {"code": "BETA", "name": "Beta"}, token=admin)
call("/api/bulk", "POST", {"project": "ALPHA", "targets": [
    {"host": f"h{i}.alpha.test", "ip_address": f"10.0.0.{i}"} for i in range(1, 6)],
    "services": [{"host": "h1.alpha.test", "port": 443, "name": "https"},
                 {"host": "h2.alpha.test", "port": 22, "name": "ssh"}],
    "vulns": [{"host": "h1.alpha.test", "title": "V1", "severity": "high", "external_id": "a1"},
              {"host": "h2.alpha.test", "title": "V2", "severity": "low", "external_id": "a2"}]},
    token=admin)
call("/api/bulk", "POST", {"project": "BETA",
    "targets": [{"host": "h1.beta.test"}]}, token=admin)

print("== google status (unconfigured) ==")
st, r = call("/api/auth/google/status")
check("status is public and reports disabled", st == 200 and r["enabled"] is False, str(r))
st, r = call("/api/auth/google/start")
check("start refuses with 503 when unconfigured", st == 503, f"status={st}")

print("\n== profile ==")
st, r = call("/api/auth/me", "PATCH", {"full_name": "Root User", "email": "r@x.io"}, token=admin)
check("can edit own name/email", st == 200 and r["full_name"] == "Root User", f"status={st}")
check("has_password reported", r["has_password"] is True and r["has_google"] is False)
st, r = call("/api/auth/me", "PATCH", {"new_password": "new-password-99"}, token=admin)
check("password change without current -> 422", st == 422, f"status={st}")
st, r = call("/api/auth/me", "PATCH",
             {"new_password": "new-password-99", "current_password": "wrong"}, token=admin)
check("wrong current password -> 403", st == 403, f"status={st}")
st, r = call("/api/auth/me", "PATCH",
             {"new_password": "new-password-99", "current_password": "root-password-1"}, token=admin)
check("correct current password -> 200", st == 200, f"status={st}")
st, r = call("/api/auth/login", "POST", {"username": "root", "password": "new-password-99"})
check("new password works", st == 200, f"status={st}")
admin = r["access_token"]

print("\n== credentials ==")
st, c = call("/api/credentials?project=ALPHA", "POST",
             {"host": "h1.alpha.test", "username": "svc_admin", "secret": "hunter2",
              "kind": "password", "validated": "works"}, token=admin)
check("create credential", st == 201, f"status={st}")
check("creator sees the secret", c["secret"] == "hunter2")
check("secret_set flag", c["secret_set"] is True)

st, _ = call("/api/users", "POST", {"username": "viewer", "password": "viewer-pass-1"}, token=admin)
st, r = call("/api/auth/login", "POST", {"username": "viewer", "password": "viewer-pass-1"})
viewer = r["access_token"]
call("/api/projects/ALPHA/acl", "POST", {"username": "viewer", "role": "readonly"}, token=admin)
st, r = call("/api/credentials?project=ALPHA", token=viewer)
check("readonly sees the row", r["total"] == 1, f"total={r['total']}")
check("readonly does NOT get the secret", r["items"][0]["secret"] is None, str(r["items"][0]["secret"]))
check("readonly still told one exists", r["items"][0]["secret_set"] is True)
st, r = call(f"/api/credentials/{c['id']}", "PATCH", {"notes": "x"}, token=viewer)
check("readonly cannot edit", st == 403, f"status={st}")

call("/api/projects/ALPHA/acl", "POST", {"username": "viewer", "role": "user"}, token=admin)
st, r = call("/api/credentials?project=ALPHA", token=viewer)
check("user role reveals the secret", r["items"][0]["secret"] == "hunter2")

print("\n== bulk patch ==")
st, tg = call("/api/targets?project=ALPHA", token=admin)
ids = [t["id"] for t in tg["items"]][:3]
st, r = call("/api/bulk/patch", "POST",
             {"kind": "targets", "ids": ids, "fields": {"alive": True, "hacked": True}}, token=admin)
check("patch 3 targets", st == 200 and r["changed"] == 3, str(r))
st, tg = call("/api/targets?project=ALPHA", token=admin)
check("values applied", sum(1 for t in tg["items"] if t["hacked"]) == 3)
st, r = call("/api/bulk/patch", "POST",
             {"kind": "targets", "ids": ids, "fields": {"alive": True, "hacked": True}}, token=admin)
check("re-patch changes nothing", r["changed"] == 0, str(r))
st, r = call("/api/bulk/patch", "POST",
             {"kind": "targets", "ids": ids, "fields": {"project_id": 2}}, token=admin)
check("cannot bulk-set project_id", st == 422, f"status={st}")
st, r = call("/api/bulk/patch", "POST",
             {"kind": "targets", "ids": ids, "fields": {"host": "x"}}, token=admin)
check("cannot bulk-set host", st == 422, f"status={st}")

print("\n== bulk ACL across projects ==")
st, beta = call("/api/targets?project=BETA", token=admin)
mixed = ids + [beta["items"][0]["id"]]
st, r = call("/api/bulk/patch", "POST",
             {"kind": "targets", "ids": mixed, "fields": {"os": "Linux"}}, token=viewer)
check("applies only the permitted subset", r["changed"] == 3 and r["skipped"] == 1, str(r))
check("refusal names the row", any("no access" in e for e in r["errors"]), str(r["errors"]))
st, b2 = call("/api/targets?project=BETA", token=admin)
check("the BETA row was NOT touched", b2["items"][0]["os"] is None, str(b2["items"][0]["os"]))

print("\n== bulk delete ==")
st, sv = call("/api/services?project=ALPHA", token=admin)
sids = [s["id"] for s in sv["items"]]
st, r = call("/api/bulk/delete", "POST", {"kind": "services", "ids": sids}, token=admin)
check("delete services", r["changed"] == len(sids), str(r))
st, sv = call("/api/services?project=ALPHA", token=admin)
check("they are gone", sv["total"] == 0, f"total={sv['total']}")
st, r = call("/api/bulk/delete", "POST", {"kind": "targets", "ids": [99999]}, token=admin)
check("missing ids reported not fatal", st == 200 and "did not exist" in str(r["errors"]), str(r))
st, r = call("/api/bulk/delete", "POST", {"kind": "nope", "ids": [1]}, token=admin)
check("unknown kind rejected", st == 422, f"status={st}")

print("\n== cascade on bulk target delete ==")
st, tg = call("/api/targets?project=ALPHA", token=admin)
h1 = next(t for t in tg["items"] if t["host"] == "h1.alpha.test")
st, r = call("/api/bulk/delete", "POST", {"kind": "targets", "ids": [h1["id"]]}, token=admin)
st, v = call("/api/vulns?project=ALPHA", token=admin)
check("child vulns cascaded", all(x["host"] != "h1.alpha.test" for x in v["items"]), str(v["total"]))

print(f"\n{'='*54}\n  {ok} passed, {fail} failed\n{'='*54}")
