"""Project creation by any user: scope classification, contacts, members, Slack override."""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json, urllib.request, urllib.error

import os
BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8011")
ok = fail = 0

def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")

def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None: r.data = json.dumps(b).encode(); r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=30) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:200]

admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
for u in ("alice", "bob", "carol"):
    call("/api/users", "POST", {"username": u, "password": f"{u}-password-1"}, token=admin)
alice = call("/api/auth/login", "POST", {"username": "alice", "password": "alice-password-1"})[1]["access_token"]
bob = call("/api/auth/login", "POST", {"username": "bob", "password": "bob-password-1"})[1]["access_token"]

print("== anyone can create a project ==")
st, me = call("/api/auth/me", token=alice)
check("alice is not a site admin", me["user"]["is_site_admin"] is False)
st, r = call("/api/projects", "POST", {
    "code": "falcon-1", "name": "Falcon Engagement", "client": "Acme Corp",
    "scope": ["10.0.0.0/24", "192.168.1.5", "2001:db8::/32", "2001:db8::1",
              "portal.acme.com", "https://vpn.acme.com/login", "  WWW.Acme.com. ",
              "!10.0.0.5", "-staging.acme.com",
              "*.acme.com", "10.0.0.0/99", "localhost", ""],
    "contacts": [{"name": "Dana Reed", "email": "dana@acme.com",
                  "title": "CISO", "primary_contact": True},
                 {"name": "Sam Vale", "email": "sam@acme.com", "phone": "+1 555 0100"}],
    "members": [{"username": "bob", "role": "user"},
                {"username": "carol", "role": "viewer"},
                {"username": "nobody", "role": "admin"}],
    "slack_token": "xoxb-project-override", "slack_channel": "#acme-falcon",
}, token=alice)
check("non-site-admin created a project", st == 201, f"status={st}")
check("code normalised", r["project"]["code"] == "FALCON-1", r["project"]["code"])
check("customer recorded", r["project"]["client"] == "Acme Corp")

print("\n== scope classification ==")
kinds = {}
for e in r["scope"]:
    kinds.setdefault(e["kind"], []).append(e["value"])
check("cidr v4 + v6", sorted(kinds.get("cidr", [])) == ["10.0.0.0/24", "2001:db8::/32"], str(kinds.get("cidr")))
check("ipv4", kinds.get("ipv4") == ["10.0.0.5", "192.168.1.5"] or sorted(kinds.get("ipv4", [])) == ["10.0.0.5", "192.168.1.5"], str(kinds.get("ipv4")))
check("ipv6", kinds.get("ipv6") == ["2001:db8::1"], str(kinds.get("ipv6")))
check("fqdn incl. URL-stripped and normalised",
      sorted(kinds.get("fqdn", [])) == ["portal.acme.com", "staging.acme.com", "vpn.acme.com", "www.acme.com"],
      str(sorted(kinds.get("fqdn", []))))
excl = sorted(e["value"] for e in r["scope"] if not e["included"])
check("exclusions preserved", excl == ["10.0.0.5", "staging.acme.com"], str(excl))
check("bad lines named, not fatal", len(r["scope_errors"]) == 2, str(r["scope_errors"])[:120])
# A wildcard is not a host and never will be, but it IS a scope entry —
# scope documents are written with them, and the list is now enforced,
# so refusing to record one meant refusing to enforce it.
check("wildcard classified, not rejected",
      kinds.get("wildcard") == ["*.acme.com"], str(kinds.get("wildcard")))
check("single label rejected", any("single label" in e for e in r["scope_errors"]))

print("\n== contacts and members ==")
check("contacts stored", len(r["contacts"]) == 2, str(len(r["contacts"])))
check("primary flagged", sum(1 for c in r["contacts"] if c["primary_contact"]) == 1)
roles = {m["username"]: m["role"] for m in r["members"]}
check("creator is admin", roles.get("alice") == "admin", str(roles))
check("bob is user", roles.get("bob") == "user")
check("'viewer' maps to readonly", roles.get("carol") == "readonly", str(roles))
check("unknown member reported, not fatal", len(r["member_errors"]) == 1, str(r["member_errors"]))

print("\n== slack override is write-only ==")
# Check for the VALUE, not the substring "slack_token" — that also matches
# the slack_token_set flag, which is supposed to be there.
check("token value never returned anywhere in the response",
      "xoxb-project-override" not in json.dumps(r))
check("but its presence is", r["project"]["slack_token_set"] is True)
check("channel is returned, normalised", r["project"]["slack_channel"] == "acme-falcon",
      r["project"]["slack_channel"])
call("/api/projects/FALCON-1", "PATCH", {"name": "Renamed", "slack_token": ""}, token=alice)
st, pr = call("/api/projects/FALCON-1", token=alice)
check("blank token means unchanged", pr["slack_token_set"] is True and pr["name"] == "Renamed")
call("/api/projects/FALCON-1/slack-token", "DELETE", token=alice)
check("explicit DELETE clears it",
      call("/api/projects/FALCON-1", token=alice)[1]["slack_token_set"] is False)

print("\n== the creator's authority is scoped to this project ==")
st, r2 = call("/api/projects", "POST", {"code": "OTHER", "name": "Other"}, token=bob)
check("bob can create his own", st == 201, f"status={st}")
check("alice cannot see bob's project", call("/api/projects/OTHER", token=alice)[0] == 404)
check("alice is still not a site admin", call("/api/users", token=alice)[0] == 403)
check("bob sees falcon as 'user', not admin",
      call("/api/projects/FALCON-1", token=bob)[0] == 200
      and call("/api/projects/FALCON-1/acl", token=bob)[0] == 403)

print("\n== scope management afterwards ==")
st, r = call("/api/projects/FALCON-1/scope", "POST", {"lines": ["172.16.0.0/16", "10.0.0.0/24"]}, token=alice)
check("append works, existing kept not duplicated",
      sum(1 for e in r["scope"] if e["value"] == "10.0.0.0/24") == 1, str(st))
check("new entry added", any(e["value"] == "172.16.0.0/16" for e in r["scope"]))
st, sc = call("/api/projects/FALCON-1/scope", token=bob)
check("a 'user' can read scope", st == 200, f"status={st}")
check("a 'user' cannot change scope",
      call("/api/projects/FALCON-1/scope", "POST", {"lines": ["8.8.8.8"]}, token=bob)[0] == 403)
check("duplicate code refused",
      call("/api/projects", "POST", {"code": "FALCON-1", "name": "dup"}, token=bob)[0] == 409)

# --- slack delivery, visibility and naming -----------------------------
print("\n== slack delivery / visibility / naming ==")
st, r = call("/api/projects", "POST", {
    "code": "SLACKTEST", "name": "Slack", "client": "Acme",
    "slack_delivery": "both"}, token=alice)
check("override/both without a token is refused", st == 422, f"status={st}")

st, r = call("/api/projects", "POST", {
    "code": "SLACKTEST", "name": "Slack", "client": "Acme",
    "slack_token": "xoxb-a", "slack_delivery": "both",
    "slack_channel": "#Acme Falcon!!", "slack_private": False}, token=alice)
check("both accepted with a token", st == 201, f"status={st}")
p = r["project"]
check("channel normalised to Slack's rules", p["slack_channel"] == "acme-falcon", p["slack_channel"])
check("delivery recorded", p["slack_delivery"] == "both")
check("explicit public honoured", p["slack_private"] is False and p["slack_private_effective"] is False)

st, r = call("/api/projects", "POST", {
    "code": "DEFAULTS", "name": "Defaults", "client": "Acme"}, token=alice)
p = r["project"]
check("channel defaults to prefix+codename", p["slack_channel"] == "eng-defaults", p["slack_channel"])
check("visibility inherits the site default",
      p["slack_private"] is None and p["slack_private_effective"] is True,
      f"{p['slack_private']}/{p['slack_private_effective']}")

st, _ = call("/api/settings", "PATCH",
             {"values": {"slack.default_private": False}}, token=admin)
st, p2 = call("/api/projects/DEFAULTS", token=alice)
check("changing the site default moves inheriting projects",
      p2["slack_private_effective"] is False, str(p2["slack_private_effective"]))
st, p3 = call("/api/projects/SLACKTEST", token=alice)
check("a project that chose is unaffected", p3["slack_private"] is False)

call("/api/projects/SLACKTEST/slack-token", "DELETE", token=alice)
st, p4 = call("/api/projects/SLACKTEST", token=alice)
check("clearing the token resets delivery to site",
      p4["slack_delivery"] == "site" and p4["slack_token_set"] is False,
      f"{p4['slack_delivery']}/{p4['slack_token_set']}")

# add_scope runs in its own request — a name error there only shows here
st, r = call("/api/projects/DEFAULTS/scope", "POST", {"lines": ["10.1.0.0/16"]}, token=alice)
check("add_scope endpoint actually executes", st == 200, f"status={st} {str(r)[:70]}")

# ===================================================== codename
# The code is the client's and appears in their deliverables; the
# codename is ours — a client code is ACME, its operation name FALCON — and it is what the
# scan directories, the Slack channels and the operators are named
# after. They are different strings and both have to survive a round
# trip. `_out` in the projects router listed its fields by hand, so
# codename was stored correctly and dropped from every response.
print("\n== project codename ==")
st, r = call("/api/projects", "POST",
             {"code": "CN1", "name": "Codename test", "codename": "falcon"}, token=admin)
check("a project can be created with a codename", st == 201, f"{st} {str(r)[:90]}")
check("and it is uppercased like the code",
      (r or {}).get("project", {}).get("codename") == "FALCON",
      str((r or {}).get("project", {}).get("codename")))

st, lst = call("/api/projects?limit=100", token=admin)
row = next((p for p in (lst or {}).get("items", []) if p["code"] == "CN1"), None)
check("the codename survives into the listing", (row or {}).get("codename") == "FALCON",
      str((row or {}).get("codename")))
check("and the code is untouched by it", (row or {}).get("code") == "CN1")

st, r = call("/api/projects/CN1", "PATCH", {"codename": "kestrel"}, token=admin)
check("it can be changed", st == 200 and (r or {}).get("codename") == "KESTREL",
      f"{st} {str(r)[:80]}")

st, r = call("/api/projects", "POST",
             {"code": "CN2", "name": "No codename"}, token=admin)
check("a project without one is fine",
      st == 201 and (r or {}).get("project", {}).get("codename") is None,
      f"{st} {str((r or {}).get('project', {}).get('codename'))}")

# Every column of ProjectOut that exists on the model must be returned.
# Hand-listing them is what lost codename in the first place.
from app.routers.projects import _COPY, _EXPLICIT
from app.schemas import ProjectOut
from app.models import Project as _P
missing = [k for k in ProjectOut.model_fields
           if hasattr(_P, k) and k not in _COPY and k not in _EXPLICIT]
check("no model-backed field is dropped from the response", missing == [], str(missing))

# ===================================================== target kind
print("\n== target kind ==")
st, t = call("/api/targets?project=CN1", "POST",
             {"host": "com.example.app", "kind": "mobile",
              "ip_address": "10.0.0.5", "alive": True}, token=admin)
check("a mobile target can be created", st == 201, f"{st} {str(t)[:90]}")
check("its kind is recorded", (t or {}).get("kind") == "mobile", str((t or {}).get("kind")))
# An empty ip on a host means "not resolved yet". On an app it means
# there is nothing to resolve, so a pasted address is cleared rather
# than making the app look scannable.
check("an address supplied for a mobile target is cleared",
      (t or {}).get("ip_address") is None, str((t or {}).get("ip_address")))
check("and liveness is cleared too, because there is nothing to probe",
      (t or {}).get("alive") is None, str((t or {}).get("alive")))

st, h = call("/api/targets?project=CN1", "POST",
             {"host": "web.cn1.example", "ip_address": "10.0.0.6", "alive": True}, token=admin)
check("a host target defaults to kind=host", (h or {}).get("kind") == "host",
      str((h or {}).get("kind")))
check("and keeps its address", (h or {}).get("ip_address") == "10.0.0.6")
check("and its liveness", (h or {}).get("alive") is True)

st, r = call("/api/targets?project=CN1&limit=50", token=admin)
kinds = {x["host"]: x["kind"] for x in (r or {}).get("items", [])}
check("kind survives into the listing",
      kinds.get("com.example.app") == "mobile" and kinds.get("web.cn1.example") == "host",
      str(kinds))

st, r = call("/api/targets?project=CN1", "POST",
             {"host": "bad.cn1.example", "kind": "laptop"}, token=admin)
check("an unknown kind is refused rather than stored", st == 422, f"{st} {str(r)[:80]}")

# ===================================================== cloud targets
# A cloud resource is a third kind of asset. It is not a host: an ARN
# fails every DNS rule, and refusing it would leave the engagement's
# cloud findings with nowhere to live. It is not a mobile app either —
# a bucket endpoint frequently does resolve, so its address is kept.
print("\n== cloud targets ==")
st, c = call("/api/targets?project=CN1", "POST",
             {"host": "mybucket.s3.amazonaws.com", "kind": "cloud",
              "provider": " AWS ", "ip_address": "52.1.2.3"}, token=admin)
check("a cloud target can be created", st == 201, f"{st} {str(c)[:90]}")
check("its kind is recorded", (c or {}).get("kind") == "cloud")
check("the provider is normalised", (c or {}).get("provider") == "aws",
      str((c or {}).get("provider")))
check("and unlike mobile it KEEPS its address, because a bucket resolves",
      (c or {}).get("ip_address") == "52.1.2.3", str((c or {}).get("ip_address")))

for ident in ("arn:aws:iam::123456789012:role/admin",
              "projects/acme-prod/buckets/backups",
              "/subscriptions/0000/resourceGroups/rg/providers/x"):
    st, r = call("/api/targets?project=CN1", "POST",
                 {"host": ident, "kind": "cloud", "provider": "aws"}, token=admin)
    check(f"accepts a non-hostname identifier: {ident[:34]}", st == 201,
          f"{st} {str(r)[:90]}")

st, r = call("/api/targets?project=CN1", "POST",
             {"host": "arn:aws:iam::1:role/x"}, token=admin)
check("the same string is refused for a plain host", st == 422, f"{st} {str(r)[:90]}")

st, r = call("/api/targets?project=CN1", "POST",
             {"host": "*.s3.amazonaws.com", "kind": "cloud"}, token=admin)
check("a wildcard is still refused for cloud", st == 422, f"{st} {str(r)[:90]}")

st, r = call("/api/targets?project=CN1", "POST",
             {"host": "plainhost.cn1.example", "provider": "aws"}, token=admin)
check("a provider on a non-cloud target is dropped, not stored",
      (r or {}).get("provider") is None, str((r or {}).get("provider")))

st, r = call("/api/targets?project=CN1&limit=100", token=admin)
kinds = {}
for x in (r or {}).get("items", []):
    kinds[x["kind"]] = kinds.get(x["kind"], 0) + 1
check("all three kinds coexist in one project",
      set(kinds) >= {"host", "mobile", "cloud"}, str(kinds))

st, r = call("/api/targets?project=CN1", "POST",
             {"host": "x.cn1.example", "kind": "datacentre"}, token=admin)
check("an unknown kind is still refused", st == 422, f"{st} {str(r)[:70]}")

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
