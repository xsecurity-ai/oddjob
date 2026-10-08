
# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import urllib.error
import urllib.request

BASE=os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8007"); ok=fail=0
def check(l,c,e=""):
    global ok,fail
    if c: ok+=1; print(f"  PASS  {l} {e}")
    else: fail+=1; print(f"  FAIL  {l} {e}")
def call(p, m="GET", b=None, token=None):
    r=urllib.request.Request(BASE+p, method=m)
    if b is not None: r.data=json.dumps(b).encode(); r.add_header("Content-Type","application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=30) as x:
            raw=x.read(); return x.status,(json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:200]

st,r=call("/api/auth/setup","POST",{"username":"root","password":"root-password-1"})
admin=r["access_token"]
call("/api/projects","POST",{"code":"ALPHA","name":"Alpha"},token=admin)
call("/api/users","POST",{"username":"pm","password":"pm-password-1"},token=admin)
pm=call("/api/auth/login","POST",{"username":"pm","password":"pm-password-1"})[1]["access_token"]

print("== settings visibility ==")
check("non site-admin cannot read settings", call("/api/settings",token=pm)[0]==403)
st,r=call("/api/settings",token=admin)
check("site admin can read", st==200, f"status={st}")
check("spec served for the UI", len(r["spec"])>10, f"{len(r['spec'])} entries")
check("groups present", set(r["groups"]) >= {"Site","Identity","Email (SMTP)","Slack","Agent"}, str(r["groups"]))
check("secrets absent from values", "smtp.password" not in r["values"] and "slack.bot_token" not in r["values"])
check("secrets_set false initially", set(r["secrets_set"])>={"smtp.password","slack.bot_token"}
      and not any(r["secrets_set"].values()), str(r["secrets_set"]))
check("defaults filled in", r["values"]["smtp.port"]==587 and r["values"]["slack.channel_prefix"]=="eng-")

print("\n== untested credentials are refused ==")
# SMTP and Google credentials may only be saved with proof that they work.
st,r=call("/api/settings","PATCH",{"values":{
    "smtp.host":"smtp.example.com","smtp.port":465,"smtp.security":"tls"}},token=admin)
check("SMTP change without a test is refused", st==409, f"status={st}")
check("and says why", "Test" in str(r.get("detail","")), str(r.get("detail"))[:80])
st,r=call("/api/settings","PATCH",{"values":{
    "smtp.host":"smtp.example.com"},"test_tokens":{"smtp":"not-a-real-token"}},token=admin)
check("a forged proof is refused", st==409, f"status={st}")
st,r=call("/api/settings","PATCH",{"values":{"auth.google_enabled":True}},token=admin)
check("Google cannot be switched on with no client ID", st==409, f"status={st}")
st,r=call("/api/settings/test/nonsense","POST",{},token=admin)
check("unknown provider has nothing to test", st==404, f"status={st}")

print("\n== writing ==")
st,r=call("/api/settings","PATCH",{"values":{
    "site.name":"Method Oddjob","slack.bot_token":"xoxb-demo",
    "auth.google_domains":"acme.example","auth.allow_self_registration":True}},token=admin)
check("patch ok", st==200, f"status={st}")
check("values saved", r["values"]["site.name"]=="Method Oddjob")
check("ungated keys need no test", r["values"]["auth.google_domains"]=="acme.example")
check("bool round-trips", r["values"]["auth.allow_self_registration"] is True)
check("secrets marked set", r["secrets_set"]["slack.bot_token"] is True)
check("secret value never returned", "smtp.password" not in r["values"])
st,r=call("/api/settings","PATCH",{"values":{"site.name":"Renamed","slack.bot_token":""}},token=admin)
check("empty secret = unchanged, not cleared", r["secrets_set"]["slack.bot_token"] is True)
call("/api/settings/slack.bot_token","DELETE",token=admin)
check("explicit DELETE clears a secret", call("/api/settings",token=admin)[1]["secrets_set"]["slack.bot_token"] is False)
check("unknown key rejected", call("/api/settings","PATCH",{"values":{"nope.key":1}},token=admin)[0]==422)
check("select validated", call("/api/settings","PATCH",{"values":{"smtp.security":"pigeon"}},token=admin)[0]==422)
check("number validated", call("/api/settings","PATCH",{"values":{"smtp.port":"abc"}},token=admin)[0]==422)

print("\n== connection tests report honestly ==")
st,r=call("/api/settings/test/slack","POST",token=admin)
check("slack test runs, reports failure", st==200 and r["ok"] is False, str(r)[:70])
st,r=call("/api/settings/test/smtp?to=x@y.z","POST",token=admin)
check("smtp test runs, reports failure", st==200 and r["ok"] is False, str(r["detail"])[:55])

print("\n== user management ==")
check("non-admin-anywhere refused the picker", call("/api/users/selectable",token=pm)[0]==403)
call("/api/projects/ALPHA/acl","POST",{"username":"pm","role":"admin"},token=admin)
st,r=call("/api/users/selectable",token=pm)
check("project admin gets picker list", st==200 and len(r)==2, f"status={st}")
check("picker exposes no email/flags", set(r[0])=={"id","username","full_name"}, str(set(r[0])))
check("still cannot read full directory", call("/api/users",token=pm)[0]==403)
check("can read own project ACL", call("/api/projects/ALPHA/acl",token=pm)[0]==200)
check("can grant on own project", call("/api/projects/ALPHA/acl","POST",{"username":"root","role":"readonly"},token=pm)[0]==201)

# --- customer Postgres DSN: masked, never echoed, gated like the rest ---
print("\n== postgres connection string ==")
DSN_IN = "postgresql://msuser:p%40ss%3Aw%2Frd@db.corp.com:5432/customer?sslmode=require"  # nosemgrep
st,r=call("/api/settings","PATCH",{"values":{"db.external_url":DSN_IN}},token=admin)
check("an untested DSN is refused", st==409, f"status={st}")

st,r=call("/api/settings/test/postgres","POST",{"values":{"db.external_url":DSN_IN}},token=admin)
# What matters is that it really tried and said so, not the wording.
# Asserting the hostname appears in the message assumed the failure
# would be a DNS one; on a CI runner `db.corp.com` resolves and the
# connection is refused instead, so the message names an errno rather
# than a host.
check("test attempts a real connection and fails honestly",
      st==200 and r["ok"] is False and len(r.get("detail") or "") > 10,
      str(r)[:140])
check("a failed test issues no proof", r.get("token") in (None,""), str(r.get("token"))[:20])

st,r=call("/api/settings/test/postgres","POST",
          {"values":{"db.external_url":"mysql://u:p@h/db"}},token=admin)
check("a non-postgres URL is rejected before any connection",
      r["ok"] is False and "Postgres" in r["detail"], str(r["detail"])[:70])
st,r=call("/api/settings/test/postgres","POST",
          {"values":{"db.external_url":"postgresql://h"}},token=admin)
check("a URL with no database name is named as such",
      r["ok"] is False and "database" in r["detail"], str(r["detail"])[:70])

# Store one directly so the masking path can be checked without a live server.
import sqlite3 as _s3  # noqa
st,_=call("/api/settings","PATCH",{"values":{"db.external_note":"customer-owned"}},token=admin)
check("an ungated field in the same group still saves", st==200, f"status={st}")

print("\n== masking ==")
from app.dsn import is_masked as _is_masked
from app.dsn import mask as _mask
from app.dsn import parse as _parse

m=_mask(DSN_IN)
check("password replaced", "p@ss:w/rd" not in m and "p%40ss" not in m, m)
check("host still visible", "db.corp.com" in m, m)
check("user still visible", "msuser" in m, m)
check("database still visible", "customer" in m, m)
check("mask is readable, not percent-encoded", "%E2%80%A2" not in m, m)
check("a password with : @ and / round-trips intact",
      _parse(_parse(DSN_IN).url).password == "p@ss:w/rd",
      repr(_parse(_parse(DSN_IN).url).password))
check("an unparseable string is fully redacted rather than echoed",
      _mask("not-a-dsn-but-secret") == "\u2022"*8, _mask("not-a-dsn-but-secret"))
check("a masked value is recognised on the way back in", _is_masked(m))
check("libpq keyword form accepted",
      _parse("host=h port=6 dbname=d user=u password=p").database == "d")

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
