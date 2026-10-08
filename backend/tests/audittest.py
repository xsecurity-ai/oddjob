"""The audit trail: /audit/log, /audit/json, and what must never reach them.

The point of these is not that the lines are formatted nicely. It is
that the trail RECORDS, that only a site admin can read it, and above
all that it does not become a place where credentials are written down.
An audit feature that logs a magic-link token has not added security, it
has moved an account takeover from "intercept an email" to "read a page
every site admin can open".
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8016")
DB = os.environ.get("ODDJOB_DB", "")
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  PASS  {label}")
    else:
        fail += 1; print(f"  FAIL  {label} {extra}")


def call(path, method="GET", body=None, token=None, raw=False):
    r = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        r.data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            b = x.read()
            if raw:
                return x.status, b.decode("utf-8", "replace")
            return x.status, (json.loads(b) if b else None)
    except urllib.error.HTTPError as e:
        b = e.read()
        if raw:
            return e.code, b.decode("utf-8", "replace")
        try:
            return e.code, json.loads(b)
        except Exception:
            return e.code, b[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]

print("== only a site admin may read it ==")
st, _ = call("/audit/log", raw=True)
check("anonymous cannot read the log", st in (401, 403), f"status={st}")
st, _ = call("/audit/json")
check("anonymous cannot read the json", st in (401, 403), f"status={st}")

call("/api/users", "POST",
     {"username": "plain", "password": "plain-password-123"}, token=admin)
plain = call("/api/auth/login", "POST",
             {"username": "plain", "password": "plain-password-123"})[1]["access_token"]
# raw=True deliberately: this endpoint answers in TEXT, and parsing it
# as JSON would make a weakened gate crash the suite rather than fail
# this check, which is the one thing it is here to catch.
st, body = call("/audit/log", token=plain, raw=True)
check("an ordinary user is refused", st == 403, f"status={st} {str(body)[:80]}")
st, _ = call("/audit/json", token=plain)
check("and refused the json too", st == 403, f"status={st}")

print("\n== every request is recorded, with who and from where ==")
call("/api/projects", "POST",
     {"code": "AUD", "name": "Audited", "codename": "LANTERN"}, token=admin)
st, j = call("/audit/json?limit=500", token=admin)
check("the json reads", st == 200, f"status={st}")
entries = (j or {}).get("entries") or []
reqs = [e for e in entries if e["source"] == "middleware"]
check("requests are recorded", len(reqs) > 0, str(len(reqs)))
check("with a method and a path",
      all(e.get("method") and e.get("path") for e in reqs), str(reqs[:1])[:160])
check("with a status", all(isinstance(e.get("status"), int) for e in reqs),
      str(reqs[:1])[:160])
check("and the caller's address", any(e.get("ip") for e in reqs), str(reqs[:1])[:160])
named = [e for e in reqs if e.get("username") == "root"]
check("an authenticated request names the user", len(named) > 0,
      str([e.get("username") for e in reqs[:6]]))

print("\n== a refused request is recorded too ==")
# The entry most worth having. A middleware inside the gate never sees
# one, which is why this one sits outside it.
call("/api/projects", token=None)
st, j = call("/audit/json?limit=500", token=admin)
denied = [e for e in (j or {}).get("entries", [])
          if e.get("status") in (401, 403)]
check("a 401 lands in the trail", len(denied) > 0,
      str([e.get("status") for e in (j or {}).get("entries", [])[:8]]))

print("\n== credentials never reach the trail ==")
# Magic-link tokens travel in the URL PATH and are bearer credentials.
# Recording the path verbatim would put live account-takeover tokens in
# a table every site admin can read.
SECRET = "MAGICTOKENVALUEdoesnotappear0123456789"
call(f"/api/auth/magic/{SECRET}")
st, body = call("/audit/log?limit=1000", token=admin, raw=True)
check("the magic token is not in the log", SECRET not in body, body[:200])
check("and the path is kept, redacted",
      "/api/auth/magic/<redacted>" in body, body[-400:])

QS = "SHOULDNEVERAPPEARqs"
call(f"/api/projects?bogus={QS}", token=admin)
st, body = call("/audit/log?limit=1000", token=admin, raw=True)
check("query strings are never recorded", QS not in body, body[:200])

st, j = call("/audit/json?limit=1000", token=admin)
blob = json.dumps(j)
check("nor does the json carry them", QS not in blob and SECRET not in blob)
check("and no entry carries a request body",
      all("password" not in (e.get("detail") or "").lower()
          for e in (j or {}).get("entries", [])))

print("\n== backend operations are recorded, not just requests ==")
st, j = call("/audit/json?limit=1000&source=ui", token=admin)
acts = {e["action"] for e in (j or {}).get("entries", [])}
check("creating a project is an entry", "project.create" in acts, str(acts))
proj = [e for e in (j or {}).get("entries", []) if e["action"] == "project.create"]
check("naming the engagement it made",
      any(e.get("project") == "AUD" for e in proj), str(proj)[:200])
check("and who made it", any(e.get("username") == "root" for e in proj),
      str(proj)[:200])

call("/api/projects/AUD/acl", "POST", {"username": "plain", "role": "user"},
     token=admin)
st, j = call("/audit/json?limit=1000&action=project.member", token=admin)
mem = (j or {}).get("entries") or []
check("adding a team member is an entry", len(mem) > 0, str(j)[:160])
check("naming who was added and as what",
      any("plain" in (e.get("detail") or "") for e in mem), str(mem)[:200])

call("/api/projects/AUD/slack", "PUT", {"channel": "eng-lantern"}, token=admin)
st, j = call("/audit/json?limit=1000&action=project.slack", token=admin)
check("changing the slack destination is an entry",
      len((j or {}).get("entries") or []) > 0, str(j)[:160])

print("\n== filters ==")
st, j = call("/audit/json?limit=5", token=admin)
check("limit is honoured", len((j or {}).get("entries", [])) <= 5,
      str(len((j or {}).get("entries", []))))
st, j = call("/audit/json?source=middleware&limit=50", token=admin)
check("source filters", all(e["source"] == "middleware"
                            for e in (j or {}).get("entries", [])))
st, j = call("/audit/json?action=project&limit=50", token=admin)
check("action is a prefix match",
      all(e["action"].startswith("project") for e in (j or {}).get("entries", [])),
      str([e["action"] for e in (j or {}).get("entries", [])][:6]))
st, j = call("/audit/json?username=root&limit=50", token=admin)
check("username filters", all(e["username"] == "root"
                              for e in (j or {}).get("entries", [])))
st, j = call("/audit/json?limit=3", token=admin)
nb = (j or {}).get("next_before")
check("a full page offers somewhere to page from", nb is not None, str(j)[:120])
st, j2 = call(f"/audit/json?limit=3&before={nb}", token=admin)
check("and paging back returns older entries",
      all(e["id"] < nb for e in (j2 or {}).get("entries", [])),
      str([e["id"] for e in (j2 or {}).get("entries", [])]))

print("\n== static noise is not recorded ==")
st, body = call("/audit/log?limit=1000", token=admin, raw=True)
check("assets are skipped", "/assets/" not in body)
check("and the health probe is not an action", "/healthz" not in body)

print("\n== retention ==")
st, s = call("/api/settings", token=admin)
vals = (s or {}).get("values") or {}
check("the window defaults to 7 days", vals.get("audit.retain_days") == 7,
      str(vals.get("audit.retain_days")))
st, j = call("/audit/json?limit=1", token=admin)
check("and the json says what it is", (j or {}).get("retain_days") == 7,
      str((j or {}).get("retain_days")))
st, _ = call("/api/settings", "PATCH",
             {"values": {"audit.retain_days": 30}}, token=admin)
st, j = call("/audit/json?limit=1", token=admin)
check("a changed window is reflected", (j or {}).get("retain_days") == 30,
      str((j or {}).get("retain_days")))

# It has to be reachable from Site Config, or "configurable" means
# "editable by someone who reads the source".
st, s = call("/api/settings", token=admin)
spec = next((x for x in (s or {}).get("spec", [])
             if x.get("key") == "audit.retain_days"), None)
check("it is offered in Site Config", spec is not None, str(spec))
check("in the Site group, as a number, defaulting to 7",
      spec and spec.get("group") == "Site" and spec.get("type") == "number"
      and spec.get("default") == 7, str(spec))

# 0 would delete the entry recording the change that set it, so it is
# read as a mistake rather than obeyed.
for bad in (0, -5):
    call("/api/settings", "PATCH",
         {"values": {"audit.retain_days": bad}}, token=admin)
    st, j = call("/audit/json?limit=1", token=admin)
    check(f"a window of {bad} falls back to the default, not to nothing",
          (j or {}).get("retain_days") == 7, str((j or {}).get("retain_days")))
call("/api/settings", "PATCH",
     {"values": {"audit.retain_days": 30}}, token=admin)

if DB and _pathlib.Path(DB).exists():
    # Reach into the suite's own SQLite file to age an entry, which is
    # the only way to test a window measured in days without waiting one.
    con = sqlite3.connect(DB)
    old = (datetime.now(UTC) - timedelta(days=99)).isoformat()
    con.execute("INSERT INTO audit_events (at, source, action, detail) "
                "VALUES (?,?,?,?)", (old, "backend", "test.ancient", "aged"))
    con.commit()
    n_before = con.execute("SELECT COUNT(*) FROM audit_events "
                           "WHERE action='test.ancient'").fetchone()[0]
    con.close()
    check("an aged entry can be planted", n_before == 1, str(n_before))

    import asyncio
    os.environ["ODDJOB_DB"] = DB
    from app.audit import prune
    from app.db import SessionLocal

    async def _sweep():
        async with SessionLocal() as s:
            return await prune(s, 7)
    removed = asyncio.run(_sweep())
    check("the sweep removes what is past the window", removed >= 1, str(removed))

    con = sqlite3.connect(DB)
    left = con.execute("SELECT COUNT(*) FROM audit_events "
                       "WHERE action='test.ancient'").fetchone()[0]
    recent = con.execute("SELECT COUNT(*) FROM audit_events "
                         "WHERE action='project.create'").fetchone()[0]
    con.close()
    check("the aged entry is gone", left == 0, str(left))
    check("and today's entries are untouched", recent >= 1, str(recent))

    # 0 would mean "keep nothing", which would delete the entry recording
    # the change that caused it. Treated as the default instead.
    async def _zero():
        async with SessionLocal() as s:
            return await prune(s, 0)
    check("a window of 0 does not empty the table",
          asyncio.run(_zero()) == 0 and recent >= 1)

print("\n== each origin is addressable on its own ==")
# The common narrowing, as a URL rather than a query whose spelling has
# to be remembered. Same handlers, same filters; the path pins `source`.
for origin in ("middleware", "ui", "drone", "backend"):
    st, j = call(f"/audit/{origin}/json?limit=200", token=admin)
    check(f"/audit/{origin}/json answers", st == 200, f"status={st}")
    check(f"/audit/{origin}/json returns only {origin}",
          all(e["source"] == origin for e in (j or {}).get("entries", [])),
          str({e["source"] for e in (j or {}).get("entries", [])}))
    check(f"/audit/{origin}/json says which origin it pinned",
          (j or {}).get("source") == origin, str((j or {}).get("source")))
    st, body = call(f"/audit/{origin}/log?limit=200", token=admin, raw=True)
    check(f"/audit/{origin}/log answers as text",
          st == 200 and body.startswith("#"), body[:70])
    check(f"/audit/{origin}/log says it is narrowed",
          f"[{origin} only]" in body, body[:120])

# The path is the more specific statement of intent, so it wins. A
# query that disagreed used to be the kind of thing that silently
# returned the wrong rows.
st, j = call("/audit/drone/json?source=ui&limit=50", token=admin)
check("the path beats a contradicting ?source=",
      all(e["source"] == "drone" for e in (j or {}).get("entries", []))
      and (j or {}).get("source") == "drone", str(j)[:140])

# An empty page for a typo looks exactly like a quiet day, which is the
# wrong thing for an audit tool to imply.
st, r = call("/audit/drone-agent/json", token=admin)
check("an unknown origin is a 404, not an empty page", st == 404, f"status={st}")
check("and the 404 names the valid origins",
      all(w in str(r) for w in ("middleware", "ui", "drone", "backend")), str(r)[:170])

st, r = call("/audit/drone/json")
check("the per-origin routes are admin-only too", st in (401, 403), f"status={st}")
st, r = call("/audit/ui/json", token=plain)
check("and refuse an ordinary user", st == 403, f"status={st}")

print("\n== the text view ==")
st, body = call("/audit/log?limit=20", token=admin, raw=True)
check("it reads as text", st == 200 and body.startswith("#"), body[:80])
check("and says what it does not record",
      "never recorded" in body, body[:300])

print("\n== every documented type answers in both formats ==")
# The contract is /audit/$type/$format for four types and two formats.
# A combination that 404s is a documented URL that does not exist.
for t in ("ui", "backend", "middleware", "drone"):
    st, _ = call(f"/audit/{t}/json", token=admin)
    check(f"/audit/{t}/json", st == 200, f"status={st}")
    st, b = call(f"/audit/{t}/log", token=admin, raw=True)
    check(f"/audit/{t}/log", st == 200 and b.startswith("#"),
          f"status={st} {str(b)[:60]}")


def entries(src=None, action=None, tok=admin):
    q = f"/audit/{src}/json" if src else "/audit/json"
    q += f"?limit=500{'&action=' + action if action else ''}"
    return (call(q, token=tok)[1] or {}).get("entries", [])


print("\n== destructive things leave a record that outlives them ==")
# The case this was built for. Deleting a project destroys its targets,
# its findings and its timeline, so the audit entry is the ONLY place
# that still says the engagement existed.
call("/api/projects", "POST", {"code": "GONE", "name": "Doomed"}, token=admin)
call("/api/targets?project=GONE", "POST",
     {"host": "a.acme.example"}, token=admin)
call("/api/targets?project=GONE", "POST",
     {"host": "b.acme.example"}, token=admin)
st, _ = call("/api/projects/GONE?confirm=GONE", "DELETE", token=admin)
check("the project is gone", st == 204, f"status={st}")

es = entries("ui", "project.delete")
check("and its deletion is recorded", len(es) == 1, str(es)[:140])
check("by whom", es and es[0]["username"] == "root", str(es)[:120])
check("naming the engagement, which no longer exists anywhere else",
      es and es[0]["project"] == "GONE" and "Doomed" in (es[0]["detail"] or ""),
      str(es)[:200])
check("and how much went with it",
      es and "2 targets" in (es[0]["detail"] or ""), str(es)[:200])

print("\n== merging records what was absorbed ==")
call("/api/projects", "POST", {"code": "MRGA", "name": "Merge audit"}, token=admin)
for h in ("198.51.100.9", "web.acme.example"):
    call("/api/targets?project=MRGA", "POST", {"host": h}, token=admin)
st, _ = call("/api/enumerate/merge?project=MRGA&host=198.51.100.9", "POST",
             {"into": "web.acme.example", "confirm": True}, token=admin)
check("the merge went through", st == 200, f"status={st}")
es = entries("ui", "target.merge")
check("and is in the trail, not only on the surviving target",
      es and "198.51.100.9" in (es[0]["detail"] or ""), str(es)[:180])

print("\n== settings record the key, never the value ==")
# Short on purpose. The repo's own secret scanner matches
# `xoxb-[A-Za-z0-9-]{20,}`, and a longer fake here fails that check —
# correctly: a scanner that can tell this from a real token could be
# told the same thing by somebody committing a real one. What the test
# needs is a value it can search the audit log for, not a realistic
# length.
SECRET = "xoxb-never-logged"
call("/api/settings", "PATCH", {"values": {"slack.bot_token": SECRET}},
     token=admin)
es = entries("ui", "settings.update")
check("the change is recorded", es, str(es)[:120])
check("naming which key moved",
      es and "slack.bot_token" in (es[0]["detail"] or ""), str(es)[:160])
# The whole point. Every site admin can read this table.
whole = call("/audit/log?limit=2000", token=admin, raw=True)[1]
check("and the token itself appears nowhere in the log",
      SECRET not in str(whole), "LEAKED")
check("nor anywhere in the json",
      SECRET not in json.dumps(entries()), "LEAKED")

print("\n== a failed sign-in is recorded, the password is not ==")
PW = "wrong-password-never-logged"
call("/api/auth/login", "POST", {"username": "root", "password": PW})
es = entries("ui", "auth.login.fail")
check("the failure is recorded", es, str(es)[:120])
check("with the username that was tried",
      es and es[0]["username"] == "root", str(es)[:120])
whole = call("/audit/log?limit=2000", token=admin, raw=True)[1]
check("and the attempted password is nowhere in it",
      PW not in str(whole), "LEAKED")
# A real sign-in too, or the log only ever shows failures and a normal
# session looks like an absence.
check("a successful sign-in is recorded as well",
      entries("ui", "auth.login"), "none")

print("\n== the backend records what it does on its own ==")
es = entries("backend")
check("startup is in the trail",
      any(e["action"] == "server.start" for e in es), str(es)[:160])
check("attributed to no person, because none was involved",
      all(e["username"] is None for e in es if e["action"] == "server.start"),
      str(es)[:160])

print("\n== a logged value cannot forge a log line ==")
# This is the audit log. A newline in a logged field lets a caller
# invent an entry nobody wrote, and a forged entry here is not cosmetic
# -- it is evidence. Sanitised at the logging site, because the callers
# are the part that keeps changing.
from app.audit import for_log  # noqa: E402

_forged = "scan\n2026-01-01 12:00:00 INFO  authorised by root"
check("a newline cannot start a second line",
      "\n" not in for_log(_forged), repr(for_log(_forged))[:90])
check("and the text is still readable, not dropped",
      "authorised by root" in for_log(_forged), repr(for_log(_forged))[:90])
for _ch, _name in [("\r", "carriage return"), ("\x1b", "escape"),
                   ("\x00", "null")]:
    check(f"a {_name} is escaped", _ch not in for_log(f"a{_ch}b"),
          repr(for_log(f"a{_ch}b")))
check("ordinary text is left alone", for_log("nmap.bulk") == "nmap.bulk",
      for_log("nmap.bulk"))
check("and it is bounded, so one field cannot flood the log",
      len(for_log("x" * 5000)) <= 200, str(len(for_log("x" * 5000))))

print("\n== audit search looks in more than the message ==")
# The thing half-remembered is as often the username, the path or the
# address as the detail text, and one search box that only reads one
# column trains people not to use it.
st, r = call("/audit/json?q=auth&limit=50", token=admin)
check("a free-text search is accepted", st == 200, f"status={st}")
_hits = (r or {}).get("entries", [])
check("and finds entries", len(_hits) > 0, str(r)[:120])
check("matching on any of the columns a person would type",
      all(any("auth" in str(e.get(k) or "").lower()
              for k in ("action", "username", "detail", "path", "project", "ip"))
          for e in _hits),
      str(_hits[:1])[:200])

st, r = call("/audit/json?q=zzz-definitely-not-present-anywhere", token=admin)
check("a search matching nothing returns nothing, not everything",
      st == 200 and (r or {}).get("entries") == [], str(r)[:120])

print("\n== audit export ==")
st, body = call("/audit/csv?limit=5", token=admin, raw=True)
check("csv exports", st == 200, f"status={st}")
_lines = [l for l in (body or "").splitlines() if l.strip()]
check("with a fixed header row",
      _lines and _lines[0].startswith("at,id,source,action,username"),
      (_lines[0] if _lines else "")[:80])
# Exporting must honour the filters. Someone who narrowed to one user
# and one afternoon means that afternoon; 5,000 unrelated rows is a
# different document.
st, filtered = call("/audit/csv?q=zzz-definitely-not-present-anywhere",
                    token=admin, raw=True)
_flines = [l for l in (filtered or "").splitlines() if l.strip()]
check("and exports what the filters select, not the whole table",
      len(_flines) == 1, f"{len(_flines)} line(s) for a filter matching nothing")

st, _ = call("/audit/csv?limit=5")
check("export needs a session", st in (401, 403), f"status={st}")

print("\n== the health page ==")
st, h = call("/api/health/site", token=admin)
check("site health is served to a site admin", st == 200, f"status={st}")
for _k in ("database", "cve_feed", "exploit_feed", "slack", "smtp",
           "drones", "audit", "server"):
    check(f"it reports {_k}", _k in (h or {}), str(list((h or {}).keys()))[:120])
check("the database is reachable and says how fast",
      (h or {}).get("database", {}).get("state") == "ok"
      and "latency_ms" in (h or {}).get("database", {}),
      str((h or {}).get("database"))[:140])

# Three states, never two. A subsystem nothing has ever used is not
# healthy and is not broken, and reporting it as either is how a page
# earns the habit of being ignored.
check("a subsystem that has never run says so, rather than reading green",
      (h or {}).get("slack", {}).get("state") == "unused",
      str((h or {}).get("slack"))[:140])
check("and says why it is unused",
      (h or {}).get("slack", {}).get("note"),
      str((h or {}).get("slack"))[:140])

st, _ = call("/api/health/site")
check("health needs a session", st in (401, 403), f"status={st}")

print("\n== health is recorded from inside the send, not at its call sites ==")
# There are ten slack.post call sites and four send_mail ones. Recording
# at each is how one gets forgotten, and the forgotten one is the path
# whose silence nobody notices.
import asyncio as _aio  # noqa: E402

from app import servicehealth as _sh  # noqa: E402
from app import slack as _slack
from app.db import SessionLocal as _SL  # noqa: E402
from app.models import ServiceHealth as _SH  # noqa: E402


async def _post_with(stub):
    real, _slack._call = _slack._call, stub
    try:
        return await _slack.post("xoxb-test", "#chan", "hello")
    finally:
        _slack._call = real


async def _row():
    async with _SL() as s:
        return await s.get(_SH, "slack")


async def _boom(*a, **k):
    raise RuntimeError("channel_not_found")


async def _fine(*a, **k):
    return {"ok": True, "ts": "1.2", "channel": "C1"}


_r = _aio.run(_post_with(_boom))
check("a failed post is reported as failed", _r.ok is False, str(_r))
_row1 = _aio.run(_row())
check("and recorded without touching the call site",
      _row1 is not None and _row1.error_count == 1, str(_row1 and _row1.error_count))
check("with the reason kept", "channel_not_found" in (_row1.last_error or ""),
      str(_row1.last_error)[:80])
# The channel, never the text: a finding's title names a client's host,
# and every site admin reads this page.
check("and the channel, not the message", _row1.last_detail == "post to #chan",
      str(_row1.last_detail))
check("the message body is never stored",
      "hello" not in str(_row1.last_detail) + str(_row1.last_error or ""),
      str(_row1.last_detail))

_aio.run(_post_with(_fine))
_row2 = _aio.run(_row())
check("a later success is recorded", _row2.ok_count == 1, str(_row2.ok_count))
check("and the earlier failure is NOT cleared — intermittent faults are "
      "exactly what gets missed",
      "channel_not_found" in (_row2.last_error or ""), str(_row2.last_error)[:80])
check("though the state reads healthy again",
      _sh.describe(_row2)["state"] == "ok", _sh.describe(_row2)["state"])

# An unconfigured install is not a broken one.
_r = _aio.run(_slack.post(None, None, "x"))
check("an unconfigured slack records nothing at all",
      _r.ok is False and _aio.run(_row()).ok_count == 1, str(_r.error))

check("a subsystem with no row is 'unused', not 'ok'",
      _sh.describe(None)["state"] == "unused", str(_sh.describe(None)))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
