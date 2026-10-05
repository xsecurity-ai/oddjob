"""End-to-end API check for Oddjob."""
import json, time, urllib.request, urllib.error, threading

import os
BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8000")
ok = fail = 0

def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label} {extra}")
    else:    fail += 1; print(f"  FAIL  {label} {extra}")

# Filled in by the setup call below. Every request carries it: the API has
# no anonymous surface left apart from signing in.
TOKEN = None

def call(path, method="GET", body=None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")

TOKEN = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]

# --- SSE listener running in the background --------------------------------
events = []
def listen():
    try:
        ereq = urllib.request.Request(BASE + "/api/events")
        ereq.add_header("Authorization", f"Bearer {TOKEN}")
        with urllib.request.urlopen(ereq, timeout=25) as r:
            for line in r:
                s = line.decode(errors="replace").strip()
                if s.startswith("data:"):
                    events.append(s[5:].strip())
    except Exception:
        pass
t = threading.Thread(target=listen, daemon=True); t.start()
time.sleep(1.0)

print("\n== bulk import ==")
payload = {
  "project": "APITEST", "project_name": "API test",
  "targets": [
    {"host": "web01.example.com", "ip_address": "10.0.0.5", "hacked": True, "os": "Ubuntu 24.04"},
    {"host": "db01.example.com",  "ip_address": "10.0.0.6"},
    {"host": "10.0.0.7",          "ip_address": "10.0.0.7", "notes": "bare IP asset"},
  ],
  "services": [
    {"host": "web01.example.com", "port": 443, "protocol": "tcp", "state": "open",
     "name": "https", "banner": "nginx/1.27.1"},
    {"host": "web01.example.com", "port": 22, "protocol": "tcp", "state": "open",
     "name": "ssh", "banner": "OpenSSH_9.6p1"},
    {"host": "web01.example.com", "port": 3306, "protocol": "tcp", "state": "closed",
     "name": "mysql"},
    {"host": "db01.example.com",  "port": 5432, "protocol": "tcp", "state": "open",
     "name": "postgresql", "banner": "PostgreSQL 16.4"},
    {"host": "10.0.0.7",          "port": 161, "protocol": "udp", "state": "open",
     "name": "snmp", "banner": "public"},
  ],
  "vulns": [
    {"host": "web01.example.com", "title": "RCE in upload handler", "severity": "critical",
     "external_id": "X-1"},
    {"host": "web01.example.com", "title": "Outdated TLS", "severity": "high", "external_id": "X-2"},
    {"host": "web01.example.com", "title": "Verbose banner", "severity": "low", "external_id": "X-3"},
    {"host": "db01.example.com",  "title": "Default creds", "severity": "critical", "external_id": "X-4"},
    {"host": "orphan.example.com","title": "found via autocreate", "severity": "info"},
  ],
  "pocs": [
    {"host": "web01.example.com", "title": "poc-rce", "status": "confirmed", "exit_code": 0},
    {"host": "db01.example.com",  "title": "poc-creds", "status": "unconfirmed", "exit_code": 2},
  ],
}
st, r1 = call("/api/bulk", "POST", payload)
check("bulk returns 200", st == 200, f"status={st}")
print("   created:", r1["created"], "\n   updated:", r1["updated"],
      "\n   skipped:", r1["skipped"], "\n   errors:", r1["errors"], f"({r1['elapsed_ms']}ms)")
check("4 targets created (3 declared + 1 autocreated orphan)", r1["created"]["targets"] == 4)
check("5 services created", r1["created"]["services"] == 5)
check("5 vulns created", r1["created"]["vulns"] == 5)
check("2 pocs created", r1["created"]["pocs"] == 2)

print("\n== idempotency: same payload again ==")
st, r2 = call("/api/bulk", "POST", payload)
check("nothing created on re-run", sum(r2["created"].values()) == 0, str(r2["created"]))
check("rows accounted as updated/skipped (15 declared)",
      sum(r2["updated"].values()) + sum(r2["skipped"].values()) == 15,
      f"updated={r2['updated']} skipped={r2['skipped']}")

print("\n== targets + derived counts ==")
st, tg = call("/api/targets")
check("targets total == 4", tg["total"] == 4, f"got {tg['total']}")
web = next(t for t in tg["items"] if t["host"] == "web01.example.com")
check("web01 total_vulns == 3", web["total_vulns"] == 3, f"got {web['total_vulns']}")
check("web01 criticals == 1", web["total_criticals"] == 1, f"got {web['total_criticals']}")
check("web01 highs == 1", web["total_highs"] == 1, f"got {web['total_highs']}")
check("web01 pocs == 1", web["total_pocs"] == 1, f"got {web['total_pocs']}")
check("web01 open ports == 2 (3306 closed excluded)", web["total_ports"] == 2, f"got {web['total_ports']}")
check("web01 hacked flag true", web["hacked"] is True)

print("\n== ports view is open-only ==")
st, pt = call("/api/ports")
check("4 open ports (closed 3306 excluded)", pt["total"] == 4, f"got {pt['total']}")
check("no closed row present", all(p["state"] == "open" for p in pt["items"]))
st, sv = call("/api/services")
check("services view shows all 5 incl. closed", sv["total"] == 5, f"got {sv['total']}")

print("\n== search / sort ==")
st, s1 = call("/api/services?q=openssh")
check("full search finds banner text", s1["total"] == 1 and s1["items"][0]["port"] == 22)
st, s2 = call("/api/services?q=5432")
check("search matches numeric port as text", s2["total"] == 1)
st, s3 = call("/api/targets?sort=total_vulns&order=desc")
check("sort by derived count works", s3["items"][0]["host"] == "web01.example.com",
      f"first={s3['items'][0]['host']}")
st, s4 = call("/api/targets?q=bare+IP")
check("search hits notes column", s4["total"] == 1)
st, s5 = call("/api/targets?sort=nope")
check("bad sort field -> 422", s5 is not None and st == 422, f"status={st}")

print("\n== single mutation fires SSE ==")
before = len(events)
st, _ = call("/api/targets/APITEST/db01.example.com", "PATCH", {"hacked": True})
check("patch ok", st == 200)
time.sleep(1.2)
check("SSE event received", len(events) > before, f"{len(events)-before} new event(s)")
if len(events) > before:
    print("   last event:", events[-1][:120])

print("\n== cascade delete ==")
st, _ = call("/api/targets/APITEST/web01.example.com", "DELETE")
check("delete 204", st == 204, f"status={st}")
st, sv2 = call("/api/services?host=web01.example.com")
check("services cascaded away", sv2["total"] == 0, f"got {sv2['total']}")
st, st2 = call("/api/stats")
check("stats reflect delete", st2["targets"] == 3, f"targets={st2['targets']}")

print("\n== unknown api path 404s as JSON ==")
st, body = call("/api/definitely-not-a-thing")
check("404 not HTML", st == 404, f"status={st}")

print(f"\n{'='*52}\n  {ok} passed, {fail} failed\n{'='*52}")
