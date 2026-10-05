"""Report generation: the three kinds, status flow, both formats, the gate
on agentic edits, and the email notification."""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json, os, socket, threading, time, urllib.request, urllib.error, zipfile

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8019")
SMTP_PORT = int(os.environ.get("ODDJOB_TEST_SMTP_PORT", "8035"))
ok = fail = 0
INBOX: list[str] = []


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


def smtp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", SMTP_PORT)); srv.listen(5)
    while True:
        try: c, _ = srv.accept()
        except OSError: return
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def handle(c):
    f = c.makefile("rwb")
    say = lambda s: c.sendall((s + "\r\n").encode())
    say("220 localhost ESMTP test")
    body, in_data = [], False
    while True:
        line = f.readline()
        if not line: break
        txt = line.decode(errors="replace").rstrip("\r\n")
        if in_data:
            if txt == ".":
                INBOX.append("\n".join(body)); body, in_data = [], False; say("250 OK")
            else: body.append(txt)
            continue
        up = txt.upper()
        if up.startswith(("EHLO", "HELO")): say("250-localhost"); say("250 AUTH LOGIN PLAIN")
        elif up.startswith(("MAIL", "RCPT")): say("250 OK")
        elif up.startswith("DATA"): say("354 go"); in_data = True
        elif up.startswith("QUIT"): say("221 bye"); break
        else: say("250 OK")
    c.close()


threading.Thread(target=smtp_server, daemon=True).start()
time.sleep(0.3)


def call(p, m="GET", b=None, token=None, raw=False):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode(); r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=180) as x:
            data = x.read()
            if raw: return x.status, data, x.headers
            # An empty body is not JSON. `b"" in b"[{"` is True, which is
            # how a 204 ended up being handed to json.loads.
            if not data: return x.status, None
            return x.status, (json.loads(data) if data[:1] in (b"[", b"{") else data)
    except urllib.error.HTTPError as e:
        d = e.read()
        if raw: return e.code, d, e.headers
        try: return e.code, json.loads(d)
        except Exception: return e.code, d[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1",
              "email": "root@example.com"})[1]["access_token"]
call("/api/projects", "POST",
     {"code": "REP", "name": "Report test", "client": "Acme Corp",
      "scope": ["10.0.0.0/24", "portal.acme.com", "!10.0.0.5"]}, token=admin)
call("/api/scans/import?project=REP", "POST", {"format": "auto", "content": json.dumps({
    "project": "x"})}, token=admin)

# Seed data through the bulk API so there is something to report on.
call("/api/bulk", "POST", {"project": "REP", "targets": [
    {"host": "web01.acme.com", "ip_address": "10.0.0.10", "alive": True,
     "os": "Ubuntu 22.04", "hacked": True},
    {"host": "db01.acme.com", "ip_address": "10.0.0.11", "alive": True},
    {"host": "old.acme.com", "ip_address": "10.0.0.12"}],
    "services": [{"host": "web01.acme.com", "port": 443, "name": "https",
                  "banner": "nginx 1.25"}],
    "vulns": [
     {"host": "web01.acme.com", "title": "RCE in upload handler",
      "severity": "critical", "description": "Arbitrary file upload leads to RCE.",
      "remediation": "Validate the content type and store uploads outside the webroot.",
      "external_id": "A-1", "port": 443},
     {"host": "web01.acme.com", "title": "Missing HSTS", "severity": "low",
      "description": "No Strict-Transport-Security header.", "external_id": "A-2"},
     {"host": "db01.acme.com", "title": "Default credentials",
      "severity": "high", "description": "postgres/postgres accepted.",
      "external_id": "A-3"},
     {"host": "db01.acme.com", "title": "Coverage: port sweep",
      "severity": "info", "description": "Swept 10.0.0.0/24.", "external_id": "A-4"},
    ]}, token=admin)


def wait(rid, limit=120):
    for _ in range(limit):
        time.sleep(0.5)
        rows = call("/api/reports?project=REP", token=admin)[1]
        row = next(r for r in rows if r["id"] == rid)
        if row["status"] in ("ready", "failed"): return row
    return row


print("== the three kinds, and what each contains ==")
st, kinds = call("/api/reports/kinds", token=admin)
by = {k["name"]: k for k in kinds}
check("three kinds offered", st == 200 and len(kinds) == 3, str(len(kinds)))
check("full = exec, scope, findings, appendix",
      by["full"]["sections"] == ["Executive Summary", "Scope", "Findings",
                                 "Appendix A: Targets Found"], str(by["full"]["sections"]))
check("executive = exec + top findings",
      by["executive"]["sections"] == ["Executive Summary", "Top Findings (max 10)"])
check("findings = findings + appendix",
      by["findings"]["sections"] == ["Findings", "Appendix A: Targets Found"])

print("\n== status flow ==")
st, r = call("/api/reports?project=REP", "POST", {"kind": "full"}, token=admin)
check("queued immediately, not after it finishes", st == 202 and r["status"] == "queued",
      f'{st} {r.get("status")}')
check("the row exists while it builds",
      any(x["id"] == r["id"] for x in call("/api/reports?project=REP", token=admin)[1]))
full = wait(r["id"])
check("becomes ready", full["status"] == "ready", f'{full["status"]} {full.get("error")}')
check("records a size", (full["size_bytes"] or 0) > 1000, str(full["size_bytes"]))
check("records who asked", full["requested_by_name"] == "root")
check("records when it finished", full["finished_at"] is not None)

print("\n== download is refused until ready, then works in both formats ==")
st, body, hdrs = call(f"/api/reports/{full['id']}/download?format=pdf", token=admin, raw=True)
check("pdf downloads", st == 200, f"status={st}")
check("it is a real PDF", body[:5] == b"%PDF-" and body.rstrip()[-5:] == b"%%EOF")
check("served as a pdf attachment",
      "application/pdf" in hdrs.get("Content-Type", "")
      and ".pdf" in hdrs.get("Content-Disposition", ""), hdrs.get("Content-Disposition"))
open("/tmp/rt-full.pdf", "wb").write(body)

st, body, hdrs = call(f"/api/reports/{full['id']}/download?format=docx", token=admin, raw=True)
check("docx downloads", st == 200, f"status={st}")
open("/tmp/rt-full.docx", "wb").write(body)
check("it is a real DOCX", zipfile.is_zipfile("/tmp/rt-full.docx"))
check("with a document part",
      "word/document.xml" in zipfile.ZipFile("/tmp/rt-full.docx").namelist())
check("an unknown format is refused",
      call(f"/api/reports/{full['id']}/download?format=txt", token=admin)[0] == 422)

print("\n== content ==")
import sys; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sqlite3
from app.reports.model import ReportDoc
db = sqlite3.connect(os.environ.get("ODDJOB_DB", "/tmp/ms-rep.db"))
doc = ReportDoc.from_json(json.loads(
    db.execute("select content from reports where id=?", (full["id"],)).fetchone()[0]))
heads = [s.heading for s in doc.sections]
check("sections in order", heads == ["Executive Summary", "Scope", "Findings",
                                     "Appendix A: Targets Found"], str(heads))
text = doc.plain_text()
check("the summary counts hosts", "3 hosts" in text, text[:200])
check("it names the compromised host count", "1 host was compromised" in text
      or "compromised" in text)
check("scope entries appear", "portal.acme.com" in text)
check("an excluded scope entry is shown as excluded", "10.0.0.5" in text)

findings = [f for s in doc.sections for b in s.blocks
            for f in b.findings if b.kind == "findings"]
check("critical first", findings[0].severity == "critical", findings[0].severity)
check("every required column is present",
      all(f.severity and f.host and f.title for f in findings))
check("remediation carried through",
      any("outside the webroot" in (f.remediation or "") for f in findings))
check("informational excluded by default",
      not any(f.severity == "info" for f in findings))
check("and the omission is stated, not silent",
      "informational" in text and "omitted" in text)

appendix = [b for s in doc.sections if s.heading.startswith("Appendix")
            for b in s.blocks if b.kind == "table"]
check("appendix lists every target", len(appendix[0].rows) == 3, str(len(appendix[0].rows)))
check("a never-probed host is not reported as down",
      [r for r in appendix[0].rows if r[0] == "old.acme.com"][0][3] == "—",
      str([r for r in appendix[0].rows if r[0] == "old.acme.com"]))

print("\n== executive is the short one ==")
ex = wait(call("/api/reports?project=REP", "POST",
               {"kind": "executive"}, token=admin)[1]["id"])
check("ready", ex["status"] == "ready", str(ex.get("error")))
check("smaller than the full report", ex["size_bytes"] < full["size_bytes"],
      f'{ex["size_bytes"]} < {full["size_bytes"]}')

print("\n== severity threshold ==")
everything = wait(call("/api/reports?project=REP", "POST",
                       {"kind": "findings", "min_severity": "info"}, token=admin)[1]["id"])
d2 = ReportDoc.from_json(json.loads(
    db.execute("select content from reports where id=?", (everything["id"],)).fetchone()[0]))
f2 = [f for s in d2.sections for b in s.blocks for f in b.findings if b.kind == "findings"]
check("asking for everything includes informational",
      any(f.severity == "info" for f in f2), str([f.severity for f in f2]))
crit = wait(call("/api/reports?project=REP", "POST",
                 {"kind": "findings", "min_severity": "critical"}, token=admin)[1]["id"])
d3 = ReportDoc.from_json(json.loads(
    db.execute("select content from reports where id=?", (crit["id"],)).fetchone()[0]))
f3 = [f for s in d3.sections for b in s.blocks for f in b.findings if b.kind == "findings"]
check("critical-only means critical only",
      [f.severity for f in f3] == ["critical"], str([f.severity for f in f3]))

print("\n== the agentic guard: edits may not alter figures ==")
from app.reports.agentic import _apply, _collect, _keeps_numbers, _parse
check("an edit that keeps the numbers is allowed",
      _keeps_numbers("47 hosts were scanned", "A total of 47 hosts were scanned"))
check("an edit that drops a number is rejected",
      not _keeps_numbers("47 hosts were scanned", "Several dozen hosts were scanned"))
check("an edit that changes a number is rejected",
      not _keeps_numbers("29 critical findings", "28 critical findings"))
fields, index = _collect(doc)
check("only prose fields are offered to the model",
      all(f["id"] in index for f in fields) and len(fields) > 0, str(len(fields)))
check("no severity, host or title is offered",
      not any(k in json.dumps(fields) for k in ('"severity_field"', '"host_field"')))
before = len(findings)
applied, rejected = _apply(doc, index, [
    {"id": list(index)[0], "text": "Nonsense with no numbers at all."}])
check("a numberless rewrite of a numeric passage is rejected",
      applied == 0 and rejected == 1, f"{applied}/{rejected}")
check("the agent cannot add a finding — there is no path for it",
      len([f for s in doc.sections for b in s.blocks
           for f in b.findings if b.kind == "findings"]) == before)
check("a reply wrapped in prose and fences still parses",
      _parse('here you go:\n```json\n{"fields":[{"id":"x","text":"y"}]}\n```')
      == [{"id": "x", "text": "y"}])
check("a reply with no JSON yields nothing rather than guessing",
      _parse("I could not do that") == [])

print("\n== email on completion ==")
n = len(INBOX)
st, _ = call("/api/settings", "PATCH", {"values": {
    "smtp.host": "127.0.0.1", "smtp.port": SMTP_PORT, "smtp.security": "none",
    "smtp.from_address": "noreply@example.com", "site.base_url": BASE}},
    token=admin)
check("SMTP needs a passing test even here", st == 409, f"status={st}")
st, r = call("/api/settings/test/smtp", "POST", {"values": {
    "smtp.host": "127.0.0.1", "smtp.port": SMTP_PORT, "smtp.security": "none",
    "smtp.from_address": "noreply@example.com", "site.base_url": BASE},
    "to": "root@example.com"}, token=admin)
tok = r.get("token")
call("/api/settings", "PATCH", {"values": {
    "smtp.host": "127.0.0.1", "smtp.port": SMTP_PORT, "smtp.security": "none",
    "smtp.from_address": "noreply@example.com", "site.base_url": BASE},
    "test_tokens": {"smtp": tok}}, token=admin)
n = len(INBOX)
mailed = wait(call("/api/reports?project=REP", "POST", {"kind": "executive"},
                   token=admin)[1]["id"])
time.sleep(1.0)
check("the requester is emailed", mailed["emailed_to"] == "root@example.com",
      str(mailed.get("emailed_to") or mailed.get("email_error")))
check("a mail actually went out", len(INBOX) > n, f"inbox grew by {len(INBOX)-n}")
check("it says the report is ready",
      "ready to download" in INBOX[-1].lower(), INBOX[-1][-160:].replace("\n", " "))

print("\n== no email address, no silent failure ==")
call("/api/users", "POST", {"username": "noemail", "password": "noemail-pass-1"},
     token=admin)
ne = call("/api/auth/login", "POST",
          {"username": "noemail", "password": "noemail-pass-1"})[1]["access_token"]
call("/api/projects/REP/acl", "POST", {"username": "noemail", "role": "readonly"},
     token=admin)
r2 = wait(call("/api/reports?project=REP", "POST", {"kind": "executive"},
               token=ne)[1]["id"])
check("a reader can still produce a report", r2["status"] == "ready", str(r2.get("error")))
check("and is told why no email arrived",
      "no email" in (r2["email_error"] or "").lower(), str(r2.get("email_error")))

print("\n== authorisation ==")
call("/api/users", "POST", {"username": "outsider", "password": "outsider-pass-1"},
     token=admin)
out = call("/api/auth/login", "POST",
           {"username": "outsider", "password": "outsider-pass-1"})[1]["access_token"]
check("someone with no grant cannot list", call("/api/reports?project=REP",
                                                token=out)[0] == 404)
check("nor download", call(f"/api/reports/{full['id']}/download", token=out)[0] == 404)
check("a readonly member cannot delete",
      call(f"/api/reports/{full['id']}", "DELETE", token=ne)[0] == 403)
check("an admin can", call(f"/api/reports/{ex['id']}", "DELETE", token=admin)[0] == 204)

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
