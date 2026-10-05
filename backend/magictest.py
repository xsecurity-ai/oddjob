"""Magic-link sign-in: issue, redeem, single-use, expiry, throttle, invite.

Runs a throwaway SMTP server in-process so the full path is exercised —
there is no point asserting that we *would* have sent an email.
"""
import json, re, socket, threading, time, urllib.request, urllib.error, http.cookiejar

import os
BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8009")
SMTP_PORT = int(os.environ.get("ODDJOB_TEST_SMTP_PORT", "8025"))
ok = fail = 0
INBOX: list[str] = []


def check(label, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  PASS  {label} {extra}")
    else:    fail += 1; print(f"  FAIL  {label} {extra}")


def smtp_server():
    """Minimal SMTP sink. Enough of the protocol for smtplib to be happy."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", SMTP_PORT)); srv.listen(5)
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def handle(c):
    f = c.makefile("rwb")
    def say(s): c.sendall((s + "\r\n").encode())
    say("220 localhost ESMTP test")
    body, in_data = [], False
    while True:
        line = f.readline()
        if not line:
            break
        txt = line.decode(errors="replace").rstrip("\r\n")
        if in_data:
            if txt == ".":
                INBOX.append("\n".join(body)); body, in_data = [], False
                say("250 OK")
            else:
                body.append(txt)
            continue
        up = txt.upper()
        if up.startswith(("EHLO", "HELO")): say("250-localhost"); say("250 AUTH LOGIN PLAIN")
        elif up.startswith(("MAIL", "RCPT")): say("250 OK")
        elif up.startswith("AUTH"): say("235 OK")
        elif up.startswith("DATA"): say("354 go ahead"); in_data = True
        elif up.startswith("QUIT"): say("221 bye"); break
        else: say("250 OK")
    c.close()


threading.Thread(target=smtp_server, daemon=True).start()
time.sleep(0.4)


def call(path, method="GET", body=None, token=None, jar=None, follow=True):
    op = (urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
          if jar is not None else urllib.request.build_opener())
    if not follow:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k): return None
        op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar if jar is not None else http.cookiejar.CookieJar()),
            NoRedirect)
    r = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        r.data = json.dumps(body).encode(); r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with op.open(r, timeout=30) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw[:200])
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:200]


def link_from_last_email():
    """Read the token out of the RAW message — no decoding.

    If a token only survives quoted-printable decoding, the link is broken
    for anything that reads the plain text, so the test must not paper over
    it by decoding first.
    """
    m = re.search(r"/api/auth/magic/([A-Za-z0-9_\-]+)", INBOX[-1])
    return m.group(1) if m else None


# ---------------------------------------------------------------- setup
st, r = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1", "email": "root@example.com"})
admin = r["access_token"]

print("== methods advertised before SMTP is configured ==")
st, r = call("/api/auth/methods")
check("public endpoint", st == 200, f"status={st}")
check("magic_link off without SMTP", r["magic_link"] is False, str(r))

# SMTP credentials can only be saved once they have been proven to work, so
# this is also the end-to-end check of that gate: test against the draft
# values, then present the resulting proof with the save.
SMTP_DRAFT = {
    "smtp.host": "127.0.0.1", "smtp.port": SMTP_PORT, "smtp.security": "none",
    "smtp.from_address": "noreply@example.com",
    "site.base_url": BASE, "site.name": "Oddjob Test"}

st, r = call("/api/settings", "PATCH", {"values": SMTP_DRAFT}, token=admin)
check("saving untested SMTP is refused", st == 409, f"status={st}")

st, r = call("/api/settings/test/smtp", "POST",
             {"values": SMTP_DRAFT, "to": "root@example.com"}, token=admin)
check("test runs against the draft, not the stored config", st == 200 and r["ok"] is True, str(r)[:90])
check("a pass issues a proof", bool(r.get("token")))
proof = r["token"]
time.sleep(0.4)
check("the test actually sent mail", len(INBOX) == 1, f"inbox={len(INBOX)}")

st, r = call("/api/settings", "PATCH",
             {"values": {**SMTP_DRAFT, "smtp.host": "127.0.0.2"},
              "test_tokens": {"smtp": proof}}, token=admin)
check("the proof does not cover different values", st == 409, f"status={st}")

st, r = call("/api/settings", "PATCH",
             {"values": SMTP_DRAFT, "test_tokens": {"smtp": proof}}, token=admin)
check("tested values save", st == 200, f"status={st}")
st, r = call("/api/auth/methods")
check("magic_link on once SMTP is set", r["magic_link"] is True, str(r))

# Unrelated settings must not drag the gate in with them.
st, _ = call("/api/settings", "PATCH",
             {"values": {"auth.allow_self_registration": True}}, token=admin)
check("an ungated change still saves freely", st == 200, f"status={st}")

print("\n== requesting a link never reveals account existence ==")
before = len(INBOX)
st, r = call("/api/auth/magic-link", "POST", {"identifier": "nobody@example.com"})
check("unknown address still 202", st == 202, f"status={st}")
check("and sends nothing", len(INBOX) == before, f"inbox grew by {len(INBOX)-before}")
st, r2 = call("/api/auth/magic-link", "POST", {"identifier": "root@example.com"})
check("known address 202, same body", st == 202 and r2 == r, f"{r2}")
time.sleep(0.6)
check("email actually sent", len(INBOX) == before + 1, f"inbox={len(INBOX)}")
tok = link_from_last_email()
check("email carries a link", bool(tok), f"token len={len(tok or '')}")
check("token is not split by quoted-printable soft breaks",
      "=\n" not in INBOX[-1] and len(tok or "") >= 40, f"len={len(tok or '')}")

print("\n== throttle ==")
n = len(INBOX)
call("/api/auth/magic-link", "POST", {"identifier": "root@example.com"})
time.sleep(0.4)
check("same address again inside the cooldown sends nothing",
      len(INBOX) == n, f"inbox grew by {len(INBOX)-n}")
# A different, unknown identifier must not be blocked by the first one's
# cooldown — that was the bug: one shared limit silently ate real requests.
st, _ = call("/api/auth/magic-link", "POST", {"identifier": "someone-else@example.com"})
check("a different identifier is not blocked by it", st == 202, f"status={st}")

print("\n== redeeming ==")
jar = http.cookiejar.CookieJar()
st, _ = call(f"/api/auth/magic/{tok}", jar=jar, follow=False)
check("redeem redirects", st == 303, f"status={st}")
check("session cookie issued", any(c.name == "oddjob_token" for c in jar), [c.name for c in jar])
st, me = call("/api/auth/me", jar=jar)
check("signed in as the right account", st == 200 and me["user"]["username"] == "root", str(me)[:70])

st, r = call(f"/api/auth/magic/{tok}", follow=False)
check("second redeem refused", st == 400 and "already been used" in str(r), str(r)[:70])
st, r = call("/api/auth/magic/not-a-real-token", follow=False)
check("bogus token refused", st == 400, f"status={st}")

print("\n== expiry ==")
# Age the links through the model rather than with raw SQL, so a rename
# of the column breaks this loudly at import instead of silently matching
# zero rows and leaving the test asserting nothing.
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from datetime import datetime, timezone
from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session
from app.models import MagicLink

_eng = create_engine("sqlite:///" + os.environ.get("ODDJOB_DB", "/tmp/ms-m.db"))
with Session(_eng) as _s:
    _s.execute(update(MagicLink).values(
        used_at=None, expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc)))
    _s.commit()
_eng.dispose()
st, r = call(f"/api/auth/magic/{tok}", follow=False)
check("expired link refused", st == 400 and "expired" in str(r), str(r)[:70])

print("\n== disabled account ==")
call("/api/users", "POST", {"username": "gone", "password": "gone-password-1",
                            "email": "gone@example.com"}, token=admin)
call("/api/auth/magic-link", "POST", {"identifier": "gone@example.com"})
time.sleep(0.6)
tok2 = link_from_last_email()
call("/api/users/gone", "PATCH", {"is_active": False}, token=admin)
st, r = call(f"/api/auth/magic/{tok2}", follow=False)
check("link for a disabled account refused", st == 403, f"status={st}")

print("\n== invite (site admin, reports honestly) ==")
call("/api/users", "PATCH", {}, token=admin)
st, r = call("/api/auth/invite/root", "POST", token=admin)
check("invite sends", st == 200 and r["ok"] is True, str(r)[:80])
call("/api/users", "POST", {"username": "noemail", "password": "noemail-pass-1"}, token=admin)
st, r = call("/api/auth/invite/noemail", "POST", token=admin)
check("missing email reported, not hidden", r["ok"] is False and "no email" in r["detail"], str(r))
st, r = call("/api/auth/invite/nosuchuser", "POST", token=admin)
check("unknown user 404s for an admin", st == 404, f"status={st}")
st, r = call("/api/auth/login", "POST", {"username": "noemail", "password": "noemail-pass-1"})
st, r = call("/api/auth/invite/root", "POST", token=r["access_token"])
check("non site-admin cannot invite", st == 403, f"status={st}")

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
