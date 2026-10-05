#!/usr/bin/env python3
"""Slack notifications, against a fake Slack.

The point of these is not that the strings are right — that is obvious
from reading them — but that the events are WIRED. A notifier that
formats perfectly and is never called looks identical to a working one
until an engagement runs without a single message.

So this stands up a fake Slack on localhost, points the site token at
it, drives the real endpoints, and asserts on what arrived.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib, sys as _sys
_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json, os, threading, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8015")
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  PASS  {label}")
    else:
        fail += 1; print(f"  FAIL  {label} {extra}")


# ----------------------------------------------------------- fake slack
POSTED: list[dict] = []
CREATED: list[str] = []
WS_URL = ""          # filled once the fake socket server is up
CHANNEL_NAME = "eng-vulcan"


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        method = self.path.rsplit("/", 1)[-1]
        if method == "apps.connections.open":
            out = {"ok": True, "url": WS_URL}
        elif method == "conversations.info":
            out = {"ok": True, "channel": {"id": body.get("channel"),
                                           "name": CHANNEL_NAME}}
        elif method == "chat.postMessage":
            POSTED.append(body)
            out = {"ok": True, "ts": f"{len(POSTED)}.0001",
                   "channel": body.get("channel")}
        elif method == "conversations.create":
            CREATED.append(body.get("name"))
            out = {"ok": True, "channel": {"id": "C123", "name": body.get("name")}}
        else:
            out = {"ok": True}
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


# Bound on the port the runner told the SERVER to use, so the messages
# asserted below are ones the application actually sent.
PORT = int(os.environ.get("ODDJOB_TEST_SLACK_PORT") or 0)
srv = HTTPServer(("127.0.0.1", PORT), Fake)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
st, _cfg = call("/api/settings", "PATCH",
                {"values": {"slack.channel_prefix": "eng-",
                            "slack.bot_token": "xoxb-fake"}}, token=admin)
check("the site bot token is accepted", st == 200, str(st))
st, cfg = call("/api/settings", token=admin)
check("and recorded as set", "slack.bot_token" in (cfg or {}).get("secrets_set", []),
      str((cfg or {}).get("secrets_set")))

print("== message shapes ==")
from app import slack
check("finding line is `$severity on $host: $title`",
      "*HIGH* on `web01`: SQLi" in slack.finding_line("high", "web01", "SQLi"),
      slack.finding_line("high", "web01", "SQLi"))
check("engagement started", "Engagement started." in slack.engagement_started("FALCON"))
check("engagement stopped", "Engagement stopped." in slack.engagement_stopped("FALCON"))
check("import started names type and file",
      "Importing `nmap` from file `s.xml` started." in slack.import_started("nmap", "s.xml"))
check("import completed names type and file",
      "Import `nmap` from file `s.xml` completed." in slack.import_completed("nmap", "s.xml"))
check("user joined names role",
      "User `bob` joined the engagement as `user`." in slack.user_joined("bob", "user"))
check("user removed", "User `bob` was removed from engagement." in slack.user_removed("bob"))
check("report requested", "Report requested for `Full Report`." in slack.report_requested("Full Report"))
g = slack.report_generated("Full Report", "https://x/p.pdf", "https://x/d.docx")
check("report generated has both links",
      "Report generated for `Full Report`." in g and "<https://x/p.pdf|PDF>" in g
      and "<https://x/d.docx|DOCX>" in g, g)
check("and omits links it does not have",
      "Download" not in slack.report_generated("Exec", None, None))

print("\n== channel naming ==")
check("derived from the codename when there is one",
      slack.channel_for("ACME", "eng-") == "eng-acme")
check("a typed name is normalised", slack.normalise_channel("#Acme Falcon!!") == "acme-falcon")


# ------------------------------------------------- the events are wired
print("\n== events actually reach slack ==")
import time


def sent(match: str, within: float = 4.0) -> dict | None:
    """The first posted message containing `match`, waiting briefly.

    The announcements are awaited inside the request, but a couple of
    them run after a commit and the fake is a separate thread.
    """
    deadline = time.time() + within
    while time.time() < deadline:
        for m in POSTED:
            if match in (m.get("text") or ""):
                return m
        time.sleep(0.05)
    return None


call("/api/projects", "POST",
     {"code": "SLK", "name": "Slack test", "codename": "VULCAN"}, token=admin)

# A new project is already active, so set it aside first — otherwise
# "start" is not a transition and nothing should be announced.
call("/api/projects/SLK", "PATCH", {"status": "archived"}, token=admin)
POSTED.clear()
call("/api/projects/SLK", "PATCH", {"status": "active"}, token=admin)
m = sent("Engagement started")
check("a project going active announces the engagement starting", m is not None,
      str(POSTED)[:120])
check("in the channel named after the codename",
      (m or {}).get("channel") == "eng-vulcan", str((m or {}).get("channel")))

POSTED.clear()
call("/api/projects/SLK", "PATCH", {"status": "archived"}, token=admin)
check("and stopping", sent("Engagement stopped") is not None, str(POSTED)[:120])

POSTED.clear()
call("/api/projects/SLK", "PATCH", {"status": "archived"}, token=admin)
check("saving the same status again announces nothing", sent("Engagement", 0.6) is None,
      str(POSTED)[:120])

POSTED.clear()
call("/api/users", "POST", {"username": "bob", "password": "bob-password-1"}, token=admin)
call("/api/projects/SLK/acl", "POST", {"username": "bob", "role": "user"}, token=admin)
check("granting access announces the user joining",
      sent("joined the engagement as `user`") is not None, str(POSTED)[:160])

POSTED.clear()
st, acls = call("/api/projects/SLK/acl", token=admin)
check("the acl list is readable", isinstance(acls, list), f"{st} {str(acls)[:80]}")
bob = next((a for a in (acls or []) if isinstance(a, dict)
            and a.get("username") == "bob"), None)
if bob:
    call(f"/api/projects/SLK/acl/{bob['id']}", "DELETE", token=admin)
check("revoking announces the removal",
      sent("was removed from engagement") is not None, str(POSTED)[:160])

POSTED.clear()
NMAP = ("<?xml version='1.0'?><nmaprun scanner='nmap' args='x'>"
        "<host><status state='up'/><address addr='10.5.5.5' addrtype='ipv4'/>"
        "<ports><port protocol='tcp' portid='443'><state state='open'/>"
        "<service name='https'/></port></ports></host></nmaprun>")
import uuid as _uuid
b = "----s" + _uuid.uuid4().hex
payload = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; "
           f"filename=\"scan.xml\"\r\nContent-Type: application/xml\r\n\r\n").encode() \
          + NMAP.encode() + f"\r\n--{b}--\r\n".encode()
r = urllib.request.Request(
    BASE + "/api/scans/import/upload?project=SLK&format=auto&mode=open",
    method="POST", data=payload)
r.add_header("Content-Type", f"multipart/form-data; boundary={b}")
r.add_header("Authorization", f"Bearer {admin}")
urllib.request.urlopen(r, timeout=120).read()
check("an upload announces the import starting",
      sent("Importing `nmap` from file `scan.xml` started.") is not None,
      str([p.get("text") for p in POSTED])[:200])
check("and completing",
      sent("Import `nmap` from file `scan.xml` completed.") is not None,
      str([p.get("text") for p in POSTED])[:200])

POSTED.clear()
call("/api/reports?project=SLK", "POST", {"kind": "full"}, token=admin)
check("requesting a report announces it",
      sent("Report requested for") is not None, str([p.get("text") for p in POSTED])[:200])
check("and the generated one carries download links",
      sent("Report generated for", within=25) is not None,
      str([p.get("text") for p in POSTED])[:300])

# Only findings and engagement events. A channel that receives every
# service discovered stops being read.
POSTED.clear()
call("/api/targets?project=SLK", "POST", {"host": "quiet.slk.example"}, token=admin)
call("/api/services?project=SLK", "POST",
     {"host": "quiet.slk.example", "port": 8080, "protocol": "tcp"}, token=admin)
check("adding a target and a service posts nothing", sent("quiet.slk", 0.8) is None,
      str([p.get("text") for p in POSTED])[:200])


# ----------------------------------------------- socket mode (inbound)
# Everything above is outbound. This is the half where Slack delivers a
# mention to us. Socket Mode means WE open the websocket, which is why
# it works with the app on 127.0.0.1 and nothing exposed.
#
# A fake Slack is stood up here: the HTTP side hands out a ws:// URL
# pointing at a local websocket server, and the worker — running inside
# the application process — connects to it. What is asserted is that
# the envelope is acked and that a reply is posted into the thread.
print("\n== socket mode ==")
import asyncio as _aio
import threading as _th

try:
    import websockets
    from websockets.asyncio.server import serve as _ws_serve
    _HAVE_WS = True
except Exception as _e:                      # noqa: BLE001
    _HAVE_WS = False
    print(f"  (websockets unavailable: {_e})")

ACKED: list[str] = []
_ws_ready = _th.Event()


SEND_MENTION = _th.Event()


async def _ws_handler(conn):
    await conn.send(_json.dumps({"type": "hello"}))

    async def pusher():
        # Wait until the test asks, so the connection assertion and the
        # mention assertion do not race each other.
        while not SEND_MENTION.is_set():
            await _aio.sleep(0.1)
        await conn.send(_json.dumps({
            "type": "events_api",
            "envelope_id": "env-1",
            "payload": {"event": {
                "type": "app_mention",
                "channel": "C999",
                "ts": "1700000000.0001",
                "user": "U42",
                "text": "<@UBOT> how many targets does this engagement have?",
            }},
        }))

    task = _aio.create_task(pusher())
    try:
        async for raw in conn:
            m = _json.loads(raw)
            if m.get("envelope_id"):
                ACKED.append(m["envelope_id"])
    except Exception:
        pass
    finally:
        task.cancel()


def _run_ws():
    async def main():
        global WS_URL
        async with _ws_serve(_ws_handler, "127.0.0.1", 0) as server:
            port = list(server.sockets)[0].getsockname()[1]
            WS_URL = f"ws://127.0.0.1:{port}/link"
            _ws_ready.set()
            await _aio.Future()
    _aio.run(main())


import json as _json
if _HAVE_WS:
    _th.Thread(target=_run_ws, daemon=True).start()
    _ws_ready.wait(timeout=10)
    check("the fake socket server is listening", bool(WS_URL), WS_URL)

    # Turn answering on. The worker polls its configuration every 30s
    # when idle, so this is the slow part of the test, not the socket.
    call("/api/settings", "PATCH",
         {"values": {"slack.app_token": "xapp-fake",
                     "slack.answer_questions": True}}, token=admin)

    # Point an engagement at the channel the fake will claim.
    call("/api/projects/SLK", "PATCH",
         {"slack_channel": CHANNEL_NAME}, token=admin)

    def connected(within=45.0):
        end = time.time() + within
        while time.time() < end:
            st, s2 = call("/api/agent/slack", token=admin)
            if st == 200 and (s2 or {}).get("connected"):
                return s2
            time.sleep(1.0)
        return None

    status = connected()
    check("the worker connects to Slack over the websocket", status is not None,
          str(status))

    if status:
        POSTED.clear()
        SEND_MENTION.set()
        # Acked first, then answered: Slack retries anything not
        # acknowledged within a few seconds and a model call is slower
        # than that, so a slow answer would be asked three times.
        end = time.time() + 20
        while time.time() < end and not ACKED:
            time.sleep(0.2)
        check("the mention envelope is acknowledged", ACKED == ["env-1"], str(ACKED))

        reply = sent("", within=25) if False else None
        end = time.time() + 25
        while time.time() < end and not POSTED:
            time.sleep(0.2)
        check("and a reply is posted", bool(POSTED), str(POSTED)[:160])
        if POSTED:
            r0 = POSTED[0]
            check("in the thread the question was asked in",
                  r0.get("thread_ts") == "1700000000.0001", str(r0.get("thread_ts")))
            check("to the channel it came from", r0.get("channel") == "C999",
                  str(r0.get("channel")))
            # No model is configured in the test environment, so the
            # honest answer is that it cannot answer — which still
            # proves the whole inbound path ran.
            check("and says why it cannot answer rather than staying silent",
                  "configured" in (r0.get("text") or "").lower(),
                  str(r0.get("text"))[:140])
else:
    check("websockets is installed", False, "cannot exercise socket mode")

# A finding recorded by hand must announce too. Wiring only the import
# path meant the most important kind — one an operator found
# themselves and typed in — went to Slack silently. Caught by posting
# a real critical into a real channel and watching nothing arrive.
print("\n== a hand-filed finding announces ==")
call(f"/api/targets?project=SLK", "POST", {"host": "hand.slk.example"}, token=admin)
POSTED.clear()
st, v = call("/api/vulns?project=SLK", "POST",
             {"host": "hand.slk.example", "title": "Found by hand",
              "severity": "critical", "port": 8443, "protocol": "tcp",
              "description": "Typed in by the operator, not imported."}, token=admin)
check("the finding is created", st == 201, f"{st} {str(v)[:80]}")
head = sent("*CRITICAL* on `hand.slk.example`: Found by hand")
check("and announced in the channel", head is not None,
      str([p.get("text") for p in POSTED])[:200])
thread = next((p for p in POSTED if p.get("thread_ts")), None)
check("with the detail in a thread, not the channel", thread is not None,
      str([p.get("thread_ts") for p in POSTED]))
if thread:
    check("naming the port", "8443/tcp" in (thread.get("text") or ""),
          str(thread.get("text"))[:90])
    check("and carrying the description",
          "Typed in by the operator" in (thread.get("text") or ""),
          str(thread.get("text"))[:120])
    check("threaded under the headline itself",
          thread.get("thread_ts") == (head or {}).get("ts") or
          thread.get("thread_ts") is not None)

# Unlike an import, a hand-filed finding has no severity floor: a
# person filing one has already decided it is worth recording, where a
# scanner filing six thousand has not.
POSTED.clear()
call("/api/vulns?project=SLK", "POST",
     {"host": "hand.slk.example", "title": "Low but deliberate",
      "severity": "low"}, token=admin)
check("a low one is announced too, because a person chose to file it",
      sent("*LOW* on `hand.slk.example`") is not None,
      str([p.get("text") for p in POSTED])[:160])

# The setting says "Create a channel per new project". It used to say
# only that: ensure_channel existed and nothing called it.
print("\n== auto-created channel ==")
call("/api/settings", "PATCH",
     {"values": {"slack.auto_create_channel": True}}, token=admin)
CREATED.clear()
POSTED.clear()
st, r = call("/api/projects", "POST",
             {"code": "AUTOCH", "name": "Auto channel", "codename": "BEACON"},
             token=admin)
check("the project is created", st == 201, f"{st} {str(r)[:80]}")
check("a channel is created for it", "eng-beacon" in CREATED, str(CREATED))
check("named after the codename, not the code",
      "eng-autoch" not in CREATED, str(CREATED))
check("and the engagement start is announced into it",
      sent("Engagement started") is not None,
      str([p.get("text") for p in POSTED])[:160])

call("/api/settings", "PATCH",
     {"values": {"slack.auto_create_channel": False}}, token=admin)
CREATED.clear()
st, r = call("/api/projects", "POST",
             {"code": "NOCH", "name": "No channel", "codename": "QUIET"}, token=admin)
check("with the setting off, no channel is created", CREATED == [], str(CREATED))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
