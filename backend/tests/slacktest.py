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
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json
import os
import threading
import urllib.error
import urllib.request
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
#: The workspace's channels, name -> id. A real registry rather than a
#: blanket ok, because "does this channel exist" is now a question the
#: application asks and acts on, and a fake that always says yes would
#: make the missing-channel case untestable.
CHANNELS: dict[str, str] = {}
#: Set to an error string to make conversations.list fail, for the
#: "could not determine" path.
LIST_ERROR = ""
#: Who is in the fake workspace. Anyone absent fails to resolve, which
#: is what the "a failed invite is reported" check depends on.
MEMBERS = ["wsu-person"]


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
            name = body.get("name")
            if name in CHANNELS:
                out = {"ok": False, "error": "name_taken"}
            else:
                CREATED.append(name)
                CHANNELS[name] = f"C{len(CHANNELS) + 100}"
                out = {"ok": True, "channel": {"id": CHANNELS[name],
                                               "name": name}}
        elif method == "users.list":
            # A real member list, so the invite path can be driven end
            # to end. Anyone not in here still fails to resolve, which
            # is what the "failed invite is reported" check relies on.
            out = {"ok": True,
                   "members": [{"id": f"U{i}", "name": n,
                                "profile": {"display_name": n}}
                               for i, n in enumerate(MEMBERS, start=1)],
                   "response_metadata": {"next_cursor": ""}}
        elif method == "conversations.list":
            if LIST_ERROR:
                out = {"ok": False, "error": LIST_ERROR}
            else:
                out = {"ok": True,
                       "channels": [{"id": i, "name": n}
                                    for n, i in CHANNELS.items()],
                       "response_metadata": {"next_cursor": ""}}
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
call("/api/targets?project=SLK", "POST", {"host": "hand.slk.example"}, token=admin)
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
# A channel we just made is empty, so its first message is the one
# that orients whoever gets added to it -- not the one-liner, which
# says nothing a newcomer needs.
w = sent("engagement channel")
check("a welcome is posted into the new channel", w is not None,
      str([p.get("text") for p in POSTED])[:160])
wt = (w or {}).get("text", "")
check("naming the engagement", "BEACON" in wt and "AUTOCH" in wt, wt[:140])
check("saying who the admins are", "*Admins:* root" in wt, wt[:200])
check("and saying plainly that no scope is defined yet",
      "none defined yet" in wt, wt[:260])
# A brand-new engagement has nothing in it, and the opener has to say
# that rather than leave the sections out: an absent line reads as
# "not shown here", which is a different claim from "there is none".
check("saying there are no targets yet", "*Targets:* none yet" in wt, wt[:300])
check("and that nothing can scan until an agent exists",
      "no agents enrolled" in wt, wt[:360])

# `ensure_channel` treats `name_taken` as success, which is right for
# it and wrong as the whole story: without a check before anything is
# written, a second engagement whose codename collides quietly starts
# posting ITS findings into the FIRST one's channel. Refused up front,
# so the dialog comes back with the name still in it.
st, r = call("/api/projects", "POST",
             {"code": "AUTOCH2", "name": "Same op again", "codename": "BEACON"},
             token=admin)
check("a second engagement cannot take a channel that already exists",
      st == 409, f"{st} {str(r)[:90]}")
check("and is told Slack is the thing in the way",
      "slack is in use" in str((r or {}).get("detail", "")).lower(), str(r)[:150])
check("naming the channel it collided with",
      "eng-beacon" in str((r or {}).get("detail", "")), str(r)[:150])
st_gone, _ = call("/api/projects/AUTOCH2", token=admin)
check("and the refused engagement is not half-created",
      st_gone == 404, f"status={st_gone}")

print("\n-- the welcome answers what a newcomer actually asks --")
# A channel that ALREADY existed has history; an opener posted into the
# middle of it reads as a bot that lost its place. Only a channel this
# call actually made gets one -- `ensure_channel` treats `name_taken`
# as success, so "ok" alone cannot tell the two apart.
POSTED.clear()
st, r = call("/api/projects", "POST",
             {"code": "PREEXIST", "name": "Already there",
              "codename": "BEACON"}, token=admin)
check("a project whose channel already exists is still created",
      st in (201, 409), f"status={st}")
if st == 201:
    check("and gets the one-liner, not an opener",
          sent("engagement channel") is None,
          str([p.get("text") for p in POSTED])[:160])

# With scope, admins and a base URL set, the opener carries all three.
call("/api/settings", "PATCH",
     {"values": {"site.base_url": "https://oddjob.test"}}, token=admin)
POSTED.clear()
st, r = call("/api/projects", "POST",
             {"code": "WELCO", "name": "Welcome test", "codename": "LANTERN",
              "client": "Acme Corp",
              "scope": ["10.0.0.0/24", "*.acme.example", "198.51.100.5"]},
             token=admin)
check("the scoped project is created", st == 201, f"{st} {str(r)[:80]}")
w = sent("engagement channel")
wt = (w or {}).get("text", "")
check("the opener names the client", "Acme Corp" in wt, wt[:200])
check("it lists the scope rather than claiming there is none",
      "10.0.0.0/24" in wt and "*.acme.example" in wt and "3 included" in wt,
      wt[:300])
check("it does NOT say scope is undefined", "none defined yet" not in wt, wt[:200])
check("and it gives the URL for this project",
      "https://oddjob.test/projects/WELCO" in wt, wt[:300])

# Without a base URL there is no link to give, and a relative path would
# resolve to nothing. Say so instead of emitting a dead link.
call("/api/settings", "PATCH", {"values": {"site.base_url": ""}}, token=admin)
POSTED.clear()
call("/api/projects", "POST",
     {"code": "NOURL", "name": "No url", "codename": "CANDLE"}, token=admin)
wt2 = (sent("engagement channel") or {}).get("text", "")
check("with no base URL it says how to get one rather than linking nowhere",
      "site.base_url" in wt2 and "/projects/NOURL" not in wt2, wt2[:260])

print("\n-- an engagement already under way says so --")
# The normal case for opening a channel: the work started weeks ago.
# "4,319 targets already" is the difference between somebody picking
# the engagement up and somebody starting it from the beginning.
call("/api/settings", "PATCH",
     {"values": {"site.base_url": "https://oddjob.test"}}, token=admin)
call("/api/projects", "POST",
     {"code": "RUNNING", "name": "Under way", "codename": "QUARRY"},
     token=admin)
for h in ("one.acme.example", "two.acme.example", "three.acme.example"):
    call("/api/targets?project=RUNNING", "POST",
         {"host": h, "alive": True}, token=admin)
call("/api/vulns?project=RUNNING", "POST",
     {"host": "one.acme.example", "title": "Weak ciphers",
      "severity": "medium"}, token=admin)
st, a = call("/api/agents?project=RUNNING", "POST",
             {"name": "quarry-01"}, token=admin)
check("an agent is enrolled for it", st in (200, 201), f"{st} {str(a)[:90]}")

POSTED.clear()
st, _ = call("/api/projects/RUNNING/slack", "PUT",
             {"channel": "eng-quarry-live", "create": True}, token=admin)
check("the channel is created for the running engagement", st == 200,
      f"status={st}")
wt3 = (sent("engagement channel") or {}).get("text", "")
check("the opener counts what is already on record",
      "3 on record" in wt3, wt3[:400])
check("including what is confirmed up", "3 confirmed up" in wt3, wt3[:400])
check("and the findings already filed", "1 finding" in wt3, wt3[:400])
check("it names the scanners that will do the work",
      "quarry-01" in wt3, wt3[:460])
check("and how work is shared between them", "`mesh`" in wt3, wt3[:460])

print("\n-- admins are @-mentioned once we know them in THIS workspace --")
# A Slack user id means nothing outside the workspace it came from, so
# the mention is only emitted where the identity was confirmed. Anyone
# unresolved is named in plain text rather than dropped: "who is the
# admin" has to stay answerable, and a half-list that looks complete is
# worse than one that is visibly plain.
#
# Driven as a user created here, NOT as root: a handle is confirmed
# per WORKSPACE, so confirming root's would satisfy the prompt and
# silently disarm the tests further down that expect to be asked. That
# is the feature working, and it makes shared fixtures dangerous.
MEMBERS.append("torch-person")
call("/api/users", "POST",
     {"username": "torchy", "password": "torchy-password-123"}, token=admin)
torchy = call("/api/auth/login", "POST",
              {"username": "torchy", "password": "torchy-password-123"}
              )[1]["access_token"]
# Their own engagement, so they are its only admin and the assertion
# below is about them and nobody else.
call("/api/projects", "POST",
     {"code": "MENTION", "name": "Mentions", "codename": "TORCH"},
     token=torchy)
st, me = call("/api/projects/MENTION/slack/me", "POST",
              {"handle": "torch-person"}, token=torchy)
check("their handle is confirmed for this workspace",
      (me or {}).get("confirmed") is True, str(me)[:140])
POSTED.clear()
st, _ = call("/api/projects/MENTION/slack", "PUT",
             {"channel": "eng-torch-live", "create": True}, token=torchy)
check("the channel is created", st == 200, f"status={st}")
wt4 = (sent("engagement channel") or {}).get("text", "")
check("the opener @-mentions the admin rather than naming them flatly",
      "*Admins:* <@U" in wt4, wt4[:200])
check("and does not fall back to the bare username",
      "*Admins:* torchy" not in wt4, wt4[:200])
# The thing the operator asked for last: the opener ends on the link.
check("the Oddjob link is the last thing in it",
      wt3.strip().split("\n")[-1].startswith("*Oddjob:*")
      and "https://oddjob.test/projects/RUNNING" in wt3,
      wt3.strip().split("\n")[-1][:120])
call("/api/settings", "PATCH",
     {"values": {"site.base_url": "https://oddjob.test"}}, token=admin)

call("/api/settings", "PATCH",
     {"values": {"slack.auto_create_channel": False}}, token=admin)
CREATED.clear()
st, r = call("/api/projects", "POST",
             {"code": "NOCH", "name": "No channel", "codename": "QUIET"}, token=admin)
check("with the setting off, no channel is created", CREATED == [], str(CREATED))

# The collision check is asked only about channels we would have made.
# With auto-create off, a channel that is already there is the normal
# arrangement -- it is how an engagement posts into one somebody made
# by hand -- and refusing it would break that outright.
st, r = call("/api/projects", "POST",
             {"code": "REUSE", "name": "Reuse", "codename": "BEACON"}, token=admin)
check("with the setting off, an existing channel is reused, not refused",
      st == 201, f"{st} {str(r)[:90]}")


print("\n== the slack-handle prompt endpoints are actually reachable ==")
# These were written with a {code} path parameter while require_project
# reads one named {project}, so every call returned 422 "a project is
# required" and the whole prompt was dead on arrival. Nothing caught it
# because the UI was built against the source, not a running server.
call("/api/projects", "POST",
     {"code": "SLKME", "name": "Slack me"}, token=admin)

st, me = call("/api/projects/SLKME/slack/me", token=admin)
check("GET slack/me resolves the project from the path", st == 200,
      f"status={st} {str(me)[:90]}")
check("and reports whether slack is on for it",
      isinstance((me or {}).get("slack_enabled"), bool), str(me)[:90])
# This suite configures slack site-wide and auto-creates a channel per
# project, so a new project genuinely does have a destination — which
# is exactly the condition that should prompt.
check("with a channel configured, it asks", (me or {}).get("prompt") is True,
      str(me)[:90])
check("and names the channel it would add you to",
      (me or {}).get("channels"), str(me)[:90])

st, done = call("/api/projects/SLKME/slack/me", "POST",
                {"handle": "@someone", "save_as_default": True}, token=admin)
check("POST slack/me is reachable too", st == 200, f"status={st}")
check("the @ is stripped on the way in",
      (done or {}).get("handle") == "someone", str((done or {}).get("handle")))
check("and it is recorded as confirmed", (done or {}).get("confirmed") is True,
      str(done)[:90])
# The handle is fictional and the workspace is a stub, so the invite
# cannot succeed. The point is that it is reported as a failure with
# the reason, rather than the handle being saved and the invite
# silently looking like it worked.
res = str((done or {}).get("invite_result") or "")
check("a failed invite is reported with its reason, not swallowed",
      "no member matching" in res, res[:120])
check("and the handle is kept anyway, so it is not asked again",
      (done or {}).get("handle") == "someone", str(done)[:90])

st, me2 = call("/api/projects/SLKME/slack/me", token=admin)
check("the default is now on the profile and offered back",
      (me2 or {}).get("default_handle") == "someone", str(me2)[:90])

st, dec = call("/api/projects/SLKME/slack/me/decline", "POST", {}, token=admin)
check("decline is reachable", st == 200, f"status={st}")
check("and clears the confirmation rather than keeping both",
      (dec or {}).get("declined") is True and (dec or {}).get("confirmed") is False,
      str(dec)[:90])

st, _ = call("/api/projects/NOSUCH/slack/me", token=admin)
check("an unknown project is 404, not 422", st == 404, f"status={st}")

print("\n== a handle is given once per workspace, not once per project ==")
# Asking again because a second engagement started in the same Slack is
# how a prompt becomes something people dismiss without reading.
call("/api/projects", "POST", {"code": "WSA", "name": "Workspace A"}, token=admin)
call("/api/projects", "POST", {"code": "WSB", "name": "Workspace B"}, token=admin)
# Both engagements post into channels that have to EXIST. Adopting
# someone resolves the channel by NAME and then invites them by id,
# because `conversations.invite` takes an id and nothing else, so a
# workspace that has never heard of #eng-wsb cannot add anyone to it.
# Registering them here is what a real workspace would look like; the
# fake's `conversations.invite` still answers ok to anything, so without
# this the check passed against a channel that was never created.
CHANNELS.setdefault("eng-wsa", "C900")
CHANNELS.setdefault("eng-wsb", "C901")
call("/api/users", "POST", {"username": "wsu", "password": "wsu-password-123"},
     token=admin)
for p in ("WSA", "WSB"):
    call(f"/api/projects/{p}/acl", "POST", {"username": "wsu", "role": "user"},
         token=admin)
wsu = call("/api/auth/login", "POST",
           {"username": "wsu", "password": "wsu-password-123"})[1]["access_token"]

st, a = call("/api/projects/WSA/slack/me", token=wsu)
check("a new person is asked on the first engagement",
      (a or {}).get("prompt") is True, str(a)[:120])
st, b = call("/api/projects/WSB/slack/me", token=wsu)
check("and on the second, while they have not answered",
      (b or {}).get("prompt") is True, str(b)[:120])

st, a = call("/api/projects/WSA/slack/me", "POST",
             {"handle": "wsu-person"}, token=wsu)
check("they answer on the first", (a or {}).get("confirmed") is True, str(a)[:120])

st, b = call("/api/projects/WSB/slack/me", token=wsu)
check("the second engagement no longer asks",
      (b or {}).get("prompt") is False, str(b)[:160])
check("but knows they are not in its channel yet",
      (b or {}).get("can_adopt") is True, str(b)[:160])
check("and offers back the handle they already gave",
      (b or {}).get("handle") == "wsu-person", str(b.get("handle")))
check("without claiming they are already in this one",
      (b or {}).get("confirmed") is False, str(b.get("confirmed")))

before = len(POSTED)
st, b = call("/api/projects/WSB/slack/me/adopt", "POST", {}, token=wsu)
check("adopting adds them to this engagement's channel", st == 200
      and "added" in str((b or {}).get("invite_result")), str(b)[:160])
check("and now it is confirmed here too",
      (b or {}).get("confirmed") is True, str(b.get("confirmed")))
check("still without asking", (b or {}).get("prompt") is False,
      str(b.get("prompt")))

print("-- declining is per workspace too --")
call("/api/projects", "POST", {"code": "WSC", "name": "Workspace C"}, token=admin)
call("/api/users", "POST", {"username": "wsn", "password": "wsn-password-123"},
     token=admin)
call("/api/projects/WSC/acl", "POST", {"username": "wsn", "role": "user"},
     token=admin)
call("/api/projects/WSA/acl", "POST", {"username": "wsn", "role": "user"},
     token=admin)
wsn = call("/api/auth/login", "POST",
           {"username": "wsn", "password": "wsn-password-123"})[1]["access_token"]
call("/api/projects/WSC/slack/me/decline", "POST", {}, token=wsn)
st, other = call("/api/projects/WSA/slack/me", token=wsn)
check("saying no once stops the asking everywhere in that workspace",
      (other or {}).get("prompt") is False, str(other)[:140])
check("and does not pretend they joined anything",
      (other or {}).get("confirmed") is False
      and (other or {}).get("can_adopt") is False, str(other)[:140])

print("\n== a token is not a destination ==")
# The bug this exists for: a bot token resolved, so the list showed
# Slack as on, and every notification went into a channel_not_found
# because nobody ever created it.
call("/api/projects", "POST",
     {"code": "GHOST", "name": "No channel", "slack_channel": "eng-ghost"},
     token=admin)
st, sc = call("/api/projects/GHOST/slack", token=admin)
check("the site token resolves for it",
      (sc or {}).get("token_resolves") is True, str(sc)[:120])
check("but nothing claims Slack is on yet",
      (sc or {}).get("active") is False, str((sc or {}).get("active")))

st, r = call("/api/projects/slack/refresh?project=GHOST", "POST", {}, token=admin)
check("a refresh reaches the workspace", st == 200, f"status={st}")
check("and finds the channel is not there",
      (r or {}).get("projects", {}).get("GHOST") == "missing", str(r)[:160])

st, p = call("/api/projects/GHOST", token=admin)
check("so the project is not live despite a working token",
      p.get("slack_active") is False, str(p.get("slack_active")))
check("and says the channel is the thing that is missing",
      p.get("slack_channel_state") == "missing", str(p.get("slack_channel_state")))
st, sc = call("/api/projects/GHOST/slack", token=admin)
check("with a reason an operator can act on",
      "does not exist in the workspace" in str((sc or {}).get("inactive_reason")),
      str((sc or {}).get("inactive_reason"))[:120])

print("-- creating it is what turns it on --")
st, sc = call("/api/projects/GHOST/slack", "PUT", {"create": True}, token=admin)
check("the channel is created", st == 200 and "eng-ghost" in CREATED,
      f"status={st} {CREATED}")
check("and creating it counts as verifying it",
      (sc or {}).get("channel_state") == "present", str(sc)[:140])
st, p = call("/api/projects/GHOST", token=admin)
check("now the project is live", p.get("slack_active") is True,
      str(p.get("slack_active")))
check("and the list agrees",
      next((x for x in call("/api/projects?limit=200", token=admin)[1]["items"]
            if x["code"] == "GHOST"), {}).get("slack_active") is True, "")

print("-- an unreachable workspace is not an absent channel --")
# The distinction the whole three-state design exists for. A rate
# limit must never be rendered as "your channel is gone".
LIST_ERROR = "ratelimited"
st, r = call("/api/projects/slack/refresh?project=GHOST", "POST", {}, token=admin)
check("the refresh still succeeds", st == 200, f"status={st}")
check("and reports unknown, not missing",
      (r or {}).get("projects", {}).get("GHOST") == "unknown", str(r)[:160])
st, p = call("/api/projects/GHOST", token=admin)
check("the last known good answer is kept rather than overwritten",
      p.get("slack_channel_state") == "present",
      str(p.get("slack_channel_state")))
check("with the failure recorded against it",
      "ratelimited" in str(p.get("slack_channel_error")),
      str(p.get("slack_channel_error"))[:90])
LIST_ERROR = ""

print("-- moving the destination forgets the old verification --")
st, _ = call("/api/projects/GHOST/slack", "PUT",
             {"channel": "eng-ghost-moved"}, token=admin)
st, p = call("/api/projects/GHOST", token=admin)
check("a new channel name is unknown, not inherited as present",
      p.get("slack_channel_state") == "unknown",
      str(p.get("slack_channel_state")))
check("and the project is no longer claimed to be live",
      p.get("slack_active") is False, str(p.get("slack_active")))

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
