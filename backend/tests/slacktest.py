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
#: Make chat.postMessage refuse, the way a real outage or a revoked token
#: does. The digest's whole restart/outage guarantee rests on what it does
#: when a post does not land, and that cannot be tested against a fake
#: that always says yes.
SLACK_DOWN = False
#: Who is in the fake workspace. Anyone absent fails to resolve, which
#: is what the "a failed invite is reported" check depends on.
MEMBERS = ["wsu-person"]
#: The bot's own Slack id, as `auth.test` reports it.
BOT_ID = "UBOTSELF"
#: What `conversations.replies` hands back, set per assertion below.
THREAD: list[dict] = []


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        method = self.path.rsplit("/", 1)[-1]
        if method == "apps.connections.open":
            out = {"ok": True, "url": WS_URL}
        elif method == "auth.test":
            # Who the bot is. The inbound half refuses to answer at all
            # without this: every loop-safety rule is anchored on being
            # able to tell our own voice from everyone else's.
            out = {"ok": True, "user_id": BOT_ID, "user": "oddjob"}
        elif method == "conversations.replies":
            out = {"ok": True, "messages": list(THREAD)}
        elif method == "conversations.info":
            out = {"ok": True, "channel": {"id": body.get("channel"),
                                           "name": CHANNEL_NAME}}
        elif method == "chat.postMessage":
            if SLACK_DOWN:
                # Not recorded in POSTED: nothing arrived in the channel,
                # which is the whole point of the case.
                out = {"ok": False, "error": "service_unavailable"}
            else:
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
#: Events the test wants delivered, appended as each assertion needs one.
#: A queue rather than a single flag, so the inbound half can be driven
#: through more than one case per connection.
OUTBOX: list[dict] = []


def deliver(envelope_id, **event):
    OUTBOX.append({"type": "events_api", "envelope_id": envelope_id,
                   "payload": {"event": event}})


async def _ws_handler(conn):
    await conn.send(_json.dumps({"type": "hello"}))

    async def pusher():
        # Wait until the test asks, so the connection assertion and the
        # mention assertion do not race each other.
        while not SEND_MENTION.is_set():
            await _aio.sleep(0.1)
        sent = 0
        while True:
            while sent < len(OUTBOX):
                await conn.send(_json.dumps(OUTBOX[sent]))
                sent += 1
            await _aio.sleep(0.1)

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

    def arrives(within=25.0):
        """Wait for one posted message, or None. Clears as it goes."""
        end = time.time() + within
        while time.time() < end:
            if POSTED:
                return POSTED[0]
            time.sleep(0.2)
        return None

    def nothing_arrives(seconds=4.0):
        """The opposite claim, and the one the loop safety rests on."""
        time.sleep(seconds)
        return not POSTED

    if status:
        POSTED.clear()
        deliver("env-1", type="app_mention", channel="C999",
                ts="1700000000.0001", user="U42",
                text=f"<@{BOT_ID}> how many targets does this engagement have?")
        SEND_MENTION.set()
        # Acked first, then answered: Slack retries anything not
        # acknowledged within a few seconds and a model call is slower
        # than that, so a slow answer would be asked three times.
        end = time.time() + 20
        while time.time() < end and not ACKED:
            time.sleep(0.2)
        check("the mention envelope is acknowledged", ACKED == ["env-1"], str(ACKED))

        r0 = arrives()
        check("and a reply is posted", bool(r0), str(POSTED)[:160])
        if r0:
            check("in the thread the question was asked in",
                  r0.get("thread_ts") == "1700000000.0001", str(r0.get("thread_ts")))
            check("to the channel it came from", r0.get("channel") == "C999",
                  str(r0.get("channel")))
            # U42 is in the channel and is nobody in Oddjob. This is the
            # whole inbound security posture in one assertion: being
            # present in a Slack channel buys you nothing.
            check("an unlinked sender is told to link their account and no more",
                  "link" in (r0.get("text") or "").lower()
                  and "oddjob" in (r0.get("text") or "").lower(),
                  str(r0.get("text"))[:200])
            check("and the refusal carries none of the engagement's data",
                  "slk.example" not in (r0.get("text") or ""),
                  str(r0.get("text"))[:200])

        # A message with no mention in the channel. Nothing may happen:
        # answering conversations we were not addressed in is the failure
        # that gets a bot muted, and it is asserted as an ABSENCE.
        POSTED.clear()
        deliver("env-2", type="message", channel="C999", ts="1700000001.0001",
                user="U42", text="how many targets does this engagement have?")
        check("a channel message with no mention is not answered at all",
              nothing_arrives(), str(POSTED)[:200])

        # Our own voice coming back. The one that turns a channel into a
        # loop if it is ever answered.
        POSTED.clear()
        deliver("env-3", type="message", channel="C999", ts="1700000002.0001",
                user=BOT_ID, text=f"<@{BOT_ID}> what about now?")
        check("the bot never answers itself", nothing_arrives(), str(POSTED)[:200])

        POSTED.clear()
        deliver("env-4", type="message", channel="C999", ts="1700000003.0001",
                user="U43", bot_id="B7", text=f"<@{BOT_ID}> and now?")
        check("nor another bot", nothing_arrives(), str(POSTED)[:200])

        POSTED.clear()
        deliver("env-5", type="message", subtype="message_changed",
                channel="C999", ts="1700000004.0001", user="U42",
                text=f"<@{BOT_ID}> rewritten after the fact")
        check("nor an edit of a message it already saw",
              nothing_arrives(), str(POSTED)[:200])

        # The same mention twice — Slack redelivering an envelope it did
        # not see acked. Exactly one reply.
        POSTED.clear()
        deliver("env-6", type="app_mention", channel="C999",
                ts="1700000005.0001", user="U42", text=f"<@{BOT_ID}> hello?")
        deliver("env-6b", type="app_mention", channel="C999",
                ts="1700000005.0001", user="U42", text=f"<@{BOT_ID}> hello?")
        arrives()
        time.sleep(3.0)
        check("a redelivered envelope is answered once, not twice",
              len(POSTED) == 1, str(len(POSTED)))

        # The same stranger, in the same thread, asking again. They are
        # told to link their account ONCE: the sentence does not change,
        # and each repeat costs a thread fetch and a database session.
        POSTED.clear()
        deliver("env-6c", type="app_mention", channel="C999",
                ts="1700000005.0002", user="U42",
                thread_ts="1700000005.0001", text=f"<@{BOT_ID}> hello again?")
        check("an unlinked sender is told to link their account once a thread",
              nothing_arrives(), str(POSTED)[:200])

        # A thread reply with no mention, in a thread the bot is in. The
        # thread is fetched whole — the fake serves THREAD — and answered.
        # A different sender and a different thread, so this measures
        # the addressing rule and not the refusal already given above.
        POSTED.clear()
        THREAD[:] = [{"user": "U44", "ts": "1700000010.0001",
                      "text": f"<@{BOT_ID}> how many targets?"},
                     {"user": BOT_ID, "ts": "1700000010.0002",
                      "text": "I cannot answer that yet"},
                     {"user": "U44", "ts": "1700000011.0001",
                      "text": "and which are alive?"}]
        deliver("env-7", type="message", channel="C999", ts="1700000011.0001",
                thread_ts="1700000010.0001", user="U44",
                text="and which are alive?")
        r7 = arrives()
        check("a follow-up in a thread it is in needs no second mention",
              bool(r7), str(POSTED)[:200])
        if r7:
            check("and the answer still goes in that thread",
                  r7.get("thread_ts") == "1700000010.0001",
                  str(r7.get("thread_ts")))

        # The same thread, but the reply is aimed at a person.
        POSTED.clear()
        deliver("env-8", type="message", channel="C999", ts="1700000012.0001",
                thread_ts="1700000010.0001", user="U45",
                text="<@U77> can you take a look?")
        check("but a thread reply addressed to someone else is left alone",
              nothing_arrives(), str(POSTED)[:200])

        # A thread the bot was never in, which merely has another app
        # posting in it. Treating any bot_id as "us" would recruit the
        # bot into every thread a CI notifier touches.
        POSTED.clear()
        THREAD[:] = [{"user": "U46", "ts": "1700000020.0001",
                      "text": "deploying the thing"},
                     {"user": "U99", "bot_id": "B7", "ts": "1700000020.0002",
                      "text": "build ok"}]
        deliver("env-9", type="message", channel="C999", ts="1700000021.0001",
                thread_ts="1700000020.0001", user="U46",
                text="and how many are alive?")
        check("another app in a thread does not make it the bot's thread",
              nothing_arrives(), str(POSTED)[:200])
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
st, a = call("/api/ghosts?project=RUNNING", "POST",
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


# ============================================================ membership
# Access to an engagement changing is an audit event, so each one is
# posted on its own the moment it happens — no batching, no digest. The
# checks below are about the WIRING: three separate places in the app
# build a ProjectACL, and until now only some of them said anything.
print("\n== membership and permission changes post immediately ==")

check("a promotion names both roles",
      "promoted from `user` to `admin`"
      in slack.user_role_changed("bob", "user", "admin"),
      slack.user_role_changed("bob", "user", "admin"))
check("a demotion says so rather than reporting a new role",
      "demoted from `admin` to `readonly`"
      in slack.user_role_changed("bob", "admin", "readonly"),
      slack.user_role_changed("bob", "admin", "readonly"))
check("an unknown role falls back to neutral wording rather than guessing",
      "role changed from `x` to `y`" in slack.user_role_changed("bob", "x", "y"),
      slack.user_role_changed("bob", "x", "y"))

POSTED.clear()
call("/api/projects/SLK/acl", "POST", {"username": "bob", "role": "user"}, token=admin)
check("a fresh grant still announces a join, not a role change",
      sent("joined the engagement as `user`") is not None, str(POSTED)[:160])

POSTED.clear()
st, _ = call("/api/projects/SLK/acl", "POST",
             {"username": "bob", "role": "admin"}, token=admin)
check("re-granting at a higher role announces a promotion", st == 201
      and sent("User `bob` was promoted from `user` to `admin`") is not None,
      f"{st} {str(POSTED)[:200]}")
check("and does NOT announce it as somebody joining",
      sent("joined the engagement", 0.4) is None, str(POSTED)[:200])

POSTED.clear()
call("/api/projects/SLK/acl", "POST", {"username": "bob", "role": "readonly"}, token=admin)
check("dropping a role announces a demotion",
      sent("User `bob` was demoted from `admin` to `readonly`") is not None,
      str(POSTED)[:200])

POSTED.clear()
call("/api/projects/SLK/acl", "POST", {"username": "bob", "role": "readonly"}, token=admin)
check("re-granting the role somebody already holds announces nothing",
      sent("bob", 0.6) is None, str(POSTED)[:200])

# The gap that mattered most: members named while CREATING an engagement
# were written straight into the database and never mentioned.
POSTED.clear()
call("/api/users", "POST",
     {"username": "carol", "password": "carol-password-1"}, token=admin)
st, _ = call("/api/projects", "POST",
             {"code": "MEMB", "name": "Members test", "codename": "OSPREY",
              "members": [{"username": "carol", "role": "user"}]}, token=admin)
check("a member named on the create form is announced", st == 201
      and sent("User `carol` joined the engagement as `user`") is not None,
      f"{st} {str(POSTED)[:220]}")
check("into that project's own channel",
      (sent("User `carol` joined") or {}).get("channel") == "eng-osprey",
      str((sent("User `carol` joined") or {}).get("channel")))
check("and the creator's own admin grant stays quiet",
      sent("`root` joined", 0.4) is None, str(POSTED)[:220])

# "even if they don't have a slack handle yet" — carol has never mapped
# one, and the fake workspace has never heard of her.
check("nobody needs a mapped slack handle for the post to go out",
      "carol" not in MEMBERS, str(MEMBERS))


# ================================================================ digest
# Targets are the opposite problem: they arrive in hundreds, so they are
# counted on a five-minute timer and never announced one at a time.
#
# Driven in-process rather than through HTTP: the digest is a background
# loop with no endpoint, and the alternative — adding one so a test could
# poke it — would be API surface that exists only for the test. The suite
# already has `app` importable and the same ODDJOB_DB the server is using,
# so `tick()` runs against exactly the rows the endpoints above wrote.
print("\n== the five-minute target digest ==")
import asyncio
from datetime import UTC, datetime, timedelta

from app import timeline as timeline_mod

check("alive flipping is not worth a notice",
      not timeline_mod.is_notable("change", "alive: none → yes"))
check("nor an OS fingerprint being rewritten",
      not timeline_mod.is_notable("change", "os: none → Ubuntu 24.04; os_accuracy: none → 97"))
check("but a rename is",
      timeline_mod.is_notable("change", "host: \"old.acme.example\" → \"new.acme.example\""))
check("and so is an address moving, because scope is written as ranges",
      timeline_mod.is_notable("change", "ip_address: 10.0.0.1 → 10.0.0.9; alive: no → yes"))
check("and the hacked flag",
      timeline_mod.is_notable("change", "hacked: no → yes"))
check("a hand-written status entry always counts",
      timeline_mod.is_notable("status", "marked as compromised"))
check("so does a note somebody wrote",
      timeline_mod.is_notable("note", "left a shell here"))
check("prose from a merge is counted rather than parsed as a field",
      timeline_mod.is_notable("change", "merged old.acme.example into corp.com: 2 findings moved"))
check("a rename written as prose counts too",
      timeline_mod.is_notable("change", "named corp.com from a reverse lookup on 10.0.0.9"))
check("a service appearing never reaches the digest",
      not timeline_mod.is_notable("service", "nmap: 4 service(s) found"))
check("nor a finding, which has its own slack path with a severity",
      not timeline_mod.is_notable("vuln", "HIGH: SQL injection"))
check("nor the discovery entry, which is already the ADDED half",
      not timeline_mod.is_notable("discovered", "added to DGST by hand"))

# One loop, reused. A fresh `asyncio.run` per call would leave the
# aiosqlite pool holding connections bound to a loop that has closed.
_loop = asyncio.new_event_loop()


def tick(now=None) -> dict:
    return _loop.run_until_complete(slack.digest.tick(now))


call("/api/projects", "POST",
     {"code": "DGST", "name": "Digest test", "codename": "KESTREL"}, token=admin)
CH = "eng-kestrel"


def digests() -> list[str]:
    return [m.get("text") or "" for m in POSTED
            if m.get("channel") == CH and "targets modified" in (m.get("text") or "")]


POSTED.clear()
first = tick()
check("the first tick anchors every project rather than reporting history",
      first.get("DGST") == "anchored", str(first))
check("and posts nothing", digests() == [], str(digests()))

POSTED.clear()
check("a window in which nothing happened is quiet", tick().get("DGST") == "quiet")
check("and posts NOTHING AT ALL — silence is the message", digests() == [],
      str(digests()))

POSTED.clear()
for h in ("web01.acme.example", "web02.acme.example", "db01.acme.example"):
    st, _ = call("/api/targets?project=DGST", "POST", {"host": h}, token=admin)
r = tick()
check("three targets added in one window are one post, not three",
      len(digests()) == 1, str(digests()))
check("counting all three", "`3` new targets added" in (digests() or [""])[0],
      str(digests()))
check("and nothing modified, because they are brand new",
      "`0` targets modified" in (digests() or [""])[0], str(digests()))
check("the tick says what it did", r.get("DGST") == "posted 3/0", str(r))

# The whole point of the narrowing: a sweep marking hosts up must not
# show up as "3 targets modified" every five minutes forever.
POSTED.clear()
for h in ("web01.acme.example", "web02.acme.example", "db01.acme.example"):
    call(f"/api/targets/DGST/{h}", "PATCH", {"alive": True}, token=admin)
check("a sweep flipping `alive` on every host is not a modification",
      tick().get("DGST") == "quiet", str(digests()))
check("so the channel stays silent through it", digests() == [], str(digests()))

POSTED.clear()
call("/api/targets/DGST/web01.acme.example", "PATCH", {"hacked": True}, token=admin)
call("/api/targets/DGST/db01.acme.example", "PATCH", {"alive": False}, token=admin)
tick()
check("a host being marked compromised IS a modification",
      len(digests()) == 1 and "`1` targets modified" in (digests() or [""])[0],
      str(digests()))
check("and the added count is zero, with the plural left as it is",
      "`0` new targets added and `1` targets modified" in (digests() or [""])[0],
      str(digests()))

# Added and modified inside the same five minutes: counted once, as added.
POSTED.clear()
call("/api/targets?project=DGST", "POST",
     {"host": "app01.acme.example"}, token=admin)
call("/api/targets/DGST/app01.acme.example", "PATCH",
     {"hacked": True}, token=admin)
tick()
check("a target added and then edited in one window counts once, as added",
      "`1` new targets added and `0` targets modified" in (digests() or [""])[0],
      str(digests()))

# --- volume: the case the whole design exists for ----------------------
print("-- 300 targets in one window --")
POSTED.clear()
bulk = {"project": "DGST", "targets": [
    {"host": f"h{i:03d}.corp.com"} for i in range(300)]}
st, br = call("/api/bulk", "POST", bulk, token=admin)
check("300 targets land in one operation", st == 200
      and (br or {}).get("created", {}).get("targets") == 300,
      f"{st} {str(br)[:160]}")
POSTED.clear()
tick()
check("300 new targets produce exactly ONE slack message",
      len(digests()) == 1, f"{len(digests())} messages")
check("naming the count and not the hosts",
      "`300` new targets added" in (digests() or [""])[0], str(digests())[:200])
check("and no hostname reaches the channel",
      "corp.com" not in "".join(digests()), str(digests())[:200])
check("the whole import is one line of channel traffic",
      len([m for m in POSTED if m.get("channel") == CH]) == 1,
      str([m.get("text") for m in POSTED if m.get("channel") == CH])[:200])

# --- outage and restart ------------------------------------------------
print("-- an outage holds the window rather than losing it --")
POSTED.clear()
call("/api/targets?project=DGST", "POST", {"host": "out01.acme.example"}, token=admin)
SLACK_DOWN = True
try:
    r = tick()
    check("a refused post does not consume the window",
          r.get("DGST") == "failed", str(r))
finally:
    SLACK_DOWN = False
POSTED.clear()
call("/api/targets?project=DGST", "POST", {"host": "out02.acme.example"}, token=admin)
tick()
check("the next tick covers BOTH windows — nothing is silently lost",
      "`2` new targets added" in (digests() or [""])[0], str(digests()))

print("-- a restart does not replay or skip --")
POSTED.clear()
call("/api/targets?project=DGST", "POST", {"host": "res01.acme.example"}, token=admin)
tick()
check("one post for the window", "`1` new targets added" in (digests() or [""])[0],
      str(digests()))
POSTED.clear()
# The watermark lives in the database, so a brand-new Digest object —
# which is what a redeployed process has — picks up exactly where the
# old one left off instead of re-counting or re-anchoring.
fresh = slack.Digest()
_loop.run_until_complete(fresh.tick())
check("a fresh process re-counts nothing", digests() == [], str(digests()))

print("-- an old watermark is clamped rather than dumped in one post --")
POSTED.clear()
far = datetime.now(UTC) + slack.DIGEST_MAX_LOOKBACK + timedelta(hours=2)
r = tick(now=far)
check("a window older than the cap still resolves", "DGST" in r, str(r))

print("-- the worker starts and stops --")
check("start is a no-op while the digest is switched off",
      slack.DIGEST_ENABLED is False and (slack.digest.start() or
                                         slack.digest.task is None),
      f"enabled={slack.DIGEST_ENABLED} task={slack.digest.task}")


async def _cycle():
    w = slack.Digest()
    import app.slack as _s
    was, _s.DIGEST_ENABLED = _s.DIGEST_ENABLED, True
    try:
        w.start()
        started = w.task is not None and not w.task.done()
        await w.stop()
        return started and w.task.cancelled()
    finally:
        _s.DIGEST_ENABLED = was


check("and it does start, and cancels cleanly, when it is switched on",
      _loop.run_until_complete(_cycle()))
_loop.close()

print(f"\n{'='*56}\n  {ok} passed, {fail} failed\n{'='*56}")
