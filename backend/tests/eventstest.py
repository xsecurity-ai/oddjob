"""Who receives which change event.

The SSE stream was authenticated and nothing else. Every logged-in user got
every event in the installation, and those events carry the engagement code
and frequently the hostname that changed -- so anyone with a login could sit
on `/api/events` and watch every other engagement's work go past: its code,
its hosts, and when somebody was touching them. The route's own docstring
named the risk and then solved only the unauthenticated half of it.

Three parts, in the order they would catch a regression:

  1. **The source guard.** Every `broker.publish` call site either names a
     project or is on the waiver list below with a reason. This is the part
     that matters in a year: the leak happened because adding a publish call
     without a project was the easy thing to do and nothing objected.

  2. **The broker filters.** Unit tests on delivery, including the two that
     decide whether the fix is worth anything -- an event for an engagement
     you cannot read never enters your queue, and an unlabelled event reaches
     site admins only.

  3. **End to end.** Two accounts against a live server, one of them a
     non-admin with access to exactly one of two engagements. The static
     check and the unit tests can both pass while the route hands the stream
     the wrong user.

Fail-closed is the design and part 2 asserts it deliberately: an event with
no project is delivered to *fewer* people, not more. The cost of forgetting
is a table that waits for its next poll. The cost of the opposite default is
a hostname in a stranger's browser, which is what this is about.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import asyncio
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8013")
APP = _pathlib.Path(__file__).resolve().parents[1] / "app"
ok = fail = 0


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read(); return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw[:300]


# =====================================================================
# Part 1 — every publish names its engagement, or says why it does not
# =====================================================================
print("\n--- every change event names the engagement it belongs to ---")

#: Call sites that are installation-wide on purpose. The value is the reason,
#: and it has to still be true: each of these drives a view that is behind
#: `require_site_admin`, so site-admin-only delivery is not a compromise, it
#: is the right audience. Adding a line here is a decision about who can see
#: something -- make it deliberately.
WAIVED = {
    ("auth.py", "users"): "the user list is a site-admin view",
    ("magic.py", "users"): "invites are administered by site admins",
    ("google.py", "users"): "ditto, via the Google registration path",
    ("settings.py", "settings"): "settings are installation-wide, admin-only",
    ("actions.py", "actions"): "only on the branch where the service is gone, "
                               "so there is no project left to resolve",
}

CALL = re.compile(r"broker\.publish\(\s*(?P<kind>[\"'][a-z_]+[\"']|[A-Za-z_][\w.]*)"
                  r"(?P<rest>.*?)\)\s*$", re.S | re.M)

unlabelled, total = [], 0
for path in sorted(APP.rglob("*.py")):
    src = path.read_text()
    if "broker.publish" not in src:
        continue
    # Match each call and its arguments across continuation lines.
    for m in re.finditer(r"broker\.publish\((?P<args>(?:[^()]|\([^()]*\))*)\)", src):
        total += 1
        args = m.group("args")
        kind = re.match(r"\s*[\"']([a-z_]+)[\"']", args)
        kind = kind.group(1) if kind else "<dynamic>"
        if "project=" in args:
            continue
        line = src[:m.start()].count("\n") + 1
        key = (path.name, kind)
        if key in WAIVED:
            continue
        unlabelled.append(f"{path.name}:{line} publish({kind})")

check("publish call sites found at all", total >= 60, f"{total} call sites")
check("every publish names a project or is waived with a reason",
      not unlabelled,
      "unlabelled: " + "; ".join(unlabelled[:8]) if unlabelled else
      f"{total} sites, {len(WAIVED)} waivers")

# A waiver for a call site that no longer exists is a stale claim about who
# can see what, and it hides the next one.
src_all = {p.name: p.read_text() for p in APP.rglob("*.py")}
stale = [f"{f}:{k}" for (f, k) in WAIVED
         if f not in src_all or f'publish("{k}"' not in src_all[f]]
check("no waiver names a call site that has gone away", not stale, "; ".join(stale))

# `project` must stay keyword-only, or it can arrive by accident in **data
# and the filter reads a value nobody meant to set.
import inspect  # noqa: E402

from app.events import Broker, Sub  # noqa: E402

p = inspect.signature(Broker.publish).parameters
check("project is keyword-only on publish",
      p["project"].kind is inspect.Parameter.KEYWORD_ONLY, str(p["project"].kind))
check("...and defaults to installation-wide", p["project"].default is None)


# =====================================================================
# Part 2 — the filter itself
# =====================================================================
print("\n--- the broker delivers to the right subscribers ---")


def drain(s: Sub) -> list[dict]:
    out = []
    while not s.queue.empty():
        out.append(json.loads(s.queue.get_nowait()))
    return out


async def filters():
    b = Broker()
    alpha = await b.subscribe(frozenset({"ALPHA"}))
    both = await b.subscribe(frozenset({"ALPHA", "BETA"}))
    none = await b.subscribe(frozenset())
    admin = await b.subscribe(None)

    await b.publish("targets", project="ALPHA", host="a.example")
    check("a subscriber on the engagement gets it", len(drain(alpha)) == 1)
    check("a subscriber on both gets it", len(drain(both)) == 1)
    check("a subscriber on neither does NOT", drain(none) == [])
    check("a site admin gets it", len(drain(admin)) == 1)

    # The leak, stated as a test.
    await b.publish("targets", project="BETA", host="secret.beta.example")
    got = drain(alpha)
    check("an engagement you cannot read never reaches your queue", got == [], got)
    check("...and the hostname with it", not any(
        "secret.beta.example" in json.dumps(e) for e in got))
    check("the subscriber who can read it does get it", len(drain(both)) == 1)
    drain(admin); drain(none)

    # Fail closed.
    await b.publish("settings", action="update")
    check("an unlabelled event reaches site admins", len(drain(admin)) == 1)
    check("...and nobody else, however many projects they hold",
          drain(both) == [] and drain(alpha) == [] and drain(none) == [])

    # The payload still carries the project for the client that may read it.
    await b.publish("vulns", project="ALPHA", id=7)
    ev = drain(admin)[0]
    check("the payload names the project", ev.get("project") == "ALPHA", ev)
    check("...and keeps the rest of the data", ev.get("id") == 7, ev)
    drain(alpha); drain(both); drain(none)

    # Access changes mid-stream: the stream mutates `codes` in place on each
    # heartbeat, so the set the broker reads is the current one.
    alpha.codes = frozenset({"ALPHA", "BETA"})
    await b.publish("targets", project="BETA")
    check("a grant takes effect without reconnecting", len(drain(alpha)) == 1)
    alpha.codes = frozenset()
    await b.publish("targets", project="ALPHA")
    check("and a revocation stops delivery the same way", drain(alpha) == [])

    # A full queue drops the oldest rather than growing or blocking, and that
    # must not become a way to push events into a queue that should not have
    # them at all.
    from app.events import QUEUE_SIZE
    for i in range(QUEUE_SIZE + 10):
        await b.publish("targets", project="ALPHA", n=i)
    check("a stalled subscriber's queue stays bounded",
          both.queue.qsize() == QUEUE_SIZE, both.queue.qsize())
    kept = drain(both)
    check("...keeping the newest", kept[-1]["n"] == QUEUE_SIZE + 9, kept[-1])
    check("...and a full queue still delivers nothing to the unentitled",
          drain(none) == [])

    await b.unsubscribe(alpha)
    await b.publish("targets", project="ALPHA")
    check("an unsubscribed stream receives nothing", alpha.queue.empty())
    check("subscriber_count tracks it", b.subscriber_count == 3, b.subscriber_count)


asyncio.run(filters())


# =====================================================================
# Part 3 — against a live server, with two real accounts
# =====================================================================
print("\n--- end to end: a non-admin sees only their own engagement ---")

ROOT_TOKEN = call("/api/auth/setup", "POST",
                  {"username": "root", "password": "root-password-1"})[1]["access_token"]

for code, name in (("EVA", "Events A"), ("EVB", "Events B")):
    call("/api/projects", "POST", {"code": code, "name": name}, ROOT_TOKEN)

st, body = call("/api/users", "POST",
                {"username": "watcher", "password": "watcher-password-1",
                 "full_name": "Watcher"}, ROOT_TOKEN)
check("a second, non-admin account exists", st in (200, 201), f"{st} {body}")
check("...and is not a site admin", not (body or {}).get("is_site_admin"), body)
st, _ = call("/api/projects/EVA/acl", "POST",
             {"username": "watcher", "role": "user"}, ROOT_TOKEN)
check("granted on EVA only", st in (200, 201), st)

WATCH_TOKEN = call("/api/auth/login", "POST",
                   {"username": "watcher", "password": "watcher-password-1"}
                   )[1]["access_token"]
check("the watcher can read EVA", call("/api/projects/EVA", token=WATCH_TOKEN)[0] == 200)
check("...and cannot read EVB", call("/api/projects/EVB", token=WATCH_TOKEN)[0] == 404)

seen = []


def listen(token, sink):
    try:
        r = urllib.request.Request(BASE + "/api/events")
        r.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(r, timeout=12) as resp:
            for line in resp:
                s = line.decode(errors="replace").strip()
                if s.startswith("data:"):
                    sink.append(s[5:].strip())
    except Exception:
        pass


t = threading.Thread(target=listen, args=(WATCH_TOKEN, seen), daemon=True)
t.start()
time.sleep(1.5)

# root, who can read both, makes a change in each.
call("/api/targets?project=EVA", "POST", {"host": "allowed.eva.example"}, ROOT_TOKEN)
call("/api/targets?project=EVB", "POST", {"host": "secret.evb.example"}, ROOT_TOKEN)
time.sleep(2.0)

payloads = [json.loads(s) for s in seen if s.startswith("{")]
check("the watcher received the EVA change",
      any(e.get("project") == "EVA" for e in payloads), payloads)
check("the watcher received NOTHING for EVB",
      not any(e.get("project") == "EVB" for e in payloads), payloads)
check("...and never saw its hostname",
      not any("secret.evb.example" in json.dumps(e) for e in payloads))

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
