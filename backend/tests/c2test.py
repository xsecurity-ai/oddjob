"""Listeners, and what a shell landing on one does to the target.

Two halves.

The first is configuration: which Ghost is told to hold which port,
and what the API refuses. The part worth asserting is that
`enabled` and `state` stay apart -- one is what an operator asked
for and the other is what the Ghost managed, and a UI that shows
the first while meaning the second sends somebody to debug a
payload when the real answer is that nginx already had the port.

The second is the consequence. **A shell IS the compromise**, so a
callback sets the same pwned flag an imported beacon sets. Getting
that wrong is silent: the session is recorded either way and the
host simply never turns red, so nobody notices until the report is
written against an estate that looks clean.
"""

import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import json  # noqa: E402
import os  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

BASE = os.environ.get("ODDJOB_TEST_BASE", "http://127.0.0.1:8035")
ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {label}")
    else:
        fail += 1
        print(f"  FAIL  {label} {extra}")


def call(p, m="GET", b=None, token=None):
    r = urllib.request.Request(BASE + p, method=m)
    if b is not None:
        r.data = json.dumps(b).encode()
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw[:300]


admin = call("/api/auth/setup", "POST",
             {"username": "root", "password": "root-password-1"})[1]["access_token"]
call("/api/projects", "POST", {"code": "C2T", "name": "C2 test"}, token=admin)
call("/api/projects/C2T/scope", "POST",
     {"lines": ["198.51.100.0/24", "shell.acme.example"]}, token=admin)
call("/api/targets?project=C2T", "POST",
     {"host": "198.51.100.7"}, token=admin)

st, ghost = call("/api/ghosts?project=C2T", "POST",
                 {"name": "edge-01", "target_os": "linux"}, token=admin)
GID = ((ghost or {}).get("agent") or {}).get("id")
check("a ghost to hang listeners off", st in (200, 201) and GID,
      f"{st} {ghost}")


print("== setting ports on a ghost ==")
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "tcp", "ports": [443, 80, 8443]},
             token=admin)
check("several ports in one go", st == 200 and r["added"] == [443, 80, 8443],
      f"{st} {r}")
check("...and it says the ghost has not got them yet",
      "heartbeat" in r.get("note", ""), r.get("note"))

st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "udp", "ports": [53]}, token=admin)
check("udp as well as tcp", st == 200 and r["added"] == [53], f"{st} {r}")

st, rows = call("/api/c2/listeners?project=C2T", token=admin)
check("one ghost holds several ports", st == 200 and len(rows) == 4,
      f"{st} {len(rows) if isinstance(rows, list) else rows}")
check("...and each row names the ghost",
      all(x["agent_id"] == GID and x["agent_name"] for x in rows))
check("...and tcp and udp are not the same listener",
      {(x["protocol"], x["port"]) for x in rows}
      == {("tcp", 443), ("tcp", 80), ("tcp", 8443), ("udp", 53)})

# The distinction the whole feature rests on.
check("nothing is reported as bound before the ghost says so",
      all(x["state"] == "pending" for x in rows),
      str({x["state"] for x in rows}))
check("...and a ghost with no tunnel is not shown as online",
      all(x["agent_online"] is False for x in rows))

print("\n== what it refuses ==")
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "tcp", "ports": [443]}, token=admin)
check("the same port twice is refused, not duplicated",
      st == 200 and not r["added"] and r["refused"], f"{st} {r}")
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "tcp", "ports": [0]}, token=admin)
check("port 0 is refused -- a payload cannot call back to “whatever is free”",
      st == 200 and not r["added"], f"{st} {r}")
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "tcp", "ports": [70000]}, token=admin)
check("a port above 65535 is refused", st == 200 and not r["added"], f"{st} {r}")
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "sctp", "ports": [9000]}, token=admin)
check("a protocol that is not tcp or udp is refused", st == 422, f"{st} {r}")
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": 9999, "protocol": "tcp", "ports": [9000]}, token=admin)
check("a ghost on another engagement is a 404, not a listener", st == 404,
      f"{st} {r}")

# One form, one bad port: the good ones still land. A refusal of the
# whole batch means retyping five ports because of one typo.
st, r = call("/api/c2/listeners?project=C2T", "POST",
             {"agent_id": GID, "protocol": "tcp", "ports": [9001, 0, 9002]},
             token=admin)
check("one bad port does not refuse the good ones",
      st == 200 and r["added"] == [9001, 9002] and r["refused"], f"{st} {r}")

print("\n== turning one off ==")
st, rows = call("/api/c2/listeners?project=C2T", token=admin)
lid = next(x["id"] for x in rows if x["port"] == 80)
st, r = call(f"/api/c2/listeners/{lid}?project=C2T", "PATCH",
             {"enabled": False}, token=admin)
check("a listener can be switched off", st == 200 and r["enabled"] is False,
      f"{st} {r}")
st, rows = call("/api/c2/listeners?project=C2T", token=admin)
check("...and the row stays, so it can be switched back on",
      any(x["id"] == lid for x in rows))

print("\n== what the ghost is told ==")
import asyncio  # noqa: E402

from sqlalchemy import select  # noqa: E402

from app import listeners as L  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import Agent, Project, Target  # noqa: E402


async def plan():
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        return await L.desired(s, a.id)


want = asyncio.run(plan())
check("the beat carries the enabled listeners",
      {(x["protocol"], x["port"]) for x in want}
      == {("tcp", 443), ("tcp", 8443), ("tcp", 9001), ("tcp", 9002),
          ("udp", 53)},
      str(sorted((x["protocol"], x["port"]) for x in want)))
check("...and not the one that was switched off",
      ("tcp", 80) not in {(x["protocol"], x["port"]) for x in want})


print("\n== what the ghost says back ==")


async def says(report):
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        await L.report(s, a.id, report)
        await s.commit()
        return {(r.protocol, r.port): (r.state, r.state_detail)
                for r in await L.for_agent(s, a.id)}


ids = {(x["protocol"], x["port"]): x["id"]
       for x in call("/api/c2/listeners?project=C2T", token=admin)[1]}
state = asyncio.run(says([
    {"id": ids[("tcp", 443)], "bound": True},
    {"id": ids[("tcp", 8443)], "bound": False,
     "error": "listen tcp :8443: bind: address already in use"},
]))
check("a bound port is recorded as bound", state[("tcp", 443)][0] == "bound",
      str(state[("tcp", 443)]))
check("a failed bind is recorded as failed",
      state[("tcp", 8443)][0] == "failed", str(state[("tcp", 8443)]))
check("...and keeps the reason, which is the whole answer",
      "already in use" in (state[("tcp", 8443)][1] or ""),
      str(state[("tcp", 8443)][1]))

# The one that would be easy to get wrong, and silent.
check("a port the ghost did not mention is NOT marked failed",
      state[("udp", 53)][0] == "pending", str(state[("udp", 53)]))
state = asyncio.run(says([]))
check("...and an agent that reports nothing at all changes nothing",
      state[("tcp", 443)][0] == "bound" and state[("udp", 53)][0] == "pending")

# Disabling must not leave a stale "bound" behind: it would claim a
# port is held that the ghost has been told to drop.
st, _ = call(f"/api/c2/listeners/{ids[('tcp', 443)]}?project=C2T", "PATCH",
             {"enabled": False}, token=admin)
rows = {x["id"]: x for x in call("/api/c2/listeners?project=C2T", token=admin)[1]}
check("switching one off clears what the ghost last said about it",
      rows[ids[("tcp", 443)]]["state"] == "pending",
      rows[ids[("tcp", 443)]]["state"])


print("\n== a callback owns the host ==")
from app import proxytunnel, shellwork  # noqa: E402
from app.shellhub import hub  # noqa: E402


def announcement(peer, protocol=None, port=None):
    if protocol is None:
        return peer.encode()
    return json.dumps({"peer": peer, "protocol": protocol,
                       "port": port}).encode()


peer_, proto_, port_ = shellwork._announcement(
    announcement("198.51.100.7:51000", "tcp", 443))
check("an announcement says which listener caught it",
      (peer_, proto_, port_) == ("198.51.100.7:51000", "tcp", 443),
      f"{peer_} {proto_} {port_}")
peer_, proto_, port_ = shellwork._announcement(
    announcement("198.51.100.7:51000"))
check("...and a bare address from an older ghost still parses",
      (peer_, proto_, port_) == ("198.51.100.7:51000", None, None),
      f"{peer_} {proto_} {port_}")


async def callback(peer, port=443):
    """Drive one ARRIVED frame the way the tunnel would."""
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        # The hub holds the route home; a frame with no tunnel
        # registered has nowhere to attach its stream.
        hub.register(a.id, _sink)
        frame = proxytunnel.Frame(
            kind=proxytunnel.ARRIVED, stream=callback.n,
            payload=announcement(peer, "tcp", port))
        callback.n += 1
        await shellwork.on_frame(s, a, frame)
    async with SessionLocal() as s:
        pr = (await s.execute(select(Project).where(
            Project.code == "C2T"))).scalar_one()
        host = peer.rsplit(":", 1)[0]
        t = (await s.execute(select(Target).where(
            Target.project_id == pr.id, Target.host == host))).scalar_one_or_none()
        return t


callback.n = 1


async def _sink(_b):
    return None


t = asyncio.run(callback("198.51.100.7:51000"))
check("a shell on a known host marks it pwned", t is not None and t.hacked is True,
      str(getattr(t, "hacked", None)))

st, detail = call("/api/targets/C2T/198.51.100.7/timeline", token=admin)
entries = (detail or {}).get("items", []) if isinstance(detail, dict) else []
check("...and the timeline says why it is red",
      any("compromised" in (e.get("summary") or "") for e in entries),
      str([e.get("summary") for e in entries][:4]))
check("...and names the port it landed on",
      any("443" in (e.get("summary") or "") for e in entries),
      str([e.get("summary") for e in entries][:4]))

st, rows = call("/api/targets?project=C2T&hacked=true", token=admin)
items = (rows or {}).get("items", rows)
check("the pwned filter finds it", st == 200 and len(items) == 1,
      f"{st} {items}")

# A second shell is another event, not another compromise.
t = asyncio.run(callback("198.51.100.7:51001"))
st, detail = call("/api/targets/C2T/198.51.100.7/timeline", token=admin)
entries = (detail or {}).get("items", [])
check("a second shell does not claim a second compromise",
      sum(1 for e in entries if "compromised" in (e.get("summary") or "")) == 1,
      str([e.get("summary") for e in entries][:5]))
check("...but is still recorded",
      any("another shell" in (e.get("summary") or "") for e in entries),
      str([e.get("summary") for e in entries][:5]))

# A callback from an address nothing in the inventory knows. The
# session is kept -- throwing away a live shell because the inventory
# was behind is the worse failure -- and no target is invented for it,
# because the source of a callback is as often a NAT egress as the
# host that was popped.
before = call("/api/targets?project=C2T&limit=200", token=admin)[1]
t = asyncio.run(callback("203.0.113.99:40000"))
after = call("/api/targets?project=C2T&limit=200", token=admin)[1]
check("a callback from an unknown address invents no target",
      len(after.get("items", [])) == len(before.get("items", [])),
      f"{len(before.get('items', []))} -> {len(after.get('items', []))}")
st, sess = call("/api/c2/sessions?project=C2T&active=true", token=admin)
check("...and the shell is kept anyway", st == 200 and len(sess) == 3,
      f"{st} {len(sess) if isinstance(sess, list) else sess}")
check("...with the port it landed on, so it can be told from the others",
      all(x["listen_port"] == 443 for x in sess),
      str([x["listen_port"] for x in sess]))
check("...and the one with no target says so rather than guessing",
      sum(1 for x in sess if x["host"] is None) == 1,
      str([x["host"] for x in sess]))

print("\n== a listener is the engagement's, not the world's ==")
call("/api/projects", "POST", {"code": "OTHER", "name": "other"}, token=admin)
st, rows = call("/api/c2/listeners?project=OTHER", token=admin)
check("another engagement sees none of these", st == 200 and rows == [],
      f"{st} {rows}")
st, r = call(f"/api/c2/listeners/{ids[('udp', 53)]}?project=OTHER", "PATCH",
             {"enabled": False}, token=admin)
check("...and cannot reach one by id", st == 404, f"{st} {r}")

print("\n== deleting one keeps what it caught ==")
st, _ = call(f"/api/c2/listeners/{ids[('tcp', 443)]}?project=C2T", "DELETE",
             token=admin)
check("a listener can be removed", st == 204, st)
st, sess = call("/api/c2/sessions?project=C2T&active=true", token=admin)
check("...and the shells it caught are still there", len(sess) == 3,
      str(len(sess)))

print(f"\n{'=' * 56}\n  {ok} passed, {fail} failed\n{'=' * 56}")
raise SystemExit(1 if fail else 0)
