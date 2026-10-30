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
from app import shellhub  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import Agent, Project, ShellExchange, ShellSession, Target  # noqa: E402


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

# A callback from an address nothing in the inventory knows.
#
# It GETS a target. A callback is the strongest evidence an
# engagement produces that a host exists and is reachable, which is
# a better claim than most rows in the inventory have.
#
# The caution this replaced -- that the source of a callback is as
# often a NAT egress as the box that was popped -- is still true,
# which is why the row records where it came from and why a
# session can be re-pointed at the real host.
before = call("/api/targets?project=C2T&limit=200", token=admin)[1]
t = asyncio.run(callback("203.0.113.99:40000"))
after = call("/api/targets?project=C2T&limit=200", token=admin)[1]
check("a callback from an unknown address creates a target for it",
      len(after.get("items", [])) == len(before.get("items", [])) + 1,
      f"{len(before.get('items', []))} -> {len(after.get('items', []))}")
made = next((x for x in after.get("items", [])
             if x["host"] == "203.0.113.99"), None)
check("...marked alive, because it just connected to us",
      made and made.get("alive") is True, str(made))
check("...and saying where it came from, because it may be a NAT egress",
      made and "callback" in (made.get("notes") or "").lower(),
      str(made.get("notes") if made else None))

st, sess = call("/api/c2/sessions?project=C2T&state=live", token=admin)
check("...and the shell is filed against it", st == 200 and any(
      x["host"] == "203.0.113.99" for x in sess), f"{st}")
check("...with the port it landed on, so it can be told from the others",
      all(x["listen_port"] == 443 for x in sess),
      str([x["listen_port"] for x in sess]))

# An address that cannot be a host is still refused, however it
# arrives. A callback from one is a Ghost talking to itself.
n_before = len(call("/api/targets?project=C2T&limit=300",
                    token=admin)[1].get("items", []))
asyncio.run(callback("0.0.0.0:40000"))
n_after = len(call("/api/targets?project=C2T&limit=300",
                   token=admin)[1].get("items", []))
check("a callback from an impossible address invents no target",
      n_after == n_before, f"{n_before} -> {n_after}")

print("\n== the row says where a payload should call back to ==")
# The two things an operator needs to write a payload, and which one
# they need depends on the target: an address always works, a name
# survives the address changing and is what a proxy will allow.


async def say(ip, name, note, can_bind):
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        a.outbound_ip = ip
        a.public_name = name
        a.public_name_note = note
        a.can_bind_privileged = can_bind
        await s.commit()


asyncio.run(say("203.0.113.40", "ghost-01.acme.example", None, True))
row = call("/api/c2/listeners?project=C2T", token=admin)[1][0]
check("the listener carries the ghost's public address",
      row["agent_ip"] == "203.0.113.40", row["agent_ip"])
check("...and what that address is called",
      row["agent_name_public"] == "ghost-01.acme.example",
      row["agent_name_public"])

# "No PTR" and "we could not ask" are different facts. A blank cell
# for both hides the one that means OUR lookup failed rather than
# that the address has no name.
asyncio.run(say("203.0.113.40", None,
                "could not reach 8.8.8.8:53: i/o timeout", True))
row = call("/api/c2/listeners?project=C2T", token=admin)[1][0]
check("a failed lookup carries its reason rather than reading as unnamed",
      row["agent_name_public"] is None
      and "8.8.8.8" in (row["agent_name_note"] or ""),
      str(row["agent_name_note"]))

# NULL is "the ghost has not said", which is not "it cannot".
# Warning about a ghost that is fine is how an operator learns to
# ignore the warning.
asyncio.run(say("203.0.113.40", None, None, None))
row = call("/api/c2/listeners?project=C2T", token=admin)[1][0]
check("a ghost that has not reported its capability is NULL, not false",
      row["agent_can_bind_privileged"] is None,
      str(row["agent_can_bind_privileged"]))
asyncio.run(say("203.0.113.40", None, None, False))
row = call("/api/c2/listeners?project=C2T", token=admin)[1][0]
check("...and one that says it cannot bind 443 says so plainly",
      row["agent_can_bind_privileged"] is False,
      str(row["agent_can_bind_privileged"]))

print("\n== output reaches the transcript without a second frame ==")
# The bug an operator saw as "I type `ls` and nothing comes back".
#
# Output was buffered and written only when the NEXT frame arrived
# more than FLUSH_AFTER later -- so the last chunk of every
# command's output was never written at all, because nothing else
# arrived to make the comparison. A few hundred bytes of `ls` sat in
# memory for ever. It only looked like it worked for a 256 KB dump,
# which crosses MAX_PENDING on its own.
#
# So: ONE data frame, nothing after it, and the bytes must land.
_out: list = []


async def _devnull(b):
    _out.append(b)


async def one_command_one_frame():
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        hub.register(a.id, _devnull)
        stream = callback.n
        callback.n += 1
        await shellwork.on_frame(s, a, proxytunnel.Frame(
            kind=proxytunnel.ARRIVED, stream=stream,
            payload=announcement("198.51.100.7:53000", "tcp", 443)))
        sid = (await s.execute(select(ShellSession.id)
                               .order_by(ShellSession.id.desc())
                               .limit(1))).scalar_one()
        # One frame of output, as `ls` produces. Nothing follows it.
        await shellwork.on_frame(s, a, proxytunnel.Frame(
            kind=proxytunnel.DATA, stream=stream,
            payload=b"bin  etc  home  usr\n"))
    # Longer than the debounce, and no further traffic.
    await asyncio.sleep(shellhub.FLUSH_IDLE * 3)
    async with SessionLocal() as s:
        rows = (await s.execute(
            select(ShellExchange.output).where(
                ShellExchange.session_id == sid))).scalars().all()
    return sid, [r for r in rows if r]


SID_OUT, outputs = asyncio.run(one_command_one_frame())
check("a single chunk of output is written without anything following it",
      any("bin  etc  home  usr" in (o or "") for o in outputs),
      f"transcript holds {outputs!r}")

print("\n== terminating a session kills the shell, not just the row ==")
# The row saying `closed` while our own shell keeps running on a
# client's machine is the wrong direction for the record to be
# wrong in. Terminating sends a CLOSE frame down the tunnel; the
# Ghost closes the socket, which is what ends `nc -e /bin/sh`.
#
# The HUB is tested in-process and the ROUTE over HTTP, because the
# hub is per-process state: a tunnel registered here is invisible to
# the server handling the request, so an HTTP test could only ever
# exercise the no-route path. Pretending otherwise would be a test
# that passes because of the harness rather than the code.
_sent: list = []


async def _record(b):
    _sent.append(b)


async def terminate_with_tunnel():
    """Register a tunnel, attach a session to it, terminate it."""
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        hub.register(a.id, _record)
        frame = proxytunnel.Frame(
            kind=proxytunnel.ARRIVED, stream=callback.n,
            payload=announcement("198.51.100.7:52000", "tcp", 443))
        callback.n += 1
        await shellwork.on_frame(s, a, frame)
        sid = (await s.execute(select(ShellSession.id)
                               .order_by(ShellSession.id.desc())
                               .limit(1))).scalar_one()
    _sent.clear()
    went = await hub.terminate(sid)
    return sid, went


SID, went = asyncio.run(terminate_with_tunnel())
check("terminating reports that it reached the host", went is True, str(went))
kinds = [proxytunnel.decode(b).kind for b in _sent]
check("...and a CLOSE frame actually went down the tunnel",
      proxytunnel.CLOSE in kinds, f"{len(_sent)} frame(s): {kinds}")
check("...and the session is detached, so nobody can still type at it",
      hub.holds(SID) is False)
check("terminating one with no route says so rather than raising",
      asyncio.run(hub.terminate(999999)) is False)

# The route, over HTTP. The server process holds no tunnel for this
# agent, which is exactly the no-route case -- and the answer must
# say the far end was not reached rather than fold it into success.
st, r = call(f"/api/c2/sessions/{SID}/close?project=C2T", "POST", {}, token=admin)
check("the route closes the row", st == 200 and r.get("state") == "closed",
      f"{st} {r}")
check("...and with no route does NOT claim the shell was killed",
      r.get("terminated") is False, str(r.get("terminated")))
check("...and says so plainly", "still alive" in (r.get("note") or ""),
      r.get("note"))

print("\n== a restart does not leave a session claiming to be open ==")
# `open` claims this process holds a tunnel to a live socket. At
# startup it holds none, so every open row is a claim nothing backs
# -- and the UI showed "it should come back on its own" for ever,
# which it does not: the Ghost closes those sockets when its tunnel
# drops.


async def open_one():
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        hub.register(a.id, _record)
        frame = proxytunnel.Frame(
            kind=proxytunnel.ARRIVED, stream=callback.n,
            payload=announcement("198.51.100.7:52001", "tcp", 443))
        callback.n += 1
        await shellwork.on_frame(s, a, frame)
        return (await s.execute(select(ShellSession.id)
                                .order_by(ShellSession.id.desc())
                                .limit(1))).scalar_one()


async def restart():
    """What startup does, against rows a dead process left behind."""
    async with SessionLocal() as s:
        return await shellwork.adopt_orphans(s)


async def state_of(sid):
    async with SessionLocal() as s:
        return (await s.get(ShellSession, sid)).state


SID3 = asyncio.run(open_one())
check("a fresh session is open", asyncio.run(state_of(SID3)) == "open",
      asyncio.run(state_of(SID3)))

n = asyncio.run(restart())
check("startup marks orphaned sessions", n >= 1, str(n))
check("...as LOST, not closed -- we know our route went, not that the "
      "shell died", asyncio.run(state_of(SID3)) == "lost",
      asyncio.run(state_of(SID3)))
check("...and a terminated one is left alone, not revived",
      asyncio.run(state_of(SID)) == "closed", asyncio.run(state_of(SID)))
check("a second startup finds nothing left to do",
      asyncio.run(restart()) == 0)

print("\n== a session says WHOSE address called back ==")
# The question a callback actually raises. A listener on 443 open
# to the world catches a payload and the internet both, and telling
# them apart by squinting at an octet is how a real shell gets
# dismissed as noise -- or noise gets written up as a shell. That
# happened: a session from a cloud provider in Belgium was read as
# the operator's own home connection.
st, sess = call("/api/c2/sessions?project=C2T&state=all", token=admin)
check("every session carries a peer_geo field, even when empty",
      st == 200 and all("peer_geo" in x for x in sess), f"{st}")

# Documentation addresses have no geolocation, and that is the
# ordinary case rather than an error: the field is null and the UI
# simply shows the address.
doc = [x for x in sess if (x["peer"] or "").startswith("198.51.100.")]
check("a documentation address geolocates to nothing, without erroring",
      doc and doc[0]["peer_geo"] is None,
      str(doc[0]["peer_geo"]) if doc else "no such session")

# The port must not reach the lookup, and an IPv6 peer is
# `[::1]:4444` -- so the split is on the LAST colon, unwrapped.
from app.routers.c2 import _peer_geo  # noqa: E402

check("a v4 peer strips its port before looking up",
      _peer_geo("203.0.113.9:40000") is None)   # no geo for TEST-NET-3
check("a v6 peer is unwrapped rather than split on its first colon",
      _peer_geo("[2001:db8::1]:4444") is None)
check("no peer is no lookup", _peer_geo(None) is None
      and _peer_geo("") is None)

print("\n== a scanner is told apart from a shell ==")
# A listener on 443 open to the internet catches both. On the first
# fleet to run one, four scanner sessions arrived within hours and
# were indistinguishable from the real one -- which is how a Google
# Cloud range in Belgium got read as the operator's home connection.
from app import shellprobe  # noqa: E402

st, why = shellprobe.classify(b"GET / HTTP/1.1\r\nHost: 20.0.0.1\r\n")
check("an HTTP request is a scanner, not a shell",
      st == shellprobe.SCANNER and "HTTP" in why, f"{st} {why}")
check("...and the reason quotes the request line so it can be checked",
      "GET / HTTP/1.1" in why, why)

st, _ = shellprobe.classify(bytes([0x16, 0x03, 0x01, 0x02, 0x00]) + b"\x01")
check("a TLS handshake is a scanner", st == shellprobe.SCANNER, st)
# A ClientHello carries plenty of ASCII -- the SNI for one -- so a
# printability test alone would read it as shell output. Checked
# structurally for that reason.
st, _ = shellprobe.classify(
    bytes([0x16, 0x03, 0x01, 0x00, 0x40]) + b"\x01\x00\x00<" + b"web.acme.example")
check("...even one whose SNI makes it look like text",
      st == shellprobe.SCANNER, st)

st, _ = shellprobe.classify(b"SSH-2.0-OpenSSH_9.6\r\n")
check("an SSH banner is a scanner", st == shellprobe.SCANNER, st)

st, _ = shellprobe.classify(b"web01.acme.example\n")
check("a hostname coming back is a SHELL", st == shellprobe.SHELL, st)
st, _ = shellprobe.classify(b"DESKTOP-4F2A1B\r\n")
check("...and so is a Windows one", st == shellprobe.SHELL, st)
st, _ = shellprobe.classify(b"sh: 1: hostname: not found\n")
check("...and so is a shell COMPLAINING, which is still a shell",
      st == shellprobe.SHELL, st)

check("nothing at all is undecided, not a verdict",
      shellprobe.classify(b"")[0] == shellprobe.PENDING)

print("\n== and the list hides scanners without deleting them ==")


async def judged(peer, state, note="x"):
    """A session already judged, as the probe would leave it."""
    async with SessionLocal() as s:
        a = await s.get(Agent, GID)
        hub.register(a.id, _devnull)
        stream = callback.n
        callback.n += 1
        await shellwork.on_frame(s, a, proxytunnel.Frame(
            kind=proxytunnel.ARRIVED, stream=stream,
            payload=announcement(peer, "tcp", 443)))
        row = (await s.execute(select(ShellSession)
                               .order_by(ShellSession.id.desc())
                               .limit(1))).scalar_one()
        row.probe, row.probe_note = state, note
        await s.commit()
        return row.id


SCAN_ID = asyncio.run(judged("203.0.113.200:40001", "scanner",
                             "sent an HTTP request"))
QUIET_ID = asyncio.run(judged("203.0.113.201:40002", "silent",
                              "nothing came back"))
REAL_ID = asyncio.run(judged("203.0.113.202:40003", "shell",
                             "answered with text"))

shown = {x["id"] for x in
         call("/api/c2/sessions?project=C2T&state=live", token=admin)[1]}
check("a scanner is hidden by default", SCAN_ID not in shown)
check("a shell is shown", REAL_ID in shown)
# The one that matters. Nothing answered, which is not the same as
# something answering wrongly: a real shell can be slow, speak its
# own protocol, or never have got the probe.
check("a SILENT session is still shown -- absence of evidence is not "
      "evidence", QUIET_ID in shown)

shown_all = {x["id"] for x in
           call("/api/c2/sessions?project=C2T&state=live&scans=true",
                token=admin)[1]}
check("...and the scanner is still there when asked for",
      SCAN_ID in shown_all)
row = next(x for x in
           call("/api/c2/sessions?project=C2T&state=live&scans=true",
                token=admin)[1] if x["id"] == SCAN_ID)
check("...carrying the reason it was judged one",
      row["probe"] == "scanner" and row["probe_note"], str(row))

print("\n== moving a session to the host it is really on ==")
# A callback arrives from an ADDRESS, and the address is as often a
# NAT egress as the box that was popped. The operator is the one
# who knows which -- usually because the shell just told them.
sid = asyncio.run(callback("203.0.113.50:41000"))
sess = call("/api/c2/sessions?project=C2T&state=live", token=admin)[1]
moving = next(x for x in sess if x["peer"] == "203.0.113.50:41000")

# A host the project does not have is REFUSED, not created. A typo
# would otherwise make a second target one character from the real
# one, send the session to it, and split the evidence for one
# machine across two rows.
st, r = call(f"/api/c2/sessions/{moving['id']}/target?project=C2T", "POST",
             {"host": "typo-dc01.acme.example"}, token=admin)
check("a host the engagement does not know is refused", st == 404, f"{st} {r}")
check("...and says where to add it instead",
      "Targets page" in str(r), str(r))

# In scope first: the inventory refuses a host the engagement is
# not authorised against, which is the gate doing its job.
call("/api/projects/C2T/scope", "POST",
     {"lines": ["dc01.acme.example"]}, token=admin)
_st, _mk = call("/api/targets?project=C2T", "POST",
                {"host": "dc01.acme.example"}, token=admin)
check("the host exists before the session is moved to it",
      _st in (200, 201), f"{_st} {_mk}")
st, r = call(f"/api/c2/sessions/{moving['id']}/target?project=C2T", "POST",
             {"host": "dc01.acme.example"}, token=admin)
check("a session can be moved to a host the engagement has",
      st == 200 and r.get("host") == "dc01.acme.example", f"{st} {r}")

sess = call("/api/c2/sessions?project=C2T&state=live", token=admin)[1]
moved = next(x for x in sess if x["id"] == moving["id"])
check("...and the session now reads against that host",
      moved["host"] == "dc01.acme.example", str(moved["host"]))

# The compromise follows the shell. Moving it means THAT host is
# the one with a shell on it.
st, rows = call("/api/targets?project=C2T&hacked=true&limit=50", token=admin)
check("...and the host it moved to is marked compromised",
      any(x["host"] == "dc01.acme.example" for x in rows.get("items", [])),
      str([x["host"] for x in rows.get("items", [])][:5]))
st, tl = call("/api/targets/C2T/dc01.acme.example/timeline", token=admin)
check("...with a timeline entry saying why",
      any("moved here" in (e.get("summary") or "")
          for e in (tl or {}).get("items", [])),
      str([e.get("summary") for e in (tl or {}).get("items", [])][:3]))

# Moving twice is idempotent rather than an error on the unique key.
st, r = call(f"/api/c2/sessions/{moving['id']}/target?project=C2T", "POST",
             {"host": "dc01.acme.example"}, token=admin)
check("moving to where it already is is not an error", st == 200, f"{st} {r}")

# `hosts` decides what can be a target, here as everywhere.
for bad, why in (("0.0.0.0", "an impossible address"),
                 # NOT `localhost`: the harness sets
                 # ODDJOB_ALLOW_LOOPBACK_TARGETS, so it is a legitimate
                 # target here. `.invalid` is refused unconditionally.
                 ("nope.invalid", "a reserved name"),
                 ("*.acme.example", "a pattern, not a host"),
                 ("", "nothing at all")):
    st, r = call(f"/api/c2/sessions/{moving['id']}/target?project=C2T",
                 "POST", {"host": bad}, token=admin)
    check(f"{why} is refused as a target", st == 422, f"{bad!r} -> {st}")

st, r = call(f"/api/c2/sessions/{moving['id']}/target?project=OTHER", "POST",
             {"host": "dc01.acme.example"}, token=admin)
check("a session in another engagement cannot be moved", st == 404, st)

print("\n== live and ended are separate views ==")
# Three tabs: what can be typed at now, what is kept for the
# record, and the listeners. The first question on opening the
# page is almost always the first one.
live_ids = {x["id"] for x in
            call("/api/c2/sessions?project=C2T&state=live&scans=true",
                 token=admin)[1]}
ended_ids = {x["id"] for x in
             call("/api/c2/sessions?project=C2T&state=ended&scans=true",
                  token=admin)[1]}
all_ids = {x["id"] for x in
           call("/api/c2/sessions?project=C2T&state=all&scans=true",
                token=admin)[1]}
check("live and ended do not overlap", not (live_ids & ended_ids),
      str(sorted(live_ids & ended_ids)[:5]))
check("...and together they are everything",
      live_ids | ended_ids == all_ids,
      f"{len(live_ids)}+{len(ended_ids)} vs {len(all_ids)}")
check("every live session is open",
      all(x["state"] == "open" for x in
          call("/api/c2/sessions?project=C2T&state=live&scans=true",
               token=admin)[1]))
# `closed` and `lost` are different facts and both answer "not
# live" -- the row says which, and the tab does not split on it.
ended = call("/api/c2/sessions?project=C2T&state=ended&scans=true",
             token=admin)[1]
check("ended holds closed AND lost",
      {x["state"] for x in ended} <= {"closed", "lost"}
      and len({x["state"] for x in ended}) >= 1,
      str({x["state"] for x in ended}))
st, r = call("/api/c2/sessions?project=C2T&state=sideways", token=admin)
check("a state nobody defined is refused rather than guessed at",
      st == 422, st)

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
st, sess = call("/api/c2/sessions?project=C2T&state=all", token=admin)
check("...and the shells it caught are still there",
      sum(1 for x in sess if x["listen_port"] == 443) >= 3,
      str(len(sess)))

print(f"\n{'=' * 56}\n  {ok} passed, {fail} failed\n{'=' * 56}")
raise SystemExit(1 if fail else 0)
