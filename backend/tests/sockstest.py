"""The SOCKS5 proxy: what it parses, and what it refuses.

Mostly about refusals. The protocol half is small; the half worth
testing is that this cannot become an open proxy into a client's
network by accident.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
import os as _os
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import struct  # noqa: E402

from app import socks  # noqa: E402
from app.proxyauth import GRANT_PREFIX, new_grant  # noqa: E402

ok = fail = 0


def check(label, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  PASS  {label} {extra}")
    else:
        fail += 1
        print(f"  FAIL  {label} {extra}")


print("== the method negotiation ==")
g = socks.parse_greeting(bytes((5, 1, socks.USERPASS)))
check("a client offering user/pass is accepted",
      socks.choose_method(g) == bytes((5, socks.USERPASS)))

# The one that matters. Every browser offers NO_AUTH and would use it
# happily; accepting it makes an open proxy of this port, which on an
# engagement is somebody else's foothold rather than ours.
g = socks.parse_greeting(bytes((5, 1, socks.NO_AUTH)))
check("a client offering ONLY no-auth is refused",
      socks.choose_method(g) == bytes((5, socks.NO_ACCEPTABLE)),
      socks.choose_method(g).hex())
g = socks.parse_greeting(bytes((5, 2, socks.NO_AUTH, socks.USERPASS)))
check("...and offering both does not let no-auth win",
      socks.choose_method(g) == bytes((5, socks.USERPASS)))

print("\n== it is SOCKS5 or it is nothing ==")
for label, raw in [("SOCKS4, which has no authentication at all",
                    bytes((4, 1, 0, 80))),
                   ("an empty greeting", b""),
                   ("a greeting offering no methods", bytes((5, 0))),
                   ("a truncated greeting", bytes((5, 3, 0)))]:
    try:
        socks.parse_greeting(raw)
        check(label + " is refused", False, "parsed when it should not")
    except socks.ProtocolError:
        check(label + " is refused", True)

print("\n== the connect request ==")
req = socks.parse_request(bytes((5, 1, 0, socks.ATYP_IPV4))
                          + bytes((10, 0, 0, 7)) + struct.pack("!H", 443))
check("an ipv4 destination parses", (req.host, req.port) == ("10.0.0.7", 443),
      (req.host, req.port))
check("...and is marked as a literal address", req.is_address is True)

name = b"shop.acme.example"
req = socks.parse_request(bytes((5, 1, 0, socks.ATYP_DOMAIN, len(name)))
                          + name + struct.pack("!H", 8443))
check("a hostname parses", (req.host, req.port) == ("shop.acme.example", 8443),
      (req.host, req.port))
# The Ghost is somewhere else, and split-horizon DNS inside an estate
# is the normal case. Resolving here would pick the destination from
# Oddjob's view of the world and gate a different host than the one
# the operator asked for.
check("...and is NOT resolved to an address on this side",
      req.is_address is False and not req.host.replace(".", "").isdigit())
check("...and is lowercased, so one name is not two",
      socks.parse_request(bytes((5, 1, 0, socks.ATYP_DOMAIN, 4))
                          + b"ACME" + struct.pack("!H", 80)).host == "acme")

print("\n== commands that would open a second inbound surface ==")
connect = socks.Request(socks.CONNECT, "h", 80, False)
check("CONNECT proceeds", socks.reply_for(connect) is None)
for cmd, label in ((socks.BIND, "BIND"),
                   (socks.UDP_ASSOCIATE, "UDP ASSOCIATE"),
                   (0x09, "an unknown command")):
    r = socks.reply_for(socks.Request(cmd, "h", 80, False))
    check(f"{label} is refused", r == socks.CMD_NOT_SUPPORTED, r)

print("\n== the credential ==")
user, raw, hashed = new_grant()
check("the username is prefixed, so a leak is recognisable",
      user.startswith(GRANT_PREFIX), user)
check("...and is not something a person chose",
      len(user) > len(GRANT_PREFIX) + 8, user)
check("the password is not stored in the clear", raw not in hashed)
u2, r2, _ = new_grant()
check("two grants do not collide", user != u2 and raw != r2)

creds = socks.parse_userpass(bytes((1, 4)) + b"user" + bytes((3,)) + b"pwd")
check("user/pass parses", (creds.username, creds.password) == ("user", "pwd"),
      creds.username)
for label, raw_bytes in [("a truncated auth message", bytes((1, 9)) + b"ab"),
                         ("an unknown auth version", bytes((9, 1)) + b"ab"),
                         ("an empty auth message", b"")]:
    try:
        socks.parse_userpass(raw_bytes)
        check(label + " is refused", False, "parsed when it should not")
    except socks.ProtocolError:
        check(label + " is refused", True)

print("\n== replies ==")
check("a refusal carries the code", socks.reply(socks.NOT_ALLOWED)[1]
      == socks.NOT_ALLOWED)
check("...and a well-formed address, not a lie about our network",
      socks.reply(socks.NOT_ALLOWED)[3] == socks.ATYP_IPV4)
check("auth success is zero", socks.auth_reply(True) == bytes((1, 0)))
check("auth failure is not", socks.auth_reply(False) != bytes((1, 0)))


# ====================================================== tunnel frames
from app import proxytunnel as tun  # noqa: E402

print("\n== the frame codec, against the vectors the Go half uses ==")
# These same rows are in ghost/internal/socksrelay/frame_test.go. Two
# languages implementing one codec from a paragraph of prose is how a
# tunnel hangs in production; this is the cheapest place to find out.
for label, kind, stream, payload, want in tun.VECTORS:
    got = tun.encode(kind, stream, payload).hex()
    check(f"encode: {label}", got == want, got if got != want else "")
    f = tun.decode(bytes.fromhex(want))
    check(f"decode: {label}",
          (f.kind, f.stream, f.payload) == (kind, stream, payload),
          (f.kind, f.stream, f.payload))

print("\n== losing framing drops the tunnel, so junk must raise ==")
for label, raw_bytes in [("an empty frame", b""),
                         ("one shorter than its header", bytes((tun.DATA, 0, 0, 0))),
                         ("an unknown type", bytes((0x7F, 0, 0, 0, 1)))]:
    try:
        tun.decode(raw_bytes)
        check(label + " is refused", False, "decoded when it should not")
    except tun.FrameError:
        check(label + " is refused", True)

for label, kind in [("an unknown type", 0x7F)]:
    try:
        tun.encode(kind, 1, b"")
        check("encoding " + label + " is refused", False)
    except tun.FrameError:
        check("encoding " + label + " is refused", True)

print("\n== OPEN carries a name, not an address ==")
f = tun.decode(tun.encode_open(7, "shop.acme.example", 8443))
host, port = tun.decode_open(f)
check("an OPEN round-trips", (host, port) == ("shop.acme.example", 8443),
      (host, port))
# The ghost resolves it, where the estate is. Resolving on this side
# would pick the destination from Oddjob's view of DNS.
check("...and the host is still a name", not host[0].isdigit(), host)
for bad in (0, -1, 65536):
    try:
        tun.encode_open(1, "h", bad)
        check(f"port {bad} is refused", False)
    except tun.FrameError:
        check(f"port {bad} is refused", True)
try:
    tun.decode_open(tun.decode(tun.encode(tun.DATA, 1, b"x")))
    check("a DATA frame is not read as an OPEN", False)
except tun.FrameError:
    check("a DATA frame is not read as an OPEN", True)

# The boundary that catches a signed/unsigned mistake across the two
# languages: Python's struct "!I" and Go's uint32 must agree once a
# long-lived tunnel's counter climbs past 2^31.
big = tun.decode(tun.encode(tun.DATA, 0xFFFFFFFF, b"x"))
check("a stream id with the top bit set survives the round trip",
      big.stream == 0xFFFFFFFF, big.stream)



# ========================================================= the hub
# One Ghost's tunnel, many streams over it. Routing and lifecycle,
# which is where a multiplexer goes wrong: a frame landing in the
# wrong stream reads as corruption, not as a routing bug.
import asyncio  # noqa: E402

from app import proxyhub  # noqa: E402
from app.proxytunnel import (  # noqa: E402
    CLOSE,
    DATA,
    FAILED,
    OPENED,
    decode,
    encode,
)


def run(coro):
    return asyncio.run(coro)


class Sink:
    """Collects what the hub would have sent down the websocket."""

    def __init__(self):
        self.sent = []

    async def __call__(self, raw):
        self.sent.append(decode(raw))

    def kinds(self):
        return [f.kind for f in self.sent]


print("\n== a dial that the ghost confirms ==")


async def _opens():
    sink = Sink()
    t = proxyhub.Tunnel(1, sink)
    task = asyncio.create_task(t.open("acme.example", 443, timeout=2))
    await asyncio.sleep(0)
    opened = [f for f in sink.sent if f.kind == 0x01]
    if opened:
        t.on_frame(decode(encode(OPENED, opened[0].stream, b"")))
    return await task, sink


(stream, why), sink = run(_opens())
check("an OPEN goes down the tunnel", 0x01 in sink.kinds(), sink.kinds())
check("...and a confirmed dial yields a stream", stream is not None, why)
check("...with no reason, because nothing went wrong", why == "", why)

print("\n== a dial the ghost refuses ==")


async def _fails():
    sink = Sink()
    t = proxyhub.Tunnel(1, sink)
    task = asyncio.create_task(t.open("nope.invalid", 80, timeout=2))
    await asyncio.sleep(0)
    sid = [f for f in sink.sent if f.kind == 0x01][0].stream
    t.on_frame(decode(encode(FAILED, sid, b"no such host")))
    return await task, t


(stream, why), t = run(_fails())
# A SOCKS client told OK and then finding nothing there is worse
# than one told no.
check("a refused dial yields NO stream", stream is None)
check("...and carries the ghost's reason, which SOCKS cannot express",
      "no such host" in why, why)
check("...and leaves nothing behind", t.live == 0, t.live)

print("\n== a ghost that never answers ==")


async def _times_out():
    t = proxyhub.Tunnel(1, Sink())
    return await t.open("slow.example", 80, timeout=0.05)


stream, why = run(_times_out())
check("a dial with no answer times out", stream is None)
# Said as a timeout, not a refusal: the ghost never answering is a
# different problem from the target refusing, and sends an operator
# somewhere else.
check("...and says the GHOST did not answer, not that the target refused",
      "ghost did not answer" in why, why)

print("\n== streams do not collide ==")


async def _two():
    sink = Sink()
    t = proxyhub.Tunnel(1, sink)
    a = asyncio.create_task(t.open("a.example", 80, timeout=2))
    await asyncio.sleep(0)
    b = asyncio.create_task(t.open("b.example", 80, timeout=2))
    await asyncio.sleep(0)
    ids = [f.stream for f in sink.sent if f.kind == 0x01]
    for sid in ids:
        t.on_frame(decode(encode(OPENED, sid, b"")))
    (sa, _), (sb, _) = await a, await b
    # Push distinct bytes at each and check each reader sees its own.
    t.on_frame(decode(encode(DATA, sa.id, b"for-a")))
    t.on_frame(decode(encode(DATA, sb.id, b"for-b")))
    return ids, await sa.recv(), await sb.recv()


ids, got_a, got_b = run(_two())
check("two streams get different ids", len(set(ids)) == 2, ids)
check("...and each reader sees only its own bytes",
      (got_a, got_b) == (b"for-a", b"for-b"), (got_a, got_b))

print("\n== ids are not reused ==")


async def _no_reuse():
    sink = Sink()
    t = proxyhub.Tunnel(1, sink)
    seen = []
    for _ in range(3):
        task = asyncio.create_task(t.open("x.example", 80, timeout=2))
        await asyncio.sleep(0)
        sid = [f.stream for f in sink.sent if f.kind == 0x01][-1]
        seen.append(sid)
        t.on_frame(decode(encode(OPENED, sid, b"")))
        s, _ = await task
        await s.close()
    return seen


seen = run(_no_reuse())
# A late frame for a dead stream landing in a live one is the
# failure this avoids.
check("a closed stream's id is not handed out again",
      len(set(seen)) == 3, seen)

print("\n== frames for a stream that has gone ==")


async def _orphan():
    t = proxyhub.Tunnel(1, Sink())
    # Normal on a multiplexed tunnel: both ends can close at once.
    t.on_frame(decode(encode(DATA, 999, b"late")))
    t.on_frame(decode(encode(CLOSE, 999, b"")))
    return True


check("late frames for a dead stream are dropped, not fatal", run(_orphan()))

print("\n== the tunnel ending ==")


async def _shutdown():
    sink = Sink()
    t = proxyhub.Tunnel(1, sink)
    task = asyncio.create_task(t.open("a.example", 80, timeout=2))
    await asyncio.sleep(0)
    sid = [f.stream for f in sink.sent if f.kind == 0x01][0]
    t.on_frame(decode(encode(OPENED, sid, b"")))
    s, _ = await task
    t.shutdown()
    # A reader blocked on a dead tunnel must be woken, or the SOCKS
    # connection hangs until the client gives up.
    return t.live, await asyncio.wait_for(s.recv(), 1)


live, after = run(_shutdown())
check("shutdown finishes every stream", live == 0, live)
check("...and wakes a reader with end-of-stream rather than hanging",
      after is None, after)

print("\n== the hub ==")


async def _hub():
    h = proxyhub.Hub()
    t1 = h.register(5, Sink())
    check("a registered tunnel is findable", h.get(5) is t1)
    # A ghost that reconnects after a drop has a tunnel the server
    # still believes in. Refusing the new one would leave it unable
    # to proxy until something noticed the old was dead.
    t2 = h.register(5, Sink())
    check("reconnecting replaces the old tunnel", h.get(5) is t2)
    check("...and the old one is shut down", t1._gone is True)
    # The guard: a late close from the OLD tunnel must not evict the
    # new one.
    h.drop(5, t1)
    check("a late close from the old tunnel does not evict the new",
          h.get(5) is t2)
    h.drop(5, t2)
    check("...while the current one does detach", h.get(5) is None)
    return True


run(_hub())



print("\n== the two sides agree on the tunnel path ==")
# The Ed25519 signature covers the PATH. If these two strings drift
# apart, every tunnel is a 401 and nothing says why -- the agent
# signs one string and the server verifies another. Cheap to assert,
# miserable to debug.
import re as _re  # noqa: E402

from app.routers.agents import TUNNEL_PATH  # noqa: E402

_ws_go = (_pathlib.Path(__file__).resolve().parents[2]
          / "ghost" / "internal" / "socksrelay" / "ws.go")
check("the agent's ws.go is where this expects", _ws_go.is_file(), str(_ws_go))
if _ws_go.is_file():
    _m = _re.search(r'TunnelPath\s*=\s*"([^"]+)"', _ws_go.read_text())
    check("the agent declares a tunnel path", _m is not None)
    if _m:
        check("...and it is the one the server serves",
              _m.group(1) == TUNNEL_PATH, (_m.group(1), TUNNEL_PATH))



# ============================================ the listener, for real
# A real socket, a real SOCKS5 handshake. The point is the refusals:
# everything below is what stops this being an open proxy, and a
# parser test does not prove the listener wires it up.
import socket as _socket  # noqa: E402

from app import proxyserver  # noqa: E402


async def _listen():
    srv = await proxyserver.serve("127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    return srv, port


def talk(port, payload, expect=2):
    """Send bytes, read a reply, close."""
    s = _socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(payload)
        return s.recv(expect)
    finally:
        s.close()


async def _no_auth_is_refused():
    srv, port = await _listen()
    try:
        return await asyncio.get_running_loop().run_in_executor(
            None, talk, port, bytes((5, 1, socks.NO_AUTH)))
    finally:
        srv.close()
        await srv.wait_closed()


print("\n== the listener refuses an unauthenticated client ==")
reply = run(_no_auth_is_refused())
# The whole feature turns on this byte. A browser offering only
# no-auth must be told 0xFF, or this port is an open proxy into
# whatever the ghost can reach.
check("a client offering only no-auth gets 0xFF",
      reply == bytes((5, socks.NO_ACCEPTABLE)), reply.hex() if reply else None)


async def _userpass_is_offered():
    srv, port = await _listen()
    try:
        return await asyncio.get_running_loop().run_in_executor(
            None, talk, port, bytes((5, 2, socks.NO_AUTH, socks.USERPASS)))
    finally:
        srv.close()
        await srv.wait_closed()


reply = run(_userpass_is_offered())
check("...and one offering both is steered to user/pass",
      reply == bytes((5, socks.USERPASS)), reply.hex() if reply else None)


async def _bad_credentials_are_refused():
    srv, port = await _listen()
    try:
        def go():
            s = _socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                s.sendall(bytes((5, 1, socks.USERPASS)))
                if s.recv(2) != bytes((5, socks.USERPASS)):
                    return None
                u, p = b"oddsocks_nope", b"wrong"
                s.sendall(bytes((1, len(u))) + u + bytes((len(p),)) + p)
                # A CONNECT the gate never gets to rule on, because
                # the credential is checked first.
                host = b"acme.example"
                s.sendall(bytes((5, 1, 0, socks.ATYP_DOMAIN, len(host)))
                          + host + b"\x01\xbb")
                return s.recv(10)
            finally:
                s.close()
        return await asyncio.get_running_loop().run_in_executor(None, go)
    finally:
        srv.close()
        await srv.wait_closed()


print("\n== a credential that does not resolve ==")
reply = run(_bad_credentials_are_refused())
check("an unknown credential is refused", reply is not None and len(reply) >= 2,
      reply.hex() if reply else None)
if reply and len(reply) >= 2:
    check("...with NOT_ALLOWED, not a connection",
          reply[1] == socks.NOT_ALLOWED, reply[1])


async def _socks4_is_refused():
    srv, port = await _listen()
    try:
        def go():
            s = _socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                # SOCKS4 CONNECT. It has no authentication at all, so
                # answering it would be answering an unauthenticated
                # protocol.
                s.sendall(bytes((4, 1, 0x01, 0xBB, 127, 0, 0, 1)) + b"x\x00")
                s.settimeout(3)
                try:
                    return s.recv(8)
                except (TimeoutError, OSError):
                    return b""
            finally:
                s.close()
        return await asyncio.get_running_loop().run_in_executor(None, go)
    finally:
        srv.close()
        await srv.wait_closed()


print("\n== SOCKS4 gets nothing ==")
reply = run(_socks4_is_refused())
# Either the connection is dropped or nothing useful comes back.
# What must NOT happen is a SOCKS4 success reply (0x00 0x5A).
check("a SOCKS4 client is not answered with success",
      not (reply and len(reply) >= 2 and reply[1] == 0x5A),
      reply.hex() if reply else "(closed)")


# ================================================ CONNECT over TLS
# The second way in, and the reason it exists: SOCKS5 carries its
# credential in plaintext (RFC 1929), so it is only safe down a
# tunnel somebody already authenticated. CONNECT inside TLS is what
# lets a browser be pointed straight at the host.
#
# Everything after the credential check is the SOCKS path unchanged
# -- same grants, same scopegate, same tunnel, same audit row --
# because two ways in that authorise differently is one way in
# nobody has checked.
import base64 as _b64  # noqa: E402

from app import connect as _cx  # noqa: E402

print("\n== what a CONNECT request says ==")


def _head(line, *headers):
    return line + "\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n"


_r = _cx.parse_request(_head(
    "CONNECT internal.acme.example:443 HTTP/1.1",
    "Proxy-Authorization: Basic " + _b64.b64encode(b"u1:p1").decode(),
    "User-Agent: Firefox/140.0"))
check("the destination is read", (_r.host, _r.port) ==
      ("internal.acme.example", 443), (_r.host, _r.port))
check("...and the credential with it", (_r.username, _r.password) ==
      ("u1", "p1"), (_r.username, _r.password))
check("...and it counts as authenticated", _r.authenticated)

# A browser's FIRST request carries no credential -- it waits to be
# asked. That is not a failed login and must not be recorded as one.
_r2 = _cx.parse_request(_head("CONNECT a.acme.example:8443 HTTP/1.1"))
check("no Proxy-Authorization is 'not yet', not 'wrong'",
      _r2.username is None and not _r2.authenticated, _r2)

# An IPv6 literal is the one host form that contains colons.
_r3 = _cx.parse_request(_head("CONNECT [2001:db8::1]:443 HTTP/1.1"))
check("an IPv6 literal keeps its address and loses its brackets",
      (_r3.host, _r3.port) == ("2001:db8::1", 443), (_r3.host, _r3.port))

print("\n== and what it refuses ==")
for _bad, _why in [
    ("GET / HTTP/1.1", "a browser not configured as a proxy"),
    ("CONNECT acme.example HTTP/1.1", "no port"),
    ("CONNECT acme.example:0 HTTP/1.1", "port zero"),
    ("CONNECT acme.example:99999 HTTP/1.1", "port out of range"),
    ("CONNECT http://acme.example/x:443 HTTP/1.1", "a URL, not a host"),
    ("CONNECT a@b:443 HTTP/1.1", "userinfo, which moves the destination"),
    ("CONNECT acme.example:443 HTTP/2", "not a version we speak"),
]:
    try:
        _cx.parse_request(_head(_bad))
        check(f"refused: {_why}", False, f"accepted {_bad!r}")
    except _cx.ProtocolError:
        check(f"refused: {_why}", True)

# The common mistake deserves a readable answer, not "bad request".
try:
    _cx.parse_request(_head("GET / HTTP/1.1"))
except _cx.ProtocolError as e:
    check("...and a plain GET is told what this port is",
          "proxy, not a web server" in str(e), str(e))

print("\n== a credential that cannot be decoded is not a login attempt ==")
# Same 407 either way: a browser with a stale cached credential
# should be re-prompted, not refused outright.
for _hdr in ("Basic !!!not-base64!!!", "Basic " + _b64.b64encode(b"nocolon").decode(),
             "Bearer abc", "Basic"):
    _rr = _cx.parse_request(_head("CONNECT a.acme.example:443 HTTP/1.1",
                                  "Proxy-Authorization: " + _hdr))
    check(f"undecodable {_hdr.split()[0]!r} reads as absent",
          _rr.username is None, _rr.username)

print("\n== the replies ==")
check("the challenge asks for Basic, with a realm",
      b"407" in _cx.challenge() and b'Basic realm=' in _cx.challenge())
check("...and names what the credential is for",
      b"Oddjob ghost proxy" in _cx.challenge())
check("success is exactly the tunnel-opening line",
      _cx.ok() == b"HTTP/1.1 200 Connection Established\r\n\r\n",
      _cx.ok())
# A proxy that answers every refusal identically teaches its user
# nothing, and these are all things they can fix.
check("a refusal carries its reason",
      b"not in scope" in _cx.refused("host is not in scope"))

print("\n== one port, two protocols, no ambiguity ==")
# This is the whole mechanism: a SOCKS5 greeting opens 0x05 and a
# TLS ClientHello opens 0x16, so the first byte decides and nothing
# has to guess.
from app import proxyserver as _ps  # noqa: E402

check("SOCKS5 and TLS cannot be confused by their first byte",
      _ps.SOCKS5 != _ps.TLS_HELLO and (_ps.SOCKS5, _ps.TLS_HELLO) == (5, 0x16),
      (_ps.SOCKS5, _ps.TLS_HELLO))
# Three things arrive here and none of their first bytes overlap:
# 0x05 SOCKS5, 0x16 TLS, and an uppercase ASCII letter for a plain
# HTTP verb -- which is what arrives when nginx has already taken
# the TLS off, the arrangement worth preferring.
check("...and neither can be an HTTP verb",
      not (0x41 <= _ps.SOCKS5 <= 0x5A) and not (0x41 <= _ps.TLS_HELLO <= 0x5A))
check("'C' for CONNECT is in the HTTP range the demux routes",
      0x41 <= ord("C") <= 0x5A)


async def _pushback_roundtrip():
    """The peeked byte must still be there for the handler behind."""
    r = asyncio.StreamReader()
    r.feed_data(b"\x05\x01\x02rest-of-it")
    r.feed_eof()
    first = await r.read(1)
    pb = _ps._Pushback(r, first)
    return await pb.readexactly(3), await pb.read(-1)


_three, _rest = run(_pushback_roundtrip())
check("the byte the demux consumed is given back",
      _three == b"\x05\x01\x02", _three)
check("...and the rest of the stream follows it unchanged",
      _rest == b"rest-of-it", _rest)

# Every attribute the CONNECT handler reads off a Decision has to
# exist on it. Writing `reason_code` instead of `outcome` typechecks
# nowhere and would raise on the refusal path only -- which is
# exactly how `Ruling.why` reached production here.
import inspect as _inspect  # noqa: E402
import re as _re  # noqa: E402

from app import proxyauth as _pa  # noqa: E402
from app import proxyhttps as _ph  # noqa: E402

_used = set(_re.findall(r"\bd\.([a-z_]+)", _inspect.getsource(_ph)))
check("the CONNECT handler reads only fields Decision has",
      not (_used - set(_pa.Decision.__dataclass_fields__)),
      sorted(_used - set(_pa.Decision.__dataclass_fields__)))


print("\n== the TLS listener does a real handshake ==")
# Written because the first version of this did NOT work and shipped
# anyway: the demux consumed a byte to classify the connection, and
# `loop.start_tls()` then had a ClientHello missing its first byte.
# Feeding it back through `data_received` put it in the
# StreamReader's buffer, which is not where the TLS state machine
# reads from, so the handshake hung for ever -- `openssl s_client`
# printing "Connecting to 127.0.0.1" and nothing more.
#
# There was no test because there was no certificate to hand. So:
# generate one.
import datetime as _dt  # noqa: E402
import ssl as _ssl  # noqa: E402
import tempfile as _tf  # noqa: E402

_have_crypto = True
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    _have_crypto = False


def _selfsigned(dirname):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = _dt.datetime.now(_dt.UTC)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cp = _os.path.join(dirname, "c.pem")
    kp = _os.path.join(dirname, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    return cp, kp


async def _tls_connect_probe(certfile, keyfile):
    """Full handshake, then a CONNECT inside it."""
    from app import proxyhttps
    ctx = proxyhttps.context(certfile, keyfile)
    srv = await _ps.serve_tls("127.0.0.1", 0, ctx)
    port = srv.sockets[0].getsockname()[1]

    def go():
        c = _ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = _ssl.CERT_NONE
        raw = _socket.create_connection(("127.0.0.1", port), timeout=10)
        with c.wrap_socket(raw, server_hostname="localhost") as tls:
            proto = tls.version()
            tls.sendall(b"CONNECT a.acme.example:443 HTTP/1.1\r\n"
                        b"Host: a.acme.example:443\r\n\r\n")
            return proto, tls.recv(200)

    try:
        return await asyncio.get_running_loop().run_in_executor(None, go)
    finally:
        srv.close()
        await srv.wait_closed()


if _have_crypto:
    with _tf.TemporaryDirectory() as _d:
        _cp, _kp = _selfsigned(_d)
        _proto, _reply = run(_tls_connect_probe(_cp, _kp))
    check("the TLS handshake completes", bool(_proto), _proto)
    # The floor the listener sets, because a proxy credential crosses
    # this and the whole reason it exists is that SOCKS has none.
    check("...at TLS 1.2 or better", _proto in ("TLSv1.2", "TLSv1.3"), _proto)
    check("CONNECT inside it is answered, not hung",
          _reply.startswith(b"HTTP/1.1 407"), _reply[:60])
    check("...with the credential challenge, so a browser can prompt",
          b"Proxy-Authenticate: Basic" in _reply, _reply[:120])
else:
    check("skipped: no `cryptography` to mint a test certificate", True,
          "(it is a dependency of the app, so this should not happen)")


print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
