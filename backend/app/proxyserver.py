"""The SOCKS5 listener, and the only place bytes actually move.

Everything under this is a decision or a codec with tests:
`socks.py` parses and refuses, `proxyauth.py` authorises and gates,
`proxytunnel.py` frames, `proxyhub.py` routes. This is the asyncio
that joins them, and it is deliberately the thinnest file of the set
-- the logic worth arguing about does not live here.

# Where it binds, and why not everywhere

`127.0.0.1` by default, which is useless from another machine and is
the right default anyway. Making this reachable is a separate,
deliberate setting, because a SOCKS5 proxy into a client's estate
listening on 0.0.0.0 the moment somebody upgrades is not a thing to
arrive by accident.

Port 8443 and not 443. A browser pointed at a SOCKS proxy speaks RAW
SOCKS5 -- first byte 0x05, no TLS, no SNI -- and nginx routes 443 by
SNI with `ssl_preread`, which only classifies TLS handshakes. There
is nothing for it to match on, so sharing the port would need a
first-byte demuxer nginx does not have.

# Three things arrive on this port, and the first byte names them

    0x05            a SOCKS5 greeting        -> handle()
    0x16            a TLS ClientHello        -> TLS, then CONNECT
    'A'-'Z'         a plain HTTP verb        -> CONNECT

The third is the one to prefer in a deployment, and it is why TLS
here is optional rather than required: **let nginx terminate it.**
It already holds a certificate for this host and already renews it,
`--with-stream_ssl_module` lets it listen on 8443 and hand the
decrypted stream here, and a certificate this process never sees is
a certificate this process cannot mishandle. See
deploy/nginx/oddjob-connect.conf.

Terminating TLS in-process is kept for the deployment that has no
nginx, and because a self-signed certificate is a reasonable thing
to want -- but note that a browser offers no click-through for a
PROXY certificate the way it does for a page, so a self-signed one
has to be imported into every browser's trust store first.

# The order of the handshake is the order of the checks

Method negotiation, then credentials, then the CONNECT. The
credential is checked before the destination is even read, so a
caller with no grant never learns whether a host is in scope -- the
refusal says nothing it did not already know.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl

from . import proxyauth, socks
from .db import SessionLocal
from .proxyhub import Stream, hub

log = logging.getLogger("oddjob.proxy")

#: How long a client may dawdle over the handshake. A socket that
#: opens and says nothing is either a scanner or a mistake, and
#: either way it should not hold a slot.
HANDSHAKE_TIMEOUT = 15.0

#: One read from the client. Matches the relay's buffer on the far
#: side so neither end is the one chopping stream bytes up.
CHUNK = 32 * 1024


async def _read_exactly(r: asyncio.StreamReader, n: int) -> bytes:
    return await r.readexactly(n)


async def _greeting(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> bool:
    """Negotiate the method. -> whether to carry on."""
    head = await _read_exactly(r, 2)
    g = socks.parse_greeting(head + await _read_exactly(r, head[1]))
    reply = socks.choose_method(g)
    w.write(reply)
    await w.drain()
    # NO_ACCEPTABLE. The client offered no authentication we will
    # take, which for a browser means it was configured without a
    # username -- see socks.choose_method for why that is refused.
    return reply[1] == socks.USERPASS


async def _credentials(r: asyncio.StreamReader) -> socks.Credentials:
    head = await _read_exactly(r, 2)
    ulen = head[1]
    user = await _read_exactly(r, ulen)
    plen = (await _read_exactly(r, 1))[0]
    pwd = await _read_exactly(r, plen)
    return socks.parse_userpass(bytes((head[0], ulen)) + user
                                + bytes((plen,)) + pwd)


async def _request(r: asyncio.StreamReader) -> socks.Request:
    head = await _read_exactly(r, 4)
    atyp = head[3]
    if atyp == socks.ATYP_IPV4:
        rest = await _read_exactly(r, 6)
    elif atyp == socks.ATYP_IPV6:
        rest = await _read_exactly(r, 18)
    elif atyp == socks.ATYP_DOMAIN:
        dlen = (await _read_exactly(r, 1))[0]
        rest = bytes((dlen,)) + await _read_exactly(r, dlen + 2)
    else:
        raise socks.ProtocolError(f"unsupported address type {atyp}")
    return socks.parse_request(head + rest)


async def _pump_client(r: asyncio.StreamReader, s: Stream) -> None:
    """Client -> target."""
    while True:
        data = await r.read(CHUNK)
        if not data:
            return
        await s.send(data)


async def _pump_stream(s: Stream, w: asyncio.StreamWriter) -> None:
    """Target -> client."""
    while True:
        data = await s.recv()
        if data is None:
            return
        w.write(data)
        await w.drain()


async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """One SOCKS5 connection, start to finish."""
    peer = w.get_extra_info("peername")
    host = port = None
    try:
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            if not await _greeting(r, w):
                return
            creds = await _credentials(r)
            req = await _request(r)
        host, port = req.host, req.port

        refusal = socks.reply_for(req)
        if refusal is not None:
            w.write(socks.reply(refusal))
            await w.drain()
            async with SessionLocal() as session:
                d = proxyauth.Decision(False, refusal, "refused_command",
                                       f"command {req.command} is not offered")
                await proxyauth.record(session, d, host, port)
                # Outside a request, so nothing commits for us. A
                # refusal that is not written down is the half of
                # this record that somebody will come looking for.
                await session.commit()
            return

        # Credential first, destination second. A caller with no
        # grant never learns whether a host is in scope.
        async with SessionLocal() as session:
            d = await proxyauth.decide(session, creds.username,
                                       creds.password, host, port)
            await proxyauth.record(session, d, host, port)
            await session.commit()

        if not d.allowed:
            w.write(socks.reply(d.code))
            await w.drain()
            log.info("proxy refused %s:%s from %s — %s",
                     host, port, peer, d.reason)
            return

        tunnel = hub.get(d.agent_id) if d.agent_id else None
        if tunnel is None:
            # Authorised, but the Ghost is not connected. Its own
            # reply code, because "that ghost is not here" is a
            # different thing for an operator than "refused".
            w.write(socks.reply(socks.NET_UNREACHABLE))
            await w.drain()
            log.info("proxy has no tunnel for agent %s", d.agent_id)
            return

        stream, why = await tunnel.open(host, port, grant_id=d.grant_id)
        if stream is None:
            w.write(socks.reply(socks.HOST_UNREACHABLE))
            await w.drain()
            log.info("proxy could not reach %s:%s via agent %s — %s",
                     host, port, d.agent_id, why)
            return

        w.write(socks.reply(socks.OK))
        await w.drain()

        # Both directions at once, and the first to finish ends the
        # other. A proxied stream is over when either end stops;
        # waiting for both would hold the socket on every request a
        # browser abandons.
        a = asyncio.create_task(_pump_client(r, stream))
        b = asyncio.create_task(_pump_stream(stream, w))
        try:
            done, pending = await asyncio.wait(
                {a, b}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            await stream.close()

    except (asyncio.IncompleteReadError, ConnectionResetError, TimeoutError):
        # A client that hung up or dawdled. Normal, and not worth a
        # line in the log each time.
        pass
    except socks.ProtocolError as e:
        log.info("proxy: not SOCKS5 from %s — %s", peer, e)
    except Exception as e:                                   # noqa: BLE001
        log.warning("proxy connection from %s failed: %s", peer, e)
    finally:
        with contextlib.suppress(Exception):
            w.close()
            await w.wait_closed()


#: What a TLS ClientHello starts with. A SOCKS5 greeting starts with
#: 0x05, so the two cannot be confused by their first byte -- which
#: is what lets them share a port.
TLS_HELLO = 0x16
SOCKS5 = 0x05


async def demux(r: asyncio.StreamReader, w: asyncio.StreamWriter,
                tls: ssl.SSLContext | None) -> None:
    """Route one connection to SOCKS or to CONNECT-over-TLS.

    One port, two protocols, and no ambiguity about which: a SOCKS5
    greeting opens 0x05 and a TLS ClientHello opens 0x16. The
    comment at the top of this file says nginx cannot do this
    because `ssl_preread` only classifies TLS; a one-byte peek can,
    and it is the whole mechanism.

    Why share at all: the SOCKS listener is reached through an SSH
    tunnel and must keep working exactly as it does, while a browser
    pointed at the host needs TLS on a port it can name. Giving the
    second its own port would mean another firewall hole and another
    thing to document.
    """
    try:
        first = await asyncio.wait_for(r.read(1), HANDSHAKE_TIMEOUT)
    except (TimeoutError, ConnectionResetError):
        with contextlib.suppress(Exception):
            w.close()
        return
    if not first:
        with contextlib.suppress(Exception):
            w.close()
        return

    if first[0] == TLS_HELLO:
        # A TLS ClientHello arriving HERE cannot be served, and the
        # reason is worth writing down because the obvious fix does
        # not work.
        #
        # Demuxing means consuming a byte to classify the
        # connection. `loop.start_tls()` then has a ClientHello
        # missing its first byte, and feeding that byte back through
        # `protocol.data_received()` puts it in the StreamReader's
        # buffer -- which is not where the TLS state machine reads
        # from. The handshake waits for ever for a hello that
        # already arrived: `openssl s_client` prints "Connecting to
        # 127.0.0.1" and nothing else, which is how this was found.
        #
        # So TLS gets its own listener, where asyncio wraps the
        # socket from byte zero and nothing has to be put back. See
        # `serve_tls`.
        log.info("proxy: TLS offered on the plaintext port — the TLS "
                 "listener is a separate port (proxy.tls_port)")
        with contextlib.suppress(Exception):
            w.close()
        return

    # A plain HTTP verb. Either a browser speaking CONNECT to a port
    # where something in front has ALREADY terminated TLS -- which
    # is the arrangement worth preferring, see the module header --
    # or a browser that is not configured as a proxy at all. The
    # CONNECT handler answers both, and its answer to the second is
    # more use than a dropped connection.
    if 0x41 <= first[0] <= 0x5A:
        from . import proxyhttps
        await proxyhttps.handle(_Pushback(r, first), w)
        return

    if first[0] != SOCKS5:
        log.info("proxy: first byte %#04x is none of SOCKS5, TLS or HTTP",
                 first[0])
        with contextlib.suppress(Exception):
            w.close()
        return
    await handle(_Pushback(r, first), w)


class _Pushback:
    """A StreamReader with one byte put back in front of it.

    The demux has to consume a byte to classify the connection, and
    the handler behind it expects to read the stream from its
    beginning. Wrapping is less invasive than teaching both
    protocol handlers about a prefix they should not know exists.
    """

    def __init__(self, inner: asyncio.StreamReader, head: bytes) -> None:
        self._inner = inner
        self._head = bytearray(head)

    async def readexactly(self, n: int) -> bytes:
        out = bytearray()
        if self._head:
            take = min(n, len(self._head))
            out += self._head[:take]
            del self._head[:take]
            n -= take
        if n:
            out += await self._inner.readexactly(n)
        return bytes(out)

    async def read(self, n: int = -1) -> bytes:
        if self._head:
            if n is None or n < 0:
                out = bytes(self._head) + await self._inner.read(-1)
                self._head.clear()
                return out
            take = min(n, len(self._head))
            out = bytes(self._head[:take])
            del self._head[:take]
            return out
        return await self._inner.read(n)

    def __getattr__(self, name: str):
        return getattr(self._inner, name)


async def serve(bind: str, port: int,
                tls: ssl.SSLContext | None = None) -> asyncio.AbstractServer:
    """The plaintext port: SOCKS5, and CONNECT from a TLS terminator.

    `tls` is accepted so the caller can say whether a TLS listener
    exists; terminating TLS on THIS port is not possible -- see
    `demux`.
    """
    async def _on(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await demux(r, w, tls)

    srv = await asyncio.start_server(_on, bind, port)
    where = ", ".join(str(s.getsockname()) for s in (srv.sockets or ()))
    log.warning("proxy listening on %s (SOCKS5, and CONNECT from a TLS "
                "terminator in front) — every connection is "
                "authenticated, scope-gated and recorded", where)
    return srv


async def serve_tls(bind: str, port: int,
                    tls: ssl.SSLContext) -> asyncio.AbstractServer:
    """The TLS port: CONNECT, with the handshake done by asyncio.

    Its own listener rather than a branch of the demux, because a
    demux has to read a byte to decide and TLS cannot survive having
    its first byte read elsewhere. Here `start_server(ssl=...)` wraps
    the socket from byte zero, which is the supported path and the
    one that works.

    The handler is the same one the plaintext port uses for CONNECT,
    so both carry identical authorisation -- credential, scope gate,
    audit row and tunnel are one code path, not two.
    """
    from . import proxyhttps

    srv = await asyncio.start_server(proxyhttps.handle, bind, port, ssl=tls)
    where = ", ".join(str(s.getsockname()) for s in (srv.sockets or ()))
    log.warning("proxy TLS listening on %s (CONNECT inside TLS) — the "
                "credential travels encrypted, which is what SOCKS5 "
                "cannot offer", where)
    return srv
