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

        stream, why = await tunnel.open(host, port)
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


async def serve(bind: str, port: int) -> asyncio.AbstractServer:
    """Start listening. The caller owns the server object."""
    srv = await asyncio.start_server(handle, bind, port)
    where = ", ".join(str(s.getsockname()) for s in (srv.sockets or ()))
    log.warning("SOCKS5 proxy listening on %s — every connection is "
                "authenticated, scope-gated and recorded", where)
    return srv
