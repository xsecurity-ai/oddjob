"""The CONNECT listener: a browser pointed straight at Oddjob.

The thinnest file of its set, like `proxyserver.py` beside it, and
for the same reason: `connect.py` parses, `proxyauth.py` authorises,
`proxyhub.py` routes, and this is only the asyncio that joins them.
Everything from the credential check onward is byte-for-byte the
same path the SOCKS listener takes -- same grants, same scopegate,
same tunnel, same audit row -- because two ways in that authorise
differently is one way in nobody has checked.

What differs is the transport, and it is the whole point. SOCKS5
carries its credential in plaintext (RFC 1929), so it is only safe
over a tunnel somebody already authenticated. Here the browser
completes a TLS handshake first and the credential arrives inside
it, which is what makes "point your browser at the host" a
reasonable thing to offer rather than a way to publish a route into
a client's network.

**It shares port 8443 with SOCKS** -- see `proxyserver.demux`. The
first byte tells them apart with no ambiguity: a SOCKS5 greeting
opens 0x05, a TLS ClientHello opens 0x16.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl

from . import connect, proxyauth
from .db import SessionLocal
from .proxyhub import hub
from .proxyserver import CHUNK, HANDSHAKE_TIMEOUT, _pump_client, _pump_stream

log = logging.getLogger("oddjob.proxy")


async def read_head(r: asyncio.StreamReader) -> str:
    """Read up to the blank line that ends a request head."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
        chunk = await r.read(1024)
        if not chunk:
            break
        buf += chunk
        if len(buf) > connect.MAX_HEAD:
            raise connect.ProtocolError("request head too long")
    return buf.decode("latin-1")


async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """One CONNECT request, start to finish."""
    peer = w.get_extra_info("peername")
    try:
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            head = await read_head(r)
        if not head.strip():
            return
        req = connect.parse_request(head)

        # No credential yet is not a refusal -- it is the first half
        # of how Basic auth works. The browser asks, we challenge,
        # it asks the operator and comes back.
        if not req.authenticated:
            w.write(connect.challenge())
            await w.drain()
            return

        # Credential first, destination second: a caller with no
        # grant never learns whether a host is in scope.
        async with SessionLocal() as session:
            d = await proxyauth.decide(session, req.username or "",
                                       req.password or "",
                                       req.host, req.port)
            await proxyauth.record(session, d, req.host, req.port)
            # Outside a request, so nothing commits for us. A
            # refusal nobody wrote down is the half of the record
            # somebody will come looking for.
            await session.commit()

        if not d.allowed:
            # 407 for a bad credential so the browser re-prompts;
            # 403 for anything else, because re-asking for a
            # password will not put a host in scope.
            # `outcome`, which is what Decision actually calls it.
            # Written as `reason_code` first, which typechecks
            # nowhere and would have raised AttributeError on the
            # refusal path only -- the same shape as the `Ruling.why`
            # bug that reached production here.
            bad_cred = d.outcome == "refused_auth"
            w.write(connect.challenge() if bad_cred
                    else connect.refused(d.reason))
            await w.drain()
            log.info("connect refused %s:%s from %s — %s",
                     req.host, req.port, peer, d.reason)
            return

        tunnel = hub.get(d.agent_id) if d.agent_id else None
        if tunnel is None:
            w.write(connect.refused(
                "that Ghost is authorised for this but has not dialled in, "
                "so there is nothing to route through. Check it is online.",
                code=502))
            await w.drain()
            return

        stream, why = await tunnel.open(req.host, req.port, grant_id=d.grant_id)
        if stream is None:
            w.write(connect.refused(
                f"the Ghost could not reach {req.host}:{req.port} — {why}",
                code=502))
            await w.drain()
            return

        w.write(connect.ok())
        await w.drain()

        # From here it is the SOCKS listener's relay, unchanged.
        a = asyncio.create_task(_pump_client(r, stream))
        b = asyncio.create_task(_pump_stream(stream, w))
        try:
            _done, pending = await asyncio.wait(
                {a, b}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*pending, return_exceptions=True)
        finally:
            await stream.close()

    except (asyncio.IncompleteReadError, ConnectionResetError, TimeoutError):
        pass
    except connect.ProtocolError as e:
        with contextlib.suppress(Exception):
            w.write(connect.refused(str(e), code=400))
            await w.drain()
        log.info("connect: %s from %s", e, peer)
    except Exception as e:                                   # noqa: BLE001
        log.warning("connect from %s failed: %s", peer, e)
    finally:
        with contextlib.suppress(Exception):
            w.close()
            await w.wait_closed()


def context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """TLS for the proxy port.

    A real certificate, not a self-signed one: a browser asked to
    use an HTTPS proxy will refuse a certificate it cannot verify,
    and there is no click-through for a proxy the way there is for a
    page. The host already has one for the site; point this at it.
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile, keyfile)
    # 1.2 floor. A proxy credential crosses this, and the reason
    # this listener exists at all is that the SOCKS one has no
    # transport security.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


__all__ = ["CHUNK", "context", "handle", "read_head"]
