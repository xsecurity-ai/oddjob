"""Sealing the agent channel, in both directions.

Signatures already prove who sent a request and that it arrived
unaltered. They do nothing about who can read it, and what travels on
this channel is a client's own vulnerability inventory — open ports,
service versions, findings, sometimes captured credentials — with the
agent sitting inside that client's network. A TLS-terminating proxy is
ordinary furniture there, and against one of those TLS protects the
traffic from everyone except the box whose entire job is reading it.

So the body is sealed under a key only the two endpoints hold, derived
from the X25519 halves exchanged at enrollment, and TLS stays underneath
for everything else it is good for. A middlebox sees an opaque envelope
addressed to a URL it can read, which is the most that can be given
away while remaining routable.

This lives in middleware rather than in each endpoint because an
endpoint that forgets is an endpoint that sends a scan result in the
clear, and that is not a mistake anyone would notice.

The rule that matters: **an agent holding a key-agreement half must
seal.** An unsealed request from one is refused, exactly as an unsigned
request from an agent with an identity is refused. Without that, an
attacker simply omits the header and the whole thing is decoration.
"""
from __future__ import annotations

import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import agentcrypto
from .db import SessionLocal
from .models import Agent, Setting

log = logging.getLogger("oddjob.agentseal")

#: Only the agent-facing routes. Everything else on this server talks
#: to a browser, which has no key and no way to get one.
SEALED_PREFIX = "/api/ghosts/"

#: Enrollment is the one agent route that cannot be sealed: it is the
#: exchange that establishes the key. It carries a one-time token and
#: a public half, neither of which is a secret worth hiding — the
#: token authenticates and is burned, and the public key is public.
NEVER_SEALED = ("/api/ghosts/enroll", "/api/ghosts/enrol")


async def _agent_key(agent_id: str) -> tuple[Agent, bytes] | None:
    """The shared key for a claimed agent id, without a request scope.

    Its own session: middleware runs outside the dependency that would
    normally supply one, and borrowing the request's would mean opening
    it before authentication has happened.
    """
    try:
        aid = int(agent_id)
    except (TypeError, ValueError):
        return None
    async with SessionLocal() as session:
        a = await session.get(Agent, aid)
        if a is None or not a.kex_public_key:
            return None
        row = await session.get(Setting, agentcrypto.SERVER_KEX_SETTING)
        if row is None or not row.value:
            # The server has no key-agreement half at all, which means
            # no agent could have enrolled with one. Treat as "cannot
            # seal" rather than inventing a key here.
            return None
        return a, agentcrypto.shared_key(row.value, a.kex_public_key)


class AgentSeal(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith(SEALED_PREFIX) or path in NEVER_SEALED:
            return await call_next(request)

        claimed = request.headers.get(agentcrypto.AGENT_HEADER, "").strip()
        sealed = request.headers.get(agentcrypto.SEALED_HEADER, "").strip()
        if not claimed:
            # Unsigned and unidentified: the legacy key path, or a
            # browser hitting an operator route. Nothing to unseal and
            # nothing to enforce — the route's own dependency decides.
            return await call_next(request)

        found = await _agent_key(claimed)
        if found is None:
            # No key-agreement half on file, so this agent predates
            # sealing. Allowed through unsealed; the signature still
            # has to hold.
            return await call_next(request)
        agent, key = found

        ts = request.headers.get(agentcrypto.TS_HEADER, "").strip()
        nonce = request.headers.get(agentcrypto.NONCE_HEADER, "").strip()

        if not sealed:
            # The no-downgrade rule. This agent proved it can seal when
            # it enrolled; a request from it in the clear is either a
            # broken agent or someone stripping the header, and both
            # are answered the same way.
            return JSONResponse(
                {"detail": "this agent enrolled with a key-agreement key and "
                           "must seal its requests; an unsealed one is not "
                           "accepted"}, status_code=401)
        if sealed != agentcrypto.SEAL_VERSION:
            return JSONResponse(
                {"detail": f"unknown seal version {sealed!r}; this server "
                           f"speaks {agentcrypto.SEAL_VERSION}"},
                status_code=400)

        body = await request.body()
        opened = agentcrypto.unseal(
            key, body.decode("utf-8", "ignore"),
            agentcrypto.channel_binding("req", agent.id, request.method,
                                        path, ts, nonce))
        if opened is None:
            # Wrong key, tampered envelope, or a body lifted from
            # another route. All of them mean the same thing.
            return JSONResponse(
                {"detail": "the sealed body did not open"}, status_code=401)

        # The signature was made over the sealed bytes, because that
        # is what went on the wire. Keep them: the authentication
        # dependency runs after this and would otherwise verify
        # against plaintext the agent never signed.
        request.state.sealed_body = body

        # Hand the route plaintext. Length has to move with it or the
        # framework reads past the end of the shorter body.
        request._body = opened
        headers = request.scope["headers"] = [
            (k, v) for k, v in request.scope["headers"]
            if k.lower() != b"content-length"
        ]
        headers.append((b"content-length", str(len(opened)).encode()))

        async def receive():
            return {"type": "http.request", "body": opened, "more_body": False}

        request._receive = receive
        response = await call_next(request)

        # And seal the way back. The agent verifies the same binding
        # with "res", so a response cannot be replayed as a request or
        # moved to another route.
        out = b""
        async for chunk in response.body_iterator:
            out += chunk
        envelope = agentcrypto.seal(
            key, out,
            agentcrypto.channel_binding("res", agent.id, request.method,
                                        path, ts, nonce))
        return Response(
            content=envelope, status_code=response.status_code,
            media_type="application/octet-stream",
            headers={agentcrypto.SEALED_HEADER: agentcrypto.SEAL_VERSION},
        )


def is_sealed_response(raw: bytes) -> bool:
    """Used by tests: a sealed reply is not JSON."""
    try:
        json.loads(raw)
        return False
    except ValueError:
        return True
