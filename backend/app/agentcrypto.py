"""Mutual Ed25519 identity for Drone agents.

A bearer key proves only that the caller read a secret from somewhere.
Copy it off the agent's disk and you are the agent; copy it out of the
database and you are also the agent. For a process that runs privileged
on someone else's network and is trusted to say "here is what I found",
that is a weak claim.

So each side holds a private key the other never sees:

- Oddjob has one identity for the whole instance, made on first use.
- Each agent makes its own at enrollment. The private half never leaves
  the host it was made on, and the server stores only the public half,
  so a dump of this database cannot impersonate any agent.

Both directions are signed. The agent signs what it sends so the server
knows which agent sent it; the server signs what it sends so the agent
knows it is being tasked by the Oddjob it enrolled with and not by
whoever else found the port. That mutual pinning is the part that makes
an agent belong to one server, rather than to anyone holding a token.

Signing covers method, path, a hash of the body, a timestamp and a
nonce, so a captured request cannot be replayed against another route
or after the window closes.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#: How far apart the two clocks may be. Generous enough for a host whose
#: clock drifts, tight enough that a captured request is not useful for
#: long. The nonce cache is what actually stops replay inside it.
CLOCK_SKEW = 300

#: Settings key holding this instance's private identity.
SERVER_KEY_SETTING = "agent_server_identity"

SIG_HEADER = "X-Drone-Signature"
AGENT_HEADER = "X-Drone-Agent"
TS_HEADER = "X-Drone-Timestamp"
NONCE_HEADER = "X-Drone-Nonce"


# --------------------------------------------------------- confidentiality
#
# Signing proves who sent a thing and that it arrived unaltered. It
# does not hide it. What travels between an agent and Oddjob is a
# client's own vulnerability inventory -- open ports, service
# versions, findings, sometimes captured credentials -- and the agent
# is by design sitting inside that client's network, where a
# TLS-terminating proxy is a normal piece of corporate furniture.
# Against one of those, TLS gives confidentiality from everyone except
# the box that is explicitly reading everything.
#
# So the payload is sealed under a key only the two endpoints hold,
# derived from the X25519 halves they exchanged at enrollment, and TLS
# is kept underneath for everything else it is good for. A middlebox
# sees an opaque envelope to a URL it can read, which is the most we
# can give away and still be reachable.
#
# Standard primitives, no invention: X25519 for the agreement,
# HKDF-SHA256 to turn the shared secret into a key, ChaCha20-Poly1305
# to seal. The channel binding goes in the AEAD's associated data, so
# a sealed body lifted onto a different route or a different agent
# fails to open rather than being quietly accepted.

#: Bumped if the construction below ever changes, so an old agent
#: meets a clear refusal instead of a decryption failure.
SEAL_VERSION = "v1"

#: Settings key holding this instance's X25519 private half.
SERVER_KEX_SETTING = "agent_server_kex"

SEALED_HEADER = "X-Drone-Sealed"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode(), validate=True)


def generate() -> tuple[str, str]:
    """A new identity, as (private, public), both base64 raw bytes."""
    priv = Ed25519PrivateKey.generate()
    return (
        b64(priv.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())),
        b64(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)),
    )


def public_of(private_b64: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(unb64(private_b64))
    return b64(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw))


def generate_kex() -> tuple[str, str]:
    """A new X25519 pair, as (private, public), base64 raw."""
    priv = X25519PrivateKey.generate()
    return (
        b64(priv.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())),
        b64(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)),
    )


def kex_public_of(private_b64: str) -> str:
    priv = X25519PrivateKey.from_private_bytes(unb64(private_b64))
    return b64(priv.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw))


def shared_key(private_b64: str, peer_public_b64: str) -> bytes:
    """The symmetric key for one agent-server pair.

    HKDF rather than the raw ECDH output: the X25519 result is not
    uniformly random and is not safe to use directly as a key. The info
    string pins the construction, so a future change produces a
    different key rather than two versions silently interoperating.
    """
    priv = X25519PrivateKey.from_private_bytes(unb64(private_b64))
    peer = X25519PublicKey.from_public_bytes(unb64(peer_public_b64))
    secret = priv.exchange(peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"oddjob/drone seal {SEAL_VERSION}".encode()).derive(secret)


def channel_binding(direction: str, agent_id: int, method: str, path: str,
                    ts: str, nonce: str) -> bytes:
    """What the seal is bound to.

    Passed as associated data, so it is authenticated but not
    encrypted. A sealed body replayed onto another route, in the other
    direction, or against another agent will not open -- which is the
    difference between an envelope and an envelope that only one
    recipient can use for one purpose.
    """
    return "\n".join([SEAL_VERSION, direction, str(agent_id),
                       method.upper(), path, ts, nonce]).encode()


def seal(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """Encrypt, returning nonce||ciphertext as base64."""
    nonce = secrets.token_bytes(12)
    return b64(nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad))


def unseal(key: bytes, blob: str, aad: bytes) -> bytes | None:
    """Decrypt, or None. A failure here is never partially trusted."""
    try:
        raw = unb64(blob)
        if len(raw) < 13:
            return None
        return ChaCha20Poly1305(key).decrypt(raw[:12], raw[12:], aad)
    except Exception:            # noqa: BLE001 — any failure is "no"
        return None


def canonical(method: str, path: str, body: bytes, ts: str, nonce: str) -> bytes:
    """What both sides sign.

    The body is hashed rather than included so a large nmap XML does not
    have to be held twice, and the path is included so a signature
    captured from one route cannot be replayed against another.
    """
    digest = hashlib.sha256(body or b"").hexdigest()
    return "\n".join([method.upper(), path, digest, ts, nonce]).encode()


def sign(private_b64: str, method: str, path: str, body: bytes,
         ts: str, nonce: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(unb64(private_b64))
    return b64(priv.sign(canonical(method, path, body, ts, nonce)))


def verify(public_b64: str, signature_b64: str, method: str, path: str,
           body: bytes, ts: str, nonce: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(unb64(public_b64))
        pub.verify(unb64(signature_b64),
                   canonical(method, path, body, ts, nonce))
        return True
    except (InvalidSignature, ValueError, TypeError):
        # A malformed key or signature is a failed verification, not a
        # crash. The caller gets one answer: no.
        return False


def fresh(ts: str, now: float | None = None) -> bool:
    try:
        then = float(ts)
    except (TypeError, ValueError):
        return False
    return abs((now if now is not None else time.time()) - then) <= CLOCK_SKEW


@dataclass
class _Seen:
    nonce: str
    at: float


class NonceCache:
    """Rejects a nonce already used inside the clock-skew window.

    In memory and therefore per process: a replay against a second
    worker would not be caught. Said plainly rather than implied,
    because the fix when this runs multi-process is Redis or a table,
    not a bigger dict. Within the window a replay still has to beat the
    signature, which covers the path and the body, so the exposure is a
    duplicate of a request the agent already legitimately made.
    """

    def __init__(self, window: int = CLOCK_SKEW):
        self.window = window
        self._seen: dict[str, float] = {}

    def check_and_add(self, nonce: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        if len(self._seen) > 10000:
            self._prune(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        self._seen = {n: t for n, t in self._seen.items() if t > cutoff}


nonces = NonceCache()
