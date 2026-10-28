"""HTTP CONNECT, for a browser pointed straight at Oddjob.

The SOCKS listener next door works and needs an SSH tunnel, because
SOCKS5 has no transport security at all: RFC 1929 sends the username
and password as plaintext bytes, and everything after the handshake
is the raw stream. Over a loopback-bound port reached through SSH
that is fine -- SSH is the encryption, and the person who opened the
tunnel has already proved who they are. Published to the internet it
would be a credential sniffable by anyone on path, and a
brute-forceable route into a client's network.

CONNECT is the same idea with the conversation inside TLS. A browser
does the TLS handshake first, sends `CONNECT host:443 HTTP/1.1` with
`Proxy-Authorization: Basic ...` inside it, and from the 200 onward
the socket is a tunnel exactly as SOCKS's is. So the credential is
encrypted, the destination is encrypted, and the operator points
their browser at the host instead of at a tunnel.

**Parse and decide only. No I/O.** Same split as `socks.py`, for the
same reason: the decisions are the part worth testing, and a test
that needs a socket is a test nobody writes enough of.

The two protocols share a port, which they can because their first
byte cannot collide: a SOCKS5 greeting opens with 0x05 and a TLS
ClientHello with 0x16. See `proxyserver.demux`.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

#: Longest request head we will read before giving up. A browser's
#: CONNECT is a few hundred bytes; anything approaching this is
#: either not a proxy client or is trying to make us buffer.
MAX_HEAD = 16 * 1024

#: Longest single line. Same reasoning, per line.
MAX_LINE = 4 * 1024


class ProtocolError(Exception):
    """The bytes were not a CONNECT request we will answer."""


@dataclass(frozen=True)
class Request:
    """A parsed CONNECT line plus the credential that came with it."""
    host: str
    port: int
    #: None when no `Proxy-Authorization` was sent at all, which is
    #: the normal FIRST request from a browser -- it waits to be
    #: asked. Distinct from an empty username, which is a client
    #: that tried and failed.
    username: str | None = None
    password: str | None = None
    #: What the client called itself, for the audit line.
    user_agent: str = ""

    @property
    def authenticated(self) -> bool:
        return self.username is not None


#: `CONNECT host:port HTTP/1.1`. The host may be a bracketed IPv6
#: literal, which is the one form that contains colons itself.
_LINE = re.compile(
    r"^CONNECT[ \t]+(?P<host>\[[0-9A-Fa-f:.]+\]|[^\s:/@]+):(?P<port>\d{1,5})"
    r"[ \t]+HTTP/1\.[01]$")


def parse_request(head: str) -> Request:
    """Parse a CONNECT request head. -> Request, or raise.

    `head` is everything up to and including the blank line.

    Deliberately strict. This decides where the server puts a packet
    on a client's network, so a line that is nearly right is refused
    rather than interpreted -- the same bar `_HOST_PORT` in the web
    router is held to.
    """
    if len(head) > MAX_HEAD:
        raise ProtocolError("request head too long")
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0]:
        raise ProtocolError("empty request")
    if any(len(x) > MAX_LINE for x in lines):
        raise ProtocolError("header line too long")

    m = _LINE.match(lines[0].strip())
    if not m:
        # A browser that is NOT configured as a proxy sends `GET /`.
        # Saying so is more use than "bad request".
        verb = lines[0].split(" ", 1)[0][:12]
        if verb and verb != "CONNECT":
            raise ProtocolError(
                f"{verb} is not CONNECT -- this port is a proxy, not a "
                f"web server")
        raise ProtocolError("malformed CONNECT line")

    port = int(m.group("port"))
    if not 1 <= port <= 65535:
        raise ProtocolError(f"port {port} out of range")
    host = m.group("host")
    if host.startswith("["):
        host = host[1:-1]

    user = pwd = None
    agent = ""
    for raw in lines[1:]:
        if not raw.strip():
            break
        name, _, value = raw.partition(":")
        key = name.strip().lower()
        value = value.strip()
        if key == "proxy-authorization":
            user, pwd = _basic(value)
        elif key == "user-agent":
            agent = value[:200]
    return Request(host=host, port=port, username=user, password=pwd,
                   user_agent=agent)


def _basic(value: str) -> tuple[str | None, str | None]:
    """Decode `Basic base64(user:pass)`. -> (None, None) if it is not.

    A header we cannot decode is treated as absent rather than as a
    failed login: the client gets the same 407 challenge and a
    chance to send a real one, which is what a browser does with a
    stale cached credential.
    """
    scheme, _, blob = value.partition(" ")
    if scheme.strip().lower() != "basic" or not blob.strip():
        return None, None
    try:
        raw = base64.b64decode(blob.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None, None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, None
    if ":" not in text:
        return None, None
    user, _, pwd = text.partition(":")
    return user, pwd


#: The realm a browser shows in its credential prompt. Named for the
#: thing being entered, because "Oddjob" alone leaves an operator
#: guessing which of their passwords it wants.
REALM = "Oddjob ghost proxy"


def challenge() -> bytes:
    """407, asking the browser for the grant.

    `Proxy-Connection: keep-alive` because a browser that is told to
    close will often open a fresh connection and re-ask the user
    rather than retrying with the credential it just collected.
    """
    return _response(
        407, "Proxy Authentication Required",
        extra=[f'Proxy-Authenticate: Basic realm="{REALM}", charset="UTF-8"',
               "Proxy-Connection: keep-alive"],
        body="This port is a proxy into an authorised engagement. It needs "
             "the credential issued for a specific Ghost.\n")


def ok() -> bytes:
    """200. Everything after this byte is the tunnel."""
    return b"HTTP/1.1 200 Connection Established\r\n\r\n"


def refused(reason: str, code: int = 403) -> bytes:
    """A refusal the operator can act on.

    The reason is included deliberately. A proxy that answers every
    refusal identically teaches its user nothing, and these are all
    things they can fix: the wrong ghost, a host outside scope, a
    ghost that has not dialled in.
    """
    return _response(code, "Forbidden" if code == 403 else "Bad Gateway",
                     body=reason.rstrip() + "\n")


def _response(code: int, phrase: str, *, extra: list[str] | None = None,
              body: str = "") -> bytes:
    raw = body.encode("utf-8")
    head = [f"HTTP/1.1 {code} {phrase}",
            "Content-Type: text/plain; charset=utf-8",
            f"Content-Length: {len(raw)}"]
    head += extra or []
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + raw
