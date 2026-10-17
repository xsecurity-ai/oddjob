"""SOCKS5, as far as deciding whether a connection may be made.

Oddjob can route a browser through a Ghost: the browser speaks SOCKS5
to Oddjob, Oddjob hands the stream to a Ghost over the tunnel the
Ghost already holds open, and the Ghost dials the target. That puts
the operator's traffic where the Ghost is -- inside the estate, from
the address the client already sees us at -- which is the whole point
and is also why this file is written the way it is.

**This module does no I/O and dials nothing.** It parses the
handshake, decides, and returns bytes to send back. Everything that
touches a socket lives in the server that drives it, so the part that
can say yes to reaching a host is a pure function with tests rather
than something tangled into an event loop.

# What this is, stated plainly

A SOCKS5 proxy into a client's network. If the credential leaks,
whoever has it reaches whatever the Ghost reaches. That is a bigger
blast radius than any other feature here: a task is queued, scoped
and audited, while a proxy is a live socket. The mitigations are
therefore not optional extras --

  - it is OFF per agent and the default is off;
  - a username/password is required, and SOCKS5 sends it in the clear,
    so the credential is a per-agent token that can be revoked, never
    an Oddjob login;
  - EVERY destination goes through `scopegate` before the Ghost is
    asked to dial it, so the proxy cannot reach what a task could not;
  - every accepted connection is recorded, because "who reached what,
    when" is the question this feature will be asked afterwards.

# Why username/password and not "no authentication"

SOCKS5 offers a no-auth method and every browser will use it happily.
Accepting it would make an open proxy of whatever port this listens
on, which on an engagement is somebody else's foothold rather than
ours. The method list is answered with 0x02 and nothing else; a
client that cannot do user/pass is refused with 0xFF.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

VERSION = 0x05
#: RFC 1929, the username/password subnegotiation.
AUTH_VERSION = 0x01

#: Method numbers from RFC 1928.
NO_AUTH = 0x00
USERPASS = 0x02
NO_ACCEPTABLE = 0xFF

#: Commands. Only CONNECT is implemented -- see `reply_for`.
CONNECT = 0x01
BIND = 0x02
UDP_ASSOCIATE = 0x03

#: Address types.
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

#: Reply codes.
OK = 0x00
GENERAL_FAILURE = 0x01
NOT_ALLOWED = 0x02
NET_UNREACHABLE = 0x03
HOST_UNREACHABLE = 0x04
REFUSED = 0x05
CMD_NOT_SUPPORTED = 0x07
ATYP_NOT_SUPPORTED = 0x08


class ProtocolError(Exception):
    """The bytes are not SOCKS5. The caller closes the connection.

    Its own type so a malformed handshake cannot be mistaken for a
    refusal: one is a client that does not speak the protocol, the
    other is a decision this module made, and they are answered
    differently.
    """


@dataclass(frozen=True)
class Greeting:
    """The client's opening message."""
    methods: tuple[int, ...]

    @property
    def offers_userpass(self) -> bool:
        return USERPASS in self.methods


def parse_greeting(data: bytes) -> Greeting:
    """Parse the version/method list.

    Raises `ProtocolError` on anything that is not SOCKS5. Notably on
    0x04: SOCKS4 has no authentication at all, so answering it would
    be answering an unauthenticated protocol.
    """
    if len(data) < 2:
        raise ProtocolError("greeting too short")
    ver, n = data[0], data[1]
    if ver != VERSION:
        raise ProtocolError(f"not SOCKS5 (version {ver})")
    if n == 0:
        raise ProtocolError("greeting offers no methods")
    if len(data) < 2 + n:
        raise ProtocolError("greeting truncated")
    return Greeting(methods=tuple(data[2:2 + n]))


def choose_method(g: Greeting) -> bytes:
    """-> the two-byte method reply.

    Username/password or nothing. See the module docstring: accepting
    NO_AUTH here is what would make this an open proxy.
    """
    if g.offers_userpass:
        return bytes((VERSION, USERPASS))
    return bytes((VERSION, NO_ACCEPTABLE))


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str


def parse_userpass(data: bytes) -> Credentials:
    """Parse RFC 1929 username/password.

    The password is not logged anywhere by this module, and the
    caller must not log it either: SOCKS5 sends it in clear text, so
    it is already the weakest part of the chain without also writing
    it to disk.
    """
    if len(data) < 2:
        raise ProtocolError("auth message too short")
    if data[0] != AUTH_VERSION:
        raise ProtocolError(f"unsupported auth version {data[0]}")
    ulen = data[1]
    if len(data) < 2 + ulen + 1:
        raise ProtocolError("auth message truncated")
    user = data[2:2 + ulen]
    plen = data[2 + ulen]
    rest = data[3 + ulen:]
    if len(rest) < plen:
        raise ProtocolError("auth message truncated")
    try:
        return Credentials(username=user.decode("utf-8"),
                           password=rest[:plen].decode("utf-8"))
    except UnicodeDecodeError as e:
        raise ProtocolError("credentials are not utf-8") from e


def auth_reply(ok: bool) -> bytes:
    """RFC 1929 status. Non-zero is failure; the value is not read."""
    return bytes((AUTH_VERSION, 0x00 if ok else 0x01))


@dataclass(frozen=True)
class Request:
    """A CONNECT (or refused other command) and where it points."""
    command: int
    host: str
    port: int
    #: True when the client sent a literal address rather than a name.
    is_address: bool


def parse_request(data: bytes) -> Request:
    """Parse the connect request.

    A domain is kept as a NAME and not resolved here. Resolving it on
    this side would decide the destination from Oddjob's view of DNS,
    and the Ghost is somewhere else entirely -- split-horizon DNS
    inside an estate is the normal case, not the exception, so the
    name is what gets forwarded and the Ghost resolves it where it
    sits. It also means the scope gate rules on the name the operator
    actually asked for.
    """
    if len(data) < 4:
        raise ProtocolError("request too short")
    ver, cmd, _rsv, atyp = data[0], data[1], data[2], data[3]
    if ver != VERSION:
        raise ProtocolError(f"not SOCKS5 (version {ver})")

    rest = data[4:]
    if atyp == ATYP_IPV4:
        if len(rest) < 6:
            raise ProtocolError("ipv4 request truncated")
        host = str(ipaddress.IPv4Address(rest[:4]))
        port = struct.unpack("!H", rest[4:6])[0]
        return Request(cmd, host, port, True)
    if atyp == ATYP_IPV6:
        if len(rest) < 18:
            raise ProtocolError("ipv6 request truncated")
        host = str(ipaddress.IPv6Address(rest[:16]))
        port = struct.unpack("!H", rest[16:18])[0]
        return Request(cmd, host, port, True)
    if atyp == ATYP_DOMAIN:
        if not rest:
            raise ProtocolError("domain request truncated")
        dlen = rest[0]
        if len(rest) < 1 + dlen + 2:
            raise ProtocolError("domain request truncated")
        try:
            host = rest[1:1 + dlen].decode("idna")
        except (UnicodeDecodeError, UnicodeError):
            # Not a name this can represent. Refused rather than
            # guessed at: a mangled host is a host we cannot gate.
            raise ProtocolError("domain is not a usable hostname") from None
        port = struct.unpack("!H", rest[1 + dlen:3 + dlen])[0]
        return Request(cmd, host.lower().rstrip("."), port, False)
    raise ProtocolError(f"unsupported address type {atyp}")


def reply(code: int, host: str = "0.0.0.0", port: int = 0) -> bytes:  # noqa: S104
    """Build a reply.

    The bound address is reported as 0.0.0.0:0 unless the caller knows
    better. Clients do not act on it for CONNECT, and inventing one
    would be telling the client something untrue about our network.
    """
    try:
        packed = ipaddress.ip_address(host)
    except ValueError:
        packed = ipaddress.ip_address("0.0.0.0")  # noqa: S104
    if packed.version == 4:
        return bytes((VERSION, code, 0x00, ATYP_IPV4)) + packed.packed \
            + struct.pack("!H", port)
    return bytes((VERSION, code, 0x00, ATYP_IPV6)) + packed.packed \
        + struct.pack("!H", port)


def reply_for(req: Request) -> int | None:
    """-> a refusal code for a command we will not do, or None to proceed.

    BIND and UDP ASSOCIATE are refused rather than silently ignored.
    Both need the proxy to listen or to relay datagrams on the client's
    behalf, which is a second inbound surface; CONNECT is what a
    browser uses and is the whole of what this is for.
    """
    if req.command == CONNECT:
        return None
    if req.command in (BIND, UDP_ASSOCIATE):
        return CMD_NOT_SUPPORTED
    return CMD_NOT_SUPPORTED
