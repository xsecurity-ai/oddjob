"""The frames that carry a proxied stream down to a Ghost.

One WebSocket per Ghost, many streams multiplexed over it. The Ghost
dials OUT to hold it open, because that is the only direction that
works: a Ghost sits behind NAT with nothing exposed, which is the
whole reason the agent model is poll-and-callback rather than the
server reaching in.

# The frame

    byte 0      type
    bytes 1..4  stream id, uint32 big-endian
    bytes 5..   payload

Fixed five-byte header, so a reader never has to parse to know how
much to skip. Big-endian because every other length on the wire here
is -- SOCKS5 ports, the TLS record header -- and mixing endianness
inside one program is how a field gets read backwards once.

# Why a codec and not just `json.dumps`

This carries the body of somebody's HTTP traffic. JSON would base64
every byte of it for a 33% tax on a path that is already relaying a
browser session, and would turn a binary stream into a text one for
no reason. The frames are bytes.

**This module does no I/O.** Same reason as `socks.py`: the part that
decides what a frame means is a pure function with tests, and the
socket work lives in whatever drives it. The Go half is
`ghost/internal/socksrelay`, and `VECTORS` below is shared between
the two test suites so a disagreement is a failing test rather than a
hung stream.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

HEADER = 5
#: A stream id is the server's to allocate; the Ghost only ever echoes
#: one back. Two sides allocating into one space is how you get a
#: collision that looks like data corruption.
MAX_STREAM = 0xFFFFFFFF

#: Server -> Ghost. "Dial this and tell me how it went."
OPEN = 0x01
#: Ghost -> server. The dial succeeded.
OPENED = 0x02
#: Ghost -> server. It did not; payload is the reason, for the
#: operator, not for the client -- a SOCKS reply has five codes and
#: none of them say "DNS said NXDOMAIN".
FAILED = 0x03
#: Either direction. Payload is stream bytes, verbatim.
DATA = 0x04
#: Either direction. Half-close is not modelled: a proxied TCP stream
#: that is done one way is, in practice, done.
CLOSE = 0x05
#: Agent -> server only: something connected to a port the agent is
#: listening on. A proxy stream starts because this server asked for
#: a destination; a shell stream starts because a callback arrived,
#: which the server could not have asked for and learns no other way.
#: Payload is the peer address as the agent saw it.
ARRIVED = 0x06

TYPES = (OPEN, OPENED, FAILED, DATA, CLOSE, ARRIVED)

#: Biggest payload in one frame. Not a protocol limit -- it is a cap
#: on how much a single misbehaving stream can make the other side
#: allocate before anybody has read a byte.
MAX_PAYLOAD = 1 << 20


class FrameError(Exception):
    """The bytes are not a frame this understands.

    The caller drops the whole tunnel rather than the frame. A
    multiplexer that has lost framing cannot know where the next
    frame starts, so carrying on would mean feeding one stream's
    bytes to another.
    """


@dataclass(frozen=True)
class Frame:
    kind: int
    stream: int
    payload: bytes = b""


def encode(kind: int, stream: int, payload: bytes = b"") -> bytes:
    if kind not in TYPES:
        raise FrameError(f"unknown frame type {kind}")
    if not 0 <= stream <= MAX_STREAM:
        raise FrameError("stream id out of range")
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("payload over the cap")
    return struct.pack("!BI", kind, stream) + payload


def decode(raw: bytes) -> Frame:
    if len(raw) < HEADER:
        raise FrameError("frame shorter than its header")
    kind, stream = struct.unpack("!BI", raw[:HEADER])
    if kind not in TYPES:
        raise FrameError(f"unknown frame type {kind}")
    payload = raw[HEADER:]
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("payload over the cap")
    return Frame(kind, stream, payload)


def encode_open(stream: int, host: str, port: int) -> bytes:
    """OPEN carries the destination as a NAME where it is one.

    The Ghost resolves it, for the reason `socks.py` gives: it is
    somewhere else, and split-horizon DNS inside an estate is the
    normal case rather than the exception.
    """
    if not 0 < port < 65536:
        raise FrameError("port out of range")
    h = host.encode("utf-8")
    if len(h) > 253:
        raise FrameError("host too long")
    return encode(OPEN, stream, struct.pack("!H", port) + h)


def decode_open(f: Frame) -> tuple[str, int]:
    if f.kind != OPEN:
        raise FrameError("not an OPEN frame")
    if len(f.payload) < 3:
        raise FrameError("OPEN frame truncated")
    port = struct.unpack("!H", f.payload[:2])[0]
    try:
        host = f.payload[2:].decode("utf-8")
    except UnicodeDecodeError as e:
        raise FrameError("OPEN host is not utf-8") from e
    if not 0 < port < 65536:
        raise FrameError("port out of range")
    return host, port


#: Shared with the Go suite, which encodes the same rows and compares
#: against these bytes. A codec that two languages implement from one
#: paragraph of prose is a codec that disagrees in production; this is
#: the cheapest way to find out at build time instead.
VECTORS: tuple[tuple[str, int, int, bytes, str], ...] = (
    # label, kind, stream, payload, expected hex
    ("open stream 1", OPEN, 1, struct.pack("!H", 443) + b"a.example",
     "0100000001" + "01bb" + "612e6578616d706c65"),
    ("opened", OPENED, 1, b"", "0200000001"),
    ("failed with a reason", FAILED, 2, b"no route",
     "0300000002" + "6e6f20726f757465"),
    ("data", DATA, 3, b"\x00\xff", "040000000300ff"),
    ("close", CLOSE, 4, b"", "0500000004"),
    ("a callback arrived", ARRIVED, 5, b"203.0.113.9:51234",
     "0600000005" + "3230332e302e3131332e393a3531323334"),
    # The boundary that catches a signed/unsigned mistake in either
    # language: a stream id with the top bit set.
    ("high stream id", DATA, 0xFFFFFFFF, b"x", "04ffffffff78"),
)
