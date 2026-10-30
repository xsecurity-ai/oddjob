"""Telling a shell from somebody scanning the port.

A listener on 443 open to the internet catches both, and on this
fleet the scanners outnumbered the shells four to one within hours
of the port being opened. Every one of them filed a session.

**A reverse shell says nothing until you type at it.** That is the
whole asymmetry this uses: on arrival Oddjob sends one harmless
command and watches what comes back.

Three answers, and the middle one is why this is not a boolean:

    shell    something came back that reads like a command's output
    scanner  what came back is a protocol handshake, not a shell
    silent   nothing came back inside the window

`silent` is NOT "scanner". A real shell can be slow to start, can
be a payload that speaks its own protocol, or can be behind a link
that lost our probe -- so a silent session is kept and shown, with
a marker. Hiding it by default would be the tool deciding that an
absence of evidence is evidence, which is the one judgement this
codebase keeps refusing to make.
"""
from __future__ import annotations

#: What we send. `hostname` because every shell this is likely to
#: catch has it -- cmd.exe and PowerShell included -- and because
#: the answer is useful in its own right: it names the box, which
#: is the first thing an operator wants and the thing a bare
#: address cannot say.
#:
#: CRLF, not LF: a Windows shell wants it and a POSIX shell ignores
#: the carriage return.
PROBE = b"hostname\r\n"

#: How long to wait before calling it silent. Generous, because the
#: cost of being wrong is a real shell marked as noise, and the cost
#: of waiting is a row that reads `pending` for a few more seconds.
WINDOW = 12.0

#: Most of the first response to look at. A classification needs the
#: first few bytes; holding more to decide would be holding a scan's
#: whole payload to answer a question the first line settles.
PEEK = 64

#: The states, in the words the UI shows.
PENDING = "pending"
SHELL = "shell"
SCANNER = "scanner"
SILENT = "silent"

#: Methods that begin an HTTP request. A scanner sweeping 443 sends
#: one of these in cleartext more often than anything else.
_HTTP = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE ",
         b"CONNECT ", b"TRACE ", b"PATCH ")


def classify(first: bytes) -> tuple[str, str]:
    """What the first bytes back from a peer say. -> (state, why).

    Only ever called on the FIRST thing a session produces. Later
    output is a shell talking, whatever it looks like: a `cat` of a
    certificate would otherwise re-classify a live session as a
    scanner halfway through an engagement.
    """
    head = bytes(first[:PEEK])
    if not head:
        return PENDING, ""

    # A TLS record: content type 22 (handshake), then the version as
    # 0x03 0x0n. Checked structurally rather than by guessing at
    # printability, because a ClientHello contains plenty of ASCII
    # (the SNI, for one) and would otherwise read as text.
    if head[0] == 0x16 and len(head) >= 3 and head[1] == 0x03:
        return SCANNER, "sent a TLS handshake, so it is speaking HTTPS at us"

    if any(head.startswith(m) for m in _HTTP):
        line = head.split(b"\r\n", 1)[0][:60].decode("ascii", "replace")
        return SCANNER, f"sent an HTTP request ({line}), not shell output"

    # SSH announces itself before anything else.
    if head.startswith(b"SSH-"):
        return SCANNER, "announced itself as an SSH client"

    # Anything else that is mostly text is taken as a shell. Loose
    # on purpose: the expensive mistake is calling a real shell a
    # scanner, and the two cases above are the ones that actually
    # turn up.
    printable = sum(1 for b in head if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if printable >= max(1, int(len(head) * 0.8)):
        return SHELL, "answered with text"
    return SCANNER, "sent binary that is not shell output"
