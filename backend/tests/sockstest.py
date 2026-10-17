"""The SOCKS5 proxy: what it parses, and what it refuses.

Mostly about refusals. The protocol half is small; the half worth
testing is that this cannot become an open proxy into a client's
network by accident.
"""

# Run from anywhere: the suites import `app`, which lives one level up.
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

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
