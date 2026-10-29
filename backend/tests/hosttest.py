"""What may be a target, asserted against the predicate itself.

Everything else in the suite drives the HTTP API, and that is usually
right. It is wrong here for one reason: `runtests.py` sets
`ODDJOB_ALLOW_LOOPBACK_TARGETS` so that `webtest.py` can replay a
request over a real socket to the suite's own API on 127.0.0.1. With
that switch on, the server cannot demonstrate what it does with the
switch off -- which is the behaviour an operator actually gets.

So this calls `hosts` directly with the switch cleared. No server, no
database, no port.
"""
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# Cleared before the import so nothing reads it on the way in, and
# because every assertion below is about the deployment default.
os.environ.pop("ODDJOB_ALLOW_LOOPBACK_TARGETS", None)

from app.hosts import (  # noqa: E402
    InvalidHost,
    address_refusal,
    name_refusal,
    validate_host,
)

passed = failed = 0


def check(label, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" {got}" if got is not None else ""))


def refused(host):
    try:
        validate_host(host)
        return None
    except InvalidHost as e:
        return str(e)


print("== addresses that are not hosts ==")
# Each is refused for being impossible, not for being uninteresting,
# and the message has to say which impossible thing it is -- an
# operator who typed 0.0.0.0 and one who typed 224.0.0.1 have made
# different mistakes.
CASES = [
    ("0.0.0.0", "unspecified"),
    ("0.1.2.3", "unspecified"),
    ("::", "unspecified"),
    ("127.0.0.1", "loopback"),
    ("127.1.2.3", "loopback"),
    ("::1", "loopback"),
    # The v4 address wearing a v6 hat. `is_loopback` on the v6 form
    # says no, so this only works if the mapping is unwrapped first.
    ("::ffff:127.0.0.1", "loopback"),
    ("169.254.169.254", "link-local"),
    ("fe80::1", "link-local"),
    ("224.0.0.1", "multicast"),
    ("239.255.255.250", "multicast"),
    ("ff02::1", "multicast"),
    ("255.255.255.255", "broadcast"),
    ("240.0.0.1", "240.0.0.0/4"),
]
for host, word in CASES:
    why = refused(host)
    check(f"{host} is refused", why is not None, why)
    check(f"...and said to be {word}", why is not None and word in why, why)

print("\n== and the ones that must still get through ==")
# The point of listing the categories above rather than leaning on
# `is_global`: an internal engagement is the ordinary case here, and
# the repository's own fixtures live in the documentation ranges.
for host in ("10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254",
             "192.168.1.5", "100.64.0.1",
             # The three documentation ranges. CLAUDE.md requires
             # fixtures to use these, so refusing one would make the
             # rule the repository runs on unimplementable.
             "192.0.2.1", "198.51.100.9", "203.0.113.5",
             "8.8.8.8", "1.1.1.1", "223.255.255.254",
             "2001:db8::1", "2600::1",
             "acme.example", "a.b.c.acme.example", "example.co.uk",
             # Underscore labels are real zone entries.
             "_dmarc.acme.example",
             # `.local` is mDNS AND a great many Active Directory
             # estates. Refusing it would throw away an engagement's
             # whole inventory.
             "corp.local", "dc01.corp.local"):
    check(f"{host} is a host", refused(host) is None, refused(host))

print("\n== names reserved to mean something other than a host ==")
check("localhost is refused", refused("localhost") is not None)
check("...and so is anything under it", refused("api.localhost") is not None)
check("...for being reserved, not for its shape",
      "reserved" in (refused("localhost") or ""), refused("localhost"))
check(".invalid is refused, being reserved never to exist",
      refused("nothing.invalid") is not None)
check("...and says so", "invalid" in (refused("nothing.invalid") or ""),
      refused("nothing.invalid"))
# The two that look like they belong above and must not.
check("`.example` is NOT refused — the fixtures are built on it",
      refused("acme.example") is None)
check("`.local` is NOT refused — it is somebody's AD domain",
      refused("corp.local") is None)

print("\n== the predicates answer only their own question ==")
check("address_refusal says nothing about a name",
      address_refusal("acme.example") is None)
check("...nor about empty input", address_refusal("") is None)
check("name_refusal says nothing about an address",
      name_refusal("10.0.0.1") is None)
# A zone id names which interface a link-local address is on. It must
# not stop the address being recognised in the first place.
check("a zone id does not hide a link-local address",
      address_refusal("fe80::1%eth0") is not None,
      address_refusal("fe80::1%eth0"))

print("\n== the switch, and how far it reaches ==")
os.environ["ODDJOB_ALLOW_LOOPBACK_TARGETS"] = "1"
try:
    check("with the harness switch on, loopback is allowed",
          refused("127.0.0.1") is None)
    check("...and so is localhost", refused("localhost") is None)
    # The whole point of scoping it. These are not a host on any
    # machine, so no switch turns them into one.
    for host in ("0.0.0.0", "255.255.255.255", "224.0.0.1",
                 "169.254.169.254", "240.0.0.1"):
        check(f"...but {host} is still refused", refused(host) is not None,
              refused(host))
finally:
    os.environ.pop("ODDJOB_ALLOW_LOOPBACK_TARGETS", None)
check("and clearing it puts loopback back", refused("127.0.0.1") is not None)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
