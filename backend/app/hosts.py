"""What counts as a host.

A target's `host` is the identity of a real, addressable thing: an IP literal
or a DNS hostname. It is NOT a pattern. Wildcard records like `*.acme.example`,
regex fragments and glob characters routinely appear in certificate SANs and
scanner exports, and they are not hosts -- you cannot scan one, it has no
ports, and giving it a row invents an asset that does not exist.

Rejecting them at the door matters more than it looks: `host` is the join key
for services, vulns and PoCs, so one junk host silently becomes a bucket that
unrelated findings accumulate in.
"""
from __future__ import annotations

import ipaddress
import os
import re

# A DNS label: alnum at each end, alnum/hyphen/underscore inside, <=63 chars.
# Underscore is permitted because real zones use it (_dmarc, _acme-challenge).
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")

# Anything outside this set cannot appear in a hostname. Listed explicitly so
# the error message can name the offending character.
_ALLOWED = re.compile(r"^[a-z0-9._-]+$")


class InvalidHost(ValueError):
    pass


#: Names RFC 6761 reserves to mean something other than a host on the
#: internet. `localhost` and anything under it are defined to resolve to
#: the loopback interface; `.invalid` is guaranteed never to exist.
#:
#: `.local` is deliberately NOT here. mDNS owns it, but so does a great
#: many an Active Directory estate -- `corp.local` is somebody's real
#: internal domain and refusing it would throw away a whole engagement's
#: inventory. `.example` is not here either, for the obvious reason: the
#: repository's own fixtures are built on it.
_RESERVED_NAMES = ("localhost", "invalid")


def address_refusal(value: str) -> str | None:
    """Why this IP literal cannot be a target, or None if it can.

    **An address is not automatically an asset.** Scanners, importers
    and reverse lookups all produce addresses that name no machine
    anybody can test, and until this existed every one of them got a
    row. On the live instance that produced a `0.0.0.0` target in a
    real engagement carrying four services and **175 findings** -- a
    bucket that unrelated results accumulated in, which is the exact
    failure the module docstring above describes for wildcards.

    What is refused is "this cannot be a host", never "this is not
    interesting":

      0.0.0.0/8, ::      the unspecified address. `0.0.0.0` means "any"
                         or "unknown" in every tool that emits it, and
                         a scanner writing it is saying it does not
                         know, which is not an address.
      127.0.0.0/8, ::1   loopback. It resolves to whichever machine is
                         asking, so as shared inventory it names a
                         different host for every reader.
      169.254.0.0/16     link-local, including the cloud metadata
      fe80::/10          address. Not routable, and the same value on
                         two links is two different endpoints.
      224.0.0.0/4        multicast. A group, not a host.
      ff00::/8
      240.0.0.0/4        reserved for future use, which is where
                         255.255.255.255 lives. Broadcast is every
                         host, so it is no host.

    **Private ranges are NOT refused**, and that is the point of
    listing the above rather than leaning on `is_global`. An internal
    engagement is the ordinary case here, so 10/8, 172.16/12,
    192.168/16 and 100.64/10 are all perfectly good targets -- as are
    the documentation ranges, which the test fixtures are built on and
    which `is_private` would have swallowed.
    """
    head = (value or "").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(head)
    except ValueError:
        return None          # not an address; not this function's question
    # An IPv4-mapped IPv6 literal is the IPv4 address wearing a hat.
    # `::ffff:127.0.0.1` is loopback, and `is_loopback` on the v6 form
    # says no -- so unwrap before asking anything.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.is_unspecified or (ip.version == 4 and ip in _V4_THIS_NETWORK):
        return (f"{value} is the unspecified address — a scanner writing "
                f"it is saying it does not know, which is not a host")
    if ip.is_loopback:
        if _loopback_allowed():
            return None
        return (f"{value} is loopback: it names whichever machine is "
                f"asking, so it is a different host for every reader")
    if ip.is_link_local:
        # 169.254.169.254 is the one that actually turns up, and it
        # turns up because it is worth reaching -- so the message says
        # where that finding belongs rather than only saying no.
        meant = ("  If you meant the cloud metadata endpoint, the finding "
                 "belongs on the host that can reach it, not on the address "
                 "itself." if ip.version == 4 else "")
        return (f"{value} is link-local: not routable, and the same value on "
                f"two links is two different endpoints.{meant}")
    if ip.is_multicast:
        return f"{value} is multicast — a group, not a host"
    if ip.version == 4 and ip in _V4_RESERVED:
        if ip == _V4_BROADCAST:
            return f"{value} is the broadcast address: every host, so no host"
        return f"{value} is in 240.0.0.0/4, reserved and unroutable"
    return None


def _loopback_allowed() -> bool:
    """Is loopback permitted as a target on this process?

    **This exists for the test suite and nothing else.** `webtest.py`
    replays a request over a real TCP socket to the suite's own API,
    which lives on 127.0.0.1 — the bytes going over a real socket and
    coming back off it is the whole point of those assertions, and
    there is nowhere else for that server to be.

    Read every time rather than cached, so a test can set it and unset
    it, and deliberately covering ONLY loopback. `0.0.0.0`, broadcast,
    multicast, link-local and the reserved ranges are never a host on
    any machine and no switch turns them into one.

    `runtests.py` sets it. Nothing in a deployment should: an operator
    who sets this gets an inventory row that means a different machine
    to every person reading it, which is the thing being prevented.
    """
    return os.environ.get("ODDJOB_ALLOW_LOOPBACK_TARGETS") == "1"


_V4_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_V4_RESERVED = ipaddress.ip_network("240.0.0.0/4")
_V4_BROADCAST = ipaddress.ip_address("255.255.255.255")


def name_refusal(host: str) -> str | None:
    """Why this hostname cannot be a target, or None if it can."""
    labels = host.split(".")
    for reserved in _RESERVED_NAMES:
        if host == reserved or labels[-1] == reserved:
            if reserved == "localhost":
                if _loopback_allowed():
                    return None
                return (f"{host!r} is reserved to mean the loopback "
                        f"interface, so it names a different machine for "
                        f"every reader")
            return f"{host!r} is in .invalid, which is reserved never to exist"
    return None


def normalise_host(raw: str) -> str:
    """Lowercase, trim, drop a trailing root dot. Does not validate.

    A bracketed IPv6 literal loses its brackets. `[2001:db8::1]` and
    `2001:db8::1` are one address, and keeping the brackets made the
    first parse as no address at all -- so a scope check on it
    consulted the NAME list and never the address list. The callers
    that build a host out of a URL or a SOCKS frame strip them
    already; this is the floor under the ones that do not.
    """
    h = (raw or "").strip().rstrip(".").lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def validate_host(raw: str) -> str:
    """Return the normalised host, or raise InvalidHost with a usable reason."""
    h = normalise_host(raw)
    if not h:
        raise InvalidHost("host is empty")
    if len(h) > 253:
        raise InvalidHost(f"host is {len(h)} chars, over the 253 DNS limit")

    # IP literals short-circuit: they legitimately contain ':' and '%'.
    try:
        ipaddress.ip_address(h.split("%", 1)[0])
    except ValueError:
        pass
    else:
        why = address_refusal(h)
        if why:
            raise InvalidHost(why)
        return h

    if not _ALLOWED.match(h):
        bad = sorted({c for c in h if not re.match(r"[a-z0-9._-]", c)})
        raise InvalidHost(
            f"host {raw!r} contains {', '.join(repr(c) for c in bad)} — "
            f"wildcards and patterns are not hosts"
        )
    if ".." in h or h.startswith(".") or h.startswith("-"):
        raise InvalidHost(f"host {raw!r} is not a well-formed hostname")
    if not _HOSTNAME.match(h):
        raise InvalidHost(f"host {raw!r} is not a well-formed hostname")
    why = name_refusal(h)
    if why:
        raise InvalidHost(why)
    return h


def is_valid_host(raw: str) -> bool:
    try:
        validate_host(raw)
        return True
    except InvalidHost:
        return False


#: A cloud resource identifier. Broader than a hostname because that is
#: not what clouds use: an ARN is `arn:aws:s3:::bucket`, an Azure
#: resource id is a slash-separated path, a GCP resource is
#: `projects/p/buckets/b`. Still bounded — no spaces, no wildcards, no
#: shell metacharacters — so it remains something that can be put in a
#: report and a URL without quoting.
_CLOUD_ID = re.compile(r"^[a-z0-9._:/-]+$")


def validate_cloud_id(raw: str) -> str:
    """Normalise a cloud resource identifier, or raise InvalidHost.

    A cloud target is not necessarily a hostname. `mybucket.s3.
    amazonaws.com` is, but `arn:aws:iam::123456789012:role/admin` is
    not, and refusing to record the second because it fails DNS rules
    would mean the engagement's cloud findings have nowhere to live.
    """
    h = (raw or "").strip().lower().rstrip("/")
    if not h:
        raise InvalidHost("identifier is empty")
    if len(h) > 253:
        raise InvalidHost(f"identifier is {len(h)} chars, over the 253 limit")
    if not _CLOUD_ID.match(h):
        bad = sorted({c for c in h if not re.match(r"[a-z0-9._:/-]", c)})
        raise InvalidHost(
            f"cloud identifier {raw!r} contains {', '.join(repr(c) for c in bad)} — "
            f"letters, digits, dot, dash, underscore, colon and slash only")
    if "*" in h or ".." in h:
        raise InvalidHost(f"cloud identifier {raw!r} looks like a pattern, not a resource")
    return h


def dns_subject(kind: str | None) -> bool:
    """Is a target of this kind IDENTIFIED BY a name DNS can be asked about?

    `Target.kind` is `host`, `mobile` or `cloud`, and only the first
    names a thing the DNS knows. This is the one place that says so,
    because the rule was being applied in some paths and not others
    and the two halves disagreed.

    **A cloud resource is named by whatever the provider uses** — an
    ARN, a bucket name, a subscription id, a resource path. It is not
    a hostname, which is why `validate_cloud_id` above exists at all.
    Two shapes, both wrong in their own way:

      `arn:aws:s3:::acme-backups` has no dot, so `registrable()` hands
      it back unchanged. No zone comes of it — but it was still being
      handed to a RESOLVER as a name to look up, which is a query that
      tells whoever answers it the client's resource names and cannot
      come back with anything.

      `backups.storage.example` — a bucket endpoint — is a perfectly
      well-formed hostname and `registrable()` reports
      `storage.example`. That is a zone, it is not the client's, and
      amass was being pointed at it.

    **A mobile app is named by its bundle id** — `com.acme.app`. That
    has dots in it and nothing else in common with a hostname:
    `registrable()` reports `acme.app` quite happily, a zone belonging
    to somebody who has never heard of the engagement. Two call sites
    already excluded mobile by hand for exactly this reason; they call
    this instead now.

    Note what this does NOT say. It is about the identifier in
    `Target.host`, not about the asset. A cloud resource often does
    resolve, and the names DISCOVERED for one — alternate names, TLS
    SANs, the host of a captured URL — are observed facts and remain
    good enumeration material. Only the identifier is untrustworthy as
    a name, so only the identifier is dropped.

    A missing kind reads as `host`. The column carries a server
    default, so "no kind recorded" is an old row from when `host` was
    the only kind there was — that is a known fact, not an unknown
    one.
    """
    return (kind or "host") == "host"
