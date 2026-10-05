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


def normalise_host(raw: str) -> str:
    """Lowercase, trim, drop a trailing root dot. Does not validate."""
    return (raw or "").strip().rstrip(".").lower()


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
        return h
    except ValueError:
        pass

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
