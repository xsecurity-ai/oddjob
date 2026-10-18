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
