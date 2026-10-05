"""Classify a scope entry.

The kind is derived, never asked for. A scope document arrives as a pasted
block of a few hundred lines mixing ranges, addresses and names; making a
human tag each one is both tedious and the reason a /24 ends up recorded as
a hostname.

Ambiguity is resolved in the only safe direction: anything that does not
parse cleanly is REJECTED and named back to the caller, rather than being
filed as an FQDN because that is the loosest bucket. A scope list silently
containing a typo'd range is worse than one that refused to load.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .hosts import InvalidHost, validate_host


@dataclass
class Entry:
    kind: str          # cidr | ipv4 | ipv6 | fqdn
    value: str
    included: bool


def classify(raw: str) -> Entry:
    """-> Entry, or raise ValueError naming what is wrong with it.

    A leading '!' or '-' marks an exclusion, which is how scope documents are
    usually written.
    """
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty entry")

    included = True
    if s[0] in "!-" and len(s) > 1:
        included, s = False, s[1:].strip()

    # Strip a protocol and path if somebody pasted a URL; the scope is the
    # host, and rejecting https://x.com for not being a hostname is pedantry.
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0] if ("/" in s and not _looks_like_cidr(s)) else s
    s = s.strip().rstrip(".")
    if not s:
        raise ValueError(f"{raw!r} has no host part")

    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            raise ValueError(f"{raw!r} looks like a range but is not valid: {e}")
        return Entry("cidr", str(net), included)

    # Bare address?
    try:
        ip = ipaddress.ip_address(s)
        return Entry("ipv4" if ip.version == 4 else "ipv6", str(ip), included)
    except ValueError:
        pass

    # Otherwise it must be a well-formed hostname. A wildcard is not a host
    # and is not a range, so it has no place in a target list.
    try:
        host = validate_host(s)
    except InvalidHost as e:
        raise ValueError(str(e))
    if "." not in host:
        raise ValueError(f"{raw!r} is a single label, not a fully-qualified name")
    return Entry("fqdn", host, included)


def classify_many(lines: list[str]) -> tuple[list[Entry], list[str]]:
    """-> (entries, errors). Deduplicates on value, keeping the first.

    Returns both rather than raising: a 400-line paste with two bad lines
    should import the 398 and tell you about the two, not refuse everything.
    """
    out: list[Entry] = []
    errors: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        if not raw.strip():
            continue
        try:
            e = classify(raw)
        except ValueError as err:
            errors.append(str(err))
            continue
        if e.value in seen:
            continue
        seen.add(e.value)
        out.append(e)
    return out, errors


def _looks_like_cidr(s: str) -> bool:
    head, _, tail = s.partition("/")
    return tail.isdigit() and (":" in head or head.replace(".", "").isdigit())
