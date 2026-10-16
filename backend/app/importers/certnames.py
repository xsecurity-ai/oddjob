"""What a certificate says it is valid for, as hostnames we can keep.

Two importers read certificates -- `httpx_json` from httpx's `tls`
block and `nmap` from the `ssl-cert` NSE script -- and both turn the
subject and the subject alternative names into `ParsedHost.hostnames`.
They agree on the rule because the rule lives here and not in each of
them. Two copies of "is this a usable name" drifting apart is how one
importer ends up creating `*.example.com` as a host.

**The rule, and why each clause is in it:**

* Lowercased and trailing-dot stripped, because `WWW.Example.COM.`
  and `www.example.com` are the same name and anything that compares
  them as strings -- which is everything downstream -- must see one
  spelling.
* A wildcard contributes its bare domain and nothing else.
  `*.example.com` means the certificate is good for every subdomain,
  which is a fact about `example.com`; the literal `*.example.com` is
  not a host, cannot be resolved, and must never become one. A lone
  `*` contributes nothing at all.
* Anything still holding a `*`, a space, or no dot is dropped. These
  are not hostnames: certificates in the wild carry free text in the
  CN field ("Internal CA", "localhost"), and a scanner that queued
  them would be looking up garbage against a client's resolver.
* IP entries in a SAN list are skipped. They are addresses and belong
  in the address columns; putting one in `hostnames` makes a host
  look like it has a name it does not have.

  Decided by PARSING the value, not by the `IP Address:` label nmap
  puts in front of it. The label is one renderer's convention and
  httpx's list form has no label at all, so a bare `10.0.0.1` would
  otherwise pass every other clause in this list -- it has dots, no
  space and no wildcard -- and be filed as a hostname.

**What callers must not do with the result.** These are alternate
names for a host that ALREADY EXISTS, never new targets. A shared or
CDN-issued certificate names hundreds of other people's hosts, and
creating targets from a SAN list would be scanning assets nobody
cleared. `roots.py` already mines `hostnames` for zones worth
enumerating; promoting one to a target stays a decision somebody
makes.
"""
from __future__ import annotations

import ipaddress

#: SAN entries are typed, and only DNS entries are names. nmap renders
#: them as `DNS:a.example.com, IP Address:10.0.0.1`. The prefix is
#: stripped where it is present, but it is NOT what decides whether a
#: value is an address -- see `_is_address`.
_DNS_PREFIX = "dns:"
_IP_PREFIXES = ("ip address:", "ip:")


def _is_address(value: str) -> bool:
    """Is this an IP literal rather than a name?

    Asked of the value itself so the answer does not depend on which
    tool rendered it. `10.0.0.1` and `IP Address:10.0.0.1` and
    `2001:db8::1` are all addresses; `10.0.0.1.example.com` is not,
    and that is the case a cheaper check gets wrong.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def clean_name(value: object) -> str | None:
    """One candidate name -> a usable hostname, or None.

    None means "this was not a hostname", which is a different answer
    from "" and is why this returns an option rather than a string.
    """
    if value is None:
        return None
    name = str(value).strip().lower().rstrip(".")
    if name.startswith("*."):
        # The wildcard's bare domain is the real fact here.
        name = name[2:]
    if not name or "*" in name or " " in name or "." not in name:
        return None
    if _is_address(name):
        return None
    return name


def san_names(value: object) -> list[str]:
    """A SAN field -> the hostnames in it, in order, deduplicated.

    Accepts both shapes the importers see: a list (httpx gives one)
    and nmap's single comma-joined string of typed entries.
    """
    if value is None:
        return []
    parts: list[str] = []
    if isinstance(value, (list, tuple, set)):
        parts = [str(v) for v in value]
    else:
        parts = str(value).split(",")

    out: list[str] = []
    for part in parts:
        p = part.strip()
        low = p.lower()
        if any(low.startswith(x) for x in _IP_PREFIXES):
            continue          # an address, not a name
        if low.startswith(_DNS_PREFIX):
            p = p[len(_DNS_PREFIX):]
        if (name := clean_name(p)) and name not in out:
            out.append(name)
    return out


def add_names(host, names) -> int:
    """Append to `host.hostnames` without reordering or duplicating.

    Returns how many were new, which is the number worth logging. The
    existing order is kept because the first entry is the one the
    scanner considered primary.
    """
    added = 0
    for n in names:
        if n and n not in host.hostnames:
            host.hostnames.append(n)
            added += 1
    return added
