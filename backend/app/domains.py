"""Suggesting hostnames worth trying, from what the project already knows.

**This sends no packets and performs no lookups.** It reads the estate
already recorded — targets, their alternate hostnames, TLS certificate
names captured by NSE, URLs seen by the web tools — and extrapolates. That
is a deliberate boundary: generating a name is free and reversible, while
resolving or probing one is neither, and the app's active-probe interlock
(see `app/actions.py`) is the thing that governs the second. Keeping them
apart means this can run on any project at any time without anyone having
to think about scope.

What it is good at is the pattern a real estate actually has. Organisations
name machines systematically — `web01/web02`, `api.x/api-uat.x`,
`sso/vpn/mail` recurring under every domain they own — and an operator who
has found `api.corp.com` and `vpn.other.com` can reasonably guess
`vpn.corp.com`. That is the whole idea: harvest the vocabulary the estate
has already demonstrated, then apply it to the domain in question.

What it cannot do is tell you a name exists. Every candidate is a
hypothesis, which is why they land in their own table with a reason
attached and have to be promoted deliberately.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

#: Two-level public suffixes common enough to matter. Not a full PSL —
#: pulling one in for this would be a dependency and a data-freshness
#: problem, and being wrong here costs a slightly odd root domain, not a
#: packet. Anything unlisted falls back to the last two labels.
_TWO_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "lg.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "com.cn", "com.sg", "com.hk", "com.tw", "com.mx", "com.ar",
    "co.in", "co.za", "co.kr", "com.tr", "com.pl", "com.ua",
}

#: Environment words that swap for one another. Seeded with the obvious
#: ones and extended at runtime by whatever the estate actually uses.
_ENVIRONMENTS = [
    {"prod", "production", "prd", "live"},
    {"dev", "develop", "development"},
    {"uat", "qa", "test", "tst", "staging", "stage", "stg", "preprod", "ppe"},
    {"dr", "backup", "standby"},
    {"int", "internal", "intranet"},
    {"ext", "external"},
]

#: Applied to a domain when the estate has shown us nothing to go on. Kept
#: short on purpose: a 2,000-word brute list belongs in a resolver, not in
#: a suggestion table a human has to read.
_SEED_LABELS = [
    "www", "mail", "vpn", "sso", "api", "portal", "remote", "citrix",
    "owa", "autodiscover", "webmail", "ftp", "git", "jenkins", "jira",
    "confluence", "admin", "dev", "uat", "test", "staging", "intranet",
    "extranet", "gateway", "proxy", "cdn", "static", "assets", "app",
]

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_SEQ_RE = re.compile(r"^(?P<stem>.*?)(?P<num>\d+)$")


def is_ip(host: str) -> bool:
    """An address is not a name, and must never be treated as one.

    `registrable("10.0.0.5")` used to return "0.5" — the last two
    dot-separated labels — which then appeared in the root-domain list and
    contributed "10.0" to the label vocabulary, producing candidates like
    `10.0.corp.com`. Splitting on dots does not distinguish the two, so
    this does.
    """
    try:
        ipaddress.ip_address((host or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def registrable(host: str) -> str:
    """Best-effort registrable domain, or "" for an address."""
    h = (host or "").strip().rstrip(".").lower()
    if is_ip(h):
        return ""
    labels = [l for l in h.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_of(host: str, root: str) -> str | None:
    """The part of `host` in front of `root`, or None if it is not under it.

    Suffix matching is anchored on a label boundary. `notcorp.com` must not
    count as a subdomain of `corp.com`, and a plain `endswith` says it does
    — the same identity-anchoring mistake that bites hostname matching
    everywhere else.
    """
    h = (host or "").strip().rstrip(".").lower()
    r = (root or "").strip().rstrip(".").lower()
    if not h or not r or h == r:
        return "" if h == r and h else None
    if not h.endswith("." + r):
        return None
    return h[: -len(r) - 1]


def roots_in(hosts: list[str]) -> list[tuple[str, int]]:
    """Registrable domains present, commonest first. Drives the UI's
    suggestions for which domain to run against next."""
    counts: dict[str, int] = {}
    for h in hosts:
        if is_ip((h or "").strip()):
            continue
        r = registrable(h or "")
        if r and "." in r:
            counts[r] = counts.get(r, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
