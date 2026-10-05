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


@dataclass
class Candidate:
    name: str
    root_domain: str
    source: str
    score: int
    reason: str


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


def _valid(name: str) -> bool:
    if not name or len(name) > 253 or ".." in name:
        return False
    if is_ip(name):
        return False          # candidates are names; addresses are found, not guessed
    # An all-numeric label set is an address in disguise.
    if all(l.isdigit() for l in name.split(".")):
        return False
    return all(_LABEL_RE.match(l) for l in name.split("."))


def _env_variants(label: str) -> list[tuple[str, str, str]]:
    """-> [(variant, replaced word, replacement)] for one label."""
    out = []
    # Match the environment word as a whole token inside the label, so
    # `api-uat` yields `api-dev` but `update` does not yield `dprodate`.
    for group in _ENVIRONMENTS:
        for word in group:
            for pat, repl_fmt in ((rf"(^|[-_.]){re.escape(word)}($|[-_.])", True),):
                if not re.search(pat, label):
                    continue
                for other in sorted(group - {word}):
                    variant = re.sub(pat, lambda m: f"{m.group(1)}{other}{m.group(2)}",
                                     label)
                    if variant != label:
                        out.append((variant, word, other))
    return out


def generate(domain: str, known_hosts: list[str], *, limit: int = 200,
             already: set[str] | None = None) -> list[Candidate]:
    """Candidate hostnames under `domain`, ranked, deduplicated.

    `known_hosts` is every name the project has already seen, from any
    source. `already` is names previously proposed, so a repeat run returns
    what is genuinely new instead of the same list again.
    """
    target_root = (domain or "").strip().rstrip(".").lower()
    if not target_root or is_ip(target_root):
        return []       # you cannot enumerate subdomains of an address
    root = registrable(target_root) or target_root

    # Addresses contribute nothing to naming patterns and actively corrupt
    # them, so they are dropped before anything else looks at the list.
    known = {h.strip().rstrip(".").lower() for h in known_hosts
             if h and h.strip() and not is_ip(h.strip())}
    skip = set(known) | {x.lower() for x in (already or set())} | {target_root}

    # Everything already under the domain in question: these are the shape
    # of its own naming, and the strongest evidence available.
    own_labels: list[str] = []
    for h in known:
        sub = subdomain_of(h, target_root)
        if sub:
            own_labels.append(sub)

    # Every first label used anywhere in the estate, with a count. A label
    # the organisation uses under four domains is a better bet under a
    # fifth than one it used once.
    vocabulary: dict[str, int] = {}
    for h in known:
        r = registrable(h)
        sub = subdomain_of(h, r)
        if sub:
            vocabulary[sub] = vocabulary.get(sub, 0) + 1

    out: dict[str, Candidate] = {}

    def add(name: str, source: str, score: int, reason: str) -> None:
        name = name.strip().rstrip(".").lower()
        if not _valid(name) or name in skip or name in out:
            return
        out[name] = Candidate(name=name, root_domain=target_root,
                              source=source, score=max(0, min(100, score)),
                              reason=reason)

    # 1. Sequences. web01 -> web02/web03; the single most reliable pattern
    #    in a real estate, so it scores highest.
    for sub in own_labels:
        m = _SEQ_RE.match(sub)
        if not m:
            continue
        stem, num = m.group("stem"), m.group("num")
        width = len(num)
        for nxt in range(int(num) + 1, int(num) + 4):
            padded = str(nxt).zfill(width) if num.startswith("0") else str(nxt)
            add(f"{stem}{padded}.{target_root}", "sequence", 85,
                f"{sub}.{target_root} exists; numbering suggests {stem}{padded}")
        if int(num) > 1:
            prev = str(int(num) - 1).zfill(width) if num.startswith("0") else str(int(num) - 1)
            add(f"{stem}{prev}.{target_root}", "sequence", 80,
                f"{sub}.{target_root} exists; numbering suggests {stem}{prev}")

    # 2. Environment swaps on names this domain already has.
    for sub in own_labels:
        for variant, word, other in _env_variants(sub):
            add(f"{variant}.{target_root}", "environment", 75,
                f"{sub}.{target_root} exists; environments often come in sets "
                f"({word} → {other})")

    # 3. Vocabulary the estate demonstrably uses, applied to this domain.
    #    Scored by how many other domains use it.
    for label, count in sorted(vocabulary.items(), key=lambda kv: (-kv[1], kv[0])):
        if label in own_labels:
            continue
        if "." in label:
            # A multi-level label (`a.b` under `root`) is far weaker
            # evidence than a single one; keep it but rank it below.
            score = 30 + min(count * 5, 20)
        else:
            score = 45 + min(count * 8, 35)
        plural = "s" if count != 1 else ""
        add(f"{label}.{target_root}", "label", score,
            f"'{label}' is used under {count} other domain{plural} in this project")

    # 4. Siblings: other registrable domains that already carry this name's
    #    labels. Only when the domain asked about is itself a subdomain.
    parent = registrable(target_root)
    if parent and parent != target_root:
        for h in sorted(known):
            if subdomain_of(h, parent) and not subdomain_of(h, target_root):
                add(h, "sibling", 20, f"already known under {parent}")

    # 5. Seeds, last and lowest. Only worth offering when the estate has
    #    told us little; if it has, its own vocabulary is better.
    if len(out) < limit:
        for label in _SEED_LABELS:
            add(f"{label}.{target_root}", "label", 15,
                "common hostname; not yet seen in this project")

    return sorted(out.values(), key=lambda c: (-c.score, c.name))[:limit]


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
