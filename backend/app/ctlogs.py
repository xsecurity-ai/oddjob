"""Names from Certificate Transparency, and the gate in front of them.

Every hostname Oddjob holds today came from a certificate **it
fetched**: `certnames.py` reads httpx's TLS block and nmap's
`ssl-cert`, so we only ever learn the names of hosts we had already
found. CT inverts that. Every publicly-trusted certificate issued for
a domain is in a public log, including ones for hosts that never
resolved, hosts long dead whose infrastructure is still up, and the
`uat-`, `jenkins-`, `vpn-` names nobody links to. On an external
engagement that is routinely where the thing nobody else found comes
from.

# Why this is off by default, and stays off until somebody says

Asking a CT aggregator "which certificates exist for acme.example"
**sends the client's domain to a third party**. That is not a
hypothetical: it is a query, logged at the other end, naming who we
are testing and when we started.

Semgrep's policy is that customer data does not go to an external
service before that service is approved, and an engagement signoff
covers testing the client, not onboarding a vendor. So:

- `ct.enabled` defaults to False and nothing here will run without it.
- The setting's help text says, in the place somebody turns it on,
  exactly what leaves and where it goes.
- `source` is explicit rather than a default buried in code, because
  "which third party" is the whole question being answered.

The alternative design -- stream the logs in bulk and filter locally,
so no query ever names the client -- is the OPSEC-clean one and is
noted in `STREAMING` below. It is not implemented: the public logs
run to millions of certificates a day and an engagement tool is not
where that pipeline belongs. Saying so plainly is better than
shipping a half version of it.

# What comes back is a proposal, not an estate

Names found here are **reported, never created**. A CT log for a
shared or wildcard certificate names hosts belonging to other
people, and a name in a log is not evidence that anybody agreed to
be scanned. Everything goes through `scopegate` and anything it
refuses is listed for a person, which is the same shape as a strict
import.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

#: Where a lookup may be sent. One entry, named rather than defaulted,
#: so turning this on is a choice about a specific third party.
SOURCES: dict[str, str] = {
    "crt.sh": "https://crt.sh/?q=%25.{domain}&output=json",
}

#: Not implemented, and here so the next person does not have to
#: rediscover why. Google, Cloudflare and the other log operators
#: serve the logs themselves over RFC 6962, so a client's domain need
#: never be sent anywhere: you pull entries in bulk and match offline.
#: It is the right answer for OPSEC and the wrong one for this
#: program -- the logs issue millions of certificates a day, so it
#: means a continuously-running ingest and a persisted index, which
#: is a service and not a feature of a scanner.
STREAMING = "rfc6962 bulk ingest — see the module docstring"

TIMEOUT = httpx.Timeout(60.0, connect=15.0)

#: A log entry's name field can hold junk, an email address, or a
#: wildcard. Same rules certnames.py applies, for the same reason.
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                   r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


class Disabled(RuntimeError):
    """Raised when a lookup is attempted with the gate shut.

    Its own type so a caller cannot mistake it for a network failure
    and retry. The answer to this is a person deciding, not a backoff.
    """


@dataclass
class Found:
    """What one lookup learned, before anything is written."""
    domain: str
    source: str
    #: Every distinct name the log returned, cleaned and lowercased.
    names: list[str] = field(default_factory=list)
    #: Names the log returned that are not usable hostnames at all.
    #: Counted rather than listed -- it is a fact about the log, not
    #: about the client.
    unusable: int = 0
    #: Said plainly when the lookup could not be made, so "found
    #: nothing" and "could not ask" stay different answers.
    error: str | None = None


def enabled(cfg: dict) -> bool:
    """Whether CT lookups may be made at all.

    `cfg` is the settings mapping, as `routers.settings.load_all`
    returns it -- the same shape `geoip.enabled` reads. Default
    False, and the default is the point: an installation that has
    never thought about this sends nothing.
    """
    return bool(cfg.get("ct.enabled"))


def source_url(cfg: dict) -> tuple[str, str] | None:
    """-> (source name, url template), or None if not configured."""
    name = str(cfg.get("ct.source") or "").strip()
    if name not in SOURCES:
        return None
    return name, SOURCES[name]


def clean(raw) -> tuple[list[str], int]:
    """Log name fields -> usable hostnames, and a count of the rest.

    A certificate's name list carries wildcards, the occasional email
    address, and free text. A wildcard contributes its bare domain --
    `*.acme.example` is evidence that `acme.example` exists -- and
    nothing else is invented from it.
    """
    out: list[str] = []
    seen: set[str] = set()
    bad = 0
    for item in raw:
        for part in str(item or "").replace(",", "\n").split("\n"):
            n = part.strip().lower().rstrip(".")
            if not n:
                continue
            if n.startswith("*."):
                n = n[2:]
            if "@" in n or " " in n or not _HOST.match(n):
                bad += 1
                continue
            if n not in seen:
                seen.add(n)
                out.append(n)
    return sorted(out), bad


async def lookup(cfg: dict, domain: str) -> Found:
    """Ask the configured source what certificates name `domain`.

    **This sends `domain` to a third party.** The gate is checked
    here rather than only at the caller, so there is one place that
    can be audited for it.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return Found(domain=domain, source="", error="no domain given")
    if not enabled(cfg):
        raise Disabled(
            "Certificate Transparency lookups are off. Turning them on sends "
            "this engagement's domain names to a third party, which needs to "
            "be an explicit decision — see Site settings.")
    picked = source_url(cfg)
    if picked is None:
        raise Disabled(
            "No Certificate Transparency source is configured. Choose one in "
            "Site settings; the choice is which third party the domain goes "
            f"to, and the options are: {', '.join(SOURCES)}.")
    name, template = picked

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT,
                                     follow_redirects=True) as c:
            r = await c.get(template.format(domain=d))
            r.raise_for_status()
            rows = r.json()
    except (httpx.HTTPError, ValueError, OSError) as e:
        # Reported, not raised. A source that is down is a fact about
        # the tool and must not read as "this domain has no
        # certificates", which is the one way this feature could
        # actively mislead.
        return Found(domain=d, source=name,
                     error=f"{name} could not be asked: {e}")

    if not isinstance(rows, list):
        return Found(domain=d, source=name,
                     error=f"{name} returned something that is not a list")
    raw = []
    for row in rows:
        if isinstance(row, dict):
            raw.append(row.get("name_value") or "")
            raw.append(row.get("common_name") or "")
    names, bad = clean(raw)
    return Found(domain=d, source=name, names=names, unusable=bad)
