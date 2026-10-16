"""Which countries may be scanned, for a project and for each ghost.

Two independent gates, both off by default:

    Project.scan_countries   where this ENGAGEMENT is authorised to
                             test. An empty value means everywhere,
                             which is what every project has until
                             somebody says otherwise.

    Agent.scan_countries     where this GHOST is willing to send
                             packets from itself. Empty means it will
                             take work anywhere.

They answer different questions and both have to say yes. An
engagement authorised in the UK does not become authorised in Japan
because a ghost is willing; a ghost that may only touch JP hosts does
not acquire permission because the engagement is global.

**This needs MaxMind and is off without it.** The country of a target
is `TargetAddress.geo_country`, filled by a local GeoLite2 lookup --
see `app/geoip.py`. With no database there is no country, so there is
nothing to gate on and the controls are greyed out in the UI rather
than silently ignored. `geoip.enabled()` is the one test for that.

**Why it is local, and why that matters here.** The obvious way to
build this is to ask a geolocation API. That means sending a client's
addresses to a third party, one request per host, which is the thing
an engagement's confidentiality rules exist to prevent -- and it
fails exactly when you lean on it: a rate-limited lookup returns no
country, and a gate that reads "no country" as "allowed" quietly
authorises everything the moment the service throttles you. The
lookups here never leave the machine.

**Three outcomes, never two.** This is the rule the whole module is
shaped around:

    ALLOWED   the country is known and permitted
    REFUSED   the country is known and not permitted
    UNKNOWN   we could not determine the country

UNKNOWN is **not** a pass. A host whose country we cannot establish
has not been shown to be in an authorised country, and treating it as
one is how a geographic restriction becomes decorative. It is also
not the same as REFUSED, and the reason says which it was, because
"we have not located this yet" is a gap somebody can close and "this
is in a country you excluded" is a finished answer.

The one case where UNKNOWN passes is when no restriction is in force
at all: with no list to check against there is no question to fail.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Returned when a gate has nothing to say, so callers never branch on
#: None. `allowed` is True because an empty restriction is not a
#: restriction -- see the module docstring.
OFF_REASON = "no country restriction is set"


@dataclass(frozen=True)
class CountryRuling:
    allowed: bool
    #: ALLOWED | REFUSED | UNKNOWN | OFF. Distinct so a caller can tell
    #: "excluded" from "not located yet", which want different things
    #: done about them.
    state: str
    reason: str


def parse(raw: str | None) -> set[str]:
    """`"jp, GB ,,us"` -> `{"JP", "GB", "US"}`.

    Upper-cased and de-blanked because the value is typed by a person
    and compared against MaxMind's codes, which are upper case. A
    stray empty segment from a trailing comma must not become an
    entry that matches nothing and silently narrows the list to
    nothing.
    """
    if not raw:
        return set()
    return {p.strip().upper() for p in raw.split(",") if p.strip()}


def render(codes) -> str | None:
    """The inverse, normalised. None when empty, so the column stays NULL."""
    out = sorted({str(c).strip().upper() for c in (codes or []) if str(c).strip()})
    return ",".join(out) or None


def check(allowed: set[str], country: str | None, *,
          what: str = "this host") -> CountryRuling:
    """Decide one host against one list.

    `country` is `TargetAddress.geo_country`, or None when the address
    has never been located or MaxMind had no answer for it (private
    ranges, most often).
    """
    if not allowed:
        return CountryRuling(True, "OFF", OFF_REASON)
    if not country:
        return CountryRuling(
            False, "UNKNOWN",
            f"{what} has no known country, and a country restriction is in "
            f"force — locate it, or widen the list. Not the same as being "
            f"excluded: nothing has placed it anywhere yet.")
    c = country.strip().upper()
    if c in allowed:
        return CountryRuling(True, "ALLOWED", f"{what} is in {c}, which is allowed")
    return CountryRuling(
        False, "REFUSED",
        f"{what} is in {c}, which is not in the allowed list "
        f"({', '.join(sorted(allowed))})")


def countries_of(target) -> list[str]:
    """Every country this target answers in, from its located addresses.

    A list, not one value. An anycast or CDN-fronted host genuinely
    answers in several countries at once, and collapsing that to the
    first would let a host pass on the strength of a country it also
    is not in.
    """
    out: list[str] = []
    for a in getattr(target, "addresses", None) or []:
        c = getattr(a, "geo_country", None)
        if c and c not in out:
            out.append(c)
    return out


def check_target(allowed: set[str], target, *, what: str | None = None
                 ) -> CountryRuling:
    """Decide a target with several addresses.

    **Every** country it answers in must be allowed, not merely one of
    them. A host that answers in both GB and JP is being scanned in
    Japan too, whatever the first address said, so "any match passes"
    would authorise exactly the traffic the list was drawn to prevent.

    An unlocated address counts as unknown for the same reason: the
    set of countries this host is in is not yet established.
    """
    label = what or getattr(target, "host", None) or "this host"
    if not allowed:
        return CountryRuling(True, "OFF", OFF_REASON)
    addrs = list(getattr(target, "addresses", None) or [])
    if not addrs:
        return CountryRuling(
            False, "UNKNOWN",
            f"{label} has no address yet, so there is no country to check "
            f"against the restriction in force")
    found = countries_of(target)
    if any(not getattr(a, "geo_country", None) for a in addrs):
        return CountryRuling(
            False, "UNKNOWN",
            f"{label} has an address that has not been located"
            + (f" (others are in {', '.join(found)})" if found else "")
            + " — locate it, or widen the list")
    bad = sorted({c for c in found if c not in allowed})
    if bad:
        return CountryRuling(
            False, "REFUSED",
            f"{label} answers in {', '.join(bad)}, which "
            f"{'is' if len(bad) == 1 else 'are'} not in the allowed list "
            f"({', '.join(sorted(allowed))})")
    return CountryRuling(True, "ALLOWED",
                         f"{label} answers only in {', '.join(found)}")


# ------------------------------------------------------------- database
#
# Resolving a task's targets to countries costs a query, and
# `_may_claim` runs on every poll for every waiting task. So the
# callers below are written to be skipped entirely when no
# restriction is in force -- which is every project and every agent
# until somebody sets one, and will stay the common case.


async def countries_for(session, project_id: int, hosts) -> dict[str, list[str]]:
    """host or address -> the countries it is known to answer in.

    A host absent from the result, or present with an empty list, has
    not been located. Those are different from each other only in
    bookkeeping; both mean "no country known" to a caller, and both
    must be treated as UNKNOWN rather than allowed.

    Two ways in, because a task's target may be either spelling: the
    address itself (`nmap 1.2.3.4`) or a name the project has
    recorded addresses against (`nmap host.example`).
    """
    from sqlalchemy import select

    from .models import Target, TargetAddress, target_address_links

    wanted = {h.strip().lower() for h in hosts if h and h.strip()}
    if not wanted:
        return {}
    out: dict[str, list[str]] = {}

    def add(key: str, country: str | None) -> None:
        if not country:
            out.setdefault(key, [])
            return
        seen = out.setdefault(key, [])
        if country not in seen:
            seen.append(country)

    # The address spelling.
    for addr, country in (await session.execute(
            select(TargetAddress.address, TargetAddress.geo_country)
            .where(TargetAddress.project_id == project_id,
                   TargetAddress.address.in_(wanted)))).all():
        add(addr.lower(), country)

    # The name spelling, through the link table -- a name may have
    # several addresses and each has its own country.
    for host, country in (await session.execute(
            select(Target.host, TargetAddress.geo_country)
            .join(target_address_links,
                  target_address_links.c.target_id == Target.id)
            .join(TargetAddress,
                  TargetAddress.id == target_address_links.c.address_id)
            .where(Target.project_id == project_id,
                   Target.host.in_(wanted)))).all():
        if host:
            add(host.lower(), country)
    return out


async def check_task(session, project, agent, args) -> CountryRuling:
    """Both gates against every host a task would touch.

    Returns the FIRST refusal rather than a summary: the caller is
    deciding whether to hand over one task, and one barred host is
    enough to answer that. The reason names which gate and which host,
    because "refused" with no subject is the kind of log line that
    gets ignored.
    """
    from .scopegate import as_host, task_hosts

    proj = parse(getattr(project, "scan_countries", None))
    ghost = parse(getattr(agent, "scan_countries", None)) if agent else set()
    if not proj and not ghost:
        return CountryRuling(True, "OFF", OFF_REASON)

    hosts = [as_host(h) or h for h in task_hosts(args)]
    if not hosts:
        # A task naming no host touches nothing this gate can speak
        # for. Not a refusal -- the scope gate has the same shape and
        # the same reasoning.
        return CountryRuling(True, "OFF", "the task names no host")

    found = await countries_for(session, project.id, hosts)
    for h in hosts:
        got = found.get(h.lower())
        if not got:
            return CountryRuling(
                False, "UNKNOWN",
                f"{h} has no known country, and a country restriction is in "
                f"force — locate it, or widen the list")
        for c in got:
            for allowed, who in ((proj, "this engagement"), (ghost, "this ghost")):
                if not allowed:
                    continue
                r = check(allowed, c, what=h)
                if not r.allowed:
                    return CountryRuling(
                        r.allowed, r.state, f"{r.reason} for {who}")
    return CountryRuling(True, "ALLOWED",
                         "every host is in a country both gates allow")
