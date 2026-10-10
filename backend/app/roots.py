"""Which registrable zones a project could enumerate under.

One implementation, deliberately, because there were two and they
disagreed — which is the failure this module exists to end.

The "Search for more domains" dialog asked `/domains/roots`, which
derives zones from every hostname the project has seen and from the
scope entries, both `fqdn` and `wildcard`. The `auto_amass` standing
order asked its own snapshot, which derived them from `Target.host`
alone and read only `wildcard` scope rows. So the dialog kept
offering zones the standing order could not see, and an operator with
the toggle on still found work waiting every time they looked.

On a real engagement that was not a corner case. One project had
three scope entries, all of kind `fqdn` and no wildcards at all, so
the standing order's scope list was empty: the only authorised
domains in the project were invisible to the automation meant to
enumerate them. Separately, 626 of its 1,038 targets carried
alternate names or TLS SANs that only the dialog's wider sweep read.

`tasked_subjects` carries the same warning for the same reason — two
implementations of "has this been done" would disagree, invisibly.
This is that lesson applied to "what is there to do".
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import domains as gen
from .models import ProjectScope, Target, WebAddress

#: Hostnames embedded in free text — certificate SANs, mostly.
_NAME_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                      r"[a-z]{2,24}\b", re.I)


def names_in(text: str) -> set[str]:
    return {m.group(0).lower().rstrip(".") for m in _NAME_RE.finditer(text or "")}


async def known_hosts(session: AsyncSession, project_id: int) -> list[str]:
    """Every hostname the project has seen, from every source.

    Not just the target list: alternate names from DNS and TLS, and the
    hosts of web addresses, are exactly the material that makes a
    suggestion good — and they are the names most often absent from the
    inventory, because nobody got round to adding them.
    """
    out: set[str] = set()
    rows = (await session.execute(
        select(Target.host, Target.hostnames, Target.extra)
        .where(Target.project_id == project_id))).all()
    for host, names_json, extra_json in rows:
        if host:
            out.add(host.lower())
        for blob, key in ((names_json, None), (extra_json, "hostscripts")):
            if not blob:
                continue
            try:
                data = json.loads(blob)
            except (TypeError, ValueError):
                continue
            if isinstance(data, list):
                out.update(str(x).lower() for x in data if x)
            elif isinstance(data, dict) and key:
                # TLS SANs captured by nmap's ssl-cert script are a rich
                # source of names nothing else has recorded.
                for script_out in data.get(key, {}).values() if isinstance(
                        data.get(key), dict) else []:
                    out.update(names_in(str(script_out)))
        if extra_json:
            try:
                ex = json.loads(extra_json)
            except (TypeError, ValueError):
                ex = {}
            if isinstance(ex, dict):
                for v in ex.values():
                    if isinstance(v, dict):
                        for vv in v.values():
                            if isinstance(vv, str):
                                out.update(names_in(vv))

    urls = (await session.execute(
        select(WebAddress.url).join(Target, Target.id == WebAddress.target_id)
        .where(Target.project_id == project_id))).scalars().all()
    for u in urls:
        h = (urlsplit(u).hostname or "").lower()
        if h:
            out.add(h)
    return sorted(x for x in out if x and "." in x)


async def scope_roots(session: AsyncSession, project_id: int) -> set[str]:
    """Zones the SCOPE names, from both kinds of entry.

    Both kinds, and that is the bug this function was extracted to
    fix: reading only `wildcard` leaves a project scoped entirely by
    `fqdn` with nothing to enumerate.

    A wildcard NAMES its zone, so it is taken as written. A plain
    hostname does not, so the registrable domain is inferred — and the
    inference stays out of the way of an authority that wrote the zone
    down, because `registrable()` turns `*.sub.acme.example` into
    `acme.example` and `*.example.com.ve` into the public suffix
    `com.ve`.

    Excluded entries are left out rather than offered and refused
    later: proposing work that the gate is certain to reject is noise
    in every cycle, for ever.
    """
    out: set[str] = set()
    for value, included, kind in (await session.execute(
            select(ProjectScope.value, ProjectScope.included, ProjectScope.kind)
            .where(ProjectScope.project_id == project_id,
                   ProjectScope.kind.in_(("fqdn", "wildcard"))))).all():
        if not included:
            continue
        v = (value or "").strip().lstrip("*.").lower()
        if not v:
            continue
        r = v if kind == "wildcard" else gen.registrable(v)
        if r and "." in r:
            out.add(r)
    return out


async def enumerable_roots(session: AsyncSession, project_id: int) -> set[str]:
    """Every zone worth handing to amass, from both sources at once.

    This is the set the dialog offers and the set the standing order
    works from. If they ever diverge again, an operator with the
    toggle on will keep finding work the automation did not do, which
    is exactly how this was noticed.
    """
    hosts = await known_hosts(session, project_id)
    out = {r for r, _ in gen.roots_in(hosts) if r and "." in r}
    out |= await scope_roots(session, project_id)
    return out
