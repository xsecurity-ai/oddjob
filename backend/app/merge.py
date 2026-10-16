"""Combining two targets that turned out to be one host.

This happens constantly on an engagement. An address gets scanned, a
name gets scanned, and only later does a reverse lookup show they were
always the same machine. Until now the importer refused the rename and
said "do that deliberately" — which was correct, and left nowhere to
do it deliberately.

Merging is the most destructive operation in this application. It moves
services, findings, proof-of-concepts, web exchanges, implants and a
timeline from one row to another and then deletes the row. Two
principles follow:

**Nothing is discarded silently.** Where two records genuinely cannot
coexist — the same port on both sides, the same captured exchange —
the outcome is reported and the losing record's content is folded into
the survivor rather than dropped. The one exception is an exact
duplicate, where `exchange_hash` says the two rows are byte-identical;
keeping two copies of the same request is not preserving anything.

**It is previewable.** `plan()` answers "what would this do" without
touching anything, and the UI shows that before asking. An operator
approving a merge should be approving a specific list of consequences,
not a verb.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .addresses import attach, normalise_address
from .models import Event, Implant, Poc, Service, Target, Vuln, WebAddress


@dataclass
class Plan:
    """What a merge would do. Produced without writing anything."""
    source: str
    destination: str
    #: Rows that simply move.
    services_moved: int = 0
    vulns_moved: int = 0
    pocs_moved: int = 0
    web_moved: int = 0
    implants_moved: int = 0
    events_moved: int = 0
    #: Ports present on both. Their records are combined, not dropped,
    #: but an operator should see that it is happening.
    service_conflicts: list[str] = field(default_factory=list)
    implant_conflicts: list[str] = field(default_factory=list)
    #: Exchanges byte-identical to one the destination already holds.
    #: The only thing a merge actually removes.
    web_duplicates: int = 0
    #: Addresses the destination does not have and would gain. Not a
    #: "field filled": with addresses many-to-many there is no slot to
    #: fill or to lose, so a merge is a union and nothing about the
    #: source's addresses is ever dropped or overwritten.
    addresses_gained: list[str] = field(default_factory=list)
    #: Scalar fields the destination would gain, as "field: value".
    fields_filled: list[str] = field(default_factory=list)
    #: Fields set on both and differing. The destination's is kept and
    #: the source's is written to the timeline, because "the OS was
    #: recorded as something else before we merged" is a fact about the
    #: engagement.
    fields_differing: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


#: Scalars worth carrying over. `host` is not here: which name survives
#: is the whole point of the operation and is chosen by the caller.
#:
#: Addresses are not here either, and no longer could be. They are not
#: a scalar to keep or discard — the destination takes the union, which
#: is the single most useful thing the many-to-many model buys a merge:
#: folding `203.0.113.9` into `web01.acme.example` used to mean choosing
#: between the address the row was named for and the address the name
#: already had, and now means the host has both. See `_addresses`.
CARRY = ("os", "os_accuracy", "mac_address", "mac_vendor",
         "provider", "notes", "tags")


def _source_addresses(src: Target) -> list[str]:
    """Every address the source row stands for, including its own name.

    An address-named target is the case this matters for. `198.51.100.10`
    as a `host` may carry nothing in `addresses` at all — the row IS the
    address — so folding it into `web01.acme.example` without this would
    delete the only record that the name was ever seen there, and with
    it the scope link that the gate reads back out of the inventory.
    """
    out = list(src.ip_addresses)
    if normalise_address(src.host) and src.host not in out:
        out.append(src.host)
    return out


def _gained(src: Target, dst: Target) -> list[str]:
    have = set(dst.ip_addresses)
    return [a for a in _source_addresses(src) if a not in have]


async def _svc_key(session: AsyncSession, target_id: int) -> dict[tuple, Service]:
    rows = (await session.execute(
        select(Service).where(Service.target_id == target_id))).scalars().all()
    return {(s.port, s.protocol): s for s in rows}


async def plan(session: AsyncSession, src: Target, dst: Target) -> Plan:
    """What merging `src` into `dst` would do. Writes nothing."""
    p = Plan(source=src.host, destination=dst.host)

    if src.id == dst.id:
        p.warnings.append("a target cannot be merged into itself")
        return p
    if src.project_id != dst.project_id:
        # Never. Moving findings between engagements puts one client's
        # data in another client's report.
        p.warnings.append("these targets are in different engagements")
        return p
    if src.kind != dst.kind:
        # Not refused — a mobile app and a host are different things,
        # but the operator may know better than the labels do.
        p.warnings.append(
            f"different kinds: {src.kind} and {dst.kind}. Check this is "
            f"really one asset before merging.")

    dst_svcs = await _svc_key(session, dst.id)
    for port, proto in await _svc_key(session, src.id):
        if (port, proto) in dst_svcs:
            p.service_conflicts.append(f"{port}/{proto}")
        else:
            p.services_moved += 1

    async def count(model, *where):
        return int((await session.execute(
            select(func.count()).select_from(model).where(*where))).scalar_one())

    p.vulns_moved = await count(Vuln, Vuln.target_id == src.id)
    p.pocs_moved = await count(Poc, Poc.target_id == src.id)
    p.events_moved = await count(Event, Event.target_id == src.id)

    dst_hashes = {h for (h,) in (await session.execute(
        select(WebAddress.exchange_hash)
        .where(WebAddress.target_id == dst.id))).all()}
    for (h,) in (await session.execute(
            select(WebAddress.exchange_hash)
            .where(WebAddress.target_id == src.id))).all():
        if h in dst_hashes:
            p.web_duplicates += 1
        else:
            p.web_moved += 1

    dst_imp = {(i.framework, i.implant_id) for i in (await session.execute(
        select(Implant).where(Implant.target_id == dst.id))).scalars()}
    for i in (await session.execute(
            select(Implant).where(Implant.target_id == src.id))).scalars():
        if (i.framework, i.implant_id) in dst_imp:
            p.implant_conflicts.append(f"{i.framework}:{i.implant_id}")
        else:
            p.implants_moved += 1

    p.addresses_gained = _gained(src, dst)

    for f in CARRY:
        a, b = getattr(src, f, None), getattr(dst, f, None)
        if a in (None, "") :
            continue
        if b in (None, ""):
            p.fields_filled.append(f"{f}: {a}")
        elif str(a) != str(b):
            p.fields_differing.append(f"{f}: {a} (keeping {b})")

    if src.hacked and not dst.hacked:
        p.fields_filled.append("hacked: yes")
    if src.alive is not None and dst.alive is None:
        p.fields_filled.append(f"alive: {src.alive}")
    return p


async def merge(session: AsyncSession, src: Target, dst: Target,
                actor: str) -> Plan:
    """Fold `src` into `dst` and delete it. Caller commits.

    Returns the same Plan shape, now describing what was actually done.
    """
    p = await plan(session, src, dst)
    if any(w.startswith(("a target cannot", "these targets are")) for w in p.warnings):
        return p

    dst_svcs = await _svc_key(session, dst.id)
    for (port, proto), s in (await _svc_key(session, src.id)).items():
        keep = dst_svcs.get((port, proto))
        if keep is None:
            s.target_id = dst.id
            continue
        # Both sides saw this port. Fill the gaps in the survivor from
        # the loser rather than keeping whichever row happened to be
        # scanned second — a banner captured once is evidence.
        for f in ("name", "product", "version", "extrainfo", "state",
                  "banner", "scripts", "notes", "tunnel", "method",
                  "confidence", "cpe", "reason"):
            a, b = getattr(s, f, None), getattr(keep, f, None)
            if a not in (None, "") and b in (None, ""):
                setattr(keep, f, a)
        # Web rows hanging off the losing service follow the survivor,
        # or they would point at a service that is about to vanish.
        await session.execute(
            update(WebAddress).where(WebAddress.service_id == s.id)
            .values(service_id=keep.id))
        await session.delete(s)

    # Exact duplicates go; everything else moves. `exchange_hash` is
    # the whole request and response, so two rows sharing one are the
    # same capture and keeping both preserves nothing.
    dst_hashes = {h for (h,) in (await session.execute(
        select(WebAddress.exchange_hash)
        .where(WebAddress.target_id == dst.id))).all()}
    for w in (await session.execute(
            select(WebAddress).where(WebAddress.target_id == src.id))).scalars():
        if w.exchange_hash in dst_hashes:
            await session.delete(w)
        else:
            w.target_id = dst.id

    dst_imp = {(i.framework, i.implant_id) for i in (await session.execute(
        select(Implant).where(Implant.target_id == dst.id))).scalars()}
    for i in (await session.execute(
            select(Implant).where(Implant.target_id == src.id))).scalars():
        if (i.framework, i.implant_id) in dst_imp:
            await session.delete(i)
        else:
            i.target_id = dst.id

    # No uniqueness on these, so they move wholesale. Two findings with
    # the same title become two findings on one host, which is visible
    # and fixable; dropping one would not be.
    for model in (Vuln, Poc, Event):
        await session.execute(
            update(model).where(model.target_id == src.id)
            .values(target_id=dst.id))

    # The union, not a choice. The source row is about to go, and an
    # address it carried is an observed fact about this machine that
    # nothing else records. `_source_addresses` is why the source's own
    # name is in here when that name was an address.
    gained = _source_addresses(src)
    src.addresses.clear()
    await session.flush()
    await attach(session, dst, gained)

    for f in CARRY:
        a, b = getattr(src, f, None), getattr(dst, f, None)
        if a not in (None, "") and b in (None, ""):
            setattr(dst, f, a)
    if src.hacked:
        dst.hacked = True
    if dst.alive is None and src.alive is not None:
        dst.alive = src.alive

    await session.delete(src)
    return p


def describe(p: Plan) -> str:
    """One line for the timeline, and the detail underneath it."""
    bits = []
    for n, what in ((p.services_moved, "service"), (p.vulns_moved, "finding"),
                    (p.pocs_moved, "PoC"), (p.web_moved, "web exchange"),
                    (p.implants_moved, "implant"), (p.events_moved, "event")):
        if n:
            bits.append(f"{n} {what}{'' if n == 1 else 's'}")
    moved = ", ".join(bits) or "nothing"
    out = [f"merged {p.source} into {p.destination}: {moved} moved"]
    # Named on the FIRST line, not buried in the detail. A merge that
    # arrives automatically — which an address-named row learning its
    # name now does — must not be able to absorb an accumulated set of
    # findings and summarise as "merged". Whoever reads this timeline in
    # three weeks is asking "where did these come from", and the answer
    # has to be the first thing they see.
    if p.vulns_moved or p.pocs_moved:
        out[0] += (f" — {p.source} was carrying "
                   + " and ".join(
                       f"{n} {w}{'' if n == 1 else 's'}"
                       for n, w in ((p.vulns_moved, "finding"),
                                    (p.pocs_moved, "PoC")) if n))
    if p.addresses_gained:
        out.append("addresses added: " + ", ".join(p.addresses_gained))
    if p.service_conflicts:
        out.append("ports seen on both, records combined: "
                   + ", ".join(p.service_conflicts))
    if p.implant_conflicts:
        out.append("implants already present: " + ", ".join(p.implant_conflicts))
    if p.web_duplicates:
        out.append(f"{p.web_duplicates} identical web exchange(s) dropped as "
                   f"duplicates of ones already held")
    if p.fields_filled:
        out.append("filled in: " + "; ".join(p.fields_filled))
    if p.fields_differing:
        # Kept, because what a host was previously recorded as is a
        # fact about the engagement even once it is superseded.
        out.append("differed, destination kept: " + "; ".join(p.fields_differing))
    return "\n".join(out)
