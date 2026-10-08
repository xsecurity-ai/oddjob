"""Writing addresses onto targets.

`Target.ip_addresses` is read-only on purpose (see the property's
docstring). Everything that puts an address on a target comes through
here, for three reasons that each bit us once already in the
single-column design:

**Find-or-create, never create.** An address row is unique per project
and shared between targets. Appending a fresh `TargetAddress` for
`203.0.113.9` to a second target raises an IntegrityError on the unique
constraint — which is the constraint doing its job, and not something
every caller should have to remember.

**One spelling.** `::ffff:0:1`, `::FFFF:0:1` and ` ::ffff:0:1 ` are one
address. Normalising at the single write path is what makes the
co-tenancy join (two targets, one address row) actually find both
targets, rather than filing them under two rows that look identical in
a grid.

**Nothing silently dropped.** A value that is not an address comes back
in the `invalid` list rather than being skipped. An importer handing us
`unknown` or a hostname is a fact about the scan file, and the one
thing we must not do is record it as "no address found".

This module performs no scope checking. Scope is decided by the caller,
per value, before it gets here — see `app/scopegate.py` and the note in
`attach` about why the gate cannot live down here.
"""
from __future__ import annotations

import ipaddress

from sqlalchemy import delete, func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Target, TargetAddress, target_address_links


def normalise_address(raw: str | None) -> str | None:
    """-> the canonical text of an IP literal, or None if it is not one.

    Canonical means `ipaddress`'s own compressed form, so the IPv6
    spellings of one address converge. A zone id (`fe80::1%eth0`) is
    kept: it is part of which interface the address is on, and two
    link-local addresses on different interfaces are not the same
    endpoint.
    """
    s = (raw or "").strip().strip("[]")
    if not s:
        return None
    head, sep, zone = s.partition("%")
    try:
        ip = ipaddress.ip_address(head)
    except ValueError:
        return None
    return ip.compressed + (sep + zone.lower() if sep else "")


def address_version(value: str) -> int:
    """4 or 6 for a value `normalise_address` has already accepted."""
    return ipaddress.ip_address(value.split("%", 1)[0]).version


async def loaded(session: AsyncSession, target: Target) -> list:
    """`target.addresses`, guaranteed to be readable. -> the collection.

    `lazy="selectin"` loads the collection when a target comes back
    from a query, which covers almost everything. It does NOT cover a
    target that was just constructed and flushed: the collection is
    still marked unloaded, and touching it inside the async session
    raises MissingGreenlet rather than quietly issuing a SELECT. That is
    SQLAlchemy doing the right thing — the alternative is a blocking
    query from inside the event loop — but it means every writer that
    might be handed a brand-new target has to ask for the load out
    loud, which is what this does.
    """
    if "addresses" in inspect(target).unloaded:
        await session.refresh(target, ["addresses"])
    return target.addresses


async def _row(session: AsyncSession, project_id: int,
               value: str) -> TargetAddress:
    """The project's row for this address, creating it if it is new."""
    found = (await session.execute(
        select(TargetAddress).where(TargetAddress.project_id == project_id,
                                    TargetAddress.address == value))
             ).scalar_one_or_none()
    if found is not None:
        return found
    found = TargetAddress(project_id=project_id, address=value,
                          version=address_version(value))
    session.add(found)
    # Flushed here so the row has an id before the link is written, and
    # so a second attach in the same transaction finds it rather than
    # queueing a duplicate insert that only fails at commit.
    await session.flush()
    return found


async def attach(session: AsyncSession, target: Target,
                 values) -> tuple[list[str], list[str]]:
    """Add addresses to `target`. -> (newly attached, not an address).

    Idempotent: an address the target already carries is not reported
    as newly attached, which is what lets an importer run twice without
    writing a timeline entry the second time.

    **The scope gate is not called here and must not be.** The gate
    needs to name what it is refusing ("adding 203.0.113.9 to FALCON-1")
    and the answer differs by caller — an importer records what a scan
    found, a lookup result creates new inventory. Burying a 403 in a
    helper that four routers call is how the refusal ends up with a
    message nobody can act on. Callers gate, then attach.
    """
    have = {a.address for a in await loaded(session, target)}
    added: list[str] = []
    invalid: list[str] = []
    for raw in values or ():
        value = normalise_address(raw if isinstance(raw, str) else str(raw))
        if value is None:
            text = (raw if isinstance(raw, str) else str(raw)).strip()
            if text:
                invalid.append(text)
            continue
        if value in have:
            continue
        target.addresses.append(await _row(session, target.project_id, value))
        have.add(value)
        added.append(value)
    return added, invalid


async def detach(session: AsyncSession, target: Target, value: str) -> bool:
    """Remove one address from `target`. -> whether it was there.

    The address row itself survives while any other target still points
    at it, and is pruned when none does. An orphan would be invisible
    inventory: it shows up nowhere, scopes nothing, and would quietly
    accumulate for the life of the engagement.
    """
    wanted = normalise_address(value)
    if wanted is None:
        return False
    for a in list(await loaded(session, target)):
        if a.address != wanted:
            continue
        target.addresses.remove(a)
        await session.flush()
        others = int((await session.execute(
            select(func.count())
            .select_from(target_address_links)
            .where(target_address_links.c.address_id == a.id))).scalar_one())
        if not others:
            await session.execute(
                delete(TargetAddress).where(TargetAddress.id == a.id))
        return True
    return False


async def replace(session: AsyncSession, target: Target,
                  values) -> tuple[list[str], list[str], list[str]]:
    """Make `target`'s addresses exactly `values`. -> (added, removed, invalid).

    For the paths that genuinely mean "this is the set now" — a hand
    edit, a bulk patch. Importers must NOT use this: a scan that only
    probed IPv4 would otherwise delete the AAAA record a previous scan
    found, recording a gap in one tool's coverage as a change to the
    asset.
    """
    want: list[str] = []
    invalid: list[str] = []
    for raw in values or ():
        value = normalise_address(raw if isinstance(raw, str) else str(raw))
        if value is None:
            text = (raw if isinstance(raw, str) else str(raw)).strip()
            if text:
                invalid.append(text)
        elif value not in want:
            want.append(value)

    removed = [a.address for a in await loaded(session, target)
               if a.address not in want]
    for value in removed:
        await detach(session, target, value)
    added, _ = await attach(session, target, want)
    return added, removed, invalid


async def targets_sharing(session: AsyncSession, project_id: int,
                          value: str) -> list[Target]:
    """Every target in this project that answers at `value`.

    The CDN question, asked directly. Note again that this is a record
    of observation and NOT a scope statement: the other tenants of a
    shared address are not in scope because our host is.
    """
    wanted = normalise_address(value)
    if wanted is None:
        return []
    return list((await session.execute(
        select(Target)
        .join(target_address_links,
              target_address_links.c.target_id == Target.id)
        .join(TargetAddress,
              TargetAddress.id == target_address_links.c.address_id)
        .where(Target.project_id == project_id,
               TargetAddress.address == wanted)
        .order_by(Target.host))).scalars().all())
