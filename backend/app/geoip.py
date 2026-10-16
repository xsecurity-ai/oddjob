"""Where an address is, from MaxMind's GeoLite2 databases.

Local lookups against databases this installation downloads with the
operator's own licence key. Nothing about a client's estate is sent to
MaxMind: the only request made is for the databases themselves, which
is a download of a file and carries no addresses with it. That matters
on an engagement, where "which country is this host in" is a perfectly
ordinary question and "tell a third party which hosts we are looking
at" is not an acceptable way to answer it.

# Why the databases are not shipped

GeoLite2 is free but not redistributable, and this repository is
public. The reader is a dependency; the data arrives at runtime, under
the licence of whoever configured the key, and lives in a directory
that is not in the image.

# Editions

`GeoLite2-ASN`, `GeoLite2-City` and `GeoLite2-Country` by default,
which is what MaxMind's own GeoIP.conf ships with. Configurable
because a deployment may be entitled to a different set, and because
City is 27 MB against Country's 3 MB -- an installation that only
wants a country code should not have to download the other 24.

Lookup consults them in order of specificity: City answers country as
well, so where both are present City wins and Country is never asked.
"""
from __future__ import annotations

import asyncio
import io
import ipaddress
import logging
import os
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import servicehealth

log = logging.getLogger("oddjob.geoip")

#: What MaxMind's own GeoIP.conf ships with.
DEFAULT_EDITIONS = "GeoLite2-ASN GeoLite2-City GeoLite2-Country"

#: Editions this knows how to read. An unknown one is refused at
#: configuration time rather than failing halfway through a download,
#: and the message names what is allowed -- a typo like `GeoLite-City`
#: is otherwise a 404 from MaxMind with nothing pointing at the cause.
KNOWN_EDITIONS = ("GeoLite2-ASN", "GeoLite2-City", "GeoLite2-Country")

#: Where the .mmdb files live. Outside the image on purpose, beside the
#: other state a deployment accumulates.
DB_DIR = Path(os.environ.get("ODDJOB_GEOIP_DIR", "/var/lib/oddjob/geoip"))

#: MaxMind answers the download URL with a 302 to a signed S3 link, so
#: redirects have to be followed. Without that the response is an empty
#: body with status 302 and the file silently ends up zero bytes --
#: which tar then reports as a corrupt archive, pointing nowhere near
#: the actual cause.
DOWNLOAD = "https://download.maxmind.com/geoip/databases/{edition}/download"

#: City is 27 MB and the three together are about 35 MB. Generous, and
#: bounded: a hung download must not hold a worker for ever.
TIMEOUT = httpx.Timeout(300.0, connect=30.0)


def parse_editions(spec: str | None) -> list[str]:
    """Read the configured edition list.

    Whitespace or commas, because the value is pasted from a GeoIP.conf
    (spaces) at least as often as it is typed into a web form (commas).

    Unknown names are dropped rather than refused: a deployment
    entitled to an edition this does not know how to read should not be
    stopped from downloading the ones it can.
    """
    out: list[str] = []
    for part in (spec or DEFAULT_EDITIONS).replace(",", " ").split():
        p = part.strip()
        if p in KNOWN_EDITIONS and p not in out:
            out.append(p)
    return out


@dataclass
class Location:
    """What is known about one address. Every field optional."""

    address: str = ""
    country: str | None = None          # ISO code, e.g. "JP"
    country_name: str | None = None
    city: str | None = None
    subdivision: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    #: MaxMind's own stated precision, in km. The important field, and
    #: the one most consumers drop: an anycast address like 8.8.8.8
    #: answers with the geographic centre of its COUNTRY and a radius
    #: of 1000 km, which is indistinguishable from a real position
    #: unless this is carried alongside. 162.243.56.114 answers with a
    #: radius of 20 km and a city, and is a position.
    accuracy_km: int | None = None
    asn: int | None = None
    organisation: str | None = None
    #: Which databases answered, so a thin result is explicable.
    sources: list[str] = field(default_factory=list)

    @property
    def known(self) -> bool:
        return bool(self.country or self.asn or self.city)

    @property
    def positioned(self) -> bool:
        """Is the lat/long a place, or a country-sized shrug?

        MaxMind answers an address it cannot place with the centroid
        of its country and an accuracy radius of around 1000 km. That
        is a perfectly good country-level answer and a terrible pin on
        a map, and the two are only distinguishable by the radius.
        """
        return (self.latitude is not None and self.longitude is not None
                and (self.accuracy_km or 9999) <= 200)

    def summary(self) -> str:
        """One line for a report, or "" when nothing is known.

        Place then network, because those are two different answers to
        two different questions and a reader wants both: "Tokyo, Japan"
        says where the packets land and "AS2497 Internet Initiative
        Japan" says whose equipment they land on. A CDN edge is the
        case where they disagree most usefully.

        Duplicate parts are collapsed. MaxMind answers Tokyo with a
        subdivision also called Tokyo, and "Tokyo, Tokyo, Japan" reads
        like a bug in us rather than a quirk of the data.
        """
        parts: list[str] = []
        for p in (self.city, self.subdivision,
                  self.country_name or self.country):
            if p and p not in parts:
                parts.append(p)
        where = ", ".join(parts)
        if not self.asn:
            return where
        who = f"AS{self.asn}"
        if self.organisation:
            who += f" {self.organisation}"
        return f"{where} ({who})" if where else who


@dataclass
class Tagged:
    """What one pass over the un-located addresses did.

    Named rather than counted, and the split is the substance. An
    address that was asked and answered nothing is a fact about
    MaxMind's data; one that has never been asked is a fact about us.
    "7 located" cannot tell those apart, and stamping `geo_at` exists
    precisely because they are different — a report that collapses
    them throws away the distinction the column was added to keep.
    """

    #: address -> "Tokyo, Japan (AS2497 Internet Initiative Japan)"
    located: dict[str, str] = field(default_factory=dict)
    #: Looked up, and the databases on disk know nothing about it.
    #: Ordinary for an RFC1918 address and not an error.
    unknown: list[str] = field(default_factory=list)
    #: Still never asked once this pass finished, because the batch
    #: limit was reached. Zero means the project is fully covered.
    remaining: int = 0
    #: Why nothing happened, when nothing did.
    note: str = ""


#: Said in full wherever geolocation is asked for and cannot run. Both
#: halves, because they are different jobs: a switch in Settings, or a
#: licence key and a download. One message naming only one of them
#: sends half the people who read it to the wrong page.
OFF_NOTE = ("Geolocation is switched off, or no GeoLite2 database has "
            "been downloaded yet. Settings → Site has the switch and the "
            "MaxMind licence key; Health shows which databases are on disk.")


def _readers() -> dict[str, object]:
    """Open whichever databases are on disk. Never raises."""
    import maxminddb
    out: dict[str, object] = {}
    for ed in KNOWN_EDITIONS:
        path = DB_DIR / f"{ed}.mmdb"
        try:
            if path.exists():
                out[ed] = maxminddb.open_database(str(path))
        except Exception as e:                   # noqa: BLE001
            # A truncated or corrupt file. Logged and skipped rather
            # than fatal: the other two may be perfectly good, and a
            # partial answer beats no answer.
            #
            # Deliberately broad. This was `(OSError, ValueError)`,
            # which does not catch maxminddb's own
            # InvalidDatabaseError -- that subclasses RuntimeError --
            # so the one case the handler was written for, a corrupt
            # database, was the one case it let through. Every caller
            # here is told this never raises, and a half-written file
            # is exactly what an interrupted `refresh` leaves behind.
            log.warning("geoip: %s unreadable (%s)", path.name, e)
    return out


def _close(dbs: dict[str, object]) -> None:
    for db in dbs.values():
        try:
            db.close()                   # type: ignore[attr-defined]
        except Exception:                # noqa: BLE001 - closing must not raise
            pass


def _against(dbs: dict[str, object], address: str) -> Location:
    """One address against databases somebody else opened.

    The whole of the lookup except the opening and closing, so that a
    batch can do that part once. Opening is the expensive half: the
    City database is 27 MB, and `tag_all_missing` doing two thousand
    addresses would otherwise mmap and unmap it two thousand times to
    answer two thousand questions it could have answered in one pass.
    """
    loc = Location(address=address)
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return loc

    # City first: it answers country too, so asking Country as well
    # would be a second tree walk for a value already in hand.
    city = dbs.get("GeoLite2-City")
    country = dbs.get("GeoLite2-Country")
    rec = None
    if city is not None:
        rec = city.get(address)
        if rec:
            loc.sources.append("GeoLite2-City")
    elif country is not None:
        rec = country.get(address)
        if rec:
            loc.sources.append("GeoLite2-Country")
    if rec:
        c = rec.get("country") or rec.get("registered_country") or {}
        loc.country = c.get("iso_code")
        loc.country_name = (c.get("names") or {}).get("en")
        loc.city = ((rec.get("city") or {}).get("names") or {}).get("en")
        subs = rec.get("subdivisions") or []
        if subs:
            loc.subdivision = (subs[0].get("names") or {}).get("en")
        ll = rec.get("location") or {}
        loc.latitude, loc.longitude = ll.get("latitude"), ll.get("longitude")
        loc.accuracy_km = ll.get("accuracy_radius")

    asn = dbs.get("GeoLite2-ASN")
    if asn is not None:
        a = asn.get(address)
        if a:
            loc.sources.append("GeoLite2-ASN")
            loc.asn = a.get("autonomous_system_number")
            loc.organisation = a.get("autonomous_system_organization")
    return loc


def lookup(address: str) -> Location:
    """Locate one address against whatever is on disk.

    Synchronous and CPU-only -- an mmdb lookup is a memory-mapped tree
    walk, not IO -- so it is called directly rather than through a
    thread. `locate` is the async wrapper for callers in request
    handlers, and `locate_many` is the one to reach for past a handful.
    """
    dbs = _readers()
    try:
        return _against(dbs, address)
    finally:
        _close(dbs)


def lookup_many(addresses: list[str]) -> dict[str, Location]:
    """Locate several addresses against ONE opening of the databases."""
    dbs = _readers()
    try:
        return {a: _against(dbs, a) for a in addresses}
    finally:
        _close(dbs)


async def locate(address: str) -> Location:
    """`lookup` off the event loop, for request handlers."""
    return await asyncio.to_thread(lookup, address)


async def locate_many(addresses) -> dict[str, Location]:
    """`lookup_many` off the event loop. One thread for the whole batch.

    Not `locate` in a loop: that would hop to the thread pool and back
    once per address and reopen 27 MB of database each time, which on a
    real estate is the difference between a button and a hang.
    """
    want = list(addresses)
    if not want:
        return {}
    return await asyncio.to_thread(lookup_many, want)


async def refresh(account_id: str, license_key: str,
                  editions: str | None = None) -> dict[str, str]:
    """Download the configured editions. Returns {edition: outcome}.

    Reports to the health page per edition rather than once for the
    set: three downloads where one fails is a different situation from
    three where all do, and a single boolean cannot tell them apart.
    """
    wanted = parse_editions(editions)
    if not wanted:
        await servicehealth.note("maxmind", False, "refresh",
                                 "no readable editions configured")
        return {}
    if not (account_id and license_key):
        await servicehealth.note("maxmind", False, "refresh",
                                 "account id and licence key are both needed")
        return {}

    DB_DIR.mkdir(parents=True, exist_ok=True)
    out: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 auth=(account_id, license_key)) as cli:
        for ed in wanted:
            try:
                out[ed] = await _one(cli, ed)
            except httpx.HTTPStatusError as e:
                # 401 is the common one and deserves its own words:
                # "unauthorized" against a download URL reads like the
                # database is missing rather than the key being wrong.
                code = e.response.status_code
                msg = (f"HTTP {code}" + (
                    " — check the account id and licence key"
                    if code in (401, 403) else ""))
                out[ed] = msg
                log.warning("geoip: %s failed: %s", ed, msg)
            except (httpx.HTTPError, OSError, tarfile.TarError) as e:
                out[ed] = str(e)[:200]
                log.warning("geoip: %s failed: %s", ed, e)

    good = [e for e, r in out.items() if r == "ok"]
    bad = {e: r for e, r in out.items() if r != "ok"}
    await servicehealth.note(
        "maxmind", not bad,
        f"refreshed {len(good)} of {len(wanted)} edition(s)",
        "; ".join(f"{e}: {r}" for e, r in bad.items()))
    return out


async def _one(cli: httpx.AsyncClient, edition: str) -> str:
    """Fetch and unpack one edition. Returns "ok" or raises."""
    r = await cli.get(DOWNLOAD.format(edition=edition),
                      params={"suffix": "tar.gz"})
    r.raise_for_status()

    # Unpacked to a temporary name and moved into place, so a reader
    # opening the file mid-download never sees a half-written database.
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
        member = next((m for m in tar.getmembers()
                       if m.isfile() and m.name.endswith(".mmdb")), None)
        if member is None:
            raise tarfile.TarError(f"{edition}: no .mmdb in the archive")
        src = tar.extractfile(member)
        if src is None:
            raise tarfile.TarError(f"{edition}: {member.name} unreadable")
        tmp = DB_DIR / f".{edition}.mmdb.part"
        tmp.write_bytes(src.read())
    tmp.replace(DB_DIR / f"{edition}.mmdb")
    return "ok"


def installed() -> dict[str, dict]:
    """Which databases are on disk, and how old. For the status page."""
    from datetime import UTC, datetime
    out: dict[str, dict] = {}
    for ed in KNOWN_EDITIONS:
        p = DB_DIR / f"{ed}.mmdb"
        if not p.exists():
            continue
        st = p.stat()
        out[ed] = {
            "size": st.st_size,
            "built": datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
        }
    return out


def apply_location(addr, loc: Location) -> bool:
    """Write `loc` onto a `TargetAddress`. -> was anything known?

    Split out from `tag` so a caller that already has the `Location` --
    because it wants to report what was found, not merely how many --
    does not have to look the address up a second time to get it.

    `geo_at` is stamped even when nothing is found, and that is the
    point of it. A private range answers nothing, and without a
    timestamp "no data" is indistinguishable from "never asked" — so
    every pass would look up every RFC1918 address again, for ever.
    """
    from datetime import UTC, datetime

    addr.geo_at = datetime.now(UTC)
    if not loc.known:
        return False
    addr.geo_country = loc.country
    addr.geo_country_name = loc.country_name
    addr.geo_subdivision = loc.subdivision
    addr.geo_city = loc.city
    addr.geo_asn = loc.asn
    addr.geo_org = loc.organisation
    addr.geo_accuracy_km = loc.accuracy_km
    # Coordinates only when they mean something. MaxMind answers an
    # address it cannot place with its country's centroid and a radius
    # near 1000 km; storing that as a position puts a pin in a field in
    # Kansas and invites somebody to believe it.
    if loc.positioned:
        addr.geo_latitude, addr.geo_longitude = loc.latitude, loc.longitude
    else:
        addr.geo_latitude = addr.geo_longitude = None
    return True


async def tag(session, addr) -> bool:
    """Look one `TargetAddress` up and write what is known onto it.

    Returns True when anything was written. Tagged onto the ADDRESS
    rather than onto a target because that is what it is a fact about:
    every name answering there shares it, for the same reason an open
    port does.
    """
    return apply_location(addr, await locate(addr.address))


async def enabled(session) -> bool:
    """Is geolocation switched on and actually usable?

    Both halves. A key with no database downloaded is configured and
    cannot answer, and callers that only checked the toggle would run
    a lookup per address to get nothing each time.
    """
    from .routers.settings import load_all
    cfg = await load_all(session)
    return bool(cfg.get("geoip.enabled")) and bool(installed())


async def pending(session, project_id: int) -> int:
    """How many of a project's addresses have never been looked up.

    Its own query so a caller can show the backlog without doing any
    of it — a toolbar asking "is there work here" on every render must
    not be the thing that performs the work.
    """
    from sqlalchemy import func, select

    from .models import TargetAddress

    return int((await session.execute(
        select(func.count()).select_from(TargetAddress).where(
            TargetAddress.project_id == project_id,
            TargetAddress.geo_at.is_(None)))).scalar_one())


async def tag_all_missing(session, project_id: int,
                          limit: int = 500) -> Tagged:
    """Locate addresses in this project that have never been looked up.

    Bounded. A project with forty thousand addresses should not do all
    of them inside one request, and the ones it skips are reported in
    `remaining` and picked up by the next call rather than lost.

    **Commits.** The standing-order cycle and the Targets toolbar both
    call this as a complete unit of work. `tag_addresses` is the
    variant for a caller that is mid-transaction.
    """
    from sqlalchemy import select

    from .models import TargetAddress

    out = Tagged()
    if not await enabled(session):
        out.note = OFF_NOTE
        return out

    rows = (await session.execute(
        select(TargetAddress)
        .where(TargetAddress.project_id == project_id,
               TargetAddress.geo_at.is_(None))
        # Oldest first, so repeated passes work through the backlog in
        # a stable order instead of re-rolling the dice on which 500 a
        # bounded query happens to return.
        .order_by(TargetAddress.id).limit(limit))).scalars().all()
    _write(out, rows, await locate_many(a.address for a in rows))
    if rows:
        await session.commit()
    out.remaining = await pending(session, project_id)
    return out


def _write(out: Tagged, rows, found: dict[str, Location]) -> None:
    """Put each answer on its row and into the right half of the report."""
    for addr in rows:
        loc = found.get(addr.address) or Location(address=addr.address)
        if apply_location(addr, loc):
            out.located[addr.address] = loc.summary()
        else:
            out.unknown.append(addr.address)


async def tag_addresses(session, project_id: int, values) -> Tagged:
    """Locate specific addresses, skipping any already looked up.

    For the paths that have just CREATED an address and know which one
    — a lookup result landing, an import. Cheaper and more immediate
    than waiting for a sweep to notice: the row is already in front of
    the caller, and a lookup is a memory-mapped tree walk against a
    local file.

    **Does not commit**, because those callers are mid-transaction with
    writes of their own and committing underneath them would split one
    operation into two.
    """
    from sqlalchemy import select

    from .models import TargetAddress

    out = Tagged()
    wanted = [v for v in dict.fromkeys(values or ()) if v]
    if not wanted:
        return out
    if not await enabled(session):
        out.note = OFF_NOTE
        return out

    rows = (await session.execute(
        select(TargetAddress).where(
            TargetAddress.project_id == project_id,
            TargetAddress.address.in_(wanted),
            # Never re-asked. An address already carrying an answer is
            # not made more true by a second identical tree walk, and
            # one that answered nothing is recorded as having answered
            # nothing — see `apply_location`.
            TargetAddress.geo_at.is_(None)))).scalars().all()
    _write(out, rows, await locate_many(a.address for a in rows))
    return out


async def tag_missing(session, project_id: int, limit: int = 500) -> int:
    """`tag_all_missing`, as the count the standing-order log prints."""
    return len((await tag_all_missing(session, project_id, limit)).located)


# ------------------------------------------------------------ netblocks
# Turning "the twelve addresses we resolved" into "the /22 the client
# actually announces". The forgotten assets live in the part of the
# prefix nobody enumerated, and nothing else here can see it.
#
# Entirely local. The ASN database is already on disk -- `tag_missing`
# reads it for every address -- and `get_with_prefix_len` returns the
# network the lookup matched on alongside the record. No query naming
# the client goes anywhere, which is the whole reason this is done
# here rather than against asnmap or Team Cymru.

#: Largest IPv4 prefix whose remainder is worth calling enumerable.
#: A /16 is 65,536 addresses -- a long sweep but a real one. Anything
#: bigger is a provider's allocation rather than a client's block, and
#: offering to enumerate it is offering something nobody will do.
ENUMERABLE_V4_PREFIX = 16


@dataclass
class Netblock:
    """One announced prefix, and what we hold inside it."""
    network: str
    asn: int | None
    organisation: str | None
    #: Addresses this project already has in the prefix.
    known: int = 0
    #: How many addresses the prefix holds in total. A /22 is 1,024.
    size: int = 0
    #: 4 or 6.
    version: int = 4

    @property
    def enumerable(self) -> bool:
        """Whether "the rest of this prefix" is a real thing to go and look at.

        **IPv6 is never enumerable and this is the point of the flag.**
        A v6 /32 holds 7.9e28 addresses; reporting that as unseen
        opportunity is a number that is true, useless, and actively
        misleading next to an IPv4 /24 holding 256. The first version
        of this sorted by raw `unseen` and every v6 prefix buried
        every v4 one.

        Large IPv4 blocks are excluded for the weaker reason that they
        are an allocation rather than a client's own range.
        """
        if self.version != 4:
            return False
        try:
            return ipaddress.ip_network(self.network).prefixlen >= ENUMERABLE_V4_PREFIX
        except ValueError:
            return False

    @property
    def unseen(self) -> int | None:
        """Addresses in the prefix nobody has looked at, or None.

        None when the prefix is not enumerable -- which is "this
        question does not apply here", not zero and not unknown. A
        caller must render it as such rather than as a count.
        """
        if not self.enumerable:
            return None
        return max(0, self.size - self.known)


def network_for(address: str) -> tuple[str | None, int | None, str | None]:
    """-> (CIDR, ASN, organisation) for one address, from the local db.

    The CIDR is the prefix the ASN database matched on, which is the
    routed block rather than a guess: MaxMind builds it from the
    global routing table, so a /22 here is a /22 somebody announces.

    All three are None when the database is absent or has nothing for
    the address. That is "could not determine" and callers must not
    render it as "this address is in no network".
    """
    dbs = _readers()
    try:
        asn = dbs.get("GeoLite2-ASN")
        if asn is None:
            return None, None, None
        try:
            rec, prefix_len = asn.get_with_prefix_len(address)
        except (ValueError, TypeError):
            return None, None, None
        if not rec or prefix_len is None:
            return None, None, None
        try:
            net = ipaddress.ip_network(f"{address}/{prefix_len}", strict=False)
        except ValueError:
            return None, None, None
        return (str(net), rec.get("autonomous_system_number"),
                rec.get("autonomous_system_organization"))
    finally:
        _close(dbs)


def netblocks(addresses: list[str]) -> list[Netblock]:
    """Group addresses into the prefixes that announce them.

    Sorted by how much evidence there is that the prefix belongs to
    the client -- see the note on the sort key. Density of addresses
    we already hold, not size of the unexplored remainder: the
    remainder is largest exactly where the prefix is somebody else's.

    Addresses the database cannot place are simply absent from the
    result rather than bucketed into a fake prefix. A made-up network
    would be indistinguishable from a real one in the UI.
    """
    found: dict[str, Netblock] = {}
    for a in addresses:
        cidr, asn, org = network_for(a)
        if cidr is None:
            continue
        nb = found.get(cidr)
        if nb is None:
            try:
                net = ipaddress.ip_network(cidr)
            except ValueError:
                continue
            nb = Netblock(network=cidr, asn=asn, organisation=org,
                          size=net.num_addresses, version=net.version)
            found[cidr] = nb
        nb.known += 1
    # Ordered by how much reason there is to think the prefix is the
    # CLIENT'S, which is not the same as how much of it is unseen.
    #
    # Sorting by unseen alone put a /16 holding one address at the
    # top -- measured against the real engagement, the first eight
    # rows were /16s with a single known address apiece, belonging to
    # Amazon and NTT. "65,535 addresses you have not looked at" is
    # true of every provider allocation we ever touched once and is
    # not an opportunity; it is an invitation to scan somebody else's
    # network.
    #
    # Density is the signal instead. Holding several addresses in a
    # prefix is evidence somebody allocated it to the client; holding
    # one is evidence we resolved one name. So `known` leads, and
    # `unseen` breaks ties among prefixes with equal standing.
    return sorted(
        found.values(),
        key=lambda n: (0 if n.enumerable else 1,
                       -n.known, -(n.unseen or 0), n.network))
