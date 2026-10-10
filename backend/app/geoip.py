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


def _readers() -> dict[str, object]:
    """Open whichever databases are on disk. Never raises."""
    import maxminddb
    out: dict[str, object] = {}
    for ed in KNOWN_EDITIONS:
        path = DB_DIR / f"{ed}.mmdb"
        try:
            if path.exists():
                out[ed] = maxminddb.open_database(str(path))
        except (OSError, ValueError) as e:
            # A truncated or corrupt file. Logged and skipped rather
            # than fatal: the other two may be perfectly good, and a
            # partial answer beats no answer.
            log.warning("geoip: %s unreadable (%s)", path.name, e)
    return out


def lookup(address: str) -> Location:
    """Locate one address against whatever is on disk.

    Synchronous and CPU-only -- an mmdb lookup is a memory-mapped tree
    walk, not IO -- so it is called directly rather than through a
    thread. `locate` is the async wrapper for callers in request
    handlers that want to do several.
    """
    loc = Location(address=address)
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return loc

    dbs = _readers()
    try:
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
    finally:
        for db in dbs.values():
            try:
                db.close()               # type: ignore[attr-defined]
            except Exception:            # noqa: BLE001 - closing must not raise
                pass
    return loc


async def locate(address: str) -> Location:
    """`lookup` off the event loop, for request handlers."""
    return await asyncio.to_thread(lookup, address)


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


async def tag(session, addr) -> bool:
    """Write what is known about one `TargetAddress` onto it.

    Returns True when anything was written. Tagged onto the ADDRESS
    rather than onto a target because that is what it is a fact about:
    every name answering there shares it, for the same reason an open
    port does.

    `geo_at` is stamped even when nothing is found, and that is the
    point of it. A private range answers nothing, and without a
    timestamp "no data" is indistinguishable from "never asked" — so
    every pass would look up every RFC1918 address again, for ever.
    """
    from datetime import UTC, datetime

    loc = await locate(addr.address)
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


async def enabled(session) -> bool:
    """Is geolocation switched on and actually usable?

    Both halves. A key with no database downloaded is configured and
    cannot answer, and callers that only checked the toggle would run
    a lookup per address to get nothing each time.
    """
    from .routers.settings import load_all
    cfg = await load_all(session)
    return bool(cfg.get("geoip.enabled")) and bool(installed())


async def tag_missing(session, project_id: int, limit: int = 500) -> int:
    """Tag addresses in this project that have never been looked up.

    Bounded. A project with forty thousand addresses should not do all
    of them inside one request, and the ones it skips are picked up on
    the next call rather than lost.
    """
    from sqlalchemy import select

    from .models import TargetAddress

    if not await enabled(session):
        return 0
    rows = (await session.execute(
        select(TargetAddress).where(
            TargetAddress.project_id == project_id,
            TargetAddress.geo_at.is_(None)).limit(limit))).scalars().all()
    n = 0
    for addr in rows:
        if await tag(session, addr):
            n += 1
    if rows:
        await session.commit()
    return n
