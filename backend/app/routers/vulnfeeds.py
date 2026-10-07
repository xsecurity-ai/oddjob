"""Exploit and CVE feeds: status, a manual sync, and lookups.

The lookup routes take a product and version, never a host. That is
not an accident of the API shape — it is the boundary that keeps a
client's inventory inside the building. Nothing here sends anything
anywhere; the feeds are pulled in by `app.vulnfeed` on a schedule and
every match runs against the local tables.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, vulnfeed
from ..db import get_session
from ..models import CveRecord, Exploit, FeedState, User
from ..security import get_current_user, require_site_admin

router = APIRouter(prefix="/api/vulnfeeds", tags=["vulnfeeds"])


@router.get("/status", response_model=dict)
async def feed_status(_: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """How current the feeds are, and how much they hold.

    Readable by anyone signed in, because it is the caveat that belongs
    beside every result: "no known exploits" means one thing from a
    feed synced this morning and something else from one that has never
    run.
    """
    return await vulnfeed.status(session)


@router.post("/sync", response_model=dict)
async def sync_now(source: str = Query("all", pattern="^(all|exploitdb|nvd)$"),
                   user: User = Depends(require_site_admin),
                   session: AsyncSession = Depends(get_session)):
    """Fetch now rather than waiting for the daily run.

    Site admin: it reaches out to the internet and can run for a long
    time on a first NVD sync. Started in the background so the request
    returns — the status route is how progress is read.
    """
    if source in ("all", "exploitdb"):
        st = await session.get(FeedState, "exploitdb")
        if st and st.running:
            raise HTTPException(409, "an exploitdb sync is already running")
    if source in ("all", "nvd"):
        st = await session.get(FeedState, "nvd")
        if st and st.running:
            raise HTTPException(409, "an NVD sync is already running")

    from .settings import load_all
    cfg = await load_all(session)
    api_key = str(cfg.get("vulnfeed.nvd_api_key") or "").strip()

    await audit.record(session, "ui", "vulnfeed.sync", user=user,
                       detail=f"manual sync of {source}", commit=True)

    async def _run():
        from ..db import SessionLocal
        async with SessionLocal() as s:
            if source in ("all", "exploitdb"):
                await vulnfeed.sync_exploitdb(s)
            if source in ("all", "nvd"):
                await vulnfeed.sync_nvd(s, api_key)

    asyncio.create_task(_run())
    return {"started": source,
            "note": "running in the background; poll /api/vulnfeeds/status"}


@router.get("/search", response_model=dict)
async def search_exploits(q: str = Query(..., min_length=2),
                          limit: int = Query(50, ge=1, le=200),
                          _: User = Depends(get_current_user),
                          session: AsyncSession = Depends(get_session)):
    """`searchsploit`, against the local copy."""
    like = f"%{q.strip()}%"
    rows = (await session.execute(
        select(Exploit).where(Exploit.title.ilike(like))
        .order_by(Exploit.verified.desc(), Exploit.id.desc())
        .limit(limit))).scalars().all()
    return {
        "query": q,
        "results": [{"edb_id": e.id, "title": e.title, "type": e.type,
                     "platform": e.platform, "published": e.published,
                     "verified": e.verified, "path": e.path,
                     "cves": (e.cves or "").split(",") if e.cves else []}
                    for e in rows],
        "feeds": await vulnfeed.status(session),
    }


@router.get("/cve/{cve_id}", response_model=dict)
async def get_cve(cve_id: str,
                  _: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    c = await session.get(CveRecord, cve_id.strip().upper())
    if c is None:
        st = await vulnfeed.status(session)
        raise HTTPException(
            404, f"{cve_id} is not in the local CVE table. "
                 + ("The NVD feed has never synced, so this means 'not held', "
                    "not 'does not exist'."
                    if not st["feeds"].get("nvd", {}).get("synced")
                    else "The feed is synced, so it is either withdrawn or "
                         "not a CVE id."))
    exploits = (await session.execute(
        select(Exploit).where(Exploit.cves.like(f"%{c.id}%")).limit(50))).scalars().all()
    return {"cve": c.id, "published": c.published, "modified": c.modified,
            "score": c.cvss_score, "severity": c.severity,
            "vector": c.cvss_vector, "summary": c.summary,
            "exploits": [{"edb_id": e.id, "title": e.title,
                          "verified": e.verified} for e in exploits]}


@router.get("/leads", response_model=dict)
async def service_leads(product: str = Query("", description="e.g. Apache httpd"),
                        version: str = Query(""),
                        name: str = Query("", description="nmap's service name"),
                        banner: str = Query(""),
                        limit: int = Query(25, ge=1, le=100),
                        _: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """What is publicly known about one piece of software.

    Takes the software, not the host. The host never needs to be named
    to answer this, and not naming it is what keeps the question local.
    """
    if not any((product, name, banner)):
        raise HTTPException(422, "give a product, service name or banner")
    return await vulnfeed.leads_for_service(
        session, product or None, version or None, name or None,
        banner or None, limit)


@router.get("/stats", response_model=dict)
async def feed_stats(_: User = Depends(get_current_user),
                     session: AsyncSession = Depends(get_session)):
    n_exp = int((await session.execute(
        select(func.count()).select_from(Exploit))).scalar_one())
    n_cve = int((await session.execute(
        select(func.count()).select_from(CveRecord))).scalar_one())
    verified = int((await session.execute(
        select(func.count()).select_from(Exploit)
        .where(Exploit.verified.is_(True)))).scalar_one())
    return {"exploits": n_exp, "exploits_verified": verified,
            "cves": n_cve, "feeds": await vulnfeed.status(session)}
