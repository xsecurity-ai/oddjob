"""Public exploit and CVE data, kept locally and matched locally.

**Why local.** The data is public; the question is not. "Is anything
known about Apache 2.4.49" is harmless on its own, but asked against a
third-party API on behalf of a host it becomes "this client runs Apache
2.4.49", sent out of the building, once per service, every time anybody
looks. Over a 4,000-host engagement that is a complete software
inventory of the client's estate, handed to someone who did not sign
the scope document.

So the databases come here on a schedule, and the matching — the part
that names a target — never leaves.

**Two feeds, deliberately different in character.**

  exploitdb  One CSV, about 46,000 rows, a few megabytes. Fetched
             whole every time because it is small enough that
             incremental sync would be more code than it saves, and
             because a full replace cannot drift.
  nvd        About 290,000 CVEs. Far too big to refetch, so it is
             incremental: every run asks only for what changed since
             the last success, which is what makes "current to the day"
             affordable rather than a daily 2GB download.

**Failure is reported, never papered over.** A feed that cannot reach
its source leaves the previous data in place and records why. The one
thing this must never do is answer "no known exploits" from an empty
or stale table as though it were a finding — see `status()`, which is
what every caller is expected to show alongside a result.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import CveRecord, Exploit, FeedState

log = logging.getLogger("oddjob.vulnfeed")

#: The exploitdb CSV, from the project's own repository. The raw file
#: rather than a git clone: one HTTP GET against one URL is easier to
#: allow through an egress policy than git over SSH, and an engagement
#: host frequently has the former and not the latter.
EXPLOITDB_CSV = ("https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
                 "files_exploits.csv")

#: NVD's CVE API. 2,000 records per page is its maximum.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = 2000

#: Without an API key NVD allows 5 requests per 30 seconds; with one,
#: 50. The delay is deliberately a little over the documented floor:
#: being rate-limited mid-sync costs the whole run, and the difference
#: between 6 and 7 seconds is nothing against a feed that is allowed to
#: take an hour.
NVD_DELAY_NO_KEY = 7.0
NVD_DELAY_KEY = 1.0

#: NVD refuses a range wider than 120 days, so a first sync walks
#: backwards in windows. 2002 is where its data begins.
NVD_WINDOW = timedelta(days=110)
NVD_EPOCH = datetime(2002, 1, 1, tzinfo=UTC)

_TIMEOUT = httpx.Timeout(60.0, connect=20.0)
_UA = "Oddjob vulnerability feed (authorised security assessment)"


async def _count_cves(session: AsyncSession) -> int:
    """How many CVEs are held. Counted in the database, not by loading
    every id into this process to call len() on it."""
    return int((await session.execute(
        select(func.count()).select_from(CveRecord))).scalar_one())


async def _state(session: AsyncSession, source: str) -> FeedState:
    st = await session.get(FeedState, source)
    if st is None:
        st = FeedState(source=source)
        session.add(st)
        await session.flush()
    return st


# ----------------------------------------------------------- exploitdb
def _parse_exploits(text: str) -> list[dict]:
    """Rows from the exploitdb CSV, as this database wants them.

    Separated from the fetch so it can be tested without the network,
    which matters more than usual here: the column set has changed
    before, and a silent change turns a sync into a table of nulls.
    """
    # Keyed by id, not a list: the published CSV contains the same id
    # more than once, which a straight insert discovers as a primary
    # key violation after it has already deleted the old table. Found
    # against the real feed, not a fixture — the last occurrence wins,
    # which matches how a re-published entry supersedes its predecessor.
    byid: dict[int, dict] = {}
    for row in csv.DictReader(io.StringIO(text)):
        try:
            edb = int((row.get("id") or "").strip())
        except (TypeError, ValueError):
            continue
        port = None
        try:
            p = int((row.get("port") or "").strip())
            port = p if 0 < p < 65536 else None
        except (TypeError, ValueError):
            pass
        codes = (row.get("codes") or "").strip()
        cves = ",".join(sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}",
                                              codes.upper()))))
        byid[edb] = {
            "id": edb,
            "title": (row.get("description") or "").strip()[:4000] or "(untitled)",
            "path": (row.get("file") or "").strip()[:512] or None,
            "author": (row.get("author") or "").strip()[:255] or None,
            "published": (row.get("date_published") or row.get("date")
                          or "").strip()[:32] or None,
            "platform": (row.get("platform") or "").strip().lower()[:64] or None,
            "type": (row.get("type") or "").strip().lower()[:32] or None,
            "port": port,
            "verified": (row.get("verified") or "").strip() in ("1", "true", "True"),
            "cves": cves or None,
        }
    return list(byid.values())


async def sync_exploitdb(session: AsyncSession) -> dict:
    """Replace the exploit table from Exploit-DB. -> a status dict."""
    st = await _state(session, "exploitdb")
    st.last_attempt_at = datetime.now(UTC)
    st.running = True
    await session.commit()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT,
                                     headers={"User-Agent": _UA},
                                     follow_redirects=True) as c:
            r = await c.get(EXPLOITDB_CSV)
            r.raise_for_status()
            rows = _parse_exploits(r.text)

        if not rows:
            # An empty parse is a changed format, not an empty database.
            # Keeping what we have is the only safe reading.
            raise ValueError("the feed parsed to zero rows — the CSV format "
                             "has probably changed; keeping the existing data")

        # Replace wholesale. Exploit-DB withdraws entries, and an upsert
        # would leave the withdrawn ones in place forever.
        await session.execute(delete(Exploit))
        for i in range(0, len(rows), 1000):
            session.add_all(Exploit(**r) for r in rows[i:i + 1000])
            await session.flush()

        st.records = len(rows)
        st.last_success_at = datetime.now(UTC)
        st.error = None
        st.running = False
        await session.commit()
        log.info("exploitdb: %d entries", len(rows))
        return {"source": "exploitdb", "ok": True, "records": len(rows)}
    except Exception as e:                       # noqa: BLE001
        await session.rollback()
        st = await _state(session, "exploitdb")
        st.running = False
        st.error = f"{type(e).__name__}: {e}"[:500]
        await session.commit()
        log.warning("exploitdb sync failed: %s", e)
        return {"source": "exploitdb", "ok": False, "error": st.error}


# --------------------------------------------------------- kev / epss
#
# Two small feeds that answer the question CVSS cannot.
#
# A findings list sorted by CVSS puts a 9.8 that nobody has ever used
# above a 7.5 that is being exploited this week. Both of these are
# published, free, cacheable and tiny next to NVD, and together they
# turn that ordering the right way up:
#
#   KEV   CISA's Known Exploited Vulnerabilities. Binary and
#         conservative -- an entry means somebody has been SEEN using
#         it against somebody. About 1,300 CVEs, a few hundred KB.
#   EPSS  FIRST's probability that a CVE will be exploited in the
#         next 30 days. Scores every CVE, refreshed daily, ~250k
#         rows as a gzipped CSV.
#
# Both are stored ON the CVE row rather than in tables of their own:
# one fact per CVE, always wanted together with the CVE, and a join
# per finding to answer "how should I sort this" is a join nobody
# needs.
#
# **Neither names a target.** These are whole-corpus downloads, like
# NVD and Exploit-DB: we fetch the entire list and match locally, so
# nothing about the client's estate leaves. That is the same reason
# the rest of this module exists and it is not an accident that the
# shape repeats.

#: CISA's KEV catalogue, the JSON form.
KEV_JSON = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")

#: FIRST's EPSS, current scores, gzipped CSV. The dated URL exists
#: too; this one is the rolling latest, which is what a daily sync
#: wants.
EPSS_CSV_GZ = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def _day(value: str | None) -> datetime | None:
    """A CISA `YYYY-MM-DD` into an aware datetime, or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value.strip()[:10], "%Y-%m-%d").replace(
            tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def parse_kev(doc: dict) -> dict[str, dict]:
    """CISA's catalogue into {CVE: fields}. -> {} if it is not one.

    An empty result from a document that parsed is treated by the
    caller as a format change rather than an empty catalogue, for the
    same reason `sync_exploitdb` does: CISA has never published zero.
    """
    out: dict[str, dict] = {}
    for item in (doc.get("vulnerabilities") or []):
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        out[cve] = {
            "kev": True,
            "kev_added": _day(item.get("dateAdded")),
            "kev_due": _day(item.get("dueDate")),
        }
    return out


def parse_epss(text: str) -> dict[str, tuple[float, float]]:
    """The EPSS CSV into {CVE: (score, percentile)}.

    The file opens with a `#model_version` comment line and then a
    header, both of which `csv` will happily hand back as data; rows
    that do not start with a CVE id are skipped rather than trusted.
    """
    out: dict[str, tuple[float, float]] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3:
            continue
        cve = row[0].strip().upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            out[cve] = (float(row[1]), float(row[2]))
        except (TypeError, ValueError):
            continue
    return out


async def sync_kev(session: AsyncSession) -> dict:
    """Mark which CVEs CISA says are being exploited. -> status dict."""
    st = await _state(session, "kev")
    st.last_attempt_at = datetime.now(UTC)
    st.running = True
    await session.commit()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT,
                                     headers={"User-Agent": _UA},
                                     follow_redirects=True) as c:
            r = await c.get(KEV_JSON)
            r.raise_for_status()
            found = parse_kev(r.json())

        if not found:
            raise ValueError("the KEV feed parsed to zero entries — the "
                             "format has probably changed; keeping the "
                             "existing data")

        # Cleared first, so a CVE REMOVED from the catalogue stops
        # being marked. CISA does withdraw entries, and a flag that
        # only ever goes on would quietly overstate the list for ever.
        #
        # False rather than NULL: "synced, and not on the list" is a
        # different answer from "never synced", which is the
        # distinction the column exists for.
        await session.execute(
            CveRecord.__table__.update().values(
                kev=False, kev_added=None, kev_due=None))

        marked = 0
        ids = sorted(found)
        for i in range(0, len(ids), 500):
            batch = ids[i:i + 500]
            res = await session.execute(
                CveRecord.__table__.update()
                .where(CveRecord.id.in_(batch))
                .values(kev=True))
            marked += res.rowcount or 0
            # The dates differ per CVE, so they go one at a time --
            # only over the ~1,300 that are actually listed.
            for cve in batch:
                f = found[cve]
                await session.execute(
                    CveRecord.__table__.update()
                    .where(CveRecord.id == cve)
                    .values(kev_added=f["kev_added"], kev_due=f["kev_due"]))
            await session.flush()

        st.records = len(found)
        st.last_success_at = datetime.now(UTC)
        st.error = None
        st.running = False
        await session.commit()
        # `marked` is the overlap, not the catalogue size, and the gap
        # between them is information: a KEV entry for a CVE this NVD
        # mirror has not got yet means the mirror is behind.
        log.info("kev: %d listed, %d matched a CVE we hold",
                 len(found), marked)
        return {"source": "kev", "ok": True, "records": len(found),
                "matched": marked}
    except Exception as e:                       # noqa: BLE001
        await session.rollback()
        st = await _state(session, "kev")
        st.running = False
        st.error = f"{type(e).__name__}: {e}"[:500]
        await session.commit()
        log.warning("kev sync failed: %s", e)
        return {"source": "kev", "ok": False, "error": st.error}


async def sync_epss(session: AsyncSession) -> dict:
    """Store FIRST's exploit-probability per CVE. -> status dict."""
    import gzip

    st = await _state(session, "epss")
    st.last_attempt_at = datetime.now(UTC)
    st.running = True
    await session.commit()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT,
                                     headers={"User-Agent": _UA},
                                     follow_redirects=True) as c:
            r = await c.get(EPSS_CSV_GZ)
            r.raise_for_status()
            raw = r.content
        # Served gzipped; httpx transparently decodes a
        # `Content-Encoding: gzip` but NOT a body that is simply a
        # .gz file, which this is. Try both rather than assume.
        try:
            text = gzip.decompress(raw).decode("utf-8", "replace")
        except (OSError, EOFError):
            text = raw.decode("utf-8", "replace")
        scores = parse_epss(text)

        if not scores:
            raise ValueError("the EPSS feed parsed to zero rows — the "
                             "format has probably changed; keeping the "
                             "existing data")

        # Only CVEs we hold. EPSS scores everything; writing rows for
        # CVEs this mirror has never seen would be inventing records
        # with no summary, no CPE and nothing to match a service on.
        held = {c for (c,) in (await session.execute(
            select(CveRecord.id))).all()}
        touch = sorted(held & set(scores))
        for i in range(0, len(touch), 1000):
            for cve in touch[i:i + 1000]:
                sc, pct = scores[cve]
                await session.execute(
                    CveRecord.__table__.update()
                    .where(CveRecord.id == cve)
                    .values(epss=sc, epss_percentile=pct))
            await session.flush()

        st.records = len(touch)
        st.last_success_at = datetime.now(UTC)
        st.error = None
        st.running = False
        await session.commit()
        log.info("epss: %d scored, %d matched a CVE we hold",
                 len(scores), len(touch))
        return {"source": "epss", "ok": True, "records": len(touch),
                "scored": len(scores)}
    except Exception as e:                       # noqa: BLE001
        await session.rollback()
        st = await _state(session, "epss")
        st.running = False
        st.error = f"{type(e).__name__}: {e}"[:500]
        await session.commit()
        log.warning("epss sync failed: %s", e)
        return {"source": "epss", "ok": False, "error": st.error}


# ----------------------------------------------------------------- nvd
def _cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Score, vector and severity, preferring the newest CVSS present."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            sev = (data.get("baseSeverity") or m.get("baseSeverity") or "")
            return float(score), (data.get("vectorString") or "")[:128], \
                (sev or "").lower()[:16] or None
    return None, None, None


def _cpes(cve: dict) -> tuple[list[str], str]:
    """Every CPE in the record, and a cheap product index for it."""
    out: list[str] = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                c = m.get("criteria")
                if c:
                    out.append(c)
    # cpe:2.3:a:apache:http_server:2.4.49:… -> "apache http_server"
    pairs = set()
    for c in out:
        bits = c.split(":")
        if len(bits) > 5 and bits[3] and bits[4]:
            pairs.add(f"{bits[3]} {bits[4]}".replace("_", " ").lower())
    return out, " | ".join(sorted(pairs))[:4000]


def parse_cve(item: dict) -> dict | None:
    """One NVD record, flattened. None when it is not usable."""
    cve = item.get("cve") or item
    cid = cve.get("id")
    if not cid:
        return None
    summary = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            summary = d.get("value") or ""
            break
    score, vector, sev = _cvss(cve.get("metrics") or {})
    cpes, products = _cpes(cve)

    def _dt(v):
        if not v:
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None

    return {
        "id": cid[:32],
        "published": _dt(cve.get("published")),
        "modified": _dt(cve.get("lastModified")),
        "summary": summary[:8000] or None,
        "cvss_score": score, "cvss_vector": vector, "severity": sev,
        "cpes": json.dumps(cpes[:200]) if cpes else None,
        "products": products or None,
    }


def _nvd_windows(start: datetime,
                 end: datetime) -> list[tuple[datetime, datetime]]:
    """Split a span into ranges NVD will accept.

    NVD refuses a `lastModStartDate`/`lastModEndDate` range wider than
    120 days. Everything that asks for a date range goes through here so
    there is one place that cannot emit an illegal one.
    """
    out: list[tuple[datetime, datetime]] = []
    cur = start
    while cur < end:
        nxt = min(cur + NVD_WINDOW, end)
        out.append((cur, nxt))
        cur = nxt
    return out or [(start, end)]


async def sync_nvd(session: AsyncSession, api_key: str = "",
                   max_pages: int = 400) -> dict:
    """Bring the CVE table up to date. Incremental after the first run.

    `max_pages` bounds one invocation rather than the whole sync: a
    first run over twenty years of CVEs is resumable, and the cursor
    means the next run carries on rather than starting again.
    """
    st = await _state(session, "nvd")
    st.last_attempt_at = datetime.now(UTC)
    st.running = True
    await session.commit()

    delay = NVD_DELAY_KEY if api_key else NVD_DELAY_NO_KEY
    headers = {"User-Agent": _UA}
    if api_key:
        headers["apiKey"] = api_key

    now = datetime.now(UTC)
    since = None
    if st.cursor:
        try:
            since = datetime.fromisoformat(st.cursor)
        except ValueError:
            since = None

    written = 0
    pages = 0
    requests = 0
    # Bound before the try: the failure path reads them, and a crash
    # early enough to leave them unset is exactly when it runs.
    windows: list[tuple[datetime, datetime]] = []
    resume_from: datetime | None = None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as c:
            # Chunked from the cursor, or from the epoch on a first run.
            # Always chunked, never a single span: a backfill that ran
            # out of page budget leaves the cursor years in the past, and
            # asking for (cursor, now) in one window is a range NVD
            # rejects outright — which would wedge every later sync.
            windows = _nvd_windows(since - timedelta(minutes=5) if since
                                   else NVD_EPOCH, now)

            # The boundary every window before this one is known to be
            # complete through. Parked on the failure path below, so a
            # dropped connection costs the window in flight rather than
            # the whole run. A first sync is hours long; discarding all
            # of it for one failed DNS lookup means that on a flaky
            # connection it never completes at all.
            resume_from = windows[0][0] if windows else None

            for w_start, w_end in windows:
                offset = 0
                while True:
                    if pages >= max_pages:
                        # Out of budget for this invocation. The cursor
                        # is advanced to the window we finished, so the
                        # next run resumes rather than restarts.
                        st.running = False
                        st.error = None
                        st.cursor = w_start.isoformat()
                        st.records = await _count_cves(session)
                        await session.commit()
                        return {"source": "nvd", "ok": True, "partial": True,
                                "written": written,
                                "note": "page budget reached; the next run "
                                        "resumes from the cursor"}
                    params = {
                        "resultsPerPage": NVD_PAGE, "startIndex": offset,
                        "lastModStartDate": w_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "lastModEndDate": w_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    }
                    # Paced per request, not per page within a window.
                    # Most 110-day windows hold under one page, so a
                    # page-only sleep would fire eighty requests back to
                    # back during a backfill and earn a 403.
                    if requests:
                        await asyncio.sleep(delay)
                    r = await c.get(NVD_API, params=params)
                    pages += 1
                    requests += 1
                    if r.status_code == 403:
                        raise PermissionError(
                            "NVD refused the request (403). Without an API key "
                            "it allows 5 requests per 30 seconds; set one in "
                            "Site Config to raise that to 50.")
                    r.raise_for_status()
                    body = r.json()
                    items = body.get("vulnerabilities") or []
                    for it in items:
                        rec = parse_cve(it)
                        if not rec:
                            continue
                        existing = await session.get(CveRecord, rec["id"])
                        if existing is None:
                            session.add(CveRecord(**rec))
                        else:
                            for k, v in rec.items():
                                setattr(existing, k, v)
                        written += 1
                    await session.commit()

                    total = int(body.get("totalResults") or 0)
                    offset += NVD_PAGE
                    if offset >= total or not items:
                        break
                # Every page of this window is in. Anything that fails
                # from here resumes at its end, not at the epoch.
                resume_from = w_end

        st.cursor = now.isoformat()
        st.last_success_at = now
        st.error = None
        st.running = False
        st.records = await _count_cves(session)
        await session.commit()
        log.info("nvd: %d record(s) written", written)
        return {"source": "nvd", "ok": True, "written": written}
    except Exception as e:                       # noqa: BLE001
        await session.rollback()
        st = await _state(session, "nvd")
        st.running = False
        st.error = f"{type(e).__name__}: {e}"[:500]
        # Keep the ground already covered. The rows committed before the
        # failure are in the table whatever happens here; parking the
        # cursor is what stops the next run fetching them all again, and
        # re-counting is what stops `records` reporting a number the
        # table stopped matching several thousand rows ago.
        try:
            if (resume_from is not None and windows
                    and resume_from > windows[0][0]):
                st.cursor = resume_from.isoformat()
            st.records = await _count_cves(session)
        except Exception:                        # noqa: BLE001
            # Best effort. The error above is the thing worth reporting.
            pass
        await session.commit()
        log.warning("nvd sync failed: %s", e)
        return {"source": "nvd", "ok": False, "error": st.error,
                "written": written,
                "resume_from": st.cursor}


# -------------------------------------------------------------- status
async def status(session: AsyncSession) -> dict:
    """How current each feed is, and how much it holds.

    Returned beside every match, because "no known exploits" means one
    thing from a feed synced this morning and something else entirely
    from one that has never run.
    """
    out: dict = {"feeds": {}, "usable": True, "warnings": []}
    now = datetime.now(UTC)
    for source in ("exploitdb", "nvd", "kev", "epss"):
        st = await session.get(FeedState, source)
        if st is None or st.last_success_at is None:
            out["feeds"][source] = {"synced": None, "records": 0,
                                    "error": st.error if st else None}
            # `usable` is about whether a CVE lookup can answer at
            # all, which is NVD and Exploit-DB. KEV and EPSS only
            # affect ORDERING: without them a findings list is sorted
            # less well, not wrongly, and blocking the whole feature
            # on them would be the wrong trade.
            if source in ("exploitdb", "nvd"):
                out["usable"] = False
            out["warnings"].append(
                f"{source} has never synced — a result from it means "
                f"'nothing is recorded here', not 'nothing exists'"
                if source in ("exploitdb", "nvd") else
                f"{source} has never synced, so findings are ordered by "
                f"severity alone — nothing is marked as being exploited "
                f"in the wild, which is not the same as nothing being "
                f"exploited")
            continue
        age = now - st.last_success_at
        out["feeds"][source] = {
            "synced": st.last_success_at.isoformat(),
            "age_hours": round(age.total_seconds() / 3600, 1),
            "records": st.records, "error": st.error,
            "running": st.running,
        }
        if age > timedelta(days=2):
            out["warnings"].append(
                f"{source} last synced {age.days} day(s) ago"
                + (f"; last attempt failed: {st.error}" if st.error else ""))
    return out


#: How a findings list should be ordered, worst-first.
#:
#: CVSS alone puts "a 9.8 nobody has ever used" above "a 7.5 being
#: exploited this week", which is the wrong way round for somebody
#: deciding what to fix on a Tuesday. The order is:
#:
#:   1. on CISA's KEV list      somebody has been SEEN using it
#:   2. EPSS, descending        how likely it is to be used next
#:   3. CVSS, descending        how bad it would be if it were
#:
#: KEV first and binary, because "observed in the wild" is a
#: different kind of claim from "probably will be" and should not be
#: averaged with it. EPSS before CVSS because likelihood is the thing
#: CVSS cannot express at all.
#:
#: A CVE with no EPSS sorts as though it were 0 rather than being
#: dropped: an unscored CVE is unscored, not harmless.
def triage_order(rows: list) -> list:
    """Sort CVE-ish rows worst-first. Pure, so it is testable.

    Takes anything with `.kev`, `.epss` and `.cvss_score`, or the
    mapping equivalent -- the findings list and the agent's lead tool
    hold different shapes and should not need two orderings.
    """
    def key(r):
        get = (r.get if isinstance(r, dict) else lambda k: getattr(r, k, None))
        return (0 if get("kev") else 1,
                -(get("epss") or 0.0),
                -(get("cvss_score") or 0.0))
    return sorted(rows, key=key)


# ------------------------------------------------------------ matching
#: Words that appear in half of all product strings and match nothing
#: useful. Without this, "Apache httpd" against the CVE index returns
#: every CVE that mentions a server.
_NOISE = {"server", "http", "https", "httpd", "service", "daemon", "software",
          "application", "web", "ssl", "tls", "open", "source", "the", "and"}


def product_terms(product: str | None, name: str | None = None,
                  banner: str | None = None) -> list[str]:
    """The words worth searching a CVE index for, strongest first.

    `product` is what `nmap -sV` identified and is the only one of the
    three that is reliably a product name. `name` is nmap's guess at the
    service and `banner` is whatever the port said about itself; both
    are used, and both are noisier.
    """
    words: list[str] = []
    for src in (product, name, banner):
        for w in re.split(r"[^A-Za-z0-9.+_-]+", (src or "").lower()):
            w = w.strip("-_.")
            if len(w) < 3 or w in _NOISE or w.replace(".", "").isdigit():
                continue
            if w not in words:
                words.append(w)
    return words[:6]


def version_matches(cpe: str, version: str | None) -> bool:
    """Does this CPE cover that version?

    Exact segment comparison only. CPE version ranges live in sibling
    fields this does not store, so a wildcard CPE is treated as "covers
    everything", which over-matches rather than under-matches — the
    right way round for something producing leads a person will check.
    """
    return match_kind(cpe, version) is not None


def version_candidates(version: str | None) -> list[str]:
    """The forms of a version worth comparing a CPE against.

    A banner and a CPE do not spell the same release the same way.
    OpenSSH reports `8.2p1`, and NVD records
    `cpe:2.3:a:openbsd:openssh:8.2:p1:*` — the patch level lives in the
    CPE's *update* segment, which is a different field. Comparing the
    banner string to the version segment therefore never matches, and
    every OpenSSH lookup silently returned product-level hits only.

    Also trims a packager's suffix: Debian and Ubuntu ship
    `1.18.0-6ubuntu14`, and nobody files a CVE against that.

    Scanned rather than matched with a regular expression, deliberately.
    This runs on a version string taken from a service banner, which is
    whatever a remote host chose to send us — `[a-z]+\\d*$` against a
    few hundred kilobytes of 'a' is quadratic, and the host on the other
    end picks the input. Backward scans are linear and cannot be made
    to behave badly.
    """
    v = (version or "").strip()
    if not v:
        return []
    # A version is short. Anything longer came from a banner that is not
    # really a version, and bounding it keeps the LIKE built from it
    # bounded too.
    v = v[:64]
    out = [v]

    def add(candidate: str) -> None:
        candidate = candidate.strip(".-_")
        if candidate and candidate not in out:
            out.append(candidate)

    # 1.18.0-6ubuntu14 -> 1.18.0
    cuts = [i for i in (v.find(c) for c in "-+~") if i > 0]
    if cuts:
        add(v[:min(cuts)])

    # A trailing letter run, with optional digits after it:
    # 8.2p1 -> 8.2, and 1.0.2k -> 1.0.2.
    end = len(v)
    while end > 0 and v[end - 1].isdigit():
        end -= 1
    start = end
    while start > 0 and v[start - 1].isalpha():
        start -= 1
    if start < end:                     # there was a letter run
        add(v[:start])
    return out


def match_kind(cpe: str, version: str | None) -> str | None:
    """How a CPE matched: `exact`, `any-version`, or None for no match.

    Split out from `version_matches` because the two carry very
    different weight. A wildcard CPE matches 2.4.49 and every other
    release alike, so reporting it as "version matched" would dress a
    product-level hit up as a version-level one.
    """
    bits = cpe.split(":")
    if len(bits) < 6:
        return None
    cpe_ver = bits[5]
    if cpe_ver in ("*", "-", ""):
        return "any-version"
    if not version:
        return None
    return "exact" if cpe_ver in version_candidates(version) else None


async def leads_for_service(session: AsyncSession, product: str | None,
                            version: str | None, name: str | None = None,
                            banner: str | None = None,
                            limit: int = 25) -> dict:
    """Public exploits and CVEs that might apply to one service.

    **These are leads.** Version matching against CPE strings is
    approximate, a banner is frequently wrong, and a patched system
    reports the same version as an unpatched one. Nothing here has been
    confirmed against the host — confirming it is the engagement.
    """
    # Normalised once, here. `version` of "   " is truthy, so a guard
    # written as `if version:` runs the version-specific branch and then
    # builds an or_() out of an empty candidate list — a deprecation
    # today and an error in a later SQLAlchemy. Asking the candidate
    # list whether there is a version to match on cannot drift from
    # what the matching actually uses.
    versions = version_candidates(version)

    terms = product_terms(product, name, banner)
    if not terms:
        return {"terms": [], "exploits": [], "cves": [],
                "note": "nothing identifiable about this service to search on "
                        "— a -sV pass would give it a product and version"}

    cves: list[dict] = []
    seen_cve: set[str] = set()
    for term in terms:
        rows: list[CveRecord] = []
        if versions:
            # Fetch the version-specific ones FIRST, and by name.
            #
            # Ordering the whole candidate set by score and taking the
            # top few looks reasonable and is quietly wrong: 507 Apache
            # CVEs score 9.8 or above, so the one CVE whose CPE actually
            # names 2.4.49 never entered the window, and sorting
            # afterwards cannot surface a row that was never fetched.
            # Asking the database for the version is the only way to be
            # sure the exact match is in the running at all.
            # Every spelling of the version, for the same reason
            # match_kind accepts more than one: searching only the
            # banner's own string misses the CPE that records it
            # differently, which is most of them.
            rows += (await session.execute(
                select(CveRecord)
                .where(CveRecord.products.is_not(None),
                       CveRecord.products.like(f"%{term}%"),
                       or_(*[CveRecord.cpes.like(f"%:{v}:%")
                             for v in versions]))
                .order_by(CveRecord.cvss_score.desc().nullslast())
                .limit(limit * 2))).scalars().all()
        rows += (await session.execute(
            select(CveRecord)
            .where(CveRecord.products.is_not(None),
                   CveRecord.products.like(f"%{term}%"))
            .order_by(CveRecord.cvss_score.desc().nullslast())
            .limit(limit * 4))).scalars().all()
        for c in rows:
            if c.id in seen_cve:
                continue
            try:
                cpes = json.loads(c.cpes) if c.cpes else []
            except ValueError:
                cpes = []
            kinds = {match_kind(x, version) for x in cpes} - {None}
            if version and cpes and not kinds:
                continue
            # A CVE NVD has not analysed yet carries no CPE list, so it
            # cannot be version-matched either way. It is kept rather
            # than dropped — dropping it would turn "not yet analysed"
            # into "does not apply" — and labelled so the reader can
            # tell which of the three a row is.
            if not version:
                match = "no version given"
            elif not cpes:
                match = "unknown — NVD has not published a CPE list for this CVE"
            elif "exact" in kinds:
                match = "exact — a CPE names this version"
            else:
                match = ("product only — the CPE covers every version, so this "
                         "is not evidence about the one you asked about")
            seen_cve.add(c.id)
            cves.append({"cve": c.id, "score": c.cvss_score,
                         "severity": c.severity,
                         "summary": (c.summary or "")[:300],
                         "matched_on": term,
                         "version_match": match,
                         # Tri-state, deliberately. False means CISA
                         # has not listed it; None means the KEV feed
                         # has never synced here, and a reader must
                         # not be shown those the same way.
                         "kev": c.kev,
                         "kev_added": (c.kev_added.date().isoformat()
                                       if c.kev_added else None),
                         "epss": c.epss,
                         "epss_percentile": c.epss_percentile})
            if len(cves) >= limit:
                break
        if len(cves) >= limit:
            break

    # Exact version matches first. Ordering by score alone buries the
    # one CVE that names this exact release under a dozen wildcard CPEs
    # that happen to score 9.8, which is the wrong thing to read first.
    #
    # Within that, KEV then EPSS then CVSS -- see `triage_order` for
    # why likelihood comes before severity. Version match still wins
    # over both: a CVE that names this exact release is evidence
    # about THIS host, and one being exploited elsewhere is not yet.
    _rank = {"exact": 0}
    cves.sort(key=lambda c: (
        _rank.get(str(c["version_match"]).split(" ")[0], 1),
        0 if c.get("kev") else 1,
        -(c.get("epss") or 0.0),
        -(c["score"] or 0)))

    # Exploits by CVE first — a cited CVE is a real link — then by
    # title, which is a guess.
    exploits: list[dict] = []
    seen_edb: set[int] = set()
    if seen_cve:
        for c in list(seen_cve)[:40]:
            for e in (await session.execute(
                    select(Exploit).where(Exploit.cves.like(f"%{c}%"))
                    .limit(10))).scalars():
                if e.id not in seen_edb:
                    seen_edb.add(e.id)
                    exploits.append({"edb_id": e.id, "title": e.title,
                                     "type": e.type, "platform": e.platform,
                                     "verified": e.verified, "via": c})
    for term in terms[:2]:
        for e in (await session.execute(
                select(Exploit).where(Exploit.title.ilike(f"%{term}%"))
                .limit(limit))).scalars():
            if e.id not in seen_edb and len(exploits) < limit * 2:
                seen_edb.add(e.id)
                exploits.append({"edb_id": e.id, "title": e.title,
                                 "type": e.type, "platform": e.platform,
                                 "verified": e.verified, "via": f"title~{term}"})

    def _n(prefix: str) -> int:
        return sum(1 for c in cves
                   if str(c.get("version_match", "")).startswith(prefix))

    unmatchable, loose, exact = _n("unknown"), _n("product only"), _n("exact")
    caveat = ("Leads, not findings. Version matching against CPE is "
              "approximate, a banner is often wrong, and a patched host "
              "reports the same version as an unpatched one. Confirming "
              "any of this against the target is the engagement.")
    if version and cves:
        caveat += (f" Of {len(cves)}: {exact} name this version exactly, "
                   f"{loose} match the product at any version, and "
                   f"{unmatchable} could not be matched because NVD has not "
                   "analysed them yet. Only the first group is evidence about "
                   "the version you asked about.")
    return {
        "terms": terms,
        "cves": cves,
        "exploits": exploits,
        "caveat": caveat,
        "feeds": await status(session),
    }
