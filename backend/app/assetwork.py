"""Drive the asset pipeline: fetch what is unfetched, scan what is unscanned.

Stages 1 and 2 supplied the parts -- `assetfetch` retrieves a file
and recovers its originals, `assetscan` reads them. This is the
thing that actually runs them over a project and turns what comes
back into findings.

**Both halves resume.** Fetching is keyed on `fetched_at` and
scanning on `WebAssetFile.scanned_at`, per file rather than per
asset, so a sweep interrupted after 300 of 900 files picks up at
301 and a source map that yields new sources on a later fetch gets
those scanned without re-scanning the ninety that did not change.

**Scope comes from the page, not the asset** (operator ruling: an
asset of an in-scope page is in scope). Checked here, against the
page that referenced it, because the asset's own host is frequently
a CDN that would never clear the gate -- and refusing those would
skip exactly the bundles worth reading. An asset with no
identifiable in-scope page is skipped and counted, never fetched on
the strength of its own hostname.

**A finding needs a target.** `Vuln.target_id` is NOT NULL and an
asset's target is nullable, so an asset nothing can attribute to a
host is reported as unattributable rather than filed against a
guess. Counted, so the number is visible instead of being the
difference between two other numbers.

Secrets never reach a log line here. `assetscan` redacts before a
Finding exists, and nothing in this module prints a body.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import (
    assetfetch,
    assetlinks,
    assetscan,
    lifecycle,
    lockfiles,
    manifest,
)
from .hosts import InvalidHost, normalise_host
from .models import (
    FindingSecret,
    Target,
    TargetOrigin,
    Vuln,
    WebAsset,
    WebAssetEndpoint,
    WebAssetFile,
    WebAssetRef,
)
from .scopegate import as_host, index_for
from .weburl import origin_key

log = logging.getLogger("oddjob.assetwork")

#: Default batch. Each asset is at least one request to the client's
#: estate, so a sweep is paced rather than unbounded.
FETCH_BATCH = 50

#: How many fetches are in flight at once, ACROSS hosts.
#:
#: The work is network-bound -- almost all of a fetch is waiting --
#: so doing one at a time wasted the entire budget on latency.
FETCH_CONCURRENCY = 8

#: And at most one at a time PER HOST, which is the part that
#: matters. The backlog is not spread evenly: on this estate 1,896
#: of 7,800 queued assets are on a single host, so plain global
#: concurrency would point all eight slots at one server. Every
#: host sees the same one-request-at-a-time it saw before; what
#: changes is that we now wait on several hosts at once instead of
#: on one.
_HOST_LOCKS: dict[str, asyncio.Lock] = {}


def _url_host(url: str) -> str:
    """The hostname a request will actually go to."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _host_lock(host: str) -> asyncio.Lock:
    lk = _HOST_LOCKS.get(host)
    if lk is None:
        lk = _HOST_LOCKS[host] = asyncio.Lock()
    return lk
SCAN_BATCH = 200          # one invocation covers all of them

#: Bytes of file body one sweep may hold, beside the count above.
#:
#: `SCAN_BATCH` bounds how MANY files a sweep takes and says nothing
#: about how big they are, and assetfetch keeps up to 8 MB of each
#: (`assetfetch.MAX_BYTES`) -- so 200 of them is legitimately 1.6 GB
#: of minified bundle resident in this process before a scanner has
#: been started, and opengrep then reads the same corpus again. That
#: pair is what OOM-killed the container in a loop on 2026-10-28.
#:
#: Files past the budget are not dropped, only deferred: their
#: `scanned_at` stays NULL, so the next sweep selects them again.
SCAN_BUDGET_BYTES = 24 * 1024 * 1024


def _within_budget(rows: list, budget: int = SCAN_BUDGET_BYTES) -> list:
    """The longest run of `rows` whose bodies fit inside `budget`.

    Always at least one row, even where that row alone is over it:
    refusing it would leave it at the head of the queue for ever,
    because the next sweep selects the same file and refuses it
    again. One oversized file is survivable -- the rlimit in
    `assetscan` is what stops it taking the process with it.
    """
    kept: list = []
    used = 0
    for r in rows:
        size = len(r.body or "")
        if kept and used + size > budget:
            break
        kept.append(r)
        used += size
    return kept


@dataclass
class Swept:
    considered: int = 0
    fetched: int = 0
    failed: int = 0
    #: No in-scope page could be found to authorise it.
    unauthorised: int = 0
    files: int = 0
    scanned: int = 0
    findings: int = 0
    #: Endpoints referenced by a bundle that nothing links to.
    endpoints: int = 0
    #: Cloud resources named in a bundle, added as `kind="cloud"`
    #: targets.
    cloud: int = 0
    #: ...and those refused because the scope document does not
    #: cover them, which is the ordinary case: a bundle references
    #: a lot of somebody else's cloud. Counted rather than silent,
    #: so a project seeing zero added knows whether that means
    #: "none found" or "found and all out of scope".
    cloud_refused: int = 0
    #: Findings that could not be filed because nothing ties the
    #: asset to a target. Surfaced, not swallowed.
    unattributable: int = 0
    #: Assets a bot filter refused rather than the origin. Inside
    #: `failed` as well, deliberately -- the fetch did fail -- but
    #: counted apart because the two are different problems with
    #: different answers. Nine unrelated failures is a flaky estate;
    #: nine refusals by one product is a filter to work around or
    #: accept, and that is invisible while it exists only as prose
    #: in nine `fetch_error` columns nobody reads together.
    blocked: int = 0
    #: Which products did the refusing, so the number above can be
    #: read without opening a row. {"Cloudflare": 9}.
    blocked_by: dict[str, int] = field(default_factory=dict)
    #: Entropy-only matches dropped from page results. Counted
    #: rather than silent: a suppression nobody can see is
    #: indistinguishable from a scanner that found nothing, which is
    #: the mistake trufflehog made here for weeks.
    entropy_skipped: int = 0
    notes: list[str] = field(default_factory=list)


async def _page_hosts(session: AsyncSession, asset: WebAsset) -> list[str]:
    """Every page known to reference this asset, as hosts."""
    out: list[str] = []
    if asset.first_page:
        out.append(as_host(asset.first_page) or "")
    for (u,) in (await session.execute(
            select(WebAssetRef.page_url)
            .where(WebAssetRef.asset_id == asset.id).limit(25))).all():
        if u:
            out.append(as_host(u) or "")
    return [h for h in out if h]


async def authorised(session: AsyncSession, idx, asset: WebAsset) -> bool:
    """Whether any page referencing this asset is in scope.

    ANY, not all: if an in-scope page causes a browser to fetch this
    file, we are authorised to fetch the same file. A second page
    out of scope referencing it as well does not withdraw that.
    """
    hosts = await _page_hosts(session, asset)
    return any(idx.check(h).allowed for h in hosts)


def spread_by_host(pool: list, limit: int) -> list:
    """Round-robin a candidate pool by host, up to `limit`.

    The queue is not spread evenly -- on one real estate 1,896 of
    7,800 waiting assets were on a single host -- and rows come out
    of the table in insertion order, which groups a host's assets
    together. Taking the first N therefore meant N requests at one
    server: the slowest possible ordering, because they serialise
    behind that host's lock, and the least polite one.

    Keyed on `host` rather than the URL, which is the cheap
    approximation: this only decides the ORDER work is attempted
    in, and the per-host lock keyed on the real URL is what
    actually bounds the rate at a server.
    """
    by_host: dict[str, list] = {}
    for a in pool:
        by_host.setdefault(getattr(a, "host", None) or "", []).append(a)
    out: list = []
    while len(out) < limit and by_host:
        for h in list(by_host):
            if not by_host[h]:
                del by_host[h]
                continue
            out.append(by_host[h].pop(0))
            if len(out) >= limit:
                break
    return out


async def fetch_project(session: AsyncSession, project_id: int, *,
                        user_agent: str, limit: int = FETCH_BATCH) -> Swept:
    """Retrieve assets this project knows of but has never read."""
    out = Swept()
    # Spread across hosts, not `ORDER BY id`.
    #
    # Insertion order groups a host's assets together, so a batch
    # was usually twenty requests at one server -- the slowest
    # possible ordering AND the least polite. Taking a wider slice
    # and round-robining by host means a batch of twenty is twenty
    # different servers wherever it can be, which is both faster
    # and gentler at every one of them.
    pool = (await session.execute(
        select(WebAsset)
        .where(WebAsset.project_id == project_id,
               WebAsset.fetched_at.is_(None),
               WebAsset.kind.in_(tuple(assetfetch.FETCHABLE_KINDS)))
        .order_by(WebAsset.id).limit(limit * 20))).scalars().all()
    if not pool:
        return out
    rows = spread_by_host(pool, limit)
    idx = await index_for(session, project_id)

    # Authorisation and the database work stay sequential -- they
    # share one session, which is not safe to use concurrently. Only
    # the NETWORK half runs in parallel, which is the part that was
    # costing the time.
    todo = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for a in rows:
            out.considered += 1
            if not await authorised(session, idx, a):
                out.unauthorised += 1
                # Record the ATTEMPT, so this is not reconsidered on
                # every cycle for ever. `fetched_at` is "when we last
                # tried", not "when we got it" -- the error says which
                # -- and without stamping it an asset nothing
                # authorises stays in the backlog permanently, is
                # re-examined every two minutes, and keeps `unfetched`
                # from ever reaching zero so the figure stops meaning
                # anything.
                #
                # If the scope later widens, clearing `fetch_error`
                # puts it back in the queue. That is an operator
                # action because a scope change is one.
                a.fetched_at = assetfetch.now()
                a.fetch_error = ("no in-scope page references this asset, "
                                 "so nothing authorises fetching it")
                continue
            todo.append(a)

        sem = asyncio.Semaphore(FETCH_CONCURRENCY)

        async def _grab(asset):
            # Keyed on the URL's hostname, NOT `asset.host`. That
            # column is recorded at crawl time and can disagree with
            # the URL -- and it is the URL that receives the
            # request, so locking on the column protects the wrong
            # server. Caught by the probe measuring two requests in
            # flight at one host while the lock reported none.
            async with sem, _host_lock(_url_host(asset.url)):
                return asset, await assetfetch.fetch(
                    client, asset.url, user_agent=user_agent)

        results = await asyncio.gather(*(_grab(a) for a in todo),
                                       return_exceptions=True)

        for item in results:
            if isinstance(item, BaseException):
                # A fetch that raised out of `fetch` -- which is
                # written not to -- must not lose the whole batch.
                log.warning("assetwork: fetch task failed: %s", item)
                out.failed += 1
                continue
            a, got = item
            a.fetched_at = assetfetch.now()
            a.status_code = got.status
            a.content_type = got.content_type
            a.minified = got.minified
            a.sourcemap_url = (got.sourcemap_url or None)
            if not got.ok:
                a.fetch_error = got.error
                out.failed += 1
                if got.blocked_by:
                    out.blocked += 1
                    out.blocked_by[got.blocked_by] = (
                        out.blocked_by.get(got.blocked_by, 0) + 1)
                continue
            a.fetch_error = None
            for origin, path, body in got.files:
                sha, n = assetfetch.digest(body)
                if origin == "raw":
                    a.sha256, a.bytes, a.body = sha, n, body
                existing = (await session.execute(
                    select(WebAssetFile).where(
                        WebAssetFile.asset_id == a.id,
                        WebAssetFile.origin == origin,
                        WebAssetFile.path == path))).scalar_one_or_none()
                if existing is None:
                    session.add(WebAssetFile(
                        asset_id=a.id, project_id=project_id, origin=origin,
                        path=path, body=body, sha256=sha, bytes=n))
                    out.files += 1
                elif existing.sha256 != sha:
                    # Changed since last time: new content, so the
                    # old scan verdict no longer describes it.
                    existing.body, existing.sha256 = body, sha
                    existing.bytes, existing.scanned_at = n, None
                    out.files += 1
            out.fetched += 1
    await session.commit()
    return out


def _severity_floor(sev: str) -> str:
    return sev if sev in ("critical", "high", "medium", "low", "info") else "info"


class _HasAssetId(Protocol):
    """The two columns `_target_for` reads.

    A Protocol rather than `WebAsset`, because the callers that run in
    a loop deliberately select ONLY these columns -- `WebAsset.body`
    averages 145 KB and reading it to find a target id is how a
    background sweep came to hold 3 GB. Typing this as the full model
    would make the cheap call look like the wrong one.
    """
    id: int
    target_id: int | None


async def _target_for(session: AsyncSession,
                      asset: _HasAssetId) -> int | None:
    """A target to file findings against, or None.

    The asset's own target first, then the target of any page that
    referenced it. None means nothing ties this file to a host we
    know, and the caller reports it rather than picking one.
    """
    if asset.target_id:
        return asset.target_id
    row = (await session.execute(
        select(WebAssetRef.target_id)
        .where(WebAssetRef.asset_id == asset.id,
               WebAssetRef.target_id.is_not(None)).limit(1))).first()
    return row[0] if row else None


async def _record_cloud(session: AsyncSession, project_id: int, idx,
                        f) -> tuple[int, int]:
    """Cloud resources named in one file, as targets.

    -> (added, refused)

    A bundle that talks to `acme-assets.s3.eu-west-1.amazonaws.com`
    names an asset of the estate that nothing links to and no port
    scan reaches: it is not on the client's address space, so it is
    in no CIDR anybody scans, and no crawl finds it because no page
    links to a bucket. The code is the only place it appears.

    Recorded as `kind="cloud"` with the provider set, so the rest of
    the system can tell it apart from a machine -- "no open ports"
    on a bucket is not the finding that the same result on a server
    would be.

    **Scope-checked before creation, exactly as `enumerate` does.**
    This is the whole reason these are matched as hostnames rather
    than as ARNs: a bundle references plenty of cloud that belongs
    to somebody else -- a CDN, an analytics vendor, a font host --
    and auto-creating targets for those would put a third party's
    infrastructure in an engagement, which is how a scanner ends up
    pointed at a company nobody is authorised to touch. A bucket
    hostname is an ordinary FQDN that `ScopeIndex` can rule on. An
    ARN is not, and could never be checked at all.
    """
    found = assetlinks.cloud_resources(f.body or "")
    if not found:
        return 0, 0
    # The file IS the provenance, so it is read once here rather than
    # per resource: one bundle names up to fifty of these.
    place = await _origin_of(session, f)
    added = refused = 0
    for provider, host in found:
        try:
            h = normalise_host(host)
        except InvalidHost:
            continue
        if not idx.check(h).allowed:
            # Not an error. The overwhelmingly common case is a
            # vendor's bucket, and refusing it is the feature.
            refused += 1
            continue
        dup = (await session.execute(
            select(Target).where(Target.project_id == project_id,
                                 Target.host == h))).scalar_one_or_none()
        if dup is not None:
            # An existing host row that turns out to be a cloud
            # resource is relabelled, not duplicated: the unique
            # constraint is (project, host) and the kind is new
            # information about a row we already had.
            if dup.kind == "host" and not dup.provider:
                dup.kind, dup.provider = "cloud", provider
            # Recorded even so. "This bundle names it" is true of a
            # row we already had, and it is the only answer anybody
            # has to "where did this come from".
            await _remember_origin(session, project_id, dup.id, place)
            continue
        t = Target(project_id=project_id, host=h, kind="cloud",
                   provider=provider, alive=None)
        session.add(t)
        # Flushed for its id: the origin row needs one, and a target
        # that arrives with no account of where it came from is the
        # thing this is here to stop.
        await session.flush()
        await _remember_origin(session, project_id, t.id, place)
        added += 1
    return added, refused


@dataclass(frozen=True)
class _Place:
    """The one spot a cloud identifier was read out of."""
    asset_id: int | None
    file_id: int | None
    asset_url: str | None
    file_path: str | None
    page_url: str | None
    origin_hash: str


async def _origin_of(session: AsyncSession, f) -> _Place:
    """Describe where this file sits, for the provenance row.

    `page_url` is the asset's `first_page` -- the page it was first
    seen on. Every page that loads the asset is in `web_asset_refs`
    and the API reads them from there; storing all of them here would
    be four hundred rows per bucket saying one thing.
    """
    asset = (await session.get(WebAsset, f.asset_id)
             if getattr(f, "asset_id", None) else None)
    asset_url = asset.url if asset is not None else None
    path = getattr(f, "path", None)
    return _Place(
        asset_id=getattr(f, "asset_id", None),
        file_id=getattr(f, "id", None),
        asset_url=asset_url,
        file_path=path,
        page_url=(asset.first_page if asset is not None else None),
        # Over what identifies the PLACE, not the row: the file row is
        # rewritten whenever its bytes change, and a new id each time
        # would file the same discovery again on every sweep.
        origin_hash=origin_key("asset", asset_url, path),
    )


async def _remember_origin(session: AsyncSession, project_id: int,
                           target_id: int, place: _Place) -> None:
    """Record that this target was found in this place, once.

    Upserted on (target, origin_hash), which is what the unique
    constraint keys on: the sweep reads the same bundle every pass.
    """
    have = (await session.execute(
        select(TargetOrigin.id).where(
            TargetOrigin.target_id == target_id,
            TargetOrigin.origin_hash == place.origin_hash))).first()
    if have:
        return
    session.add(TargetOrigin(
        project_id=project_id, target_id=target_id, source="asset",
        asset_id=place.asset_id, file_id=place.file_id,
        asset_url=place.asset_url, file_path=place.file_path,
        page_url=place.page_url, origin_hash=place.origin_hash))


async def scan_project(session: AsyncSession, project_id: int, *,
                       limit: int = SCAN_BATCH) -> Swept:
    """Run the scanners over files nothing has read yet."""
    out = Swept()
    have = assetscan.available()
    if not any(have.values()):
        # Not an error and not a clean result. A sweep with no
        # scanner present has not shown that these files are free of
        # anything -- it has shown nothing, and saying so is the
        # difference between a gap and a pass.
        out.notes.append(
            "no scanner is installed, so nothing was examined: "
            f"{have}. This is not a clean result.")
        return out
    if not all(have.values()):
        out.notes.append(f"only some scanners are present: {have}")

    rows = (await session.execute(
        select(WebAssetFile)
        .where(WebAssetFile.project_id == project_id,
               WebAssetFile.scanned_at.is_(None),
               WebAssetFile.body.is_not(None))
        .order_by(WebAssetFile.id).limit(limit))).scalars().all()
    rows = _within_budget(rows)

    # One index for the batch. Built here rather than per file
    # because it is a SELECT over the project's scope rows and the
    # batch is a hundred files.
    _idx = await index_for(session, project_id)

    # Endpoints first: this is text extraction, it cannot fail, and
    # it is worth having even on a sweep where the scanners are
    # missing or time out. Only for files that are actually code --
    # running it over a stylesheet finds the same handful of font
    # URLs on every project.
    for f in rows:
        if os.path.splitext(f.path)[1].lower() not in (
                ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue",
                ".json", ".html", ""):
            continue
        out.endpoints += await _record_endpoints(session, f)
        _added, _refused = await _record_cloud(session, project_id, _idx, f)
        out.cloud += _added
        out.cloud_refused += _refused

    found, ok = await scan_batch([(f.id, f.path, f.body or "") for f in rows])
    if not ok:
        # Do NOT mark these scanned. A scanner that timed out has
        # examined nothing, and stamping the file would retire it
        # from the queue for ever on the strength of a failure.
        out.notes.append(
            "a scanner did not complete, so this batch is NOT marked "
            "scanned and will be retried. Nothing here is a clean result.")
    # Hosts whose files this batch actually read. Collected even when
    # a file produced nothing, because that is precisely the case
    # that lets a finding be called resolved: the scanner ran, the
    # key is no longer in the bundle, and only a recorded look can
    # tell that apart from nobody having checked.
    swept: set[int] = set()
    for f in rows:
        out.scanned += 1
        if ok:
            f.scanned_at = assetfetch.now()
        asset = (await session.execute(
            select(WebAsset).where(WebAsset.id == f.asset_id))).scalar_one()
        tid = await _target_for(session, asset)
        findings = found.get(f.id) or []
        if tid is None:
            out.unattributable += len(findings)
            continue
        if ok:
            swept.add(tid)
        for fi in findings:
            if await _file_vuln(session, tid, fi, asset.url, asset.id):
                out.findings += 1

    # Only the scanners that were actually PRESENT, and only when the
    # run completed. A sweep recorded for a scanner that is missing
    # from the image would resolve findings nothing looked for --
    # which is not hypothetical here: trufflehog was deleted from the
    # running container by something outside this codebase and
    # `available()` answered False for weeks.
    if ok and swept:
        now = datetime.now(UTC)
        live = [n for n, present in assetscan.available().items() if present]
        for name in live:
            # These two take no run-time arguments that change what
            # they can find -- the rule set is whatever is installed
            # -- so the manifest is the scanner's own identity. It
            # compares equal to itself across runs, which is the true
            # answer: nothing about the configuration moved.
            mf, detail = manifest.build(name)
            await lifecycle.remember_manifest(session, name, mf, detail, now)
            for tid in swept:
                await lifecycle.record_sweep(session, project_id, tid,
                                             name, now, mf)
    # Committed here, after one scanner run rather than one per file:
    # the batch IS the unit of work now, so a partial commit would
    # record files as scanned that the single invocation covered
    # together.
    await session.commit()
    if rows:
        await session.execute(
            WebAsset.__table__.update()
            .where(WebAsset.id.in_({f.asset_id for f in rows}))
            .values(scanned_at=assetfetch.now()))
    await session.commit()
    return out


async def scan_batch(items: list[tuple[int, str, str]]
                     ) -> tuple[dict[int, list[assetscan.Finding]], bool]:
    """Scan many files in ONE invocation of each scanner.

    `items` is (id, path, body). Returns findings per id.

    **One invocation per batch, not per file.** Both tools spend
    almost all of their time starting up -- opengrep loads and
    compiles its ruleset every run -- so a per-file loop paid that
    cost for every file. Measured on the deployed image: 12.3s for a
    single small .js file against the javascript rules alone, and a
    timeout against the whole corpus. The same startup covers a
    hundred files just as well, which is the difference between a
    sweep that keeps up and one that never finishes.

    Files are written under names WE choose (`<id>__<base>`), not the
    paths from a source map: those are attacker-influenced, and a
    filename handed to a subprocess is the one place that could
    still matter. The id prefix is how results map back.
    """
    out: dict[int, list[assetscan.Finding]] = {i: [] for i, _, _ in items}
    if not items:
        return out, True
    have = assetscan.available()
    # Whether the scanners actually finished. A timeout returns no
    # output, which is indistinguishable from "found nothing" unless
    # it is tracked -- and a file marked scanned on the strength of a
    # timeout is a file nobody will ever look at again. This is the
    # whole "a failed lookup is not evidence" rule, applied to our
    # own tooling: 50 files were stamped exactly that way in
    # production before this existed.
    ok = True
    real = {i: path for i, path, _ in items}

    with tempfile.TemporaryDirectory(prefix="oddjob-scan-") as d:
        by_name: dict[str, int] = {}
        exts: set[str] = set()
        for fid, path, body in items:
            ext = os.path.splitext(path)[1][:8] or ".txt"
            exts.add(ext)
            name = f"{fid}__{os.path.basename(path)[:60] or 'file'}"
            if not name.endswith(ext):
                name += ext
            by_name[name] = fid
            with open(os.path.join(d, name), "w",
                      encoding="utf-8", errors="replace") as fh:
                fh.write(body)

        def owner(reported: str) -> int | None:
            base = os.path.basename(reported or "")
            if base in by_name:
                return by_name[base]
            head = base.split("__", 1)[0]
            return int(head) if head.isdigit() else None

        # The union of rule sets the batch needs, so a mixed batch is
        # still one run rather than one per language.
        rules: list[str] = []
        for e in sorted(exts):
            for r in assetscan.rules_for("x" + e):
                if r not in rules:
                    rules.append(r)

        if have.get("opengrep") and rules:
            argv = [assetscan.OPENGREP, "scan", "--json",
                    f"--max-memory={assetscan.MAX_MEMORY_MB}",
                    f"--jobs={assetscan.JOBS}"]
            argv += [f"--config={r}" for r in rules]
            argv.append(d)
            rc, so, se = await assetscan._run(
                argv, b"", env=assetscan.OPENGREP_ENV)
            if rc not in (0, 1):
                ok = False
                log.warning("assetwork: opengrep rc=%s (%s): %s",
                            rc, "TIMED OUT" if rc == -1 else "failed",
                            se[-200:])
            for f in assetscan.parse_opengrep(so, ""):
                fid = owner(f.path)
                if fid is not None:
                    out[fid].append(_reseat(f, real[fid]))

        # trufflehog over the whole directory, one invocation like
        # opengrep. `filesystem` walks it; `--no-update` keeps a
        # scanner that reads a client's source from reaching out to
        # check its own version mid-sweep.
        #
        # It is additive to detect-secrets, not a replacement. That
        # one finds strings that LOOK like credentials; this one
        # carries detectors that know what each vendor's key is for
        # and can confirm a live one with the provider. Running both
        # and deduplicating on fingerprint costs one subprocess and
        # catches what either alone would miss.
        if have.get("trufflehog"):
            rc, so, se = await assetscan._run(
                [assetscan.TRUFFLEHOG, "filesystem", d,
                 "--json", "--no-update"], b"",
                # trufflehog is a Go binary and reserves a virtual
                # arena far larger than it will ever make resident, so
                # RLIMIT_AS kills it during package init -- `panic:
                # cannot allocate memory`, before it reads a byte. The
                # directory it is handed is already capped by
                # SCAN_BUDGET_BYTES and the container limit is still
                # the backstop. See assetscan._bound_memory.
                bound_memory=False)
            # trufflehog exits non-zero when it FINDS things with
            # some flag combinations, so the output is what decides,
            # not the status. Only a run that produced nothing AND
            # failed is a failure.
            if rc not in (0, 183) and not so.strip():
                ok = False
                # The HEAD of the output, not the tail. A Go panic
                # says what went wrong on its first line and then
                # prints a stack; logging the last 200 characters
                # showed the innermost frame of a goroutine and hid
                # `panic: cannot allocate memory` entirely, which cost
                # a real diagnosis. Both ends, since a timeout says
                # nothing at either.
                log.warning("assetwork: trufflehog rc=%s (%s): %s",
                            rc, "TIMED OUT" if rc == -1 else "failed",
                            (se[:300] + (" ... " + se[-120:]
                                         if len(se) > 420 else "")))
            for f in assetscan.parse_trufflehog(so):
                fid = owner(f.path)
                if fid is not None:
                    out[fid].append(_reseat(f, real[fid]))

        # detect-secrets runs IN PROCESS, per file: it is a Python
        # library, not a subprocess, so there is no startup cost to
        # amortise and batching would only lose the per-file path.
        # It carries both vendor regexes and Shannon entropy, which
        # is what finds a credential belonging to no issuer we have
        # a pattern for.
        if have.get("detect-secrets"):
            for fid, fpath, fbody in items:
                for f in assetscan.scan_detect_secrets(fpath, fbody):
                    out[fid].append(f)
    return out, ok


def _reseat(f: assetscan.Finding, path: str) -> assetscan.Finding:
    """Put the REAL path back on a finding.

    The scanners saw our temporary name. A finding has to name the
    file the developer would recognise -- `src/auth/session.ts`, not
    `4821__session.ts` in a directory that no longer exists.
    """
    # Rebuilt from the real path, not string-replaced into the old
    # one. Substituting the basename left the temporary directory in
    # the title -- "... in /tmp/oddjob-scan-9e4nptlz/js/src/
    # dropdown.js" -- naming a directory that no longer exists, in
    # the field a client reads first.
    title = f"{f.rule} in {path}"
    return assetscan.Finding(
        scanner=f.scanner, rule=f.rule, title=title[:1000],
        severity=f.severity, path=path, line=f.line,
        detail=f.detail, fingerprint=f.fingerprint, secret=f.secret)


async def _record_endpoints(session: AsyncSession, f) -> int:
    """Store the endpoints one file references. -> how many are new.

    Upserted on (asset, value): the same path appears in a hundred
    files of one bundle and again on every later sweep, so without
    the key this table would grow without bound while saying nothing
    new.
    """
    eps = assetlinks.extract(f.body or "")
    if not eps:
        return 0
    have = {v for (v,) in (await session.execute(
        select(WebAssetEndpoint.value).where(
            WebAssetEndpoint.asset_id == f.asset_id))).all()}
    added = 0
    for e in eps:
        if e.value in have:
            continue
        host = None
        if e.kind == "url":
            hs = assetlinks.hosts_of([e])
            host = hs[0][:255] if hs else None
        session.add(WebAssetEndpoint(
            project_id=f.project_id, asset_id=f.asset_id, file_id=f.id,
            kind=e.kind, value=e.value[:2000], host=host))
        have.add(e.value)
        added += 1
    return added


#: Entropy findings whose value turns up on more than one host in
#: the same engagement.
#:
#: A credential issued to one application does not appear on
#: forty-one different hosts. What does is library content: a CDN
#: bundle, a framework build hash, a shared analytics id, the same
#: vendor script deployed everywhere.
#:
#: Measured rather than assumed. Of 1,498 entropy findings on a live
#: estate, 1,025 -- 68% -- had a value that appeared on more than one
#: host. Not one of them was that host's secret.
#:
#: Only entropy. A named vendor shape repeating across hosts is a
#: real credential reused across hosts, which is a FINDING and a
#: worse one than a single leak.
async def shared_entropy_values(session: AsyncSession,
                                project_id: int) -> set[str]:
    """Values an entropy detector found on more than one host here."""
    rows = (await session.execute(
        select(FindingSecret.secret)
        .join(Vuln, Vuln.id == FindingSecret.vuln_id)
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == project_id,
               FindingSecret.detector.in_(assetscan._ENTROPY_TYPES))
        .group_by(FindingSecret.secret)
        .having(func.count(func.distinct(Vuln.target_id)) > 1))).scalars().all()
    return set(rows)


async def prune_shared_secrets(session: AsyncSession,
                               project_id: int) -> dict[str, int]:
    """Retract entropy findings that later proved to be shared. -> counts.

    The cross-host test cannot be made at the moment a finding is
    filed: the first host to be scanned has nothing to compare
    against, and the value only becomes "shared" when the second
    host arrives. So it is a sweep, and it is idempotent.

    **Only untriaged rows.** A finding a person has looked at and
    marked is that person's judgement, and a sweep does not get to
    overturn it -- in either direction. This is the same line
    `nsefindings.record` draws when it re-asserts a severity but
    never a triage.
    """
    shared = await shared_entropy_values(session, project_id)
    out = {"shared_values": len(shared), "retracted": 0, "kept_triaged": 0}
    if not shared:
        return out
    rows = (await session.execute(
        select(Vuln, FindingSecret)
        .join(FindingSecret, FindingSecret.vuln_id == Vuln.id)
        .join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == project_id,
               FindingSecret.detector.in_(assetscan._ENTROPY_TYPES),
               FindingSecret.secret.in_(shared)))).all()
    for v, _fs in rows:
        if v.triage != "needs_investigating":
            out["kept_triaged"] += 1
            continue
        # Deleted rather than demoted. These are scanner artefacts
        # that nobody has looked at, and a list of 1,025 findings
        # marked "probably not" is still a list of 1,025 findings
        # between an operator and the four that matter.
        await session.delete(v)
        out["retracted"] += 1
    await session.commit()
    return out


def origin_block(asset_url: str, path: str, line: int | None) -> str:
    """Where a finding came from, as the tail of its description.

    A named function and not an f-string inline, because the
    `c5a2d83f61e4` migration parses this exact shape back out of
    descriptions written before the origin had columns. Two places
    that must agree about a format should be able to be tested
    against each other, which an f-string buried in a function
    body cannot be.
    """
    out = f"{asset_url}\n\nFile: {path}"
    return (out + f":{line}") if line else out


async def _file_vuln(session: AsyncSession, target_id: int,
                     f: assetscan.Finding, asset_url: str,
                     asset_id: int | None = None) -> bool:
    """Record one finding. -> True if it is new.

    Keyed on the scanner fingerprint via `external_id`, which is the
    project's existing upsert key for vulns. Re-running a sweep over
    an unchanged file therefore amends rather than growing a second
    copy of every finding.
    """
    eid = f"{f.scanner}:{f.fingerprint}"
    existing = (await session.execute(
        select(Vuln).where(Vuln.target_id == target_id,
                           Vuln.external_id == eid))).scalar_one_or_none()

    async def _keep_secret(vuln_id: int) -> None:
        """Store the credential beside the finding, never inside it.

        One row per finding, upserted: re-scanning the same bundle
        must not accumulate copies of a key.
        """
        if not f.secret:
            return
        row = (await session.execute(select(FindingSecret).where(
            FindingSecret.vuln_id == vuln_id))).scalar_one_or_none()
        # Origin stored as columns as well as in the description.
        # The description is for someone reading this one finding;
        # these are for a list that has to show where a hundred
        # credentials came from without parsing prose.
        url, where, line = asset_url[:2000], f.path[:2000], f.line
        if row is None:
            session.add(FindingSecret(
                vuln_id=vuln_id, secret=f.secret[:8000], detector=f.rule[:128],
                asset_url=url, path=where, line=line))
        else:
            row.secret, row.detector = f.secret[:8000], f.rule[:128]
            row.asset_url, row.path, row.line = url, where, line
    body = f"{f.detail}\n\n{origin_block(asset_url, f.path, f.line)}"
    # Seen again, whether or not a field moved. The scanner is the
    # one that found it (`trufflehog`, `semgrep`), not "assets": a
    # secret scanner reporting nothing says nothing about whether a
    # static-analysis finding is still there, and a shared name would
    # let either resolve the other's work.
    now = datetime.now(UTC)
    if existing is not None:
        existing.description = body[:8000]
        existing.severity = _severity_floor(f.severity)
        existing.last_seen_at = now
        if existing.first_seen_at is None:
            existing.first_seen_at = now
        if not existing.scanner:
            existing.scanner = f.scanner[:64]
        existing.found_by_manifest = manifest.build(f.scanner)[0]
        if asset_id and not existing.asset_id:
            existing.asset_id = asset_id
        await _keep_secret(existing.id)
        return False
    v = Vuln(target_id=target_id, title=f.title[:1000],
             severity=_severity_floor(f.severity), status="open",
             description=body[:8000], external_id=eid[:128],
             scanner=f.scanner[:64], first_seen_at=now, last_seen_at=now,
             found_by_manifest=manifest.build(f.scanner)[0],
             # Which bundle it came out of, where there is one. NULL
             # for a page finding: a page is not an asset, and the
             # two being indistinguishable is what made the secret
             # source viewer claim deleted evidence.
             asset_id=asset_id)
    session.add(v)
    # Flushed so the row has an id to hang the secret off.
    await session.flush()
    await _keep_secret(v.id)
    return True


# ------------------------------------------------------------- pages
#
# The same two scanners, over the pages themselves.
#
# `scan_project` above reads the files a page PULLS IN -- bundles,
# source maps, the originals recovered from them. It never read the
# page. That is a gap with nothing behind it: an API key inlined in
# a <script> block, a comment holding a staging credential and a
# JSON response carrying a token are the same finding as the same
# string in a bundle, and the bundle is the one we were reading.
#
# **2xx only**, which is the operator's rule and also the right one:
# a 404 body is the server's error template, identical across a
# thousand URLs, and scanning it files the same finding a thousand
# times. A 401 or a 403 is a page we were not shown.
#
# **The body, not the headers.** A captured exchange's header block
# is full of session cookies and bearer tokens -- the client's own,
# set by their own application, present on every authenticated
# response. detect-secrets over those would report a credential on
# every page in the estate and bury the one that is actually
# inlined in the markup. What is worth finding here is what the
# application SHIPS, so that is what is read.
#
# No scope gate and no fetching: every row here was already
# retrieved, by a ghost, against a target that cleared the gate at
# the time. This reads what is on record.

#: Content types we will read, mapped to the extension that picks a
#: ruleset. Anything else -- an image, a font, a PDF -- is bytes
#: that opengrep has no rules for and detect-secrets would only
#: find entropy in.
_PAGE_TYPES = {
    "text/html": ".html",
    "application/xhtml+xml": ".html",
    "text/javascript": ".js",
    "application/javascript": ".js",
    "application/x-javascript": ".js",
    "application/json": ".json",
    "text/json": ".json",
    "application/xml": ".xml",
    "text/xml": ".xml",
    "text/plain": ".txt",
    "text/css": ".css",
}

#: The longest body we will hand a scanner. The same cap the file
#: sweep works under in practice, and a captured response can run to
#: two megabytes of minified bundle that is already being read as an
#: asset in its own right.
PAGE_BODY_CAP = 400_000


def page_ext(url: str, content_type: str | None,
             body: str | None = None) -> str | None:
    """Which ruleset this response should be read against, or None.

    The URL's own extension first, because `/app.js` is JavaScript
    whatever a misconfigured server says the type is. The declared
    content type second. Neither matching means we do not know what
    this is, and guessing `.txt` at an unknown type is how a font
    file ends up in front of a secret scanner.
    """
    ext = os.path.splitext(urlparse(url or "").path)[1].lower()
    if ext in (".html", ".htm", ".js", ".mjs", ".json", ".xml", ".txt",
               ".css", ".jsx", ".ts"):
        return ".html" if ext == ".htm" else ext
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in _PAGE_TYPES:
        return _PAGE_TYPES[ct]
    # No extension and no type at all is not the edge case it looks
    # like: on the engagement this was built against, 48,990 of the
    # 51,059 eligible responses declared no content type -- 96%. So
    # whatever this branch returns is what the sweep actually does,
    # and `.txt` sent nearly every page to the `generic` ruleset,
    # whose `gitleaks.generic-api-key` rule then supplied 54% of
    # everything the first 300 pages produced.
    #
    # The body is the evidence and it is already in hand, so it
    # decides. `None` only when there is nothing to go on.
    if not ext and not ct:
        return sniff_ext(body) if body else None
    return None


def sniff_ext(body: str) -> str | None:
    """What a response body is, or None when we cannot tell.

    **None means "do not scan this", and that is the point.** The
    first version of this fell back to `.txt`, which selects the
    `generic` ruleset, whose `gitleaks.generic-api-key` rule then
    supplied 54% of everything the first 300 pages of the live sweep
    produced. A classifier that always answers is a classifier whose
    answer means nothing -- the same rule as everywhere else here:
    "could not determine" is its own answer and must not collapse
    into a guess.

    What the live corpus actually holds, for the 48,990 responses
    that declared no content type at all:

        8,299  HTML behind a newline or a BOM
        5,748  HTML, plainly
        1,100  JavaScript -- licence banner, IIFE, jQuery ready
          291  CSS
          161  JSON
          150  HTML behind a chunked-transfer size line
          131  PDF
           65  XML

    Each of those wants different rules, and the PDFs want none:
    reading a binary as text is how an entropy detector finds a
    credential in a compression stream.
    """
    head = _text_head(body)
    if not head:
        return None
    low = head.lower()

    # Binary first, because everything below assumes text. These are
    # magic numbers, not guesses.
    for magic in ("%pdf-", "\x89png", "gif8", "\xff\xd8\xff", "pk\x03\x04",
                  "\x7felf", "rar!", "\x1f\x8b"):
        if low.startswith(magic):
            return None
    if "\x00" in head[:256]:
        # A NUL in the first screenful is not a page. SQLite stores
        # these happily and Postgres does not, which is its own
        # entry in this repo's list of things that bite.
        return None

    if low.startswith("<?xml"):
        return ".xml"
    if low.startswith("<!doctype") or low.startswith("<html") or low.startswith("<"):
        return ".html"
    if head[0] in "{[":
        return ".json"

    # JavaScript served at a web address rather than as an asset.
    # 1,100 of them on the live corpus, and they are the bodies most
    # worth reading properly -- the javascript rules are where the
    # findings that matter come from.
    if (low.startswith(("/*", "//", "(function", "function(", "function ",
                        "!function", "+function", "$(", "import ", "export ",
                        "'use strict'", '"use strict"', "var ", "const ",
                        "let ", "window.", "document."))):
        return ".js"
    # CSS: a selector or an at-rule. Checked after JavaScript because
    # `.foo{` and a member access both start with a dot.
    if low.startswith(("@media", "@import", "@charset", "@font-face")):
        return ".css"
    if re.match(r"^[.#]?[a-z][\w .#>:,\[\]=\"'-]{0,120}\{", low):
        return ".css"

    # Text we hold and cannot name. NOT `.txt`: see the docstring.
    return None


#: Leading bytes that are not the body, stripped before anything
#: looks at it.
#:
#: A BOM is not whitespace to `str.lstrip`, so 148 responses that
#: are plainly HTML were being classified as something else by the
#: first version of this. A chunked-transfer size line is not part
#: of the body at all -- the capture stored the wire bytes without
#: de-chunking, so 150 more opened with `14e27` before their
#: doctype.
_CHUNK_SIZE_LINE = re.compile(r"^[0-9a-fA-F]{1,8}(;[^\r\n]*)?\r?\n")


def _text_head(body: str) -> str:
    """The start of a body, with what is not the body taken off."""
    if not body:
        return ""
    head = body.lstrip("\ufeff\r\n\t ")
    m = _CHUNK_SIZE_LINE.match(head)
    if m:
        head = head[m.end():].lstrip("\ufeff\r\n\t ")
    return head[:512]


def response_body(raw: str) -> str:
    """The body of a captured exchange, without the header block.

    A capture may be a raw HTTP response -- status line, headers,
    blank line, body -- or it may be the body alone, depending on
    which importer wrote it. Detected rather than configured,
    because both shapes are in the table already.

    Returns the whole string when there is no header block to strip:
    a body that happens to contain a blank line must not be cut at
    it.
    """
    if not raw:
        return ""
    if not raw[:9].upper().startswith(("HTTP/1", "HTTP/2", "HTTP/3")):
        return raw
    for sep in ("\r\n\r\n", "\n\n"):
        i = raw.find(sep)
        if i != -1:
            return raw[i + len(sep):]
    # Headers and nothing else. Not an error -- a 204 looks like
    # this -- and there is simply no body to read.
    return ""


async def scan_pages(session: AsyncSession, project_id: int, *,
                     limit: int = SCAN_BATCH) -> Swept:
    """Run the scanners over 2xx response bodies nothing has read."""
    out = Swept()
    have = assetscan.available()
    if not any(have.values()):
        # Same rule as the file sweep: a sweep with no scanner has
        # not shown these pages are clean, it has shown nothing.
        out.notes.append(
            "no scanner is installed, so no page was examined: "
            f"{have}. This is not a clean result.")
        return out

    from .models import WebAddress

    rows = (await session.execute(
        select(WebAddress)
        .join(Target, Target.id == WebAddress.target_id)
        .where(Target.project_id == project_id,
               WebAddress.scanned_at.is_(None),
               WebAddress.status_code >= 200,
               WebAddress.status_code < 300,
               WebAddress.response.is_not(None))
        .order_by(WebAddress.id).limit(limit))).scalars().all()
    if not rows:
        return out

    items: list[tuple[int, str, str]] = []
    skipped: set[int] = set()
    for w in rows:
        body = response_body(w.response or "")[:PAGE_BODY_CAP]
        ext = page_ext(w.url or "", w.content_type, body)
        if ext is None or not body.strip():
            # Nothing a scanner can read. Marked scanned so it does
            # not sit at the head of the queue for ever -- unlike a
            # scanner failure, this IS a finished answer: we looked
            # at what it is and there is nothing to read.
            skipped.add(w.id)
            w.scanned_at = assetfetch.now()
            out.scanned += 1
            continue
        # A name, not the URL. `scan_batch` writes these to disk and
        # a URL carries slashes, query strings and whatever a target
        # chose to put in a path.
        base = os.path.basename(urlparse(w.url or "").path) or "index"
        items.append((w.id, f"{base}{ext}"
                      if not base.endswith(ext) else base, body))

    found, ok = await scan_batch(items)
    if not ok:
        out.notes.append(
            "a scanner did not complete, so this batch of pages is NOT "
            "marked scanned and will be retried. Nothing here is a "
            "clean result.")
    for w in rows:
        if w.id in skipped:
            continue
        out.scanned += 1
        if ok:
            w.scanned_at = assetfetch.now()
        for fi in (found.get(w.id) or []):
            # Entropy is not a finding on a page.
            #
            # `assetscan` already says why for a bundle -- "a
            # high-entropy string in minified JavaScript is very
            # often a hash" -- and on markup it is worse: SRI
            # digests, CSP nonces, inline data URIs and analytics
            # ids are all high-entropy and none of them is a
            # credential. Measured on the first 300 pages of the
            # live sweep, 39% of everything raised was one of these
            # two detectors.
            #
            # Named vendor shapes still count. Dropping "it looked
            # random" is not the same as dropping "this is a Google
            # API key", and the second is the reason to read pages
            # at all.
            if fi.rule in assetscan._ENTROPY_TYPES:
                out.entropy_skipped += 1
                continue
            # The title has to name the PAGE. `scan_batch` saw a
            # temporary file, so without this every finding reads
            # "... in index.txt" -- which is the synthetic name this
            # function invented, tells a reader nothing, and is
            # identical across thousands of different pages.
            fi = _reseat(fi, w.url or "")
            # The URL is the origin, and a page always has a target:
            # `WebAddress.target_id` is NOT NULL, which is why there
            # is no `unattributable` count here as there is for
            # assets.
            if await _file_vuln(session, w.target_id, fi, w.url or ""):
                out.findings += 1
    await session.commit()
    return out


async def pending(session: AsyncSession, project_id: int) -> dict[str, int]:
    """What is still owed, for a page that wants to show a backlog."""
    unfetched = (await session.execute(
        select(func.count()).select_from(WebAsset).where(
            WebAsset.project_id == project_id,
            WebAsset.fetched_at.is_(None),
            WebAsset.kind.in_(tuple(assetfetch.FETCHABLE_KINDS))))).scalar_one()
    unscanned = (await session.execute(
        select(func.count()).select_from(WebAssetFile).where(
            WebAssetFile.project_id == project_id,
            WebAssetFile.scanned_at.is_(None)))).scalar_one()
    from .models import WebAddress
    unscanned_pages = (await session.execute(
        select(func.count()).select_from(WebAddress)
        .join(Target, Target.id == WebAddress.target_id)
        .where(Target.project_id == project_id,
               WebAddress.scanned_at.is_(None),
               WebAddress.status_code >= 200,
               WebAddress.status_code < 300,
               WebAddress.response.is_not(None)))).scalar_one()
    return {"unfetched": int(unfetched), "unscanned": int(unscanned),
            "unscanned_pages": int(unscanned_pages)}





# ------------------------------------------------------------- worker
#
# Automatic, for every project, with no switch to leave off.
#
# The other standing orders are opt-in because each one QUEUES SCANS
# against a client and the operator decides when that starts. This
# one is different in kind and that is why it is always on: the
# assets are files a client's own pages already serve to every
# visitor, and reading what an application ships is not an escalation
# of what we are already doing to it -- it is reading the evidence a
# crawl has already collected the references to.
#
# Paced rather than unbounded. A cycle does a small fetch batch and a
# smaller scan batch: fetching sends one request per asset to the
# client's estate, and opengrep takes seconds per file against the
# full ruleset, so a large batch would hold the loop and flood the
# far end for no benefit. The backlog drains over minutes instead of
# in one burst, which is the right shape for something nobody asked
# to start.

#: Seconds between cycles.
CYCLE_SECS = 120
#: After an unexpected failure. Longer, so a persistent error does
#: not become a hot loop against a client's servers.
ERROR_SLEEP = 300
#: Per cycle. Small on purpose -- see above.
WORKER_FETCH = 20
#: Bigger than the fetch batch on purpose. Scanning is ONE invocation
#: of each tool over the whole batch, and almost all of the cost is
#: startup: measured on the deployed image, 40 files in one run took
#: 12.8s -- 0.32s/file against 12.3s for a single file on its own.
#: A larger batch is therefore cheaper per file, where a larger
#: FETCH batch is simply more requests at a client.
WORKER_SCAN = 100


class AssetWorker:
    """Fetches and scans every project's assets, for ever."""

    def __init__(self) -> None:
        self.task = None
        self.running = False
        self.last = "not started"

    async def _cycle(self) -> None:
        from .db import SessionLocal
        from .models import Project
        from .routers.web import DEFAULT_UA

        async with SessionLocal() as session:
            projects = (await session.execute(
                select(Project).where(
                    Project.status.in_(("active", "paused"))))).scalars().all()
            did: list[str] = []
            for pr in projects:
                owed = await pending(session, pr.id)
                if not any(owed.values()):
                    continue
                if owed["unfetched"]:
                    sw = await fetch_project(
                        session, pr.id,
                        user_agent=(pr.user_agent or DEFAULT_UA),
                        limit=WORKER_FETCH)
                    if sw.fetched or sw.failed or sw.unauthorised:
                        did.append(f"{pr.code}: fetched {sw.fetched}, "
                                   f"failed {sw.failed}, "
                                   f"unauthorised {sw.unauthorised}")
                    # Said once a cycle rather than never. A filter
                    # refusing our fetches is a fact about the
                    # engagement, not a per-asset detail, and it
                    # reads as "the client's servers refuse us"
                    # until something names it.
                    if sw.blocked:
                        did.append(
                            f"{pr.code}: {sw.blocked} asset(s) refused by a "
                            f"bot filter, not by the origin: "
                            + ", ".join(f"{k} x{v}" for k, v in
                                        sorted(sw.blocked_by.items())))
                if owed["unscanned"]:
                    sc = await scan_project(session, pr.id, limit=WORKER_SCAN)
                    if sc.scanned:
                        did.append(f"{pr.code}: scanned {sc.scanned}, "
                                   f"{sc.findings} finding(s), "
                                   f"{sc.unattributable} unattributable")
                    # A missing scanner is worth saying once a cycle
                    # rather than never: a sweep that examines nothing
                    # must not look like a sweep that found nothing.
                    for n in sc.notes:
                        did.append(f"{pr.code}: {n}")
                # The pages themselves, same scanners. Last in the
                # cycle because the file sweep is the one with a
                # fetch behind it and should not wait on this.
                # Endpoints the scanners pulled out of bundles, as
                # known addresses. Cheap -- no network, and it only
                # writes rows the scope gate allows -- and it is the
                # step that was missing: the table had been filling
                # up since endpoint extraction landed and nothing
                # read it.
                ep = await record_endpoint_urls(session, pr.id)
                if ep["added"] or ep["refused"]:
                    did.append(
                        f"{pr.code}: {ep['added']} endpoint(s) from code "
                        f"became addresses, {ep['refused']} refused "
                        f"(out of scope or not a target)")
                if owed.get("unscanned_pages"):
                    sp = await scan_pages(session, pr.id, limit=WORKER_SCAN)
                    if sp.scanned:
                        did.append(f"{pr.code}: read {sp.scanned} page(s), "
                                   f"{sp.findings} finding(s)")
                    for n in sp.notes:
                        did.append(f"{pr.code}: {n}")
                # The libraries those pages ship, against the CVE
                # corpus. A version read out of a file the client
                # serves is better evidence than a banner, and until
                # now nothing was asking about it. Cheap: one query
                # per distinct (name, version), and a project has
                # tens of those because the same four libraries are
                # on every page.
                lib = await library_leads(session, pr.id)
                if lib["findings"]:
                    did.append(
                        f"{pr.code}: {lib['findings']} finding(s) from "
                        f"{lib['with_cves']} vulnerable librar(ies)")
                if lib["unattributable"]:
                    did.append(
                        f"{pr.code}: {lib['unattributable']} library "
                        f"finding(s) could not be attributed to a host")
                # Entropy findings that later proved to be shared
                # across hosts. Cannot be decided when a finding is
                # filed -- the first host has nothing to compare
                # against -- so it is a sweep, and it is idempotent.
                pr_ = await prune_shared_secrets(session, pr.id)
                if pr_["retracted"]:
                    did.append(
                        f"{pr.code}: retracted {pr_['retracted']} "
                        f"high-entropy finding(s) whose value appears on "
                        f"more than one host")
                # Said separately. A sweep that left rows alone
                # because somebody had triaged them is behaving
                # correctly and should not look like it did nothing.
                if pr_["kept_triaged"]:
                    did.append(
                        f"{pr.code}: left {pr_['kept_triaged']} shared "
                        f"finding(s) alone — a person had already ruled "
                        f"on them")
                # And the manifests that say what went INTO the
                # build, which turn up on web servers more often than
                # anybody intends. Last in the cycle: it is the
                # cheapest thing here when there are no manifests,
                # and the most expensive when there are.
                lk = await lockfile_leads(session, pr.id)
                if lk["exposed"]:
                    did.append(
                        f"{pr.code}: {lk['exposed']} dependency "
                        f"manifest(s) readable from outside")
                if lk["findings"]:
                    did.append(
                        f"{pr.code}: {lk['findings']} CVE(s) pinned by "
                        f"{lk['manifests']} manifest(s)")
                # Said rather than silently dropped: a manifest with
                # nine hundred entries is read as far as the ceiling
                # and no further, and a reader must not take the
                # result for the whole file.
                if lk["truncated"]:
                    did.append(
                        f"{pr.code}: {lk['truncated']} manifest(s) pin more "
                        f"than {LOCKFILE_PACKAGES} packages; only the first "
                        f"{LOCKFILE_PACKAGES} were looked up")
            self.last = "; ".join(did) if did else "nothing outstanding"

    async def _loop(self) -> None:
        log.info("asset worker started")
        while True:
            try:
                await self._cycle()
                await asyncio.sleep(CYCLE_SECS)
            except asyncio.CancelledError:
                log.info("asset worker stopped")
                raise
            except Exception:
                # Must outlive any single failure. A crashed background
                # task fails silently and for ever, and this one dying
                # quietly means an operator believes a client's
                # JavaScript is being read when it is not.
                log.exception("asset worker iteration failed")
                await asyncio.sleep(ERROR_SLEEP)

    def start(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop())
            self.running = True


worker = AssetWorker()


# ------------------------------- the libraries a page ships, and their CVEs
#
# `web_assets` has carried `name` and `version` since library
# detection landed -- jQuery 3.6.0, Bootstrap 5.3.2 -- and nothing
# ever asked the CVE corpus about them. `leads_for_service` was only
# ever called for PORTS.
#
# That is a gap with a client-visible cost. A service banner is a
# guess about software we cannot see; a library version is read out
# of a file the client's own page serves to every visitor, which
# makes it better evidence than most of what a scan produces. An
# estate running jQuery 1.12 on four hundred pages is a real finding
# and nothing here could say so.
#
# **These are leads, and the finding says so.** The same caveat
# `leads_for_service` carries applies harder here: a backported fix
# leaves the version string alone, a bundler can mangle it, and the
# library may not be reachable in a way that matters. The row is
# `unconfirmed`, which is this database's word for exactly that.

#: How many libraries to look up in one pass. Each distinct
#: (name, version) is one query; a project has tens of them, not
#: thousands, because the same four libraries are on every page.
LIBRARY_BATCH = 200


def library_external_id(name: str, version: str, cve: str) -> str:
    """The upsert key. Stable, so a re-run amends rather than forks."""
    return f"library:{name.lower()}:{version.lower()}:{cve}"[:128]


async def library_leads(session: AsyncSession, project_id: int,
                        limit: int = LIBRARY_BATCH) -> dict[str, int]:
    """Raise a finding per (library version, CVE). -> counts."""
    from .models import Vuln
    from .vulnfeed import leads_for_service, triage_order

    rows = (await session.execute(
        select(WebAsset.name, WebAsset.version)
        .where(WebAsset.project_id == project_id,
               WebAsset.name.is_not(None),
               WebAsset.version.is_not(None))
        .distinct().limit(limit))).all()

    out = {"libraries": len(rows), "with_cves": 0, "findings": 0,
           "unattributable": 0}
    for name, version in rows:
        leads = await leads_for_service(session, name, version, limit=25)
        # Exact CPE version matches only. "Product only" means the CPE
        # covers every release of the library, which says nothing
        # about the one this page ships and would file a finding
        # against every site using jQuery at all.
        cves = [c for c in (leads.get("cves") or [])
                if str(c.get("version_match", "")).startswith("exact")]
        if not cves:
            continue
        out["with_cves"] += 1
        # Every asset carrying this exact library, so the finding lands
        # on each host that serves it rather than on one arbitrary page.
        #
        # Read ONCE per library, and without the file.
        #
        # This used to sit inside the CVE loop below and select whole
        # `WebAsset` rows, which meant re-reading every copy of jQuery
        # on the estate once per CVE, every worker cycle, for ever --
        # and `body` is on that table, averaging 145 KB a row, so a
        # library with ten CVEs and twenty copies moved ~29 MB of
        # JavaScript into the process to use `url` and `target_id`.
        # The set does not depend on the CVE and the bytes were never
        # read. Measured on the live instance at 3 GB resident with
        # nothing large having been imported: the allocator keeps the
        # high-water mark, so churn this size never comes back down.
        assets = (await session.execute(
            select(WebAsset.id, WebAsset.target_id, WebAsset.url).where(
                WebAsset.project_id == project_id,
                WebAsset.name == name,
                WebAsset.version == version))).all()
        # Worst first, now that "is it being exploited" is knowable.
        for c in triage_order(cves):
            for a in assets:
                tid = await _target_for(session, a)
                if tid is None:
                    out["unattributable"] += 1
                    continue
                eid = library_external_id(name, version, c["cve"])
                dup = (await session.execute(
                    select(Vuln).where(Vuln.target_id == tid,
                                       Vuln.external_id == eid))
                ).scalar_one_or_none()
                body = _library_body(name, version, c, a.url)
                if dup is not None:
                    dup.description = body[:8000]
                    continue
                session.add(Vuln(
                    target_id=tid,
                    title=f"{name} {version} — {c['cve']}"[:1000],
                    severity=_severity_floor(c.get("severity") or "info"),
                    # `unconfirmed`, deliberately: a backported fix
                    # leaves the version string alone, and nothing
                    # here has tested the library is reachable in a
                    # way that matters.
                    status="open", external_id=eid, description=body[:8000]))
                out["findings"] += 1
    await session.commit()
    return out


def _library_body(name: str, version: str, cve: dict, url: str) -> str:
    """What the finding says, in the words the evidence supports."""
    bits = [f"{name} {version} is served by this host, and {cve['cve']} "
            f"names that exact version.",
            "",
            (cve.get("summary") or "").strip()[:600],
            ""]
    # The two facts that change what somebody does about it this
    # morning, when they are known. See vulnfeed.triage_order.
    if cve.get("kev"):
        bits.append("On CISA's Known Exploited Vulnerabilities list: this "
                    "has been observed being used against somebody"
                    + (f", added {cve['kev_added']}" if cve.get("kev_added")
                       else "") + ".")
    if cve.get("epss") is not None:
        bits.append(f"EPSS {cve['epss']:.4f}"
                    + (f" ({cve['epss_percentile']:.0%} of all CVEs score "
                       f"lower)" if cve.get("epss_percentile") is not None
                       else "")
                    + " — the probability it is exploited in the next 30 "
                      "days.")
    bits += [
        "",
        "This is a LEAD, not a confirmed vulnerability. The version was "
        "read from the file the page serves, which is better evidence "
        "than a banner — but a backported fix leaves the version string "
        "alone, a bundler can mangle it, and nothing here has tested "
        "that the vulnerable code path is reachable.",
        "",
        f"Served from: {url}",
    ]
    return "\n".join(b for b in bits if b is not None)

# ------------------------------------ endpoints found in code, as URLs
#
# `assetlinks.extract` has been pulling API paths out of bundles since
# endpoint extraction landed, and `web_asset_endpoints` has been
# filling up with them -- and nothing read the table. The paths were
# recorded and never became part of the estate, so nothing probed
# them, nothing scanned them, and they appeared in no inventory.
#
# This is the half that was missing. It is deliberately NOT a crawl
# seed.
#
# **Why not a seed.** `webtargets.crawl_seeds` keeps a one-way edge --
# gobuster feeds katana, a crawl never feeds itself -- because a crawl
# that produces more crawling took one project from 1,109 queued tasks
# to 97,959 in under an hour. These endpoints come OUT of files found
# BY a crawl, so seeding crawls with them closes exactly that cycle:
# crawl finds a bundle, bundle names a path, path is crawled, that
# page has a bundle, and so on with no bound anybody can state in
# advance.
#
# Recorded as web addresses instead. They become known surface --
# visible in the Web view, probed by httpx, origin-scanned like
# anything else -- without any step feeding its own input. The value
# the loop was for is in knowing the endpoint exists; walking to it
# from a crawler is not required to get that.
#
# **Scope-checked before creation, exactly as `_record_cloud` is.** A
# bundle references a great deal that belongs to somebody else -- a
# CDN, an analytics vendor, a payment provider -- and turning those
# into addresses of this engagement would put a third party's
# infrastructure in it.

#: Longest path we will turn into an address. A "path" longer than
#: this came out of a minified blob and is not a route.
MAX_ENDPOINT_PATH = 512


def endpoint_url(value: str, kind: str, page: str | None) -> str | None:
    """One extracted endpoint as an absolute URL, or None.

    A `path` is resolved against the page that loaded the bundle,
    because a path alone says nothing about which host serves it. An
    endpoint whose page is unknown is dropped rather than guessed at.
    """
    v = (value or "").strip()
    if not v or len(v) > MAX_ENDPOINT_PATH:
        return None
    if kind == "url":
        u = urlparse(v)
        return v if u.scheme in ("http", "https") and u.netloc else None
    if not v.startswith("/"):
        # Relative to the bundle rather than to the site root, which
        # we cannot resolve without knowing where the bundle lived.
        # Dropped: a wrong URL is worse than a missing one.
        return None
    if not page:
        return None
    p = urlparse(page)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}{v}"


async def record_endpoint_urls(session: AsyncSession, project_id: int,
                               limit: int = 2000) -> dict[str, int]:
    """Turn extracted endpoints into web addresses. -> counts.

    Idempotent on the address's own uniqueness key, so running it
    every cycle adds each endpoint once however often it is seen.
    """
    from .models import WebAddress, WebAssetEndpoint
    from .weburl import BadUrl, exchange_key, merge_sources, parse, url_key

    idx = await index_for(session, project_id)
    rows = (await session.execute(
        select(WebAssetEndpoint.kind, WebAssetEndpoint.value,
               WebAsset.first_page)
        .join(WebAsset, WebAsset.id == WebAssetEndpoint.asset_id)
        .where(WebAssetEndpoint.project_id == project_id)
        .limit(limit))).all()

    out = {"considered": len(rows), "added": 0, "refused": 0,
           "unresolvable": 0}
    seen: set[str] = set()
    for kind, value, page in rows:
        url = endpoint_url(value, kind, page)
        if not url:
            out["unresolvable"] += 1
            continue
        if url in seen:
            continue
        seen.add(url)
        host = as_host(url)
        if not host or not idx.check(host).allowed:
            # The common case, and the feature: most of what a bundle
            # names belongs to somebody else.
            out["refused"] += 1
            continue
        tgt = (await session.execute(
            select(Target).where(Target.project_id == project_id,
                                 Target.host == host))).scalar_one_or_none()
        if tgt is None:
            # In scope but not a target yet. Not created here: making
            # targets is `enumerate`'s job and it asks a person. An
            # endpoint is not grounds for inventing a host.
            out["refused"] += 1
            continue
        try:
            u = parse(url, base_host=host)
        except BadUrl:
            out["unresolvable"] += 1
            continue
        xk = exchange_key("", u.url, None, None)
        dup = (await session.execute(
            select(WebAddress).where(
                WebAddress.target_id == tgt.id,
                WebAddress.exchange_hash == xk))).scalar_one_or_none()
        if dup is not None:
            # Already known from a crawl or a scan. Recorded as also
            # being named in code, which is worth knowing: a path a
            # bundle calls is a live route, not a leftover.
            dup.sources = merge_sources(dup.sources, "assets")
            continue
        # `sources` says where it came from and deliberately is NOT
        # "gobuster": `crawl_seeds` keys on that string to keep its
        # one-way edge, and a row from here must never become a crawl
        # seed. See the note at the top of this section.
        session.add(WebAddress(
            target_id=tgt.id, url=u.url, url_hash=url_key(u.url),
            exchange_hash=xk, scheme=u.scheme, port=u.port, path=u.path,
            method="", sources="assets"))
        out["added"] += 1
    await session.commit()
    return out


# ------------------------- dependency manifests served to the world
#
# `library_leads` above asks the CVE corpus about every library a
# page SHIPS. This is the other half: the manifests that say what
# went INTO the build, which turn up on web servers far more often
# than anybody intends.
#
# A `package-lock.json` at a web root is two findings and they are
# not the same size. That the file is there at all is certain and is
# a fact about the deployment. What is in it is a dependency
# inventory, and the CVEs it implies are a WEAKER claim than the
# ones `library_leads` raises -- a lockfile lists what the build
# resolved, much of which is devDependencies, much of the rest is
# tree-shaken out, and a good deal never reaches a browser.
#
# The finding says which one it is. Collapsing them would put a
# build-time dependency and a running one at the same severity, and
# the first one an operator checked by hand and found unreachable
# would teach them to distrust the rest.

#: How many manifests one sweep reads. Each costs a parse and a
#: corpus query per pinned package, and a lockfile can pin nine
#: hundred of them.
LOCKFILE_BATCH = 40

#: Pinned packages per manifest that get asked about. A lockfile with
#: 900 entries is 900 corpus queries, and the ones that matter are
#: not evenly spread through it -- but nor are they at the top, so
#: this is a ceiling on cost rather than a judgement about which
#: entries deserve looking at. The finding says when it was hit.
LOCKFILE_PACKAGES = 300


def lockfile_external_id(path: str, name: str, version: str,
                         cve: str) -> str:
    """The upsert key. Carries the path: the same package pinned by
    two different manifests on one host is two pieces of evidence
    about two deployments."""
    base = (path or "").rsplit("/", 1)[-1].lower()
    return f"lockfile:{base}:{name.lower()}:{version.lower()}:{cve}"[:128]


def exposed_manifest_id(url: str) -> str:
    return f"lockfile-exposed:{url}"[:128]


async def lockfile_leads(session: AsyncSession, project_id: int,
                         limit: int = LOCKFILE_BATCH) -> dict[str, int]:
    """Read served dependency manifests. -> counts.

    Two kinds of finding per manifest: that it is reachable, and
    what it pins. The first is raised whether or not the second
    produces anything -- an exposed lockfile is a finding on its own
    and waiting for a CVE to justify saying so would be the wrong
    way round.
    """
    from .models import Vuln
    from .vulnfeed import leads_for_service, triage_order

    rows = (await session.execute(
        select(WebAssetFile.id, WebAssetFile.path, WebAssetFile.body,
               WebAssetFile.asset_id)
        .join(WebAsset, WebAsset.id == WebAssetFile.asset_id)
        .where(WebAsset.project_id == project_id,
               WebAssetFile.body.is_not(None))
        .order_by(WebAssetFile.id))).all()

    out = {"manifests": 0, "packages": 0, "with_cves": 0, "findings": 0,
           "exposed": 0, "unattributable": 0, "truncated": 0}
    seen = 0
    for _fid, path, body, asset_id in rows:
        if lockfiles.format_of(path) is None:
            continue
        seen += 1
        if seen > limit:
            break
        pairs = lockfiles.parse(path, body or "")
        out["manifests"] += 1

        asset = await session.get(WebAsset, asset_id)
        if asset is None:
            out["unattributable"] += 1
            continue
        tid = await _target_for(session, asset)
        if tid is None:
            out["unattributable"] += 1
            continue

        # 1. The file is reachable. Certain, and said first.
        eid = exposed_manifest_id(asset.url)
        if (await session.execute(select(Vuln).where(
                Vuln.target_id == tid,
                Vuln.external_id == eid))).scalar_one_or_none() is None:
            session.add(Vuln(
                target_id=tid,
                title=f"Dependency manifest served to the internet: "
                      f"{path.rsplit('/', 1)[-1]}"[:1000],
                severity="low", status="open", external_id=eid,
                scanner=LOCKFILE_SCANNER,
                first_seen_at=datetime.now(UTC), last_seen_at=datetime.now(UTC),
                description=_exposed_body(asset.url, path, pairs)[:8000]))
            out["exposed"] += 1

        # 2. What it pins.
        if len(pairs) > LOCKFILE_PACKAGES:
            out["truncated"] += 1
        for name, version in pairs[:LOCKFILE_PACKAGES]:
            out["packages"] += 1
            leads = await leads_for_service(session, name, version, limit=10)
            # Exact version matches only, for the same reason
            # `library_leads` insists on them: "product only" covers
            # every release and says nothing about this one.
            cves = [c for c in (leads.get("cves") or [])
                    if str(c.get("version_match", "")).startswith("exact")]
            if not cves:
                continue
            out["with_cves"] += 1
            for c in triage_order(cves):
                cid = lockfile_external_id(path, name, version, c["cve"])
                dup = (await session.execute(select(Vuln).where(
                    Vuln.target_id == tid,
                    Vuln.external_id == cid))).scalar_one_or_none()
                b = _lockfile_body(name, version, c, asset.url, path)
                if dup is not None:
                    dup.description = b[:8000]
                    continue
                session.add(Vuln(
                    target_id=tid,
                    title=f"{name} {version} pinned by "
                          f"{path.rsplit('/', 1)[-1]} — {c['cve']}"[:1000],
                    # One step below what `library_leads` would give
                    # the same CVE. A build-time dependency is not a
                    # running one, and the body says so.
                    severity=_one_below(c.get("severity") or "info"),
                    status="open", external_id=cid,
                    scanner=LOCKFILE_SCANNER,
                    first_seen_at=datetime.now(UTC),
                    last_seen_at=datetime.now(UTC),
                    description=b[:8000]))
                out["findings"] += 1
    await session.commit()
    return out


#: Attributed separately from the page scanners. A secret scanner
#: finding nothing says nothing about whether a lockfile CVE is
#: still there, and a shared name would let either resolve the
#: other's work. See app/lifecycle.py.
LOCKFILE_SCANNER = "lockfile"

#: One step down the ladder, for a dependency that was built with
#: rather than demonstrably served.
_LOWER = {"critical": "high", "high": "medium", "medium": "low",
          "low": "info", "info": "info"}


def _one_below(severity: str) -> str:
    return _LOWER.get(_severity_floor(severity), "info")


def _exposed_body(url: str, path: str, pairs: list) -> str:
    return "\n".join([
        f"{path.rsplit('/', 1)[-1]} is readable at {url}.",
        "",
        "A dependency manifest names every package and exact version "
        "the application was built with, which is an inventory of what "
        "to look up next. It is not supposed to be reachable from "
        "outside.",
        "",
        f"It pins {len(pairs)} package(s) at an exact version."
        if pairs else
        "Nothing in it parsed as a pinned package — which may mean the "
        "format is one this does not read, rather than that the file is "
        "empty.",
    ])


def _lockfile_body(name: str, version: str, cve: dict, url: str,
                   path: str) -> str:
    """What the finding says, kept to what the evidence supports."""
    bits = [
        f"{path.rsplit('/', 1)[-1]} at {url} pins {name} {version}, and "
        f"{cve['cve']} names that exact version.",
        "",
        (cve.get("summary") or "").strip()[:600],
        "",
        "**This is a build-time dependency, not a library this site has "
        "been seen to serve.** A lockfile lists what the build resolved: "
        "some of it is devDependencies, some is removed by tree-shaking, "
        "and some never reaches a browser. Whether this package is "
        "reachable in the running application has not been established "
        "here — that is the check to do next, and it is why this is "
        "filed one severity below the same CVE found in a library the "
        "page actually loads.",
    ]
    if cve.get("kev"):
        bits.append("")
        bits.append("On CISA's Known Exploited Vulnerabilities list: this "
                    "has been observed being used against somebody.")
    return "\n".join(b for b in bits if b is not None)
