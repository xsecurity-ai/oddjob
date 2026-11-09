"""The query-shape decisions that made the database 60% idle work.

Three changes, each of which is only correct if a specific property
holds, and each property is cheap to assert and expensive to discover
broken in production:

  the memo      `leads_for_service` answers the same question many
                times per sweep. Caching is right ONLY if the key
                distinguishes every input that changes the answer --
                a key that collapses two different services reports
                one service's CVEs against the other.

  the bulk      the EPSS sweep issues one UPDATE per chunk instead of
                one per CVE. `executemany` is right ONLY if each row
                still lands on its own id; a bound parameter sharing
                a column's name collides and writes the wrong row.

  the indexes   the trigram indexes are Postgres-only and the drops
                are not. A migration that skipped the drops off
                Postgres would leave SQLite reporting schema drift
                for ever.
"""
import pathlib as _pathlib
import sys as _sys

_sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parents[1]))
import asyncio

ok = fail = 0


def check(l, c, e=""):
    global ok, fail
    if c: ok += 1; print(f"  PASS  {l} {e}")
    else: fail += 1; print(f"  FAIL  {l} {e}")


print("--- the lead memo distinguishes everything that changes the answer ---")
from app import vulnfeed  # noqa: E402


async def memo():
    calls = []

    # Stand in for the expensive half: record what was asked, so the
    # test can see which questions actually reached the database.
    real_terms = vulnfeed.product_terms

    def counting(product, name, banner):
        calls.append((product, name, banner))
        return real_terms(product, name, banner)

    vulnfeed.product_terms = counting
    try:
        vulnfeed.reset_lead_cache()
        # A fake session is enough: `product_terms` returning nothing
        # short-circuits before any query, which is exactly the path
        # that must NOT be cached.
        class Queried(Exception):
            """Raised when the function reaches for the database.

            Which makes "did it use the memo" directly observable: a
            hit returns, a miss queries. No real session needed, and
            no guessing from timings.
            """

        class S:
            def execute(self, *_a, **_k):
                raise Queried

        await vulnfeed.leads_for_service(S(), None, None)
        await vulnfeed.leads_for_service(S(), None, None)
        check("an unidentifiable service is not cached — it costs nothing",
              len(calls) == 2, f"{len(calls)} lookups")

        # Now the keys, exercised through the real function.
        #
        # Each call below differs from the first in exactly ONE input,
        # and every one of those inputs changes the answer -- asking
        # about nginx 1.1 must not return the answer for nginx 1.2.
        # A cache keyed on too little is not slow, it is WRONG, and it
        # is wrong in the direction of reporting one service's CVEs
        # against another.
        #
        # `_LEAD_CACHE` is populated directly, because reaching the
        # real answer needs a database; what is under test is which
        # question the function decides it has already answered.
        base = ("nginx", "1.1", None, None, 25)
        variants = [("nginx", "1.2", None, None, 25),
                    ("nginx", "1.1", "http", None, 25),
                    ("nginx", "1.1", None, "banner", 25),
                    ("nginx", "1.1", None, None, 50),
                    ("apache", "1.1", None, None, 25)]
        for args in [base, *variants]:
            vulnfeed.reset_lead_cache()
            sentinel = {"cves": ["SENTINEL"]}
            # Seed the cache as the BASE question, then ask the
            # variant. A correct key means the variant misses.
            vulnfeed._LEAD_CACHE[base] = sentinel
            calls.clear()
            try:
                got = await vulnfeed.leads_for_service(
                    S(), args[0], args[1], args[2], args[3], limit=args[4])
                queried = False
            except Queried:
                got, queried = None, True
            if args == base:
                check("the identical question is answered from the memo",
                      got is sentinel and not queried)
            else:
                differs = [n for n, (a, b) in
                           zip(("product", "version", "name", "banner",
                                "limit"), zip(base, args, strict=True), strict=True)
                           if a != b]
                check(f"a different {differs[0]} is NOT served the memo",
                      queried and got is not sentinel, f"{args}")
    finally:
        vulnfeed.product_terms = real_terms


asyncio.run(memo())

# The cache must be a per-sweep thing, not a global that outlives a
# feed sync — the corpus is re-synced daily.
vulnfeed._LEAD_CACHE[("x",)] = {"stale": True}
vulnfeed.reset_lead_cache()
check("resetting actually empties it", not vulnfeed._LEAD_CACHE,
      vulnfeed._LEAD_CACHE)

print("\n--- the EPSS bulk update writes each score to its own row ---")
# The collision this guards against is silent: a bind parameter named
# after a column is bound to the SET clause as well as the WHERE, so
# every row gets the last chunk value and nothing errors.
import sqlalchemy as sa  # noqa: E402

from app.models import CveRecord  # noqa: E402


async def bulk():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as c:
        await c.run_sync(CveRecord.metadata.create_all)
    mk = async_sessionmaker(eng, expire_on_commit=False)
    async with mk() as s:
        for i in range(5):
            s.add(CveRecord(id=f"CVE-0000-{i}", epss=0.0, epss_percentile=0.0))
        await s.commit()

        stmt = (CveRecord.__table__.update()
                .where(CveRecord.id == sa.bindparam("b_id"))
                .values(epss=sa.bindparam("b_epss"),
                        epss_percentile=sa.bindparam("b_pct")))
        await s.execute(stmt, [
            {"b_id": f"CVE-0000-{i}", "b_epss": i / 10, "b_pct": i / 100}
            for i in range(5)])
        await s.commit()

        got = {r.id: (r.epss, r.epss_percentile) for r in
               (await s.execute(sa.select(CveRecord))).scalars()}
        want = {f"CVE-0000-{i}": (i / 10, i / 100) for i in range(5)}
        check("each CVE keeps its own score, not the last one in the chunk",
              got == want, f"{sorted(got.items())[:2]}…")
    await eng.dispose()


asyncio.run(bulk())

print("\n--- the migration leaves no drift on either engine ---")
import re  # noqa: E402

mig = (_pathlib.Path(__file__).resolve().parents[1]
       / "alembic" / "versions" / "e7a3f92c81d4_trigram_indexes.py").read_text()
up = mig[mig.index("def upgrade"):mig.index("def downgrade")]
# The gin creation is guarded; the drops must not be.
gin = up[up.index("if _pg():"):up.index("for name, table in _DROP:")]
check("the trigram creation is Postgres-only",
      "gin_trgm_ops" in gin and "_pg()" in gin)
after = up[up.index("for name, table in _DROP:"):]
check("the drops run on every engine, or SQLite drifts for ever",
      "_pg()" not in after, after[:60])
check("and so do the foreign-key indexes", "_FK" in after)
# A unique index enforces a constraint; "never scanned" says nothing
# about whether it is needed.
names = re.findall(r'"(ix_[a-z_]+)"', mig[mig.index("_DROP = ["):mig.index("_FK = [")])
check("no UNIQUE index is dropped",
      not any(n.startswith("uq_") for n in names), names)

print("\n--- task output retention keeps what is still evidence ---")
# 13 GB of scanner stdout, one row at 94 MB. The sweep has to free
# that without throwing away the two things that are still evidence:
# the task record itself, and the output of anything that FAILED.
from datetime import UTC, datetime, timedelta  # noqa: E402

from app.models import AgentTask, Project  # noqa: E402
from app.tasking import DEFAULT_OUTPUT_RETAIN_DAYS, prune_task_output  # noqa: E402


async def retention():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as c:
        await c.run_sync(AgentTask.metadata.create_all)
    mk = async_sessionmaker(eng, expire_on_commit=False)
    old_at = datetime.now(UTC) - timedelta(days=DEFAULT_OUTPUT_RETAIN_DAYS + 1)
    new_at = datetime.now(UTC)
    async with mk() as s:
        s.add(Project(code="RET", name="Retention"))
        await s.flush()
        mk_task = lambda st, at, out: AgentTask(  # noqa: E731
            project_id=1, kind="nmap", status=st, args="{}",
            created_at=at, output=out)
        s.add_all([
            mk_task("done", old_at, "x" * 5000),
            mk_task("cancelled", old_at, "y" * 5000),
            mk_task("failed", old_at, "the reason it failed"),
            mk_task("done", new_at, "z" * 5000),
            mk_task("running", old_at, "partial"),
        ])
        await s.commit()

        rows, freed = await prune_task_output(s)
        check("it swept the two finished, expired tasks", rows == 2, rows)
        check("and reported the bytes it freed", freed == 10000, freed)

        all_rows = (await s.execute(sa.select(AgentTask))).scalars().all()
        by = {t.status: t for t in all_rows}
        check("the task rows themselves survive — they are the history",
              len(all_rows) == 5, len(all_rows))
        check("a FAILED task keeps its output: it is the only account "
              "of how it failed",
              by["failed"].output == "the reason it failed",
              by["failed"].output)
        recent = [t for t in all_rows
                  if t.status == "done" and t.output is not None]
        check("exactly the recent done task keeps its output",
              len(recent) == 1 and len(recent[0].output) == 5000,
              [len(t.output or '') for t in recent])
        check("a RUNNING task is never swept, however old",
              by["running"].output == "partial", by["running"].output)
        swept = [t for t in all_rows if t.status == "cancelled"]
        check("and a swept row says so rather than looking empty",
              "retention" in (swept[0].summary or ""), swept[0].summary)

        # Idempotent: a second pass must find nothing, or the daily
        # sweep re-reports the same megabytes for ever.
        rows2, freed2 = await prune_task_output(s)
        check("a second sweep finds nothing left to do",
              (rows2, freed2) == (0, 0), (rows2, freed2))
    await eng.dispose()


asyncio.run(retention())

print("\n--- the heartbeat stops rewriting a row nothing reads ---")
# A Ghost beats every 15s and the beat is usually a no-op, so the only
# thing changing was the timestamp: 673,510 UPDATEs over three weeks.
# Throttling it is acceptable only while the staleness it introduces
# stays inside the window that decides an agent is offline.
from app.routers.agents import HEARTBEAT_WRITE_EVERY, OFFLINE_AFTER  # noqa: E402

check("the throttle is derived from the offline window, not chosen",
      HEARTBEAT_WRITE_EVERY == OFFLINE_AFTER / 3,
      f"{HEARTBEAT_WRITE_EVERY} vs {OFFLINE_AFTER}")
check("it is longer than one 15s beat, so it actually skips writes",
      timedelta(seconds=15) < HEARTBEAT_WRITE_EVERY, HEARTBEAT_WRITE_EVERY)
check("and shorter than the offline window, so death is still noticed",
      HEARTBEAT_WRITE_EVERY < OFFLINE_AFTER, HEARTBEAT_WRITE_EVERY)
worst = OFFLINE_AFTER + HEARTBEAT_WRITE_EVERY
check("worst-case offline detection is still under eleven minutes",
      worst <= timedelta(minutes=11), worst)


def heartbeat_writes(age_s, ip_changed=False, disabled=False):
    """Replays the decision in `heartbeat`. -> did last_seen change?"""
    now = datetime.now(UTC)
    seen = None if age_s is None else now - timedelta(seconds=age_s)
    return bool(seen is None or (now - seen) >= HEARTBEAT_WRITE_EVERY
                or ip_changed or disabled)


check("a beat 5s after the last write skips it", not heartbeat_writes(5))
check("a beat 15s after — one interval — still skips it",
      not heartbeat_writes(15))
check("a beat past the window writes",
      heartbeat_writes(int(HEARTBEAT_WRITE_EVERY.total_seconds()) + 1))
check("an agent never seen before always writes", heartbeat_writes(None))
check("a moved address always writes, however recent the beat",
      heartbeat_writes(1, ip_changed=True))
check("and the beat that finds it killed always writes",
      heartbeat_writes(1, disabled=True))

print("\n--- collapsing origins in SQL cannot change which origin wins ---")
# `discoverable` pulled every URL in the project (203,161, to reach
# 2,552 origins) and collapsed them in Python. SQL collapses on
# `scheme://authority` first.
#
# Safe ONLY because that prefix is COARSER than `origin_of`, never
# finer: `origin_of` normalises a default port away, so two prefixes
# can map to one origin but never the reverse. Coarser hands Python
# extra candidates it then collapses; finer silently drops one.
import re as _re  # noqa: E402

from app.webtargets import discoverable as _disc  # noqa: E402,F401
from app.webtargets import origin_of  # noqa: E402

#: Read out of the source, so the test follows the query rather than
#: a copy of it that can drift.
_SRC = (_pathlib.Path(__file__).resolve().parents[1]
        / "app" / "webtargets.py").read_text()
_m = _re.search(r'func\.substring\(WebAddress\.url,\s*"([^"]+)"\)', _SRC)
check("the query's prefix pattern is found in the source", _m is not None)
PATTERN = _m.group(1) if _m else "^[^/]*//[^/]*"


def _prefix(url):
    m = _re.match(PATTERN, url)
    return m.group(0) if m else None


URLS = [
    "https://app.acme.example/a/b?c=1",
    "https://app.acme.example:443/other",
    "https://app.acme.example/",
    "http://app.acme.example/a",
    "http://app.acme.example:80/b",
    "https://app.acme.example:8443/x",
    "https://other.acme.example/a",
]

for u in URLS:
    pfx = _prefix(u)
    check(f"prefix of {u[:40]} gives the same origin",
          pfx is not None and origin_of(pfx) == origin_of(u),
          f"{origin_of(pfx) if pfx else None} vs {origin_of(u)}")

check("the set of origins is identical either way",
      {origin_of(u) for u in URLS} == {origin_of(_prefix(u)) for u in URLS})

# The direction that matters, stated as a property rather than a
# sample: two URLs that share an origin must never get prefixes that
# `origin_of` then resolves differently — and a prefix that kept the
# PATH would do exactly that, which is the mistake this guards.
same_origin = [("https://app.acme.example/one", "https://app.acme.example/two"),
               ("https://app.acme.example:443/x", "https://app.acme.example/y"),
               ("http://app.acme.example:80/a", "http://app.acme.example/b")]
for a, b in same_origin:
    check(f"{a[:34]} and {b[:30]} stay one origin",
          origin_of(_prefix(a)) == origin_of(_prefix(b)) == origin_of(a),
          f"{origin_of(_prefix(a))} vs {origin_of(_prefix(b))}")

print("\n--- an origin served by two targets keeps both ---")
# `discoverable` kept whichever host the database returned first and
# dropped the rest. `suspected_cves` builds its set of hosts to
# confirm CVEs against out of those values, so a host known ONLY as
# the second target on a shared origin was never asked about.
import asyncio as _aio  # noqa: E402

from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    async_sessionmaker,
    create_async_engine,
)

from app.models import Target, WebAddress  # noqa: E402
from app.webtargets import discoverable  # noqa: E402


async def shared_origin():
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as c:
        await c.run_sync(Target.metadata.create_all)
    mk = async_sessionmaker(eng, expire_on_commit=False)
    async with mk() as s:
        s.add(Project(code="ORG", name="Origins"))
        await s.flush()
        # TWO TARGETS, ONE ORIGIN. Two different hostnames give two
        # different origins, so that is NOT the case this guards --
        # the first version of this test made that mistake and passed
        # against the bug. The real case is two targets that have each
        # recorded the SAME url, which is routine when a name and the
        # address behind it were both scanned.
        import hashlib
        shared = "https://shared.acme.example/login"
        for host in ("alpha.acme.example", "beta.acme.example"):
            t = Target(project_id=1, host=host, kind="host")
            s.add(t)
            await s.flush()
            s.add(WebAddress(
                target_id=t.id, url=shared,
                url_hash=hashlib.sha256(shared.encode()).hexdigest(),
                exchange_hash=hashlib.sha256(
                    f"{host}{shared}".encode()).hexdigest()))
        await s.commit()

        got = await discoverable(s, 1)
        check("the two targets really do collapse to ONE origin",
              len(got) == 1, sorted(got))
        hosts = {h for hs in got.values() for h in hs}
        check("both hosts survive, not just the first",
              hosts == {"alpha.acme.example", "beta.acme.example"}, hosts)
        check("and the values are lists, so nothing can be overwritten",
              all(isinstance(v, list) for v in got.values()), got)
        # Deterministic: the same call twice gives the same answer.
        again = await discoverable(s, 1)
        check("the answer is stable between calls", got == again)

        # And the consumer the comment above names. `discoverable` now
        # hands back {origin: [host, ...]}; `suspected_cves` read that
        # value as a single host and used it as a dict key, which
        # raises TypeError for a list -- even against an empty dict,
        # so there is no input that reaches the loop and survives.
        #
        # It is only called when a project sets auto_nuclei to confirm,
        # which is why nothing noticed: the exception comes out of
        # `snapshot()`, which `run_once` does not wrap, so ONE project
        # in confirm mode stops the standing-orders cycle for every
        # project, every time round, for ever.
        from app import vulnfeed as _vf
        try:
            cves = await _vf.suspected_cves(s, 1, got)
            check("suspected_cves survives an origin with several hosts",
                  isinstance(cves, dict), cves)
        except TypeError as e:
            check("suspected_cves survives an origin with several hosts",
                  False, f"TypeError: {e}")

        # Not crashing is the floor. The substance is that a CVE known
        # only on the SECOND host serving the origin is still asked
        # about -- picking one host was the original bug, and a fix
        # that merely stopped raising would reinstate it quietly.
        from app.models import Service
        for host, prod in (("alpha.acme.example", "nginx"),
                           ("beta.acme.example", "openssh")):
            t = (await s.execute(
                select(Target).where(Target.host == host))).scalar_one()
            s.add(Service(target_id=t.id, port=443, protocol="tcp",
                          state="open", name="http",
                          product=prod, version="1.0"))
        await s.commit()

        # Stubbed: the real lookup needs the CVE corpus, and what is
        # under test is which hosts get consulted, not the corpus.
        _real = _vf.leads_for_service

        async def _fake(session, product, version, name, limit=40):
            return {"cves": [{"cve": f"CVE-0000-{product}",
                              "version_match": "exact"}]}

        _vf.leads_for_service = _fake
        try:
            cves = await _vf.suspected_cves(s, 1, got)
        finally:
            _vf.leads_for_service = _real

        _for_origin = cves.get(shared.rsplit("/", 1)[0]) or []
        if not _for_origin:                      # origin key is the prefix
            _for_origin = next(iter(cves.values()), [])
        check("a CVE on the SECOND host of a shared origin is still asked about",
              set(_for_origin) == {"CVE-0000-nginx", "CVE-0000-openssh"},
              f"{cves}")
    await eng.dispose()


_aio.run(shared_origin())



print("\n--- the Enumerate gap counts, worked out where the rule lives ---")
# TargetsView fetched every target in the project to count two things:
# 10,338 rows and 8.2 MB to render two integers beside a menu.
#
# Deliberately NOT two `count(*)`s. Both answers turn on whether a
# host is an ADDRESS or a NAME, and the authoritative answer to that
# is `ipaddress.ip_address` — which understands IPv6 zones and has no
# faithful regex. A CASE approximating it would be a second opinion
# on a rule that decides what gets scanned.
_GAPS_SRC = (_pathlib.Path(__file__).resolve().parents[1]
             / "app" / "routers" / "targets.py").read_text()
_g = _GAPS_SRC[_GAPS_SRC.index("async def gaps("):
               _GAPS_SRC.index("@router.get(\"/unscanned\"")]

check("the gap count uses ipaddress, not a regex",
      "ipaddress.ip_address" in _g and "~" not in _g)
check("it reads cloud_ephemeral from cloudnames, not from a column",
      "cloudnames.classify" in _g)
check("and it streams rather than loading the table",
      "session.stream" in _g and ".all()" not in _g)
check("it selects columns, never whole Target rows",
      "select(Target.host" in _g and "select(Target)" not in _g)

# The predicate itself, against the cases that decide the counts.
import ipaddress as _ip  # noqa: E402


def _is_address(value):
    v = (value or "").strip()
    if not v:
        return False
    try:
        _ip.ip_address(v.split("%", 1)[0])
    except ValueError:
        return False
    return True


for v, want in [("198.51.100.5", True), ("2001:db8::1", True),
                ("fe80::1%eth0", True), ("one.acme.example", False),
                ("", False), (None, False), ("999.999.999.999", False),
                ("1.2.3", False)]:
    check(f"is_address({v!r}) is {want}", _is_address(v) is want)

print("\n--- every column the Targets grid offers to sort, the server can ---")
# The same guard the findings table got, for the same reason and
# before the same bug: paging moved sorting into the database, and a
# column the grid still lets you click is a 422 the moment somebody
# does. `geo_country` and `kind` were both in that state.
import re as _re2  # noqa: E402

_TV = (_pathlib.Path(__file__).resolve().parents[2]
       / "frontend" / "src" / "views" / "TargetsView.tsx")
_TR = (_pathlib.Path(__file__).resolve().parents[1]
       / "app" / "routers" / "targets.py").read_text()

check("the Targets view source is where this expects it", _TV.exists(), _TV)
_src2 = _TV.read_text()

# The server's map, read out of the apply_sort call rather than
# copied — a copy is the thing that goes stale.
_blk = _TR[_TR.index("stmt = apply_sort(stmt, sort, order, {"):]
_blk = _blk[:_blk.index("})")]
SERVER_SORTS = set(_re2.findall(r'"([a-z_]+)":', _blk))
check("the server's sort map was found and is not empty",
      len(SERVER_SORTS) > 5, sorted(SERVER_SORTS))

offered2 = []
for c in _re2.split(r"(?=\bfield:\s*')", _src2):
    m = _re2.match(r"field:\s*'([a-z_]+)'", c)
    if not m or _re2.search(r"sortable:\s*false", c):
        continue
    offered2.append(m.group(1))
check("the grid's columns were found", len(offered2) > 5, offered2)

missing2 = sorted(set(offered2) - SERVER_SORTS)
check("no sortable Targets column is one the server would refuse",
      not missing2,
      f"the grid offers {missing2}, which apply_sort in routers/targets.py "
      f"does not have — add them there or mark the column "
      f"`sortable: false`" if missing2 else f"{len(offered2)} columns")

print("\n--- the whole-estate list is names, not rows ---")
# Two autocompletes needed every host in the project: re-pointing a
# C2 session, and mapping an unknown host on import. Both read `host`
# and nothing else, and both asked for `limit=100000` to get it —
# 10,340 full rows and 8.3 MB to build a list of 10,340 strings.
_API = (_pathlib.Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "lib" / "api.ts")
_C2 = (_pathlib.Path(__file__).resolve().parents[2]
       / "frontend" / "src" / "views" / "C2View.tsx")
_UH = (_pathlib.Path(__file__).resolve().parents[2]
       / "frontend" / "src" / "components" / "UnknownHostsDialog.tsx")
for f in (_API, _C2, _UH):
    check(f"{f.name} is where this expects it", f.exists(), f)

check("the narrow endpoint exists in the client",
      "targetHosts" in _API.read_text())
for f in (_C2, _UH):
    body = f.read_text()
    check(f"{f.name} asks for names, not rows", "api.targetHosts" in body)
    check(f"{f.name} no longer fetches every row",
          "api.targets(" not in body, "still calls api.targets(")

# And the route returns ONE column. A `select(Target)` here would be
# the same 8.3 MB with a different URL.
_TR2 = (_pathlib.Path(__file__).resolve().parents[1]
        / "app" / "routers" / "targets.py").read_text()
_h = _TR2[_TR2.index("async def host_names("):_TR2.index("@router.get(\"/gaps\"")]
check("the endpoint selects only the host column",
      "select(Target.host)" in _h and "select(Target)" not in _h)
check("and orders in the database, for a stable reply",
      "order_by(Target.host)" in _h)
# The order is the DATABASE's collation, which is not JavaScript's.
# Both callers must still sort what they get, or the lists quietly
# reshuffle — this is the thing the live check caught.
for f in (_C2, _UH):
    check(f"{f.name} still sorts the names it is given",
          "sortedStrings(" in f.read_text(),
          "takes the server's order, which is a different collation")

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
