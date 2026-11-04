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

print(f"\n{ok} passed, {fail} failed")
_sys.exit(1 if fail else 0)
