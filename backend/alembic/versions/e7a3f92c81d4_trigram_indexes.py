"""Index the substring searches that were 59% of all database time.

Measured on the production mirror over three weeks: 55.3 hours of
query time, 32.9 of them in four `LIKE '%x%'` scans.

    cve_records.products LIKE   460,446 calls   98 ms   23%
    + cpes LIKE                 455,760 calls   98 ms   22%
    exploits.cves LIKE        3,433,835 calls    4 ms    7%
    exploits.title ILIKE        460,441 calls   23 ms    5%

A leading wildcard cannot use a btree, so every one of those was a
full table scan. `EXPLAIN` on the real table: a parallel sequential
scan reading all 856 MB from disk, 109,520 buffer reads against 200
cache hits, to return 176 rows out of 418,431.

`pg_trgm` indexes the three-character substrings instead, which is
exactly what `LIKE '%x%'` asks about. Measured on a copy of the real
corpus:

    products LIKE        28.3 ms -> 0.47 ms
    exploits.cves         3.9 ms -> 0.55 ms
    exploits.title ILIKE  5.0 ms -> 0.22 ms

**SQLite has no pg_trgm and does not need it.** It is not the
production database, the test corpora are tiny, and `LIKE` on a few
hundred rows is free. Every operation here is therefore skipped off
Postgres rather than emulated -- an index that exists on one engine
and not the other is honest; a fake one is not.

### What is dropped, and why that is safe

Five btree indexes on `cve_records`, all with **zero scans** in three
weeks of production traffic:

    ix_cve_records_products     32 MB   a btree CANNOT serve
                                        LIKE '%x%'. It could never
                                        have been used, and the
                                        trigram index replaces it.
    ix_cve_severity_score       95 MB
    ix_cve_triage               69 MB
    ix_cve_records_cvss_score   68 MB
    ix_cve_records_epss         44 MB

308 MB reclaimed, and more to the point 308 MB of index that the EPSS
sync has to maintain while it rewrites all 418,608 rows.

**No UNIQUE index is dropped.** A unique index enforces a constraint,
so "it is never scanned" says nothing about whether it is needed --
`uq_domcand_project_name` is unused by that measure and removing it
would let duplicates in.

### Foreign keys that had no index

`audit_events.user_id`, `agent_tasks.requested_by` and
`domain_candidates.decided_by` are foreign keys on the three largest
tables with nothing to look them up by. CLAUDE.md records what that
costs: deleting through an unindexed FK scans the whole child table
per row deleted, and 46,811 services once did not finish in ten
minutes. Deleting a user is rare, which is exactly why it would be
discovered at the worst moment.

Revision ID: e7a3f92c81d4
Revises: c5d8a12f4b67
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e7a3f92c81d4"
down_revision: str | Sequence[str] | None = "c5d8a12f4b67"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: (index, table, column) for the trigram indexes.
_TRGM = [
    ("ix_cve_records_products_trgm", "cve_records", "products"),
    ("ix_cve_records_cpes_trgm", "cve_records", "cpes"),
    ("ix_exploits_cves_trgm", "exploits", "cves"),
    ("ix_exploits_title_trgm", "exploits", "title"),
]

#: Zero scans in three weeks, and none of them UNIQUE.
_DROP = [
    ("ix_cve_records_products", "cve_records"),
    ("ix_cve_severity_score", "cve_records"),
    ("ix_cve_triage", "cve_records"),
    ("ix_cve_records_cvss_score", "cve_records"),
    ("ix_cve_records_epss", "cve_records"),
]

_FK = [
    ("ix_audit_events_user_id", "audit_events", "user_id"),
    ("ix_agent_tasks_requested_by", "agent_tasks", "requested_by"),
    ("ix_domain_candidates_decided_by", "domain_candidates", "decided_by"),
]


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _has_index(name: str, table: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return name in {i["name"] for i in insp.get_indexes(table)}


def _has_table(table: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table)


def upgrade() -> None:
    # Postgres-only: `gin_trgm_ops` does not exist anywhere else.
    if _pg():
        op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        for name, table, column in _TRGM:
            if _has_table(table) and not _has_index(name, table):
                op.execute(
                    f"CREATE INDEX {name} ON {table} "
                    f"USING gin ({column} gin_trgm_ops)")
    # The drops and the foreign-key indexes run on EVERY engine, and
    # that asymmetry is the point: the model no longer declares these
    # indexes, so leaving them behind on SQLite makes `alembic check`
    # report drift for ever on a database built from the migrations.
    # Only the thing Postgres alone can do is conditional.
    for name, table in _DROP:
        if _has_table(table) and _has_index(name, table):
            op.drop_index(name, table_name=table)
    for name, table, column in _FK:
        if _has_table(table) and not _has_index(name, table):
            op.create_index(name, table, [column])


def downgrade() -> None:
    for name, table, _ in _FK:
        if _has_table(table) and _has_index(name, table):
            op.drop_index(name, table_name=table)
    # Rebuilt as they were. The extension is left in place: dropping
    # it would break any other index built on it since.
    if _has_table("cve_records"):
        if not _has_index("ix_cve_records_products", "cve_records"):
            op.create_index("ix_cve_records_products", "cve_records",
                            ["products"])
        if not _has_index("ix_cve_severity_score", "cve_records"):
            op.create_index("ix_cve_severity_score", "cve_records",
                            ["severity", "cvss_score"])
        if not _has_index("ix_cve_triage", "cve_records"):
            op.create_index("ix_cve_triage", "cve_records",
                            ["kev", "epss", "cvss_score"])
        if not _has_index("ix_cve_records_cvss_score", "cve_records"):
            op.create_index("ix_cve_records_cvss_score", "cve_records",
                            ["cvss_score"])
        if not _has_index("ix_cve_records_epss", "cve_records"):
            op.create_index("ix_cve_records_epss", "cve_records", ["epss"])
    if _pg():
        for name, table, _ in _TRGM:
            if _has_table(table) and _has_index(name, table):
                op.drop_index(name, table_name=table)
