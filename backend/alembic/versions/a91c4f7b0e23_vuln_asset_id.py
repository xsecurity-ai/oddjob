"""link a finding to the asset it came out of

The web view could not say how many findings a bundle carries,
because nothing recorded which bundle a finding came from. The asset
URL has always been in the finding's DESCRIPTION -- see
`assetwork.origin_block` -- and parsing prose to answer a structural
question is the arrangement that put `codename` and `remediation` in
the database and nowhere else.

The backfill reads that description, which is safe for exactly the
reason the function exists: `origin_block` is a named function so
that two places can be held to one format, and migration
`c5a2d83f61e4` already parses the same shape.

Only findings that came from an asset scanner are touched --
`opengrep:` and `detect-secrets:` external ids -- and only where the
first line of the description matches an asset URL this project
actually has. A finding whose origin cannot be resolved is left
NULL, which reads as "not from an asset" and is the truth about what
is known rather than a guess.

Revision ID: a91c4f7b0e23
Revises: f4b82e05a7c1
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a91c4f7b0e23"
down_revision: str | Sequence[str] | None = "f4b82e05a7c1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # One batch, not two. SQLite cannot ALTER a constraint at all, so
    # the foreign key means `batch_alter_table`, which copies the
    # whole table -- and doing the column add outside it would copy
    # `vulns` twice for one change.
    #
    # On Postgres both are ordinary ALTERs and the batch is a no-op
    # wrapper.
    with op.batch_alter_table("vulns") as b:
        b.add_column(sa.Column("asset_id", sa.Integer(), nullable=True))
        b.create_foreign_key("fk_vulns_asset", "web_assets",
                             ["asset_id"], ["id"], ondelete="SET NULL")
    # Outside the batch: an index on a table that is about to be
    # rebuilt is an index built twice.
    op.create_index("ix_vulns_asset_id", "vulns", ["asset_id"])

    # The first line of the description is the asset URL, from
    # `origin_block`. Matched against the assets of the finding's OWN
    # project: two engagements can hold the same CDN URL and a
    # finding must not be attributed across them.
    #
    # Done in Python rather than in SQL. The obvious statement uses
    # `split_part`, which is Postgres-only -- SQLite has no such
    # function and the whole test suite runs on SQLite. That is the
    # difference this repository keeps being bitten by, and a
    # migration is the worst place to discover it.
    conn = op.get_bind()
    assets = {}
    for aid, pid, url in conn.execute(sa.text(
            "SELECT id, project_id, url FROM web_assets")):
        assets[(pid, url)] = aid

    projects = dict(conn.execute(sa.text(
        "SELECT id, project_id FROM targets")).all())

    done = 0
    rows = conn.execute(sa.text(
        "SELECT id, target_id, description FROM vulns "
        "WHERE asset_id IS NULL AND description IS NOT NULL "
        "AND (external_id LIKE 'opengrep:%' "
        "     OR external_id LIKE 'detect-secrets:%')")).fetchall()
    for vid, tid, desc in rows:
        first = (desc or "").split("\n", 1)[0].strip()
        if not first:
            continue
        aid = assets.get((projects.get(tid), first))
        if aid is None:
            # Left NULL, which reads as "not from an asset we still
            # have". That is the truth about what is known rather
            # than a guess at which bundle it might have been.
            continue
        conn.execute(sa.text("UPDATE vulns SET asset_id = :a WHERE id = :v"),
                     {"a": aid, "v": vid})
        done += 1
    print(f"  linked {done} of {len(rows)} asset finding(s) to their asset")


def downgrade() -> None:
    op.drop_index("ix_vulns_asset_id", "vulns")
    with op.batch_alter_table("vulns") as b:
        b.drop_constraint("fk_vulns_asset", type_="foreignkey")
        b.drop_column("asset_id")
