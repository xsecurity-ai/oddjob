"""Where a target was discovered.

A cloud resource named in a JavaScript bundle is not in any CIDR, is
linked to by nothing, and is met by no port scan. The file that
mentions it is the only reason we know it exists -- and until now
that fact was thrown away the moment the target row was written, so
the Targets page showed a bucket with no account of itself.

**Nothing is backfilled, and that is the honest answer.** The origin
of a row created before this table existed was never recorded
anywhere, so there is nothing to recover and nothing to infer. A
target with no row here means "not recorded", which is a different
claim from "came from nowhere"; the API and the UI keep them apart
rather than filling the gap with a guess.

Revision ID: a9c3f41d70b6
Revises: a1c7e4d20b93
"""
import sqlalchemy as sa
from alembic import op

revision = "a9c3f41d70b6"
down_revision = "a1c7e4d20b93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_origins",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        # Indexed, and not only for reads: deleting a project deletes
        # its targets and every one of those deletes goes through
        # this key. An unindexed foreign key deleted through is what
        # turned one project removal into a ten-minute sequential
        # scan on `web_addresses.service_id`.
        sa.Column("target_id", sa.Integer(),
                  sa.ForeignKey("targets.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("source", sa.String(16), nullable=False),
        # SET NULL, not CASCADE. An asset re-fetched, superseded or
        # deleted must not take the record of the discovery with it;
        # the URL and path below are snapshots for exactly that case.
        sa.Column("asset_id", sa.Integer(),
                  sa.ForeignKey("web_assets.id", ondelete="SET NULL"),
                  nullable=True, index=True),
        sa.Column("file_id", sa.Integer(),
                  sa.ForeignKey("web_asset_files.id", ondelete="SET NULL"),
                  nullable=True, index=True),
        sa.Column("asset_url", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("page_url", sa.Text(), nullable=True),
        # The uniqueness key. A URL cannot carry the index itself --
        # Postgres caps a btree entry near 2.7 KB and bundle URLs run
        # past it -- so a digest does, the same way `url_hash` does
        # for `web_addresses`.
        sa.Column("origin_hash", sa.String(64), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # One row per (target, place it was found in). The sweep reads
        # the same bundle on every pass; without this the table grows
        # without bound while saying nothing new.
        sa.UniqueConstraint("target_id", "origin_hash",
                            name="uq_target_origin"),
    )


def downgrade() -> None:
    op.drop_table("target_origins")
