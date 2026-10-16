"""Files recovered from a web asset, and what scanning them found.

`web_assets` already held one body per URL. That is the wrong grain
for scanning: a minified bundle is one URL and, once its source map
is read, a hundred original files. Secrets and vulnerable code live
in those originals, under their real paths, and a finding that can
only say "somewhere in app.min.js" is most of the way to useless.

So the bytes move to a child table, one row per FILE:

    raw          exactly what the server returned
    beautified   the raw bytes reformatted, when nothing better exists
    source       one original file out of a source map

`web_assets.body` stays where it is. Dropping a column that holds
already-collected evidence to tidy a schema is not a trade worth
making, and the view that reads it is unchanged by this.

Revision ID: d8b147f0c29a
Revises: c4f20a9d7e11
"""
from alembic import op
import sqlalchemy as sa

revision = "d8b147f0c29a"
down_revision = "c4f20a9d7e11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- what happened when we went to get it -----------------------
    op.add_column("web_assets",
                  sa.Column("fetched_at", sa.DateTime(timezone=True)))
    # Why it could not be fetched. A fetch that failed is not an asset
    # with no content: one is a gap we can close, the other is a fact
    # about the asset, and a null body cannot tell them apart.
    op.add_column("web_assets", sa.Column("fetch_error", sa.String(300)))
    op.add_column("web_assets", sa.Column("minified", sa.Boolean()))
    op.add_column("web_assets", sa.Column("sourcemap_url", sa.Text()))
    # Set when scanners have run over this asset's files, so a sweep
    # can find what it has not yet looked at without re-scanning the
    # estate every time.
    op.add_column("web_assets", sa.Column("scanned_at",
                                          sa.DateTime(timezone=True)))

    op.create_table(
        "web_asset_files",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(),
                  sa.ForeignKey("web_assets.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("project_id", sa.Integer(),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        # 'raw' | 'beautified' | 'source'
        sa.Column("origin", sa.String(16), nullable=False),
        # The path a source map gave, or the URL's own basename.
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("body", sa.Text()),
        sa.Column("sha256", sa.String(64), index=True),
        sa.Column("bytes", sa.Integer()),
        sa.Column("scanned_at", sa.DateTime(timezone=True)),
        # No server_default: TimestampMixin sets these in Python
        # (`default=utcnow`), and declaring one here is drift the
        # alembic check correctly refuses.
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # One row per (asset, origin, path). Re-fetching an unchanged
        # asset must amend rather than accumulate a copy per sweep.
        sa.UniqueConstraint("asset_id", "origin", "path",
                            name="uq_asset_file"),
    )


def downgrade() -> None:
    op.drop_table("web_asset_files")
    for c in ("scanned_at", "sourcemap_url", "minified",
              "fetch_error", "fetched_at"):
        op.drop_column("web_assets", c)
