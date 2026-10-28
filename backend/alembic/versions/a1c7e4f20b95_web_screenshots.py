"""A picture of a URL, as a browser drew it.

The ghost takes it -- it is the thing standing inside the engagement,
so it is the only place the capture comes from the egress address the
client authorised. This is where it lands.

One row per (target, url). A screenshot is not an exchange: ten
captures of the same URL are ten copies of one page at a couple of
hundred kilobytes each, across estates that have reached 51,000 URLs,
so a re-shoot replaces the image and `captured_at` says how old the
one on file is.

The bytes live here rather than on disk because this application has
no file store at all -- the only thing it writes outside the database
is a spooled upload it then deletes -- and a directory would be a
second thing to back up, a path to configure and a set of orphans to
reap. `ON DELETE CASCADE` is the reaper instead. Postgres TOASTs a
bytea this size out of line, so the rows stay small; the column is
deferred in the model so nothing drags it in by accident.

`url_hash` carries the uniqueness, never `url`: a Postgres btree entry
caps near 2.7 KB and a real URL in this database has reached 8,221
characters, where the INSERT fails rather than the query.

LargeBinary rather than Text, and deliberately: a PNG contains NUL
bytes, which Postgres rejects in a text column outright and SQLite
accepts -- the exact difference that has bitten this schema before.
The agent sends base64 and the server decodes it once, here.

Revision ID: a1c7e4f20b95
Revises: a9c3f41d70b6
"""
import sqlalchemy as sa
from alembic import op

revision = "a1c7e4f20b95"
down_revision = "a9c3f41d70b6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_screenshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        # Indexed because rows are deleted through it. An unindexed FK
        # is the landmine this codebase has already stepped on.
        sa.Column("target_id", sa.Integer(),
                  sa.ForeignKey("targets.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        # SET NULL, not CASCADE: an importer re-keying a web address
        # must not take the photograph with it.
        sa.Column("web_address_id", sa.Integer(),
                  sa.ForeignKey("web_addresses.id", ondelete="SET NULL"),
                  nullable=True, index=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("url_hash", sa.String(64), nullable=False, index=True),
        sa.Column("final_url", sa.Text()),
        sa.Column("status_code", sa.Integer()),
        sa.Column("title", sa.String(512)),
        # NOT NULL with a server_default, because a Python-side
        # `default=` is not DDL: adding a NOT NULL column without one
        # fails against a populated table. It is in the README; this
        # is the third time.
        sa.Column("content_type", sa.String(32), nullable=False,
                  server_default="image/png"),
        sa.Column("image", sa.LargeBinary(), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(64), index=True),
        sa.Column("width", sa.Integer()),
        sa.Column("height", sa.Integer()),
        sa.Column("captured_at", sa.DateTime(timezone=True)),
        sa.Column("sources", sa.String(255)),
        # No server_default on these two: TimestampMixin sets them in
        # Python, and declaring one here is drift `alembic check`
        # correctly refuses.
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("target_id", "url_hash",
                            name="uq_screenshot_url"),
    )


def downgrade() -> None:
    op.drop_table("web_screenshots")
