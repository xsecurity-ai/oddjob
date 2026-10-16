"""Endpoints found inside a web asset.

A crawl finds what an application LINKS to. Its JavaScript contains
what it CALLS -- API routes, admin paths, internal hostnames, pages
behind a feature flag -- and none of that is reachable by following
anchors. This is where those go.

Not `vulns`: an endpoint is not a finding, it is a place to go and
look. Filing it as a vulnerability would put hundreds of rows in
front of an operator that nobody can triage and bury the findings
that are real.

Not `web_addresses` either, at least not yet. Those are things we
have observed answering; these are strings out of a bundle that may
or may not exist. Keeping them apart is what lets "we found this
referenced" stay distinguishable from "we requested this and it
responded" -- the same three-outcomes discipline the rest of this
codebase runs on.

Revision ID: e3c1a85b240f
Revises: d8b147f0c29a
"""
from alembic import op
import sqlalchemy as sa

revision = "e3c1a85b240f"
down_revision = "d8b147f0c29a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_asset_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("asset_id", sa.Integer(),
                  sa.ForeignKey("web_assets.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        # Which recovered file it came from, so an operator can see
        # whether it was in the developer's source or only in the
        # shipped bundle.
        sa.Column("file_id", sa.Integer(),
                  sa.ForeignKey("web_asset_files.id", ondelete="CASCADE"),
                  nullable=True, index=True),
        # 'path' | 'url'
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        # The hostname, for URLs. Indexed because "what new hosts did
        # the bundles mention" is the question worth asking of this
        # table -- a host discovered from an in-scope target may
        # itself be in scope, which a path never is.
        sa.Column("host", sa.String(255), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # One row per (asset, value). The same path appears in a
        # hundred files of one bundle and re-appears on every sweep;
        # without this the table grows without bound and says nothing
        # new.
        sa.UniqueConstraint("asset_id", "value", name="uq_asset_endpoint"),
    )


def downgrade() -> None:
    op.drop_table("web_asset_endpoints")
