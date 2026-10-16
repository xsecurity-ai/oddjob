"""The actual credential behind a secret finding.

Kept OUT of `vulns.description` on purpose. That field is listed,
searched, exported into reports and copied into Slack; a credential
in it is a credential in every one of those places. This table is
read by one endpoint, which checks a role and writes an audit entry
before it answers.

So the finding stays shareable and the value stays deliberate: an
operator who needs to verify or rotate a key can see it, and doing
so leaves a record of who looked.

Revision ID: f7d4b19c0e58
Revises: e3c1a85b240f
"""
from alembic import op
import sqlalchemy as sa

revision = "f7d4b19c0e58"
down_revision = "e3c1a85b240f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_secrets",
        sa.Column("id", sa.Integer(), primary_key=True),
        # One secret per finding. CASCADE because a deleted finding
        # must take its credential with it -- an orphaned row here
        # is a credential nothing references and nobody reviews.
        sa.Column("vuln_id", sa.Integer(),
                  sa.ForeignKey("vulns.id", ondelete="CASCADE"),
                  nullable=False, unique=True, index=True),
        sa.Column("secret", sa.Text(), nullable=False),
        # What produced it, so the reveal can say which tool to
        # believe about the value's shape.
        sa.Column("detector", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("finding_secrets")
