"""slack identity per workspace

A person's Slack handle is a property of the workspace, not of the
engagement. It was stored per engagement, so starting a second
engagement in the same Slack asked them for the same handle again —
and a prompt that reappears after it has been answered is one people
learn to dismiss without reading.

The per-project row stays: "were they added to this channel" really is
per engagement. What moves here is "who are they in Slack".

Backfilled from the existing per-project answers, so nobody who has
already told us is asked a second time by this migration. The workspace
key cannot be computed in SQL — it is a digest of a bot token, which
lives in the settings table and may be encrypted — so rows are
backfilled by the application on first use instead, and the absence of
a backfill here is deliberate rather than forgotten.

Revision ID: c7a1f03b8e52
Revises: b4e2a91c7d30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'c7a1f03b8e52'
down_revision: Union[str, Sequence[str], None] = 'b4e2a91c7d30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_slack_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workspace_key", sa.String(length=64), nullable=False),
        sa.Column("handle", sa.String(length=128), nullable=True),
        sa.Column("slack_user_id", sa.String(length=32), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("declined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "workspace_key", name="uq_slack_identity"),
    )
    op.create_index("ix_user_slack_identities_user_id",
                    "user_slack_identities", ["user_id"])
    op.create_index("ix_user_slack_identities_workspace_key",
                    "user_slack_identities", ["workspace_key"])


def downgrade() -> None:
    op.drop_index("ix_user_slack_identities_workspace_key",
                  table_name="user_slack_identities")
    op.drop_index("ix_user_slack_identities_user_id",
                  table_name="user_slack_identities")
    op.drop_table("user_slack_identities")
