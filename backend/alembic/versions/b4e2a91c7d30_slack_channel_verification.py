"""slack channel verification

A resolved bot token is not a working destination. Posting still fails
with `channel_not_found` if nobody ever created the channel, and the
projects list was showing those engagements as having Slack on.

Whether a channel exists is a fact about a remote workspace, so it
cannot be derived at render time without an API call per row. It is
recorded here instead, refreshed in one listing call per token.

Three columns rather than a boolean, because there are three answers
and not two: the channel is there, the channel is not there, or we
have not been able to look. `slack_channel_checked_at` NULL is the
third — never looked — and is deliberately distinct from "looked and
found nothing", which is a checked_at with no id.

Revision ID: b4e2a91c7d30
Revises: 086cb7aac289
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'b4e2a91c7d30'
down_revision: Union[str, Sequence[str], None] = '086cb7aac289'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMNS = [
    # Slack's id for the channel. Present means it was seen to exist.
    sa.Column("slack_channel_id", sa.String(length=32), nullable=True),
    # When the workspace was last asked. NULL means never.
    sa.Column("slack_channel_checked_at", sa.DateTime(timezone=True),
              nullable=True),
    # Why the last check did not produce an id: "missing" when the
    # workspace answered and the channel was not in it, or the transport
    # error when the question could not be put. Kept apart so a rate
    # limit never renders as "the channel is gone".
    sa.Column("slack_channel_error", sa.String(length=300), nullable=True),
]


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for c in COLUMNS:
            b.add_column(c)


def downgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for c in COLUMNS:
            b.drop_column(c.name)
