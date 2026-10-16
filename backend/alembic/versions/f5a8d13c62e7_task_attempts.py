"""task attempts

A task that failed on an agent stayed failed. Most failures are about
the agent or the moment rather than the request — a container that
died mid-scan, a resolver that timed out, a host unreachable for a
minute — and the work still needs doing, so it goes back in the queue
for another agent to try.

Counted, because the other kind of failure exists too: a request that
is simply wrong fails identically on every agent, and retrying it
forever would grind the whole queue on one bad task.

Revision ID: f5a8d13c62e7
Revises: e3b7c21f9a04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'f5a8d13c62e7'
down_revision: Union[str, Sequence[str], None] = 'e3b7c21f9a04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("agent_tasks") as b:
        b.add_column(sa.Column("attempts", sa.Integer(), nullable=False,
                               server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("agent_tasks") as b:
        b.drop_column("attempts")
