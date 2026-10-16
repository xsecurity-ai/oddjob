"""ghost debug mode and the log it ships back

Diagnosing a ghost meant having an account on the box it runs on, and
the fleet is a GCP VM behind IAP, a Windows host whose docker lives in
WSL2, and a droplet. Three procedures to answer one question -- and
when the GCP host lost its route, no way in at all, because the only
channel that still worked was the one the agent itself dials out on.

So the agent gets somewhere to say what it is doing. Off by default:
the log names the hosts being scanned, and a store worth reading is a
store that stays small.

Revision ID: a7d4e91c3b60
Revises: 72386ed9a1f5
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a7d4e91c3b60'
down_revision: Union[str, Sequence[str], None] = '72386ed9a1f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as b:
        b.add_column(sa.Column("debug", sa.Boolean(), nullable=False,
                               server_default="false"))

    op.create_table(
        "agent_debug_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        # The agent's clock, not ours. A batch arrives seconds late and
        # a spooled one can arrive after a reconnect; stamping on
        # arrival would reorder the agent's own log.
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("line", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"],
                                ondelete="CASCADE"),
    )
    op.create_index("ix_agent_debug_logs_agent_id", "agent_debug_logs",
                    ["agent_id"])
    op.create_index("ix_agent_debug_logs_project_id", "agent_debug_logs",
                    ["project_id"])
    op.create_index("ix_agent_debug_logs_at", "agent_debug_logs", ["at"])
    # The read is always "this agent, newest first", so the pair is
    # what serves it; the single-column indexes above serve the scope
    # filter and the prune.
    op.create_index("ix_agent_debug_logs_agent_at", "agent_debug_logs",
                    ["agent_id", "at"])


def downgrade() -> None:
    op.drop_index("ix_agent_debug_logs_agent_at", "agent_debug_logs")
    op.drop_index("ix_agent_debug_logs_at", "agent_debug_logs")
    op.drop_index("ix_agent_debug_logs_project_id", "agent_debug_logs")
    op.drop_index("ix_agent_debug_logs_agent_id", "agent_debug_logs")
    op.drop_table("agent_debug_logs")
    with op.batch_alter_table("agents") as b:
        b.drop_column("debug")
