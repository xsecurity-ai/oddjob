"""task resource samples: per-task cpu, memory and network cost

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-11-12
"""
from alembic import op
import sqlalchemy as sa

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "task_resource_samples",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("cpu_seconds", sa.Float(), nullable=True),
        sa.Column("mem_peak_bytes", sa.Integer(), nullable=True),
        sa.Column("net_bytes", sa.Integer(), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["agent_tasks.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"],
                                ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_task_resources_task", "task_resource_samples",
                    ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_task_resources_task", table_name="task_resource_samples")
    op.drop_table("task_resource_samples")
