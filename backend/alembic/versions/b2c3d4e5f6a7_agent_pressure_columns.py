"""agent pressure columns

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-11-07
"""
from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("cpu_idle", sa.Float(), nullable=True))
    op.add_column("agents", sa.Column("mem_free", sa.Float(), nullable=True))
    op.add_column("agents", sa.Column("disk_free", sa.Float(), nullable=True))
    op.add_column("agents", sa.Column("pressure_history", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "pressure_history")
    op.drop_column("agents", "disk_free")
    op.drop_column("agents", "mem_free")
    op.drop_column("agents", "cpu_idle")
