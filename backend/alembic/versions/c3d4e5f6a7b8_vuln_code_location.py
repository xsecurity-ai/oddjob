"""vuln code location: file_path and line_number for SAST/SCA findings

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-11-07
"""
from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vulns", sa.Column(
        "file_path", sa.String(length=1024), nullable=True))
    op.add_column("vulns", sa.Column(
        "line_number", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("vulns", "line_number")
    op.drop_column("vulns", "file_path")
