"""port scan coverage: what was looked at, not just what was found

Revision ID: a3f7c21d4e90
Revises: f1b6c08d94a2
Create Date: 2026-10-09

A new table only. Nothing existing is altered, so there is no data to
migrate and the downgrade is a clean drop.

Existing installations start with no coverage at all, which reads as
"nothing has been scanned" and is the right answer: the records were
never kept, so every port is genuinely unknown. Scans that already ran
cannot be reconstructed — nmap's XML is not retained in a form that
could be replayed for every past scan — and inventing coverage for
them would suppress real scans on the strength of a guess.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a3f7c21d4e90"
down_revision: str | None = "f1b6c08d94a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "port_scan_coverage",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("technique", sa.String(length=16), nullable=False),
        sa.Column("port_lo", sa.Integer(), nullable=False),
        sa.Column("port_hi", sa.Integer(), nullable=False),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_port_scan_coverage_target_id", "port_scan_coverage",
                    ["target_id"])
    # The query this table exists to serve is always "what does this
    # host already have, for this protocol" before a scan is planned.
    op.create_index("ix_pscov_target_proto", "port_scan_coverage",
                    ["target_id", "protocol"])


def downgrade() -> None:
    op.drop_index("ix_pscov_target_proto", table_name="port_scan_coverage")
    op.drop_index("ix_port_scan_coverage_target_id",
                  table_name="port_scan_coverage")
    op.drop_table("port_scan_coverage")
