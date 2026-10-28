"""keep the rendered report instead of building it on every download

`GET /api/reports/{id}/download` called `render(doc, fmt)` on every
request -- seconds of work over a document that runs to twelve
megabytes, repeated for every click, every retry and every person
who opened the link.

The generator was ALREADY rendering the PDF, to measure
`size_bytes`, and throwing the bytes away. This keeps them.

`data` is LargeBinary rather than Text because a PDF is binary and
contains NUL, which Postgres rejects in a text column and SQLite
accepts. That difference has bitten this project before.

Nothing is backfilled. These rows are disposable: an old report
renders once more, the first time somebody asks for it, and is a
byte read from then on. A backfill would mean rendering every
report in the database during a deploy, to save one download each.

Revision ID: b73e1c90d84a
Revises: a1c7e4f20b95
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b73e1c90d84a"
down_revision: str | Sequence[str] | None = "a1c7e4f20b95"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_renders",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("report_id", sa.Integer,
                  sa.ForeignKey("reports.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("fmt", sa.String(8), nullable=False),
        sa.Column("data", sa.LargeBinary, nullable=False),
        sa.Column("bytes", sa.Integer, nullable=False),
        sa.Column("rendered_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("report_id", "fmt", name="uq_report_render"),
    )
    # Indexed because every delete of a report goes through it. An
    # unindexed foreign key deleted through is the bug that made
    # removing 46,811 services take longer than ten minutes.
    op.create_index("ix_report_renders_report_id", "report_renders",
                    ["report_id"])


def downgrade() -> None:
    op.drop_index("ix_report_renders_report_id", "report_renders")
    op.drop_table("report_renders")
