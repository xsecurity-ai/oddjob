"""finding lifecycle: is it still there

Oddjob could say a finding existed and never that one had gone
away. A row written in March sat at `open` for ever, through
re-scans that no longer saw it, because nothing recorded that
anybody had looked again.

`finding_sweeps` is the positive record that makes `resolved`
sayable: tool X looked at host T at time A. Without it the absence
of a finding from a new scan means nothing -- a narrower template
set, a scan that errored and a host that was down all produce the
same silence.

# Backfill

`first_seen_at` and `last_seen_at` are seeded from `created_at`,
NOT from `updated_at`. `updated_at` moves for reasons that have
nothing to do with observation -- a triage change, a remediation
being written -- and seeding `last_seen_at` from it would claim a
scan reported the finding on the day somebody edited its severity.
`created_at` is the one timestamp that definitely corresponds to a
scan having reported something.

`scanner` is deliberately left NULL on every existing row. It
cannot be recovered -- the vuln table never recorded which tool
reported what -- and guessing would make a future nmap sweep
"resolve" findings that came from somewhere else entirely. NULL
reads as `unconfirmed`, which is the honest answer for a finding
whose provenance is not known.

Revision ID: d8a3f0b61c27
Revises: c7f23a19d4e6
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d8a3f0b61c27"
down_revision: str | Sequence[str] | None = "c7f23a19d4e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("vulns", sa.Column("scanner", sa.String(64), nullable=True))
    op.add_column("vulns", sa.Column("first_seen_at",
                                     sa.DateTime(timezone=True), nullable=True))
    op.add_column("vulns", sa.Column("last_seen_at",
                                     sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_vulns_scanner", "vulns", ["scanner"])
    op.create_index("ix_vulns_last_seen_at", "vulns", ["last_seen_at"])
    # See the note above: created_at, never updated_at.
    op.execute("UPDATE vulns SET first_seen_at = created_at, "
               "last_seen_at = created_at")

    op.create_table(
        "finding_sweeps",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("target_id", sa.Integer,
                  sa.ForeignKey("targets.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("scanner", sa.String(64), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_sweeps_project_id", "finding_sweeps",
                    ["project_id"])
    # Indexed because every delete of a target goes through it. An
    # unindexed FK deleted through is the bug that made removing
    # 46,811 services take longer than ten minutes.
    op.create_index("ix_finding_sweeps_target_id", "finding_sweeps",
                    ["target_id"])
    op.create_index("ix_finding_sweeps_target_scanner", "finding_sweeps",
                    ["target_id", "scanner"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_finding_sweeps_target_scanner", "finding_sweeps")
    op.drop_index("ix_finding_sweeps_target_id", "finding_sweeps")
    op.drop_index("ix_finding_sweeps_project_id", "finding_sweeps")
    op.drop_table("finding_sweeps")
    op.drop_index("ix_vulns_last_seen_at", "vulns")
    op.drop_index("ix_vulns_scanner", "vulns")
    op.drop_column("vulns", "last_seen_at")
    op.drop_column("vulns", "first_seen_at")
    op.drop_column("vulns", "scanner")
