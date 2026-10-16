"""Triage verdict on a finding: is it real?

Separate from `status`, which is lifecycle -- open, closed, fixed.
"Is this a true positive" and "has this been dealt with" are
different questions and a finding can be any combination of them:
a confirmed issue that is still open, a false positive that is
closed. Folding them into one column would make one of the two
unanswerable.

Defaults to `needs_investigating` rather than to a verdict,
because a scanner has not decided anything. The whole point of the
field is to separate what a tool reported from what a person
concluded, and defaulting to either verdict would put words in
somebody's mouth -- and on this estate there are already 4,125
findings that nobody has looked at.

Revision ID: a9e2c7f41b63
Revises: f7d4b19c0e58
"""
from alembic import op
import sqlalchemy as sa

revision = "a9e2c7f41b63"
down_revision = "f7d4b19c0e58"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default, not just a Python default: the column is NOT
    # NULL and the table already holds thousands of rows, so the
    # DDL needs a value for them.
    op.add_column("vulns", sa.Column(
        "triage", sa.String(24), nullable=False,
        server_default="needs_investigating"))
    op.create_index("ix_vulns_triage", "vulns", ["triage"])


def downgrade() -> None:
    op.drop_index("ix_vulns_triage", table_name="vulns")
    op.drop_column("vulns", "triage")
