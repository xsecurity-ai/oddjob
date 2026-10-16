"""audit trail

Who did what to this installation, and from where. Distinct from
`events`, which is the per-target engagement narrative and is scoped to
one asset; this is keyed on time and outlives everything it refers to.

`user_id` is a nullable FK with ON DELETE SET NULL, while `username` is
a plain column written at the same moment. That is not redundancy: an
audit row whose subject has since been deleted still has to say who
acted, and a row that vanished with the account would make deleting
yourself the way to erase your history.

No backfill. There is nothing to reconstruct an audit trail FROM -- the
entries begin when the table does, and inventing earlier ones would be
worse than having none.

Revision ID: d1f6c47a0b93
Revises: c7a1f03b8e52
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'd1f6c47a0b93'
down_revision: Union[str, Sequence[str], None] = 'c7a1f03b8e52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("method", sa.String(length=8), nullable=True),
        sa.Column("path", sa.String(length=512), nullable=True),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("ms", sa.Integer(), nullable=True),
        sa.Column("project_code", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],
                                ondelete="SET NULL"),
    )
    op.create_index("ix_audit_events_at", "audit_events", ["at"])
    op.create_index("ix_audit_events_source", "audit_events", ["source"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_username", "audit_events", ["username"])
    op.create_index("ix_audit_events_project_code", "audit_events",
                    ["project_code"])
    # Reading is almost always "newest first, maybe one origin". `id`
    # rides along so entries sharing a clock tick keep a stable order
    # and do not shuffle between pages.
    op.create_index("ix_audit_at_id", "audit_events", ["at", "id"])
    op.create_index("ix_audit_source_at", "audit_events", ["source", "at"])


def downgrade() -> None:
    op.drop_index("ix_audit_source_at", table_name="audit_events")
    op.drop_index("ix_audit_at_id", table_name="audit_events")
    op.drop_index("ix_audit_events_project_code", table_name="audit_events")
    op.drop_index("ix_audit_events_username", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_source", table_name="audit_events")
    op.drop_index("ix_audit_events_at", table_name="audit_events")
    op.drop_table("audit_events")
