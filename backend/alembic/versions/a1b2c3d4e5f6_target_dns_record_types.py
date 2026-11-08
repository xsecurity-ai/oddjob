"""Record types observed for a target's name.

A JSON list of lowercase DNS record-type labels (e.g. ["a", "cname"]),
populated by the amass importer when the agent reports them from its
graph. NULL means no record-type information was recorded — either
the name came from a source that does not carry that detail, or it
predates this column.

Revision ID: a1b2c3d4e5f6
Revises: e7a3f92c81d4
"""
from alembic import op
import sqlalchemy as sa


revision = "a1b2c3d4e5f6"
down_revision = "e7a3f92c81d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("targets", schema=None) as batch_op:
        batch_op.add_column(sa.Column("dns_record_types", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("targets", schema=None) as batch_op:
        batch_op.drop_column("dns_record_types")
