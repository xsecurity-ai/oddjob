"""agent missing tools

An agent that could not install nuclei was still given nuclei tasks.
Each failed, was retried twice, and ended with "nuclei is not
installed on this agent" — true, useless, and three dispatches spent
learning something the agent knew at startup.

It now reports what it could not get and why, and the dispatcher skips
work that needs those. Pooled work is left in the pool rather than
failed: another agent may well have the tool, which is what pooling is
for.

Revision ID: a9c4e07b2d18
Revises: f5a8d13c62e7
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a9c4e07b2d18'
down_revision: Union[str, Sequence[str], None] = 'f5a8d13c62e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as b:
        b.add_column(sa.Column("missing_tools", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents") as b:
        b.drop_column("missing_tools")
