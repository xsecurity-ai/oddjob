"""What every tool that sends a User-Agent should call itself.

Nullable, and NULL means the agent's own default rather than an empty
header: a blank User-Agent is a thing some WAFs block outright, and
arriving at it by leaving a box empty would be a surprising way to
lose a scan.

Revision ID: f5c3f3ba5f23
Revises: d6b3e1a07f25
Create Date: 2026-10-12 10:21:56.846628

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f5c3f3ba5f23'
down_revision: Union[str, Sequence[str], None] = 'd6b3e1a07f25'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('projects', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_agent', sa.String(length=200), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('projects', schema=None) as batch_op:
        batch_op.drop_column('user_agent')
