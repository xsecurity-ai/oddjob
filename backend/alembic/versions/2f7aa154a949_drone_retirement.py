"""Drone retirement: what a killed drone confirmed it cleaned up

Revision ID: 2f7aa154a949
Revises: bf5d3ba5b517
Create Date: 2026-10-07 17:05:07.367400

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2f7aa154a949'
down_revision: Union[str, Sequence[str], None] = 'bf5d3ba5b517'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('retired_reason', sa.String(length=300), nullable=True))
        batch_op.add_column(sa.Column('retired_cleanup', sa.Text(), nullable=True))



def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_column('retired_cleanup')
        batch_op.drop_column('retired_reason')
        batch_op.drop_column('retired_at')
