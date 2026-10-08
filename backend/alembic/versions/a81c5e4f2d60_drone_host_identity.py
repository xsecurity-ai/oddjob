"""drone host identity: where the address came from, and what the host is

A drone in Docker reported its container address, 172.17.0.2, and the
Drones page rendered it in the same column as every egress address. The
number alone cannot be told apart from a real one, so the provenance has
to travel with it. Same for the OS: a Linux container on Windows Server
reported `linux`, which is true of the binary and wrong about the
machine.

All nullable with no default. NULL means an agent that has not
re-registered since this shipped, and must not read as "not a
container" or "not Windows" — the UI distinguishes the two.

Revision ID: a81c5e4f2d60
Revises: 2f7aa154a949
Create Date: 2026-10-08 04:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a81c5e4f2d60'
down_revision: Union[str, Sequence[str], None] = '2f7aa154a949'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('outbound_ip_source', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('outbound_ip_note', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('host_platform', sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column('host_platform_source', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('container', sa.String(length=32), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_column('container')
        batch_op.drop_column('host_platform_source')
        batch_op.drop_column('host_platform')
        batch_op.drop_column('outbound_ip_note')
        batch_op.drop_column('outbound_ip_source')
