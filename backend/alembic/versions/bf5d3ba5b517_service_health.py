"""Subsystem health: the last thing Slack, SMTP and the fleet did

Revision ID: bf5d3ba5b517
Revises: b8e1d53f0a27
Create Date: 2026-10-07 13:59:09.628851

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bf5d3ba5b517'
down_revision: Union[str, Sequence[str], None] = 'b8e1d53f0a27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('service_health',
    sa.Column('service', sa.String(length=32), nullable=False),
    sa.Column('last_ok_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_error_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.String(length=500), nullable=True),
    sa.Column('last_detail', sa.String(length=300), nullable=True),
    sa.Column('ok_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('error_count', sa.Integer(), server_default='0', nullable=False),
    sa.PrimaryKeyConstraint('service')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('service_health')
