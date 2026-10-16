"""health samples: the history behind the health cards

The cards answered "is it working" from a last-attempt row and a
running total. Neither can answer "is it getting worse", which is the
question that actually prompts somebody to act -- 41 Slack errors
reads the same whether they were all last Tuesday or all in the past
hour.

One row per real attempt (`ok`/`errors`, from `servicehealth.note`)
or per database timing (`latency_ms`, at most one a minute). Bucketed
at read time, pruned to a fortnight by the writer.

No backfill, and none possible: the history did not exist before
this, and inventing one from the cumulative counters would draw a
confident line through data nobody recorded. The cards start empty
and fill.

Revision ID: 72386ed9a1f5
Revises: dfa67929b543
Create Date: 2026-10-13 09:18:41.960745

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '72386ed9a1f5'
down_revision: Union[str, Sequence[str], None] = 'dfa67929b543'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'health_samples',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('service', sa.String(length=32), nullable=False),
        sa.Column('at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ok', sa.Integer(), server_default='0', nullable=False),
        sa.Column('errors', sa.Integer(), server_default='0',
                  nullable=False),
        sa.Column('latency_ms', sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('health_samples', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_health_samples_at'), ['at'],
                              unique=False)
        batch_op.create_index(batch_op.f('ix_health_samples_service'),
                              ['service'], unique=False)
        # The access pattern, which neither single-column index serves
        # well: every read is one service over a window, and the prune
        # is every service over a window.
        batch_op.create_index('ix_health_samples_service_at',
                              ['service', 'at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('health_samples', schema=None) as batch_op:
        batch_op.drop_index('ix_health_samples_service_at')
        batch_op.drop_index(batch_op.f('ix_health_samples_service'))
        batch_op.drop_index(batch_op.f('ix_health_samples_at'))

    op.drop_table('health_samples')
