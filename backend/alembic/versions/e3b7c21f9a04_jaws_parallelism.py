"""jaws parallelism

One agent ran one task at a time. That is the right default for a
scanner on a client's network and the wrong one for a 16-core box
asked to resolve four hundred names, so how many it may run at once
becomes a property of the engagement.

A ceiling rather than a target: the agent independently works out what
its host can stand and the lower of the two is used. Five because it
is enough to keep a queue moving without being a number anybody has to
think about, and because an operator who wants one still has to be
able to say one.

Revision ID: e3b7c21f9a04
Revises: d1f6c47a0b93
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'e3b7c21f9a04'
down_revision: Union[str, Sequence[str], None] = 'd1f6c47a0b93'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.add_column(sa.Column("jaws_max_parallel", sa.Integer(),
                               nullable=False, server_default="5"))
    # Nullable: an agent that has not reported its own assessment yet
    # is different from one that assessed itself as able to run one,
    # and the dispatcher treats them differently.
    with op.batch_alter_table("agents") as b:
        b.add_column(sa.Column("capacity", sa.Integer(), nullable=True))
        b.add_column(sa.Column("capacity_reason", sa.String(length=300),
                               nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents") as b:
        b.drop_column("capacity_reason")
        b.drop_column("capacity")
    with op.batch_alter_table("projects") as b:
        b.drop_column("jaws_max_parallel")
