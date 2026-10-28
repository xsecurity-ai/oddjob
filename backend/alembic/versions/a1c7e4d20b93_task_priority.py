"""task priority

The hand-out loop takes each kind in turn, oldest first. That is the
right order for work nobody is waiting on and the wrong one for work
somebody is: a replayed request is sent while an operator watches the
dialog, and a project holding four thousand queued crawls would make
that a twenty-minute wait for one packet.

`server_default` rather than `default=`: this table is populated on
every live installation and a Python-side default never reaches the
rows that already exist, so the NOT NULL would fail on the first
deployment that had ever queued a task.

Revision ID: a1c7e4d20b93
Revises: a91c4f7b0e23
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'a1c7e4d20b93'
down_revision: Union[str, Sequence[str], None] = 'a91c4f7b0e23'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("agent_tasks") as b:
        b.add_column(sa.Column("priority", sa.Integer(), nullable=False,
                               server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("agent_tasks") as b:
        b.drop_column("priority")
