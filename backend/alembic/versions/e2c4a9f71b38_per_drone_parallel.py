"""An operator can set one drone's parallelism

Revision ID: e2c4a9f71b38
Revises: d7a1f03be5c2
Create Date: 2026-10-08

`agents.parallel_override`: what an operator says this one drone may
run at once, overriding the agent's own assessment of its host. NULL --
the default, and what every existing row gets -- means "let the agent
decide", which is the behaviour before this column existed.

Nullable on purpose. Zero would be a real value meaning "run nothing",
and the thing that has to be expressible here is the absence of an
opinion, not a limit of none.

`batch_alter_table` so the SQLite path rebuilds the table rather than
failing on ALTER.
"""
from alembic import op
import sqlalchemy as sa

revision: str = "e2c4a9f71b38"
down_revision: str | None = "d7a1f03be5c2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as b:
        b.add_column(sa.Column("parallel_override", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents") as b:
        b.drop_column("parallel_override")
