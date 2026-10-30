"""What a Ghost's address is called, and whether it can hold port 443.

Both are facts about the agent's own host that nothing else here can
answer. The name has to come from a PUBLIC resolver -- a Ghost's own
resolver gives an internal answer, and this server's resolver is on a
different network again -- so the agent resolves it and reports it.

`can_bind_privileged` is nullable on purpose: NULL is "the agent has
not told us", which is every agent enrolled before this and every one
too old to report. False would claim a limitation we have not
observed, and the port picker would warn about a Ghost that is fine.

Revision ID: b3e9d71a40c2
Revises: a7c21f4e9b03
"""
from alembic import op
import sqlalchemy as sa

revision = "b3e9d71a40c2"
down_revision = "a7c21f4e9b03"
branch_labels = None
depends_on = None

COLS = (
    ("public_name", sa.String(253)),
    ("public_name_note", sa.String(300)),
    ("can_bind_privileged", sa.Boolean()),
    ("bind_note", sa.String(300)),
)


def upgrade() -> None:
    # Nullable with no default, so this is a plain ADD COLUMN on a
    # populated table -- see the note in CLAUDE.md about `default=`
    # being Python-side, and about adding a NOT NULL column to one.
    #
    # batch_alter_table because SQLite cannot ADD COLUMN with every
    # modifier and alembic rebuilds the table instead. Postgres
    # ignores the wrapper. Both are supported, so neither may be
    # assumed.
    with op.batch_alter_table("agents") as b:
        for name, type_ in COLS:
            b.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents") as b:
        for name, _ in reversed(COLS):
            b.drop_column(name)
