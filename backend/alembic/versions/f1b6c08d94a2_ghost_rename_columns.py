"""Drones are ghosts: the two columns that carried the old word

Revision ID: f1b6c08d94a2
Revises: e2c4a9f71b38
Create Date: 2026-10-08

`projects.drone_mode` -> `ghost_mode`, `projects.drone_max_parallel` ->
`ghost_max_parallel`. Renames, not drop-and-add: both hold operator
settings that would otherwise silently revert to their defaults, and a
fleet quietly going back to five parallel tasks is the kind of thing
nobody notices until a client asks.

These two are the only columns the rename touched. The `agents` table
and its columns keep their names: the agent's persistence identity is
not what was being renamed, and moving a table with foreign keys
pointing at it during a live engagement is risk bought for nothing.
The wire constants did not move either -- see the note in
`app/agentcrypto.py` about the seal context.

`batch_alter_table` so the SQLite path rebuilds the table rather than
failing on ALTER.
"""
from alembic import op

revision: str = "f1b6c08d94a2"
down_revision: str | None = "e2c4a9f71b38"
branch_labels = None
depends_on = None

#: old -> new. Named once so the downgrade cannot disagree with the
#: upgrade about which columns it is responsible for.
_RENAMES = (("drone_mode", "ghost_mode"),
            ("drone_max_parallel", "ghost_max_parallel"))


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for old, new in _RENAMES:
            b.alter_column(old, new_column_name=new)


def downgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for old, new in _RENAMES:
            b.alter_column(new, new_column_name=old)
