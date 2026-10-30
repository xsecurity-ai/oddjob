"""Whether a session's far end behaves like a shell.

A listener open to the internet catches scanners as well as
payloads. On the first fleet to run one, four scanner sessions
arrived within hours of the port being opened and were
indistinguishable from the real one.

`pending` for every existing row: they predate the probe and
nothing asked them anything, which is exactly what `pending`
means. Backfilling a guess would put a judgement in the record
that nobody made.

Revision ID: c81f4a2b7d63
Revises: b3e9d71a40c2
"""
from alembic import op
import sqlalchemy as sa

revision = "c81f4a2b7d63"
down_revision = "b3e9d71a40c2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # batch_alter_table: SQLite cannot ADD COLUMN with every modifier
    # and alembic rebuilds the table instead. Postgres ignores it.
    with op.batch_alter_table("shell_sessions") as b:
        b.add_column(sa.Column("probe", sa.String(16), nullable=False,
                               server_default="pending"))
        b.add_column(sa.Column("probe_note", sa.String(200)))
    op.create_index("ix_shell_sessions_probe", "shell_sessions", ["probe"])


def downgrade() -> None:
    op.drop_index("ix_shell_sessions_probe", table_name="shell_sessions")
    with op.batch_alter_table("shell_sessions") as b:
        b.drop_column("probe_note")
        b.drop_column("probe")
