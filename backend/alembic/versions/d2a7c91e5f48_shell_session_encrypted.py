"""Whether a callback arrived over TLS.

One listener takes both, decided per connection from the first
bytes, so this is a property of the session rather than of the port.

False for every existing row: they predate the feature and the
Ghost was not terminating TLS, so they genuinely were cleartext.
That is a fact rather than a default standing in for one.

Revision ID: d2a7c91e5f48
Revises: c81f4a2b7d63
"""
from alembic import op
import sqlalchemy as sa

revision = "d2a7c91e5f48"
down_revision = "c81f4a2b7d63"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("shell_sessions") as b:
        b.add_column(sa.Column("encrypted", sa.Boolean(), nullable=False,
                               server_default="false"))


def downgrade() -> None:
    with op.batch_alter_table("shell_sessions") as b:
        b.drop_column("encrypted")
