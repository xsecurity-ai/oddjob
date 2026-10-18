"""the rest of the authorisation letter: dates and a technique ceiling

The scope list has been enforced config since the beginning. The
other two sentences in the same document were not enforced at all,
so an engagement that ended on the 14th went on scanning on the
20th, and "no intrusive testing" got nuclei templates that send
payloads.

See `app/roe.py`.

Both dates are nullable and mean unbounded, which is what every
project had before this. `max_impact` is NOT NULL with a
server_default of `destructive` -- everything permitted. That is a
decision rather than an oversight: this arrives after engagements
are already running, and a default that silently stopped a live scan
would be a worse failure than the one it prevents.

Revision ID: c7f23a19d4e6
Revises: b4e91c7d2a08
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c7f23a19d4e6"
down_revision: str | Sequence[str] | None = "b4e91c7d2a08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("projects", sa.Column(
        "engagement_starts_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("projects", sa.Column(
        "engagement_ends_at", sa.DateTime(timezone=True), nullable=True))
    # server_default, because the table has rows. A Python-side
    # default produces ADD COLUMN ... NOT NULL with no DDL default,
    # which neither SQLite nor Postgres accepts here.
    op.add_column("projects", sa.Column(
        "max_impact", sa.String(16), nullable=False,
        server_default="destructive"))


def downgrade() -> None:
    op.drop_column("projects", "max_impact")
    op.drop_column("projects", "engagement_ends_at")
    op.drop_column("projects", "engagement_starts_at")
