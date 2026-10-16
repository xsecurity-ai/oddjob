"""per-project extra content-discovery paths

Revision ID: c5a2f83d61e4
Revises: b4e8d10c3f71
Create Date: 2026-10-10

One nullable column. Null means "nothing extra", which is what every
existing project wants and is distinct from an empty string somebody
typed and cleared.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c5a2f83d61e4"
down_revision: str | None = "b4e8d10c3f71"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.add_column(sa.Column("url_wordlist", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.drop_column("url_wordlist")
