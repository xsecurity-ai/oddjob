"""standing order: crawl and content discovery

Revision ID: d6b3e1a07f25
Revises: c5a2f83d61e4
Create Date: 2026-10-10

One column, defaulting to "off" like every other standing order. Each
one queues work against a client, so none of them starts switched on.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d6b3e1a07f25"
down_revision: str | None = "c5a2f83d61e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.add_column(sa.Column("auto_web", sa.String(length=16),
                               nullable=False, server_default="off"))


def downgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.drop_column("auto_web")
