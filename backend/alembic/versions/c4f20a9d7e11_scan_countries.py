"""Country gates: which countries a project may scan, and which each ghost will.

Two columns, both nullable, both meaning "no restriction" when empty.
That default is what makes this safe to add to a running deployment:
every existing project and agent keeps behaving exactly as it did
until somebody sets one.

Stored as a comma-separated list of ISO 3166-1 alpha-2 codes rather
than a join table. The values are two characters, there are fewer
than 250 of them, the whole list is read together or not at all, and
nothing ever queries "which projects allow JP" -- a table would be
three joins to answer a question nobody asks.

Revision ID: c4f20a9d7e11
Revises: a7d4e91c3b60
"""
from alembic import op
import sqlalchemy as sa

revision = "c4f20a9d7e11"
down_revision = "a7d4e91c3b60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("projects",
                  sa.Column("scan_countries", sa.String(512), nullable=True))
    op.add_column("agents",
                  sa.Column("scan_countries", sa.String(512), nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "scan_countries")
    op.drop_column("projects", "scan_countries")
