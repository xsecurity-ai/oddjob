"""A standing order for nuclei.

Two runs rather than one, and the column records which of them an
engagement has authorised:

    off   nothing
    vuln  CVE templates, critical and high, nothing needing a login
    tech  what the service IS -- recorded against the service
    both  both, as separate tasks per URL

They cannot be one task. Every technology-detection template is
`info` severity, so the `-severity critical,high` that makes the
vulnerability run useful discards all 1,228 of them; a single task
carrying both sets of flags would run the CVE half and silently skip
the other.

`server_default` as well as `default`: this is an ALTER on a
populated table, and a NOT NULL column with only a Python-side
default fails on the existing rows. "off" is also the only safe
value to backfill with -- the alternative is an upgrade switching
scanning on at a client nobody asked.

Revision ID: b4e1f90c7d52
Revises: a9e2c7f41b63
"""
import sqlalchemy as sa
from alembic import op

revision = "b4e1f90c7d52"
down_revision = "a9e2c7f41b63"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("projects", sa.Column(
        "auto_nuclei", sa.String(16),
        nullable=False, server_default="off"))


def downgrade() -> None:
    op.drop_column("projects", "auto_nuclei")
