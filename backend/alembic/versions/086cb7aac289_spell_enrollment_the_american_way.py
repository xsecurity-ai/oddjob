"""spell enrollment the american way

Renames, not drop-and-add. Autogenerate proposed dropping the three
`enrol_*` columns and adding `enroll_*` ones, which would silently
discard any outstanding enrollment token — an agent created but not
yet started would become unredeemable, and the token is one-time so
there is no recovering it.

batch_alter_table because SQLite cannot rename a column in place on
older versions and the suite runs on SQLite.

Revision ID: 086cb7aac289
Revises: 0f9cd5cb0140
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '086cb7aac289'
down_revision: Union[str, Sequence[str], None] = '0f9cd5cb0140'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PAIRS = [
    ("enrol_token_hash", "enroll_token_hash", sa.String(length=128)),
    ("enrol_expires_at", "enroll_expires_at", sa.DateTime(timezone=True)),
    ("enrol_used_at", "enroll_used_at", sa.DateTime(timezone=True)),
]


def upgrade() -> None:
    with op.batch_alter_table("agents") as b:
        for old, new, t in PAIRS:
            b.alter_column(old, new_column_name=new, existing_type=t,
                           existing_nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("agents") as b:
        for old, new, t in PAIRS:
            b.alter_column(new, new_column_name=old, existing_type=t,
                           existing_nullable=True)
