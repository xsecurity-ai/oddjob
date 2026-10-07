"""drone rename

Jaws became Drone. The two columns that carried the old name are
renamed to match the models; everything else about them is unchanged.

alter_column with new_column_name, not drop-and-add. Autogenerate
proposes the latter for a rename, which would discard every project's
routing mode and parallelism setting and replace them with defaults —
silently, and returning success.

The migrations above this one still say `jaws`. They are a record of
what ran at the time and are deliberately left alone: a migration
rewritten to describe a past that did not happen is worse than one
with an old name in it.

Revision ID: c2f91a4e6b73
Revises: a9c4e07b2d18
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'c2f91a4e6b73'
down_revision: Union[str, Sequence[str], None] = 'a9c4e07b2d18'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PAIRS = [
    ("jaws_mode", "drone_mode", sa.String(length=16)),
    ("jaws_max_parallel", "drone_max_parallel", sa.Integer()),
]


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for old, new, t in PAIRS:
            b.alter_column(old, new_column_name=new, existing_type=t,
                           existing_nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for old, new, t in PAIRS:
            b.alter_column(new, new_column_name=old, existing_type=t,
                           existing_nullable=False)
