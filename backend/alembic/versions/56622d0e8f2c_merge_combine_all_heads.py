"""merge: combine all heads

Revision ID: 56622d0e8f2c
Revises: a1c7e4f20b95, b73e1c90d84a
Create Date: 2026-10-27 19:45:36.893893

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '56622d0e8f2c'
down_revision: Union[str, Sequence[str], None] = ('a1c7e4f20b95', 'b73e1c90d84a')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
