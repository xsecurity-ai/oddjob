"""merge: add target_origins to all heads

Revision ID: c2f6705b7659
Revises: 56622d0e8f2c, a9c3f41d70b6
Create Date: 2026-10-27 19:46:55.065372

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c2f6705b7659'
down_revision: Union[str, Sequence[str], None] = ('56622d0e8f2c', 'a9c3f41d70b6')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
