"""the page sweep's index has to shrink as the queue drains

`801ff3977326` indexed `web_addresses.scanned_at` on its own, which
is the obvious thing and the wrong one. The sweep's query is

    WHERE scanned_at IS NULL AND status_code BETWEEN 200 AND 299
          AND response IS NOT NULL
    ORDER BY id LIMIT 100

and on the engagement this was built against that table holds
168,231 rows in 1,753 MB, of which 51,059 are eligible. Every row
starts with `scanned_at` NULL, so an index on that column alone
selects the whole table and the planner ignores it -- measured, on
the real database:

    Limit
      ->  Nested Loop
            ->  Index Scan using web_addresses_pkey on web_addresses
                  Filter: (response IS NOT NULL) AND (status_code ...)

It walks the primary key in id order and filters. That is cheap on
the first batch, where every row matches, and gets worse on every
one after it: the scanned rows accumulate at the low ids the scan
starts from, so batch 500 skips past 50,000 rows it has already
done to find the next hundred. 511 batches, each walking further
than the last.

A PARTIAL index is the shape this actually wants. It contains only
the rows still owed, in id order, so a batch reads its first
hundred entries -- and it SHRINKS as the queue drains, which is the
opposite of the behaviour above. This is the same lesson the
`web_addresses.service_id` foreign key taught (46,811 deletes, each
scanning 294,251 rows), applied before it costs a day instead of
after.

The plain index is dropped rather than kept beside it. Nothing
queries `scanned_at IS NOT NULL`, and an unused index on a table
this size is write cost on every captured exchange for nothing.

Revision ID: 9c2e1f4ab7d3
Revises: 801ff3977326
Create Date: 2026-10-18 02:55:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c2e1f4ab7d3'
down_revision: Union[str, Sequence[str], None] = '801ff3977326'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_index(op.f('ix_web_addresses_scanned_at'),
                  table_name='web_addresses')
    # Not `batch_alter_table`: on SQLite that copies the whole table,
    # and a partial index is expressible directly on both backends.
    op.create_index(
        'ix_web_addresses_unscanned', 'web_addresses', ['id'],
        unique=False,
        postgresql_where=sa.text('scanned_at IS NULL'),
        sqlite_where=sa.text('scanned_at IS NULL'))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_web_addresses_unscanned', table_name='web_addresses')
    op.create_index(op.f('ix_web_addresses_scanned_at'), 'web_addresses',
                    ['scanned_at'], unique=False)
