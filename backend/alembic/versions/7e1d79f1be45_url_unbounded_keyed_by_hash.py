"""url unbounded, keyed by hash

`web_addresses.url` was `String(2048)`. SQLite ignores a VARCHAR length
entirely, so that limit was never enforced and a Burp history in this
engagement stored a URL of 8,221 characters without complaint. The first
import against PostgreSQL failed on it:

    value too long for type character varying(2048)

Widening the column is not enough on its own. A Postgres btree entry is
capped near 2.7 KB, and this column carried both an index and the
uniqueness that the whole upsert depends on — so a long URL could not be
indexed at any width. The URL therefore becomes unbounded `Text`, and a
sha256 of it carries the index and the unique constraint.

Revision ID: 7e1d79f1be45
Revises: 9a07fccf96d3
Create Date: 2026-10-05 00:31:00.000000
"""
import hashlib
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '7e1d79f1be45'
down_revision: Union[str, Sequence[str], None] = '9a07fccf96d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: Rows per backfill round trip.
BATCH = 2000


def _key(url: str) -> str:
    return hashlib.sha256((url or "").encode("utf-8", "surrogatepass")).hexdigest()


def _backfill(column: str, source: str) -> int:
    """Fill `column` from sha256(`source`) for every row, in batches.

    Done in Python rather than SQL because the two backends disagree:
    SQLite has no sha256 at all, and Postgres only has one via pgcrypto,
    which a customer's database may not have installed. The hash has to
    match what the application computes, so there is exactly one
    implementation of it and this calls the same shape.
    """
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(f"SELECT id, {source} FROM web_addresses")).fetchall()
    for i in range(0, len(rows), BATCH):
        chunk = rows[i:i + BATCH]
        bind.execute(
            sa.text(f"UPDATE web_addresses SET {column} = :h WHERE id = :i"),
            [{"i": r[0], "h": _key(r[1])} for r in chunk])
    return len(rows)


def upgrade() -> None:
    """Upgrade schema."""
    # Three steps, not one: adding a NOT NULL column with no default to
    # a populated table is rejected outright, and this table holds
    # hundreds of thousands of rows by the time anyone runs it.
    with op.batch_alter_table('web_addresses', schema=None) as batch_op:
        batch_op.add_column(sa.Column('url_hash', sa.String(length=64),
                                      nullable=True))
        batch_op.alter_column('url',
                              existing_type=sa.VARCHAR(length=2048),
                              type_=sa.Text(),
                              existing_nullable=False)

    n = _backfill("url_hash", "url")
    print(f"  backfilled url_hash for {n} web address(es)")

    with op.batch_alter_table('web_addresses', schema=None) as batch_op:
        batch_op.alter_column('url_hash', existing_type=sa.String(length=64),
                              nullable=False)
        batch_op.drop_index(batch_op.f('ix_web_addresses_url'))
        batch_op.drop_constraint(batch_op.f('uq_weburl_target_method_url'),
                                 type_='unique')
        batch_op.create_unique_constraint('uq_weburl_target_method_url',
                                          ['target_id', 'method', 'url_hash'])
        batch_op.create_index(batch_op.f('ix_web_addresses_url_hash'),
                              ['url_hash'], unique=False)


def downgrade() -> None:
    """Downgrade schema.

    Narrowing `url` back to 2048 would truncate or fail on exactly the
    rows that motivated this change, so the column is left as Text. The
    index and the constraint go back to the URL itself.
    """
    with op.batch_alter_table('web_addresses', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_web_addresses_url_hash'))
        batch_op.drop_constraint('uq_weburl_target_method_url', type_='unique')
        batch_op.create_unique_constraint(
            batch_op.f('uq_weburl_target_method_url'),
            ['target_id', 'method', 'url'])
        batch_op.create_index(batch_op.f('ix_web_addresses_url'), ['url'],
                              unique=False)
        batch_op.drop_column('url_hash')
