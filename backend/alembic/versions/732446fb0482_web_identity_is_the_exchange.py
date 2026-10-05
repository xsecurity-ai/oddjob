"""web identity is the exchange

Identity was (target, method, url): one row per address, keeping only
whichever response was imported last. For a proxy history that is the
wrong unit — the same endpoint probed ten different ways is ten pieces
of evidence, and the differences between the responses are usually the
finding. A 2.5 GB history collapsed from 357,276 captured exchanges to
289,695 rows on that key alone.

Identity is now sha256(method, url, request, response). The URL keeps
its own index so the UI can group the hits back together under it.

Revision ID: 732446fb0482
Revises: 7e1d79f1be45
"""
import hashlib
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '732446fb0482'
down_revision: Union[str, Sequence[str], None] = '7e1d79f1be45'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BATCH = 2000


def _key(method, url, request, response) -> str:
    h = hashlib.sha256()
    for part in ((method or "").upper(), url or "", request or "", response or ""):
        h.update(str(part).encode("utf-8", "surrogatepass"))
        h.update(b"\x1f")
    return h.hexdigest()


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('web_addresses', schema=None) as batch_op:
        batch_op.add_column(sa.Column('exchange_hash', sa.String(length=64),
                                      nullable=True))

    bind = op.get_bind()
    rows = bind.execute(sa.text(
        "SELECT id, method, url, request, response FROM web_addresses")).fetchall()
    for i in range(0, len(rows), BATCH):
        bind.execute(
            sa.text("UPDATE web_addresses SET exchange_hash = :h WHERE id = :i"),
            [{"i": r[0], "h": _key(r[1], r[2], r[3], r[4])} for r in rows[i:i + BATCH]])
    print(f"  backfilled exchange_hash for {len(rows)} web address(es)")

    # Existing rows were unique on (target, method, url), so their
    # exchange hashes are unique too and the new constraint can go on
    # without deduplicating anything first.
    with op.batch_alter_table('web_addresses', schema=None) as batch_op:
        batch_op.alter_column('exchange_hash', existing_type=sa.String(length=64),
                              nullable=False)
        batch_op.drop_constraint('uq_weburl_target_method_url', type_='unique')
        batch_op.create_unique_constraint('uq_weburl_target_method_url',
                                          ['target_id', 'exchange_hash'])
        batch_op.create_index(batch_op.f('ix_web_addresses_exchange_hash'),
                              ['exchange_hash'], unique=False)


def downgrade() -> None:
    """Downgrade schema.

    Going back loses rows: several exchanges for one address collapse
    into one row under the old key, and there is no way to choose which
    survives. The constraint is restored and the column dropped; any
    duplicates have to be resolved by hand first, which this reports
    rather than guessing at.
    """
    bind = op.get_bind()
    dupes = bind.execute(sa.text(
        "SELECT COUNT(*) FROM (SELECT target_id, method, url_hash "
        "FROM web_addresses GROUP BY target_id, method, url_hash "
        "HAVING COUNT(*) > 1) d")).scalar()
    if dupes:
        raise RuntimeError(
            f"{dupes} address(es) hold more than one captured exchange. "
            f"The old key cannot represent that; remove the extras first.")
    with op.batch_alter_table('web_addresses', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_web_addresses_exchange_hash'))
        batch_op.drop_constraint('uq_weburl_target_method_url', type_='unique')
        batch_op.create_unique_constraint('uq_weburl_target_method_url',
                                          ['target_id', 'method', 'url_hash'])
        batch_op.drop_column('exchange_hash')
