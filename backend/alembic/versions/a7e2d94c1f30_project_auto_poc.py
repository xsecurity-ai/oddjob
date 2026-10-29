"""auto_poc standing order

Guarded, like `d1f3b82c460a`: the live database has had columns added
to it by hand before, and an unguarded `add_column` over one that is
already there fails the migration and stops the app from starting.

`server_default` and not `default`: `default=` is Python-side, so a
NOT NULL column added without one fails the moment the table has a
row in it — and this table always does.

Revision ID: a7e2d94c1f30
Revises: e4a9c70d215b
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a7e2d94c1f30"
down_revision: str | Sequence[str] | None = "e4a9c70d215b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMN = "auto_poc"
#: The standing order is phrased as "findings at or above the floor
#: with no proof", so the proof has to be able to name the finding.
_POC_COLUMN = "vuln_id"


def _has(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def _present() -> bool:
    return _has("projects", _COLUMN)


def upgrade() -> None:
    if not _present():
        op.add_column("projects", sa.Column(
            _COLUMN, sa.String(length=16),
            nullable=False, server_default="off"))
    if not _has("pocs", _POC_COLUMN):
        # `batch_alter_table` so the foreign key lands on SQLite too.
        # CLAUDE.md warns that batch mode copies the whole table, and
        # that warning is about cost: `pocs` holds a handful of rows
        # per engagement, so the copy is free and the alternative --
        # a model declaring a constraint the dev database does not
        # have -- fails `alembic check` for ever.
        #
        # Nullable with no backfill: an existing PoC genuinely does
        # not name a finding, and inventing a link would claim
        # evidence for something it was never written against.
        with op.batch_alter_table("pocs") as b:
            b.add_column(sa.Column(_POC_COLUMN, sa.Integer(), nullable=True))
            b.create_foreign_key("fk_pocs_vuln_id", "vulns",
                                 [_POC_COLUMN], ["id"], ondelete="SET NULL")
        op.create_index("ix_pocs_vuln_id", "pocs", [_POC_COLUMN])


def downgrade() -> None:
    if _has("pocs", _POC_COLUMN):
        op.drop_index("ix_pocs_vuln_id", table_name="pocs")
        with op.batch_alter_table("pocs") as b:
            b.drop_constraint("fk_pocs_vuln_id", type_="foreignkey")
            b.drop_column(_POC_COLUMN)
    if _present():
        op.drop_column("projects", _COLUMN)
