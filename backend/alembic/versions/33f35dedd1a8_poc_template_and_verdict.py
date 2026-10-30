"""poc template and verdict

The proof itself, where it was pointed, when it last ran and what it
said. See `models.Poc` for why a template rather than a script.

Guarded, like `d1f3b82c460a` and `a7e2d94c1f30`: the live database has
had columns added to it by hand, and an unguarded `add_column` over
one that is already there fails the migration and stops the app from
starting. Checked per column rather than per table -- a half-applied
earlier attempt is exactly the state this has to survive.

All nullable with no backfill. A PoC that predates these columns has
no template recorded and saying so is correct; inventing one would be
claiming a proof nobody wrote.

Revision ID: 33f35dedd1a8
Revises: a7e2d94c1f30
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "33f35dedd1a8"
down_revision: str | Sequence[str] | None = "a7e2d94c1f30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    ("template", sa.Text()),
    ("target_url", sa.Text()),
    ("validated_at", sa.DateTime(timezone=True)),
    ("verdict", sa.Text()),
)


def _have() -> set[str]:
    insp = sa.inspect(op.get_bind())
    return {c["name"] for c in insp.get_columns("pocs")}


def upgrade() -> None:
    have = _have()
    missing = [(n, t) for n, t in _COLUMNS if n not in have]
    if not missing:
        return
    # One batch for all of them: on SQLite each `batch_alter_table`
    # copies the whole table, so four separate ones would copy it
    # four times. `pocs` is small either way, but the habit is what
    # matters on the tables that are not.
    with op.batch_alter_table("pocs") as b:
        for name, type_ in missing:
            b.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    have = _have()
    present = [n for n, _ in _COLUMNS if n in have]
    if not present:
        return
    with op.batch_alter_table("pocs") as b:
        for name in reversed(present):
            b.drop_column(name)
