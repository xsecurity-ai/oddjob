"""A proof somebody asked for, as distinct from one a floor covered.

`projects.auto_poc` is a FLOOR: "prove everything this bad or worse,
from now on". It is the right control for a standing policy and the
wrong one for "prove the findings on THIS host" -- raising the floor
to cover a host commits the engagement to every finding at that
severity across the whole estate, and lowering it afterwards does not
un-send what went out meanwhile.

So requests are recorded per finding. The worker drains them ahead of
the floor sweep, because a request is a question somebody is waiting
on and the sweep is a backlog.

Guarded, like `a7e2d94c1f30`: the live database has had columns added
to it by hand before, and an unguarded `add_column` over one already
there fails the migration and stops the app from starting.

Nullable with no `server_default`: NULL means nobody asked, which is
true of every finding that already exists, so there is nothing to
backfill and no NOT NULL to satisfy.

Revision ID: b8c4e71a9d23
Revises: d2a7c91e5f48
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b8c4e71a9d23"
down_revision: str | Sequence[str] | None = "d2a7c91e5f48"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "vulns"
_COLUMN = "poc_requested_at"
_INDEX = "ix_vulns_poc_requested_at"


def _has_column() -> bool:
    insp = sa.inspect(op.get_bind())
    return _COLUMN in {c["name"] for c in insp.get_columns(_TABLE)}


def _has_index() -> bool:
    insp = sa.inspect(op.get_bind())
    return _INDEX in {i["name"] for i in insp.get_indexes(_TABLE)}


def upgrade() -> None:
    if not _has_column():
        op.add_column(_TABLE, sa.Column(
            _COLUMN, sa.DateTime(timezone=True), nullable=True))
    if not _has_index():
        # The worker asks "is anything requested and unproved" on
        # every cycle, against a table with tens of thousands of rows
        # per engagement and a handful of requested ones. Without the
        # index that is a sequential scan every thirty seconds.
        op.create_index(_INDEX, _TABLE, [_COLUMN])


def downgrade() -> None:
    if _has_index():
        op.drop_index(_INDEX, table_name=_TABLE)
    if _has_column():
        op.drop_column(_TABLE, _COLUMN)
