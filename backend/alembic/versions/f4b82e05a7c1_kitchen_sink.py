"""standing orders for the rest of enumeration, and one switch for all of it

Six policies covered six of the things an operator does by hand and
left two alone: virtual-host discovery and probing known URLs. Both
are the same shape as the six -- in-house, repeatable, and the thing
somebody otherwise has to remember.

There is no `auto_geolocate`. Geolocation already runs for every
project the worker touches, against a local database, so a switch
for it would not switch anything.

`kitchen_sink` is one switch for the engagement where the answer to
every "should we also..." is yes. It is resolved when the policies
are READ rather than copied into the other columns, so turning it
off returns a project to whatever was set before instead of to
whatever the sink left behind.

It deliberately does not imply Certificate Transparency or
archived-URL lookups. Those send a client's domain to a third party
and are gated by an explicit site decision; a convenience switch
that routed around a vendor-approval gate would be the gate not
existing.

Revision ID: f4b82e05a7c1
Revises: e2c7b45d93f1
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f4b82e05a7c1"
down_revision: str | Sequence[str] | None = "e2c7b45d93f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLS = ("auto_vhost", "auto_httpx", "kitchen_sink")


def upgrade() -> None:
    # server_default, because the table has rows. A Python-side
    # default produces ADD COLUMN ... NOT NULL with no DDL default,
    # which neither SQLite nor Postgres accepts here.
    for c in _COLS:
        op.add_column("projects", sa.Column(
            c, sa.Boolean(), nullable=False, server_default="false"))


def downgrade() -> None:
    for c in reversed(_COLS):
        op.drop_column("projects", c)
