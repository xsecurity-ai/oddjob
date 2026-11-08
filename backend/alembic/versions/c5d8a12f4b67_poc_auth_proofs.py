"""Proving a credential still AUTHENTICATES, not just that it is served.

Two different claims about the same finding:

  exposure  the key is still sitting in that asset. Provable by
            fetching the asset and matching the key's format, and the
            credential's value is never needed to do it.
  auth      the key still works. Only provable by presenting it, so
            the check has to carry the real value at run time.

`pocs.needs_secret` marks the second kind. The template stored in the
row holds a `{{secret}}` PLACEHOLDER and never the value -- the value
is released to the agent that holds the task, once, over its own
authenticated route, and is not written into `agent_tasks.args` where
the tasks view would show it.

`vulns.poc_request_mode` carries which of the two was asked for,
because a request is drained minutes later by a worker and the mode
has to survive the wait.

Guarded, like `a7e2d94c1f30`: the live database has had columns added
by hand before.

Revision ID: c5d8a12f4b67
Revises: b8c4e71a9d23
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c5d8a12f4b67"
down_revision: str | Sequence[str] | None = "b8c4e71a9d23"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has(table: str, column: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    if not _has("pocs", "needs_secret"):
        # `server_default`, not `default`: a Python-side default
        # produces `ADD COLUMN ... NOT NULL` with no DDL default,
        # which fails against a table that already has rows.
        op.add_column("pocs", sa.Column(
            "needs_secret", sa.Boolean(), nullable=False,
            server_default=sa.false()))
    if not _has("vulns", "poc_request_mode"):
        # Nullable: NULL means nobody asked, which is true of every
        # finding that already exists.
        op.add_column("vulns", sa.Column(
            "poc_request_mode", sa.String(length=16), nullable=True))


def downgrade() -> None:
    if _has("vulns", "poc_request_mode"):
        op.drop_column("vulns", "poc_request_mode")
    if _has("pocs", "needs_secret"):
        op.drop_column("pocs", "needs_secret")
