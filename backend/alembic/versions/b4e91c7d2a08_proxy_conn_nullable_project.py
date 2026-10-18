"""proxy_connections.project_id nullable, so a refused credential leaves a row

The table's own docstring said it was "written for ACCEPTED and
REFUSED alike", and for the most interesting refusal it was not.

`decide` returns `refused_auth` with no project -- there is no
engagement to attribute an unresolvable credential to -- and `record`
returned early rather than write a row with a NULL in a NOT NULL
column. So every failed credential attempt against the internet-facing
TLS port left nothing behind. A sustained brute force produced zero
rows in the one table somebody would look in.

Nullable is the honest shape: "which project" genuinely has no answer
for a username that resolved to nothing, and inventing one would file
the attempt against an engagement it had nothing to do with.

`refused_command` had the same problem and is covered by the same
change: an unauthenticated client probing BIND and UDP-ASSOCIATE is
exactly what should be visible.

Revision ID: b4e91c7d2a08
Revises: 0edd843fa357
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b4e91c7d2a08"
down_revision: str | Sequence[str] | None = "0edd843fa357"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # batch_alter_table because on SQLite `alter_column` cannot change
    # nullability in place -- it copies the table. Postgres does it as
    # a catalogue update either way.
    with op.batch_alter_table("proxy_connections") as b:
        b.alter_column("project_id", existing_type=sa.Integer(),
                       nullable=True)


def downgrade() -> None:
    # The rows this migration exists to allow cannot survive going
    # back: a refusal with no project has no project to invent. They
    # are deleted rather than silently breaking the constraint.
    op.execute("DELETE FROM proxy_connections WHERE project_id IS NULL")
    with op.batch_alter_table("proxy_connections") as b:
        b.alter_column("project_id", existing_type=sa.Integer(),
                       nullable=False)
