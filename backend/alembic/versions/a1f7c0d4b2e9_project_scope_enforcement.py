"""project scope enforcement

The scope list stops being a record of what was agreed and starts being
the thing that refuses work. Two changes make that possible.

`project_scope.country` is an operator-DECLARED country for the addresses
an entry covers, ISO 3166-1 alpha-2. It exists because the alternative
way to answer "which country is this host in" is to send the client's
target list to a geolocation service, and that is a disclosure of the
engagement. Nullable, and null means undetermined rather than nowhere.

`project_scope.kind` widens from 8 to 16 characters to hold `wildcard`
and `country`. Eight was exactly enough for `wildcard` and not for
`country`; Postgres enforces the length and SQLite ignores it, so left
alone this would have passed every test and failed on the first real
deployment. SQLite cannot ALTER a column at all, so it goes through
batch_alter_table, which rebuilds the table — same reason as
d56d143dc4e1.

Nothing is backfilled and nothing existing is deleted. A project that
already has scope rows acquires enforcement from them, which is the
point: the list it was given is the list it is held to. Existing targets
outside it are untouched — the lists govern what is NEW, and clearing
out what is already there is a deliberate act in the UI, with the hosts
named.

Revision ID: a1f7c0d4b2e9
Revises: 460ed412e342
Create Date: 2026-10-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1f7c0d4b2e9'
down_revision: Union[str, Sequence[str], None] = '460ed412e342'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("project_scope") as b:
        b.add_column(sa.Column("country", sa.String(length=2), nullable=True))
        b.alter_column("kind",
                       existing_type=sa.String(length=8),
                       type_=sa.String(length=16),
                       existing_nullable=False)


def downgrade() -> None:
    # Narrowing `kind` back would truncate or reject the rows this
    # migration made possible, so they go first. Dropped rather than
    # rewritten to something shorter: a `country` row silently becoming
    # `countr` is a scope entry that matches nothing while still looking
    # like a rule.
    op.execute("DELETE FROM project_scope WHERE kind IN ('wildcard', 'country')")
    with op.batch_alter_table("project_scope") as b:
        b.alter_column("kind",
                       existing_type=sa.String(length=16),
                       type_=sa.String(length=8),
                       existing_nullable=False)
        b.drop_column("country")
