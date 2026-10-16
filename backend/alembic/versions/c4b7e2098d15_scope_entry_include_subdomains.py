"""scope entry: include subdomains

`project_scope.include_subdomains` records, on an FQDN entry, that the
zone under it is in scope with it. Before this an operator who pasted
`*.acme.example` found the apex refused — correct, because that is how
DNS and TLS read a wildcard, and wrong in practice, because the refusal
reads like a bug and the fix was a second line nobody knew to add.

A column rather than quietly writing the second line for them. The
reasoning is on models.ProjectScope.include_subdomains; the short of it
is that two rows are two rules, and the operator stated one.

NOT NULL with a server_default, not a Python-side default: `ADD COLUMN
... NOT NULL` with no DDL default is rejected against a populated table,
and project_scope is populated on every deployment that has ever had an
engagement. `batch_alter_table` because SQLite cannot ALTER at all.

Nothing is backfilled, and false is the honest value for every existing
row. A project scoped to an apex today covers the apex today; turning
that into zone coverage on behalf of someone who never asked would
widen live scope lists during a migration, which is the one thing this
table must never do by itself.

Revision ID: c4b7e2098d15
Revises: a81c5e4f2d60
Create Date: 2026-10-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c4b7e2098d15'
down_revision: Union[str, Sequence[str], None] = 'a81c5e4f2d60'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("project_scope") as b:
        b.add_column(sa.Column("include_subdomains", sa.Boolean(),
                               server_default="0", nullable=False))


def downgrade() -> None:
    # The flag goes, and with it the coverage it carried. An entry that
    # covered a zone becomes an entry that covers one name — a NARROWER
    # scope, which is the safe direction for a downgrade to take. The
    # alternative, materialising a `*.x.y` row per flagged entry so
    # nothing is lost, would have a downgrade widening nothing but
    # silently adding rules to the enforced list, and a reversal that
    # writes new scope entries is worse than one that loses a flag.
    with op.batch_alter_table("project_scope") as b:
        b.drop_column("include_subdomains")
