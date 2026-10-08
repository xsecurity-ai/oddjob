"""Four standing orders a project can leave running

Revision ID: d7a1f03be5c2
Revises: c41b7e9a2d08
Create Date: 2026-10-08

Adds the four automation settings to `projects`: hand new zones to
amass, resolve hostnames that have no address, find names for
address-only hosts, and scan new hosts with nmap.

All four default to OFF, and that is the only defensible default. Each
one puts packets on a client's estate, and an upgrade that silently
starts scanning because a column appeared is the kind of thing that
ends an engagement. `auto_nmap` is a string rather than a boolean for
the same reason: the difference between the hundred commonest ports and
all 65,535 is hours of traffic, so it is chosen rather than implied.

`batch_alter_table` throughout, so the SQLite path rebuilds the table
instead of failing on ALTER.
"""
from alembic import op
import sqlalchemy as sa

revision: str = "d7a1f03be5c2"
down_revision: str | None = "c41b7e9a2d08"
branch_labels = None
depends_on = None

#: Named once. The downgrade drops exactly what the upgrade added, and
#: a list that is written twice is a list that eventually disagrees.
_BOOLS = ("auto_amass", "auto_resolve_ips", "auto_reverse_dns")


def upgrade() -> None:
    with op.batch_alter_table("projects") as b:
        for name in _BOOLS:
            # server_default as well as default: the Python-side default
            # does not reach rows that already exist, and a NULL here
            # would read as neither on nor off.
            b.add_column(sa.Column(name, sa.Boolean(), nullable=False,
                                   server_default="false"))
        b.add_column(sa.Column("auto_nmap", sa.String(16), nullable=False,
                               server_default="off"))


def downgrade() -> None:
    with op.batch_alter_table("projects") as b:
        b.drop_column("auto_nmap")
        for name in _BOOLS:
            b.drop_column(name)
