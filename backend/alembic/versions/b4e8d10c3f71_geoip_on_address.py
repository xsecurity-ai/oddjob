"""geolocation tagged onto the address

Revision ID: b4e8d10c3f71
Revises: a3f7c21d4e90
Create Date: 2026-10-10

Columns only, all nullable, no backfill. Existing addresses read as
"never looked up" (geo_at is null), which is true, and is deliberately
distinguishable from "looked up and nothing known" — a private range
answers nothing, and without the timestamp every pass would ask again.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b4e8d10c3f71"
down_revision: str | None = "a3f7c21d4e90"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLS = [
    ("geo_country", sa.String(length=2)),
    ("geo_country_name", sa.String(length=80)),
    ("geo_subdivision", sa.String(length=80)),
    ("geo_city", sa.String(length=120)),
    ("geo_latitude", sa.Float()),
    ("geo_longitude", sa.Float()),
    ("geo_accuracy_km", sa.Integer()),
    ("geo_asn", sa.Integer()),
    ("geo_org", sa.String(length=160)),
    ("geo_at", sa.DateTime(timezone=True)),
]


def upgrade() -> None:
    # batch_alter_table: SQLite cannot ADD COLUMN with every modifier
    # and alembic rebuilds the table instead. Postgres ignores the
    # wrapper. Both are supported here, so neither may be assumed.
    with op.batch_alter_table("target_addresses") as b:
        for name, type_ in COLS:
            b.add_column(sa.Column(name, type_, nullable=True))
    op.create_index("ix_target_addresses_geo_asn", "target_addresses",
                    ["geo_asn"])


def downgrade() -> None:
    op.drop_index("ix_target_addresses_geo_asn", table_name="target_addresses")
    with op.batch_alter_table("target_addresses") as b:
        for name, _ in reversed(COLS):
            b.drop_column(name)
