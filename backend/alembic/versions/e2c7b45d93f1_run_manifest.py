"""what a scan was configured to look for

`resolved` had a hole in it:

    nuclei -severity critical,high      found CVE-2021-44228
    nuclei -severity critical           did not

The second run is not evidence the first finding is gone -- it was
configured not to look. Same tool, same host, later timestamp, and
the lifecycle said `resolved` out loud.

A manifest is the selection-relevant part of a run's configuration,
hashed. What changes WHAT CAN BE FOUND goes in; pacing, timeouts and
output format do not, or an engagement that tuned its rate limit
would become incomparable with itself.

Nothing is backfilled. Every existing sweep and every existing
finding keeps a NULL manifest, which reads as "the configuration was
not recorded" -- a weaker `resolved` that says so, rather than a
confident one that would be inventing a configuration nobody stored.

Revision ID: e2c7b45d93f1
Revises: d8a3f0b61c27
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e2c7b45d93f1"
down_revision: str | Sequence[str] | None = "d8a3f0b61c27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("finding_sweeps",
                  sa.Column("manifest", sa.String(32), nullable=True))
    op.create_index("ix_finding_sweeps_manifest", "finding_sweeps",
                    ["manifest"])
    op.add_column("vulns",
                  sa.Column("found_by_manifest", sa.String(32), nullable=True))

    op.create_table(
        "run_manifests",
        # The hash IS the key: two runs with identical configuration
        # are the same manifest, so there is nothing for a surrogate
        # id to distinguish.
        sa.Column("manifest", sa.String(32), primary_key=True),
        sa.Column("scanner", sa.String(64), nullable=False),
        sa.Column("detail", sa.Text, nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_run_manifests_scanner", "run_manifests", ["scanner"])


def downgrade() -> None:
    op.drop_index("ix_run_manifests_scanner", "run_manifests")
    op.drop_table("run_manifests")
    op.drop_column("vulns", "found_by_manifest")
    op.drop_index("ix_finding_sweeps_manifest", "finding_sweeps")
    op.drop_column("finding_sweeps", "manifest")
