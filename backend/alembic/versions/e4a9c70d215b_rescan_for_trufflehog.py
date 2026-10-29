"""re-open the asset sweep so a newly added scanner sees the corpus

`web_asset_files.scanned_at` is ONE timestamp meaning "the scanners
have read this", not one per scanner. So adding a scanner to the
image changes nothing by itself: every file is already stamped, the
sweep selects `scanned_at IS NULL`, and trufflehog would run over an
empty queue for ever while the Assets tab goes on reporting what
opengrep found months ago.

Clearing the stamp is what actually puts the corpus back in front of
the scanners. On the deployment this was written for that is 61,953
files -- a sweep that will churn for a while, which is the honest
cost of adding a scanner and is cheaper than the alternative of
believing a clean result nothing produced.

Safe to re-run over findings that already exist: `_file_vuln` keys on
the scanner's own fingerprint, so a second pass amends rather than
duplicating, and it backfills `asset_id` on any finding that was
written before that column was populated.

This is also only safe BECAUSE of the ceilings added in #93. Before
them a full re-sweep is exactly the workload that OOM-killed the
container 126 times: 200 files a batch, up to 8 MB each, against
opengrep with 16 workers and no memory bound.

Nothing is deleted and nothing is recomputed eagerly -- the work
happens on the normal sweep schedule, a batch at a time.

Revision ID: e4a9c70d215b
Revises: d1f3b82c460a
"""
from collections.abc import Sequence

from alembic import op

revision: str = "e4a9c70d215b"
down_revision: str | Sequence[str] | None = "d1f3b82c460a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Both tables: the file rows are what the sweep selects, and the
    # asset rows carry their own stamp that the sweep sets alongside.
    op.execute("UPDATE web_asset_files SET scanned_at = NULL")
    op.execute("UPDATE web_assets SET scanned_at = NULL")


def downgrade() -> None:
    # Deliberately nothing. The old timestamps are gone and inventing
    # one would claim a file was read at a time nothing read it --
    # the sweep simply runs again, which is not a loss.
    pass
