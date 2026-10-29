"""users.last_login_at: has this account ever signed in

The Invite button emails a sign-in link so somebody can set a
password. Offered against an account already in use, it sends that
email to a working user -- so it needs to know whether the account
has ever been signed in to, and nothing recorded that.

`auth.login` audit entries say the same thing and then expire on the
retention sweep, which would quietly re-enable the button months
later. A column does not.

Nullable, and NULL is meaningful: it is exactly what an invited
account looks like until somebody uses the link. Every existing row
starts NULL, which reads as "never signed in" -- slightly generous to
accounts that plainly have, and self-correcting the first time each
one logs in. Backfilling from the audit trail was the alternative and
would be wrong for any account whose entries have already aged out.

Guarded, like `c8f1a0d35e74`: the live database has had columns added
to it by hand before, and an unguarded `add_column` over one that is
already there fails the migration and stops the app from starting.

Revision ID: d1f3b82c460a
Revises: c8f1a0d35e74
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d1f3b82c460a"
down_revision: str | Sequence[str] | None = "c8f1a0d35e74"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMN = "last_login_at"


def _present() -> bool:
    insp = sa.inspect(op.get_bind())
    return _COLUMN in {c["name"] for c in insp.get_columns("users")}


def upgrade() -> None:
    if not _present():
        op.add_column("users", sa.Column(
            _COLUMN, sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    if _present():
        op.drop_column("users", _COLUMN)
