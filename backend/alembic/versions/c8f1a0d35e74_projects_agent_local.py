"""per-project local LLM config: base url and token

`Project.agent_local_base_url` and `Project.agent_local_token` were
added to the model and to three routers without a migration, so every
deployment built from the migrations was missing them. The startup
guard catches exactly this and refuses to serve --

    RuntimeError: the database schema is older than the models:
      projects: missing agent_local_base_url, agent_local_token

-- which took CI with it: `backend tests`, `backend tests on
postgres`, `migrations build the models` and `image builds and the
stack comes up` all failed on main for the same reason, and the app
would not start locally either.

Both are nullable, which is what makes this a one-step migration
rather than the add-nullable/backfill/set-NOT-NULL dance: NULL is
already meaningful here. It means "inherit the site setting", which
is what lets one engagement point at a customer's own LLM without
moving every other project with it.

**Guarded, because the columns already exist on at least one
deployment.** The live server has both -- added by hand to keep it
serving while the model carried them and no migration did -- and its
`alembic_version` is still behind this revision. An unguarded
`add_column` there raises `DuplicateColumn`, the migration step fails,
and the app does not start: the deploy would be an outage rather than
a fix. Adding a column only if it is absent is the one way a
correction for a drifted schema can be safe on both a clean database
and the drifted one.

`Text`, matching `agent_anthropic_token` and `agent_openai_token`
beside them, rather than a bounded `String`: a base URL has no honest
length limit, and this project has had a `String(2048)` quietly hold
an 8,221-character URL on SQLite before Postgres refused it.

Revision ID: c8f1a0d35e74
Revises: b73e1c90d84a
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c8f1a0d35e74"
down_revision: str | Sequence[str] | None = "b73e1c90d84a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: The columns this revision is responsible for.
_COLUMNS = ("agent_local_base_url", "agent_local_token")


def _present() -> set[str]:
    """Which of them the database already has."""
    insp = sa.inspect(op.get_bind())
    return {c["name"] for c in insp.get_columns("projects")}


def upgrade() -> None:
    have = _present()
    for name in _COLUMNS:
        if name not in have:
            op.add_column("projects", sa.Column(name, sa.Text, nullable=True))


def downgrade() -> None:
    have = _present()
    for name in reversed(_COLUMNS):
        if name in have:
            op.drop_column("projects", name)
