"""shell sessions

A reverse shell a Ghost caught, and one row per thing typed on it.

Two new tables, so the guard is per TABLE rather than per column --
but it is still a guard, for the same reason every migration here has
one: the live database has been changed by hand before, and a
migration that cannot be re-run strands a deployment half-way.

Revision ID: 22f780585296
Revises: 33f35dedd1a8
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "22f780585296"
down_revision: str | Sequence[str] | None = "33f35dedd1a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    have = _tables()

    if "shell_sessions" not in have:
        op.create_table(
            "shell_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=True),
            sa.Column("agent_id", sa.Integer(), nullable=True),
            sa.Column("peer", sa.String(length=64), nullable=True),
            sa.Column("listen_port", sa.Integer(), nullable=True),
            sa.Column("state", sa.String(length=16),
                      server_default="open", nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True),
                      nullable=True),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("label", sa.String(length=200), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      nullable=False),
            sa.ForeignKeyConstraint(["project_id"], ["projects.id"],
                                    ondelete="CASCADE"),
            # SET NULL on both: losing the target or the agent must not
            # erase the record of what was done through the session.
            sa.ForeignKeyConstraint(["target_id"], ["targets.id"],
                                    ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.id"],
                                    ondelete="SET NULL"),
        )
        op.create_index("ix_shell_sessions_project_id", "shell_sessions",
                        ["project_id"])
        op.create_index("ix_shell_sessions_target_id", "shell_sessions",
                        ["target_id"])
        op.create_index("ix_shell_sessions_agent_id", "shell_sessions",
                        ["agent_id"])
        op.create_index("ix_shell_sessions_state", "shell_sessions", ["state"])
        # The C2 list reads by project and state, which is the one
        # query this table exists to answer quickly.
        op.create_index("ix_shell_sessions_project_state", "shell_sessions",
                        ["project_id", "state"])

    if "shell_exchanges" not in have:
        op.create_table(
            "shell_exchanges",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("session_id", sa.Integer(), nullable=False),
            sa.Column("seq", sa.Integer(), nullable=False),
            sa.Column("command", sa.Text(), nullable=True),
            sa.Column("output", sa.Text(), nullable=True),
            sa.Column("actor_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      nullable=False),
            # CASCADE here, unlike above: an exchange is meaningless
            # without the session it belongs to.
            sa.ForeignKeyConstraint(["session_id"], ["shell_sessions.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["actor_id"], ["users.id"],
                                    ondelete="SET NULL"),
            sa.UniqueConstraint("session_id", "seq",
                                name="uq_shell_exchange_seq"),
        )
        op.create_index("ix_shell_exchanges_session_id", "shell_exchanges",
                        ["session_id"])


def downgrade() -> None:
    have = _tables()
    if "shell_exchanges" in have:
        op.drop_table("shell_exchanges")
    if "shell_sessions" in have:
        op.drop_table("shell_sessions")
