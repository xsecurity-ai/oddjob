"""Ports a Ghost has been told to hold open.

The listener was implicit before this: a Ghost caught a callback
because a task had asked it to, and the port went away with the task.
That is the wrong lifetime for a shell. An operator who has sent a
payload needs the port held across every scan, every restart and
every redeploy, and needs to see which Ghost is holding which port
without reading an agent's log.

`state` is separate from `enabled` because they are different facts:
one is what was asked for and the other is what the Ghost managed.
A port that nginx already owns is a failure the operator has to be
told about, and it is indistinguishable from a working listener
until somebody says so.

Revision ID: a7c21f4e9b03
Revises: 22f780585296
"""
from alembic import op
import sqlalchemy as sa

revision = "a7c21f4e9b03"
down_revision = "22f780585296"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "shell_listeners",
        sa.Column("id", sa.Integer(), primary_key=True),
        # Denormalised from the agent: the Listeners tab reads by
        # project, and that is an index this table can have.
        sa.Column("project_id", sa.Integer(),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        # CASCADE, and indexed because the heartbeat reads by it on
        # every beat and deleting a Ghost deletes through it.
        sa.Column("agent_id", sa.Integer(),
                  sa.ForeignKey("agents.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("protocol", sa.String(3), nullable=False,
                  server_default="tcp"),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False,
                  server_default="true"),
        # pending means the Ghost has not reported, which is a third
        # answer and not a quiet failure.
        sa.Column("state", sa.String(16), nullable=False,
                  server_default="pending"),
        sa.Column("state_detail", sa.String(300)),
        sa.Column("state_at", sa.DateTime(timezone=True)),
        sa.Column("note", sa.String(300)),
        sa.Column("created_by_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        # Asking for the same port twice is the same ask. Two rows
        # would have the Ghost bind, fail on the second, and report a
        # failure that is really a duplicate.
        sa.UniqueConstraint("agent_id", "protocol", "port",
                            name="uq_shell_listener_agent_port"),
    )
    op.create_index("ix_shell_listeners_project_id", "shell_listeners",
                    ["project_id"])
    op.create_index("ix_shell_listeners_agent_id", "shell_listeners",
                    ["agent_id"])
    op.create_index("ix_shell_listeners_project_enabled", "shell_listeners",
                    ["project_id", "enabled"])


def downgrade() -> None:
    op.drop_index("ix_shell_listeners_project_enabled",
                  table_name="shell_listeners")
    op.drop_index("ix_shell_listeners_agent_id", table_name="shell_listeners")
    op.drop_index("ix_shell_listeners_project_id", table_name="shell_listeners")
    op.drop_table("shell_listeners")
