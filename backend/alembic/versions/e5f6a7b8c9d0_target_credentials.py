"""explicit credential-to-target assignment

A credential's `host` is free text filed by the importers, and nothing
makes a find on one name apply to another. This table is the operator's
decision that a credential belongs to a target whatever either of them
is called; matching at task-queue time is the union of these rows and
credentials whose host equals the target's own name (see app.credauth).

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-11-12
"""
from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_id"], ["credentials.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", "credential_id",
                            name="uq_target_credential"),
    )
    op.create_index("ix_target_credentials_target", "target_credentials",
                    ["target_id"])
    op.create_index("ix_target_credentials_credential", "target_credentials",
                    ["credential_id"])


def downgrade() -> None:
    op.drop_index("ix_target_credentials_credential",
                  table_name="target_credentials")
    op.drop_index("ix_target_credentials_target",
                  table_name="target_credentials")
    op.drop_table("target_credentials")
