"""ivanti itsm: integration kind + advisory_ticket

Revision ID: d4e5f6a7b8c9
Revises: c1d2e3f4a5b6
Create Date: 2026-10-06 18:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c1d2e3f4a5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ENUM = "systemintegrationkind_enum"
_VALUES_BEFORE = ("NVD", "VIRUSTOTAL", "ENTRA_SSO", "MAILBOX_SYNC")


def upgrade() -> None:
    op.execute(f"ALTER TYPE {_ENUM} ADD VALUE IF NOT EXISTS 'IVANTI_ITSM'")
    op.create_table(
        "advisory_ticket",
        sa.Column("advisory_id", sa.UUID(), nullable=False),
        sa.Column("system", sa.String(length=32), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=False),
        sa.Column("number", sa.String(length=64), nullable=True),
        sa.Column("rec_id", sa.String(length=64), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("service", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("subcategory", sa.Text(), nullable=False),
        sa.Column("team", sa.Text(), nullable=False),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        sa.Column("attachment_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("warning", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["advisory_id"],
            ["advisory.id"],
            name=op.f("fk_advisory_ticket_advisory_id_advisory"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["user_account.id"],
            name=op.f("fk_advisory_ticket_created_by_id_user_account"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_advisory_ticket")),
    )
    op.create_index(op.f("ix_advisory_ticket_advisory_id"), "advisory_ticket", ["advisory_id"])
    op.create_index(op.f("ix_advisory_ticket_created_at"), "advisory_ticket", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_advisory_ticket_created_at"), table_name="advisory_ticket")
    op.drop_index(op.f("ix_advisory_ticket_advisory_id"), table_name="advisory_ticket")
    op.drop_table("advisory_ticket")
    # PostgreSQL can't drop an enum value: rebuild the type without it (D-023).
    op.execute("DELETE FROM system_integration WHERE kind = 'IVANTI_ITSM'")
    op.execute(f"ALTER TYPE {_ENUM} RENAME TO {_ENUM}_old")
    values = ", ".join(f"'{v}'" for v in _VALUES_BEFORE)
    op.execute(f"CREATE TYPE {_ENUM} AS ENUM ({values})")
    op.execute(
        f"ALTER TABLE system_integration ALTER COLUMN kind TYPE {_ENUM} USING kind::text::{_ENUM}"
    )
    op.execute(f"DROP TYPE {_ENUM}_old")
