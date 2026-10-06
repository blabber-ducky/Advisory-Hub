"""entra sso + mailbox sync: integration kinds, config column, sync state

Revision ID: c1d2e3f4a5b6
Revises: 7b3e2f1a9c4d
Create Date: 2026-10-06 10:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c1d2e3f4a5b6"
down_revision: str | None = "7b3e2f1a9c4d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ENUM = "systemintegrationkind_enum"
_OLD_VALUES = ("NVD", "VIRUSTOTAL")


def upgrade() -> None:
    # New values are only usable after this transaction commits; nothing in
    # this migration inserts them, so that's fine.
    op.execute(f"ALTER TYPE {_ENUM} ADD VALUE IF NOT EXISTS 'ENTRA_SSO'")
    op.execute(f"ALTER TYPE {_ENUM} ADD VALUE IF NOT EXISTS 'MAILBOX_SYNC'")

    op.add_column(
        "system_integration",
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    op.create_table(
        "mailbox_sync_state",
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("folder_id", sa.Text(), nullable=True),
        sa.Column("delta_link", sa.Text(), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.Text(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("fetched_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_too_large_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mailbox_sync_state")),
    )
    op.create_index(op.f("ix_mailbox_sync_state_created_at"), "mailbox_sync_state", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_mailbox_sync_state_created_at"), table_name="mailbox_sync_state")
    op.drop_table("mailbox_sync_state")
    op.drop_column("system_integration", "config")
    # PostgreSQL can't drop enum values: rebuild the type without them
    # (D-023). Rows of the new kinds go first — they can't be represented.
    op.execute("DELETE FROM system_integration WHERE kind IN ('ENTRA_SSO', 'MAILBOX_SYNC')")
    op.execute(f"ALTER TYPE {_ENUM} RENAME TO {_ENUM}_old")
    values = ", ".join(f"'{v}'" for v in _OLD_VALUES)
    op.execute(f"CREATE TYPE {_ENUM} AS ENUM ({values})")
    op.execute(
        f"ALTER TABLE system_integration ALTER COLUMN kind TYPE {_ENUM} USING kind::text::{_ENUM}"
    )
    op.execute(f"DROP TYPE {_ENUM}_old")
