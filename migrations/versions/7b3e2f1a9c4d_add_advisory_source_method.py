"""add advisory.source_method

Revision ID: 7b3e2f1a9c4d
Revises: 65629d602d24
Create Date: 2026-10-05 19:30:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "7b3e2f1a9c4d"
down_revision: str | None = "65629d602d24"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_VALUES = ("SENDER", "REFERENCE", "MANUAL", "NONE")
_ENUM = postgresql.ENUM(*_VALUES, name="sourcemethod_enum")


def upgrade() -> None:
    # add_column() doesn't CREATE TYPE — create it first (see 65629d602d24).
    _ENUM.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "advisory",
        sa.Column(
            "source_method",
            postgresql.ENUM(*_VALUES, name="sourcemethod_enum", create_type=False),
            nullable=True,
        ),
    )
    # Before this column, the source came from the sender or nothing: an
    # advisory under the UNKNOWN source matched nothing, every other one
    # matched its sender.
    op.execute(
        """
        UPDATE advisory a
        SET source_method = CASE WHEN s.short_code = 'UNKNOWN' THEN 'NONE' ELSE 'SENDER' END
            ::sourcemethod_enum
        FROM source s
        WHERE s.id = a.source_id
        """
    )
    op.alter_column("advisory", "source_method", nullable=False)


def downgrade() -> None:
    op.drop_column("advisory", "source_method")
    # drop_column() leaves the native enum type behind — D-023.
    op.execute("DROP TYPE IF EXISTS sourcemethod_enum")
