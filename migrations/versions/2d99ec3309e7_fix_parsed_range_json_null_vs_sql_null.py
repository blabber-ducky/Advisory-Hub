"""fix parsed_range json null vs sql null

`AdvisoryProduct.parsed_range` was `JSONB` without `none_as_null=True`, so
SQLAlchemy stored a Python `None` as a literal JSON `null`
(`'null'::jsonb`), not a true SQL `NULL`. The ORM read path masks this —
JSON `null` deserialises back to Python `None` — but a SQL-level
`IS NOT NULL` filter matched every row regardless, parsed or not. Found by
directly inspecting the real ah-test corpus after a live reparse, not by
unit tests (which only ever read through the ORM). See D-033.

The model fix (`none_as_null=True`) only changes behaviour for *future*
writes; this migration data-fixes every row already carrying the bad
literal.

Revision ID: 2d99ec3309e7
Revises: 67293c94f22d
Create Date: 2026-08-22 22:25:37.462076
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "2d99ec3309e7"
down_revision: str | None = "67293c94f22d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("UPDATE advisory_product SET parsed_range = NULL WHERE parsed_range = 'null'::jsonb")


def downgrade() -> None:
    # Not reversible in the "restore the bad literal" sense, and there is
    # no reason to: a true SQL NULL is a strict correctness fix, not a
    # behavioural change anything downgrades against.
    pass
