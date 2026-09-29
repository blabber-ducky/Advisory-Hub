"""Shared test fixtures.

Tests that need a database are marked ``integration`` and skipped when
``TEST_DATABASE_URL`` is unset, so the unit suite runs anywhere.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def engine():
    """Build the test schema by running the real Alembic migrations.

    Deliberately NOT ``Base.metadata.create_all()``: that skips everything the
    migration does beyond table DDL — notably the ``audit_log`` append-only
    trigger — leaving the migration itself untested and schema drift invisible.
    """
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")

    from alembic import command
    from alembic.config import Config

    eng = create_engine(TEST_DATABASE_URL, future=True)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "head")

    yield eng
    eng.dispose()


@pytest.fixture
def db(engine) -> Iterator[Session]:
    """A session wrapped in a transaction that is always rolled back."""
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, expire_on_commit=False, future=True)()
    try:
        yield session
    finally:
        session.close()
        # A failed flush (e.g. an IntegrityError under test) can already have
        # rolled the transaction back; rolling back again warns.
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def blob_root(tmp_path: Path) -> Path:
    root = tmp_path / "blobs"
    root.mkdir()
    return root


@pytest.fixture
def truncate_all(engine):
    def _truncate() -> None:
        from advisory_hub.core.models import Base

        with engine.begin() as conn:
            names = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
            conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))

    return _truncate
