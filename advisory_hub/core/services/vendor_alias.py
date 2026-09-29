"""`vendor_alias` seeding and lookup — Phase 2d.

Loading is a single query into a plain dict, done once per ingest/scan
operation and passed around — never a per-row query.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...inventory.normalise import SEED_VENDOR_ALIASES
from ..models.inventory import VendorAlias


def load_vendor_alias_map(db: DbSession) -> dict[str, str]:
    """Alias (lowercased) -> canonical vendor, for `normalise.normalise_vendor()`."""
    rows = db.scalars(select(VendorAlias)).all()
    return {row.alias.lower(): row.canonical_vendor for row in rows}


def seed_vendor_aliases(db: DbSession) -> list[VendorAlias]:
    """Seed the built-in vendor aliases. Idempotent — existing aliases (by
    exact `alias` text) are left untouched, including any an admin has
    since edited."""
    existing = {row.alias for row in db.scalars(select(VendorAlias)).all()}
    created: list[VendorAlias] = []
    for alias, canonical in SEED_VENDOR_ALIASES:
        if alias in existing:
            continue
        row = VendorAlias(alias=alias, canonical_vendor=canonical)
        db.add(row)
        created.append(row)
    db.flush()
    return created


__all__ = ["load_vendor_alias_map", "seed_vendor_aliases"]
