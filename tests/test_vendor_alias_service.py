"""`core.services.vendor_alias` — seeding and lookup.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import pytest

from advisory_hub.core.models.inventory import VendorAlias
from advisory_hub.core.services.vendor_alias import load_vendor_alias_map, seed_vendor_aliases
from advisory_hub.inventory.normalise import SEED_VENDOR_ALIASES

pytestmark = pytest.mark.integration


class TestSeedVendorAliases:
    def test_creates_all_seed_rows(self, db) -> None:
        created = seed_vendor_aliases(db)
        assert len(created) == len(SEED_VENDOR_ALIASES)

    def test_is_idempotent(self, db) -> None:
        seed_vendor_aliases(db)
        second_run = seed_vendor_aliases(db)
        assert second_run == []

    def test_does_not_overwrite_an_admin_edited_alias(self, db) -> None:
        db.add(VendorAlias(alias="Microsoft Corporation", canonical_vendor="custom-microsoft"))
        db.flush()
        seed_vendor_aliases(db)
        row = db.query(VendorAlias).filter_by(alias="Microsoft Corporation").one()
        assert row.canonical_vendor == "custom-microsoft"


class TestLoadVendorAliasMap:
    def test_maps_lowercased_alias_to_canonical(self, db) -> None:
        seed_vendor_aliases(db)
        alias_map = load_vendor_alias_map(db)
        assert alias_map["microsoft corporation"] == "microsoft"
        assert alias_map["google llc"] == "google"

    def test_empty_when_unseeded(self, db) -> None:
        assert load_vendor_alias_map(db) == {}
