"""CSV inventory parsing: header sniffing, auto-mapping, row parsing."""

from __future__ import annotations

import pytest

from advisory_hub.core.models.enums import InventorySourceKind
from advisory_hub.inventory.csv_parser import (
    CsvTooLargeError,
    MissingMappingError,
    auto_map,
    parse_rows,
    sniff_headers,
)
from advisory_hub.inventory.csv_profiles import CSV_PROFILES, profile_for

LANSWEEPER_CSV = (
    "SoftwareName,SoftwareVersion,Publisher,Count\n"
    "Google Chrome,120.0.6099.109,Google LLC,41\n"
    "Apache Log4j,2.14.1,Apache Software Foundation,6\n"
)


class TestSniffHeaders:
    def test_reads_the_header_row(self) -> None:
        assert sniff_headers(LANSWEEPER_CSV) == [
            "SoftwareName",
            "SoftwareVersion",
            "Publisher",
            "Count",
        ]

    def test_empty_input_returns_empty_list(self) -> None:
        assert sniff_headers("") == []


class TestAutoMap:
    def test_matches_known_lansweeper_headers(self) -> None:
        headers = sniff_headers(LANSWEEPER_CSV)
        mapping = auto_map(headers, profile_for(InventorySourceKind.CSV_LANSWEEPER))
        assert mapping["product"] == "SoftwareName"
        assert mapping["version"] == "SoftwareVersion"
        assert mapping["vendor"] == "Publisher"
        assert mapping["device_count"] == "Count"

    def test_is_case_and_whitespace_insensitive(self) -> None:
        mapping = auto_map(
            [" softwarename ", "SOFTWAREVERSION"], profile_for(InventorySourceKind.CSV_LANSWEEPER)
        )
        assert mapping["product"] == " softwarename "
        assert mapping["version"] == "SOFTWAREVERSION"

    def test_unmatched_fields_come_back_none(self) -> None:
        mapping = auto_map(["Nonsense Column"], profile_for(InventorySourceKind.CSV_LANSWEEPER))
        assert mapping["product"] is None
        assert mapping["vendor"] is None

    def test_every_csv_kind_has_a_profile(self) -> None:
        for kind in InventorySourceKind:
            if kind.value.startswith("CSV_"):
                assert kind in CSV_PROFILES


class TestParseRows:
    def test_happy_path(self) -> None:
        mapping = auto_map(
            sniff_headers(LANSWEEPER_CSV), profile_for(InventorySourceKind.CSV_LANSWEEPER)
        )
        result = parse_rows(LANSWEEPER_CSV, mapping)
        assert result.total_rows == 2
        assert len(result.rows) == 2
        assert not result.errors
        row = result.rows[0]
        assert row.vendor == "Google LLC"
        assert row.product == "Google Chrome"
        assert row.version == "120.0.6099.109"
        assert row.device_count == 41
        assert row.kind == "SOFTWARE"
        assert row.line_number == 2

    def test_blank_product_is_a_row_error(self) -> None:
        text = "SoftwareName,SoftwareVersion\n,1.0\n"
        result = parse_rows(text, {"product": "SoftwareName", "version": "SoftwareVersion"})
        assert not result.rows
        assert len(result.errors) == 1
        assert result.errors[0].line_number == 2
        assert "blank" in result.errors[0].message

    def test_non_numeric_device_count_is_a_row_error(self) -> None:
        text = "SoftwareName,Count\nChrome,notanumber\n"
        result = parse_rows(text, {"product": "SoftwareName", "device_count": "Count"})
        assert not result.rows
        assert len(result.errors) == 1
        assert "not a number" in result.errors[0].message

    def test_negative_device_count_is_a_row_error(self) -> None:
        text = "SoftwareName,Count\nChrome,-5\n"
        result = parse_rows(text, {"product": "SoftwareName", "device_count": "Count"})
        assert not result.rows
        assert "negative" in result.errors[0].message

    def test_missing_device_count_defaults_to_one(self) -> None:
        text = "SoftwareName\nChrome\n"
        result = parse_rows(text, {"product": "SoftwareName"})
        assert result.rows[0].device_count == 1

    def test_float_shaped_count_is_tolerated(self) -> None:
        text = "SoftwareName,Count\nChrome,12.0\n"
        result = parse_rows(text, {"product": "SoftwareName", "device_count": "Count"})
        assert result.rows[0].device_count == 12

    def test_missing_version_column_yields_none_version(self) -> None:
        text = "SoftwareName\nChrome\n"
        result = parse_rows(text, {"product": "SoftwareName"})
        assert result.rows[0].version is None

    def test_product_column_not_mapped_raises(self) -> None:
        with pytest.raises(MissingMappingError):
            parse_rows(LANSWEEPER_CSV, {"product": None})

    def test_azure_os_row_detection(self) -> None:
        text = (
            "displayName,version,osType,osName,osVersion\n"
            "Adobe Reader,23.1,,,\n"
            "VM-01,,Windows,Windows Server 2022,10.0.20348\n"
        )
        mapping = auto_map(sniff_headers(text), profile_for(InventorySourceKind.CSV_AZURE))
        result = parse_rows(text, mapping)
        assert len(result.rows) == 2
        software_row = next(r for r in result.rows if r.kind == "SOFTWARE")
        os_row = next(r for r in result.rows if r.kind == "OPERATING_SYSTEM")
        assert software_row.product == "Adobe Reader"
        assert os_row.product == "Windows Server 2022"
        assert os_row.version == "10.0.20348"

    def test_row_limit_is_enforced(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("CSV_MAX_ROWS", "1")
        get_settings.cache_clear()
        try:
            text = "SoftwareName\nA\nB\n"
            with pytest.raises(CsvTooLargeError):
                parse_rows(text, {"product": "SoftwareName"})
        finally:
            monkeypatch.delenv("CSV_MAX_ROWS", raising=False)
            get_settings.cache_clear()
