"""Built-in CSV column profiles, per docs/inventory-matching.md §2.

Grounded against two real exports (2026-08-22): a ManageEngine Endpoint
Central "Software Summary" report and a Lansweeper "web50" Windows-software
report — see docs/inventory-matching.md's "As built" note for what each
corrected. Profiles are starting points regardless: every deployment's
export columns differ, so the mapping they produce is always shown to the
analyst for confirmation/editing before anything is written, and the
edited mapping is then persisted onto the source for next time.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.models.enums import InventorySourceKind


@dataclass(frozen=True, slots=True)
class ColumnProfile:
    """Alias lists per canonical field, most-preferred header first."""

    product: tuple[str, ...]
    version: tuple[str, ...]
    vendor: tuple[str, ...] = ()
    device_count: tuple[str, ...] = ()
    #: A row is an operating system, not application software, when this
    #: column is non-blank (Azure) or equals `os_indicator_value` exactly
    #: (Endpoint Central's `Software Type` column, e.g. "Operating System").
    os_indicator: tuple[str, ...] = ()
    os_indicator_value: str | None = None
    #: Separate OS name/version columns (Azure). Left empty when the OS row
    #: instead reuses the regular `product`/`version` columns (Endpoint
    #: Central) — see `csv_parser.parse_rows()`.
    os_name: tuple[str, ...] = ()
    os_version: tuple[str, ...] = ()


CSV_PROFILES: dict[InventorySourceKind, ColumnProfile] = {
    # ManageEngine Endpoint Central / Desktop Central "Software Summary"
    # export. `Software Type` is one of "Desktop Apps", "Microsoft Store
    # Apps", or "Operating System" — the last one is the OS-row signal, and
    # unlike Azure's export it reuses Software Name/Version rather than
    # separate columns.
    InventorySourceKind.CSV_DESKTOP_CENTRAL: ColumnProfile(
        product=("Software Name",),
        version=("Version", "Software Version"),
        vendor=("Manufacturer", "Vendor"),
        device_count=(
            "Network Installations",
            "Managed Installations",
            "Computer Count",
            "Installations",
        ),
        os_indicator=("Software Type",),
        os_indicator_value="Operating System",
    ),
    # Lansweeper's report-builder lets admins name/reorder columns per
    # report, so this lists both the commonly documented convention
    # (`SoftwareName`/`SoftwareVersion`/`Count`) and the plain-English
    # headers a real "web50" Windows-software report actually used
    # (`Software`/`Version`/`Total`) — most-preferred (real, confirmed) first.
    InventorySourceKind.CSV_LANSWEEPER: ColumnProfile(
        product=("Software", "SoftwareName"),
        version=("Version", "SoftwareVersion"),
        vendor=("Publisher",),
        device_count=("Total", "Count", "# of Assets"),
    ),
    InventorySourceKind.CSV_AZURE: ColumnProfile(
        product=("displayName", "Name"),
        version=("version",),
        device_count=("count",),
        os_indicator=("osType", "osName"),
        os_name=("osName",),
        os_version=("osVersion",),
    ),
}


def profile_for(kind: InventorySourceKind) -> ColumnProfile:
    profile = CSV_PROFILES.get(kind)
    if profile is None:
        raise ValueError(f"{kind.value} is not a CSV source kind")
    return profile
