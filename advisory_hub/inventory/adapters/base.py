"""The adapter protocol and the common shape every adapter returns.

Deliberately vendor-agnostic: `core.services.inventory.sync_source()` maps
`DeviceRecord`/`DeviceSoftwareRecord` onto `inventory_device`/
`inventory_device_software`/`inventory_software` without knowing which
adapter produced them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(slots=True)
class DeviceSoftwareRecord:
    vendor: str | None
    product: str
    version: str | None


@dataclass(slots=True)
class DeviceRecord:
    #: Source-native ID — the thing you hand to ops. Never fabricated.
    device_identifier: str
    hostname: str | None
    os_name: str | None
    os_version: str | None
    attributes: dict[str, object] = field(default_factory=dict)
    software: list[DeviceSoftwareRecord] = field(default_factory=list)


@dataclass(slots=True)
class FetchResult:
    devices: list[DeviceRecord]
    #: True when the fetch is known-incomplete (a pagination/rate cap was
    #: hit) — surfaces as `SyncStatus.PARTIAL`, never silently as `OK`.
    truncated: bool = False
    truncated_reason: str | None = None


class ApiAdapter(Protocol):
    def test_connection(
        self, *, config: dict[str, object], credential: dict[str, str]
    ) -> tuple[bool, str]:
        """A read-only connectivity check. Returns `(ok, message)` — never
        raises for an expected failure (bad credential, unreachable host);
        only for a code-level bug."""
        ...

    def fetch(self, *, config: dict[str, object], credential: dict[str, str]) -> FetchResult:
        """Full inventory pull. Raises `ApiAdapterError` on failure — the
        caller (`sync_source()`) is responsible for leaving the previous
        snapshot as latest when this raises."""
        ...
