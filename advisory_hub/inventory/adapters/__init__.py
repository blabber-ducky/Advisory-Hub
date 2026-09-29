"""API-source adapters — Phase 2c.

Each adapter implements `ApiAdapter`: a `test_connection()` read-only check
and a `fetch()` that returns devices (with per-device software, where the
API offers it) in a common shape. `core.services.inventory.sync_source()`
is the only caller — adapters have no knowledge of the database.
"""

from __future__ import annotations

from .base import ApiAdapter, DeviceRecord, DeviceSoftwareRecord, FetchResult
from .registry import adapter_for

__all__ = [
    "ApiAdapter",
    "DeviceRecord",
    "DeviceSoftwareRecord",
    "FetchResult",
    "adapter_for",
]
