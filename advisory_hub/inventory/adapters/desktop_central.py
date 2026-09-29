"""ManageEngine Desktop Central / Endpoint Central adapter.

**Confidence caveat, stated up front**: unlike the Azure ARM and MS Graph
adapters — stable, versioned, publicly-documented Microsoft APIs this
author has strong knowledge of — Desktop Central's REST API shape varies
more across on-prem versions and the newer Endpoint Central Cloud product,
and this adapter has **not been verified against a live instance**. The
endpoint paths and field names below (`/api/1.4/inventory/computers`,
`/api/1.4/inventory/installedSoftware`, `authtoken` query auth) follow
ManageEngine's commonly documented REST API conventions, but a real
deployment may use different paths/fields. Treat this adapter as a
reviewed-but-unverified starting point — see docs/inventory-matching.md's
"As built" note — and expect to adjust it against the customer's actual
API responses before relying on it.

Auth: `API_KEY` credential, sent as the `authtoken` query parameter (the
documented Desktop Central convention — this is *not* a bearer token).

Required `config`: `base_url`. Required `credential`: `api_key`.
"""

from __future__ import annotations

import httpx

from ..api_client import ApiAdapterError, build_client, get_json
from .base import DeviceRecord, DeviceSoftwareRecord, FetchResult

MAX_COMPUTER_PAGES = 20
MAX_DEVICES_FOR_SOFTWARE = 500


def test_connection(*, config: dict[str, object], credential: dict[str, str]) -> tuple[bool, str]:
    try:
        devices, _truncated = _fetch_computers(config, credential, max_pages=1)
    except (ApiAdapterError, KeyError) as exc:
        return False, str(exc)
    return True, f"Connected — {len(devices)} computer(s) found on the first page."


def fetch(*, config: dict[str, object], credential: dict[str, str]) -> FetchResult:
    devices, devices_truncated = _fetch_computers(config, credential, max_pages=MAX_COMPUTER_PAGES)

    software_truncated = len(devices) > MAX_DEVICES_FOR_SOFTWARE
    devices_for_software = devices[:MAX_DEVICES_FOR_SOFTWARE]

    base_url = str(config.get("base_url", "")).rstrip("/")
    api_key = credential.get("api_key", "")

    with build_client() as client:
        for device in devices_for_software:
            device.software = _fetch_installed_software(
                client, base_url, api_key, device.device_identifier
            )

    truncated = devices_truncated or software_truncated
    reasons = []
    if devices_truncated:
        reasons.append(f"stopped after {MAX_COMPUTER_PAGES} pages")
    if software_truncated:
        reasons.append(f"only fetched software for the first {MAX_DEVICES_FOR_SOFTWARE} devices")

    return FetchResult(
        devices=devices, truncated=truncated, truncated_reason="; ".join(reasons) or None
    )


def _fetch_computers(
    config: dict[str, object], credential: dict[str, str], *, max_pages: int
) -> tuple[list[DeviceRecord], bool]:
    base_url = str(config.get("base_url", "")).rstrip("/")
    api_key = credential.get("api_key", "")
    if not base_url or not api_key:
        raise ApiAdapterError("base_url (config) and api_key (credential) are both required")

    devices: list[DeviceRecord] = []
    truncated = False

    with build_client() as client:
        for page in range(1, max_pages + 1):
            body = get_json(
                client,
                f"{base_url}/api/1.4/inventory/computers",
                params={"authtoken": api_key, "page": page, "pagelimit": 200},
            )
            rows = body.get("message_response", {}).get("computers", [])
            if not rows:
                break
            for row in rows:
                devices.append(
                    DeviceRecord(
                        device_identifier=str(row.get("resourceid", "")),
                        hostname=row.get("computer_name"),
                        os_name=row.get("os_platform"),
                        os_version=row.get("os_version"),
                        attributes={"domain": row.get("domain_name")},
                    )
                )
            if len(rows) < 200:
                break
            if page == max_pages:
                truncated = True

    return devices, truncated


def _fetch_installed_software(
    client: httpx.Client, base_url: str, api_key: str, resource_id: str
) -> list[DeviceSoftwareRecord]:
    if not resource_id:
        return []
    try:
        body = get_json(
            client,
            f"{base_url}/api/1.4/inventory/installedSoftware",
            params={"authtoken": api_key, "resid": resource_id},
        )
    except ApiAdapterError:
        # One device's software listing failing shouldn't abort the sync —
        # it still gets an inventory_device row, just with no software.
        return []
    rows = body.get("message_response", {}).get("software", [])
    return [
        DeviceSoftwareRecord(
            vendor=row.get("vendor"),
            product=row.get("software_name", ""),
            version=row.get("version"),
        )
        for row in rows
        if row.get("software_name")
    ]
