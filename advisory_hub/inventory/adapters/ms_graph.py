"""Microsoft Graph adapter — Intune managed devices + detected apps.

Auth: Entra app registration, client-credentials flow, scope
`https://graph.microsoft.com/.default`, requiring the
`DeviceManagementManagedDevices.Read.All` application permission (granted
by a tenant admin — not something this adapter can request itself).

Per-device `detectedApps` is a separate call per device, which doesn't
scale to an unbounded fleet inside one sync — capped at
`MAX_DEVICES_FOR_APPS`; a fleet larger than that is marked `truncated`
rather than silently reporting partial software data as complete.

Required `config`: `base_url` (normally `https://graph.microsoft.com`),
`tenant_id`. Required `credential` (`OAUTH_CLIENT_CREDENTIALS`):
`client_id`, `client_secret`. `login.microsoftonline.com` must also be on
`OUTBOUND_ALLOWLIST` — see docs/inventory-matching.md.
"""

from __future__ import annotations

import httpx

from ..api_client import (
    ApiAdapterError,
    build_client,
    fetch_oauth_client_credentials_token,
    get_json,
)
from .base import DeviceRecord, DeviceSoftwareRecord, FetchResult

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MAX_DEVICE_PAGES = 20
MAX_DEVICES_FOR_APPS = 500


def test_connection(*, config: dict[str, object], credential: dict[str, str]) -> tuple[bool, str]:
    try:
        devices, _truncated = _fetch_devices(config, credential, max_pages=1)
    except (ApiAdapterError, KeyError) as exc:
        return False, str(exc)
    return True, f"Connected — {len(devices)} managed device(s) found on the first page."


def fetch(*, config: dict[str, object], credential: dict[str, str]) -> FetchResult:
    devices, devices_truncated = _fetch_devices(config, credential, max_pages=MAX_DEVICE_PAGES)

    apps_truncated = len(devices) > MAX_DEVICES_FOR_APPS
    devices_for_apps = devices[:MAX_DEVICES_FOR_APPS]

    tenant_id = str(config.get("tenant_id", ""))
    base_url = str(config.get("base_url") or "https://graph.microsoft.com").rstrip("/")
    client_id = credential.get("client_id", "")
    client_secret = credential.get("client_secret", "")

    with build_client() as client:
        token = fetch_oauth_client_credentials_token(
            client,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            scope=GRAPH_SCOPE,
        )
        headers = {"Authorization": f"Bearer {token}"}
        for device in devices_for_apps:
            device.software = _fetch_detected_apps(
                client, base_url, device.device_identifier, headers
            )

    truncated = devices_truncated or apps_truncated
    reasons = []
    if devices_truncated:
        reasons.append(f"stopped after {MAX_DEVICE_PAGES} device pages")
    if apps_truncated:
        reasons.append(f"only fetched software for the first {MAX_DEVICES_FOR_APPS} devices")

    return FetchResult(
        devices=devices, truncated=truncated, truncated_reason="; ".join(reasons) or None
    )


def _fetch_devices(
    config: dict[str, object], credential: dict[str, str], *, max_pages: int
) -> tuple[list[DeviceRecord], bool]:
    tenant_id = str(config.get("tenant_id", ""))
    base_url = str(config.get("base_url") or "https://graph.microsoft.com").rstrip("/")
    client_id = credential.get("client_id", "")
    client_secret = credential.get("client_secret", "")
    if not tenant_id or not client_id or not client_secret:
        raise ApiAdapterError(
            "tenant_id (config) and client_id/client_secret (credential) are all required"
        )

    with build_client() as client:
        token = fetch_oauth_client_credentials_token(
            client,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            scope=GRAPH_SCOPE,
        )
        headers = {"Authorization": f"Bearer {token}"}

        url: str | None = f"{base_url}/v1.0/deviceManagement/managedDevices"
        devices: list[DeviceRecord] = []
        truncated = False

        for page in range(max_pages):
            assert url is not None
            body = get_json(client, url, headers=headers)
            for d in body.get("value", []):
                devices.append(
                    DeviceRecord(
                        device_identifier=d.get("id", ""),
                        hostname=d.get("deviceName"),
                        os_name=d.get("operatingSystem"),
                        os_version=d.get("osVersion"),
                        attributes={
                            "compliance_state": d.get("complianceState"),
                            "user_principal_name": d.get("userPrincipalName"),
                        },
                    )
                )
            next_link = body.get("@odata.nextLink")
            if not next_link:
                break
            if page == max_pages - 1:
                truncated = True
                break
            url = next_link

        return devices, truncated


def _fetch_detected_apps(
    client: httpx.Client, base_url: str, device_id: str, headers: dict[str, str]
) -> list[DeviceSoftwareRecord]:
    if not device_id:
        return []
    url = f"{base_url}/v1.0/deviceManagement/managedDevices/{device_id}/detectedApps"
    try:
        body = get_json(client, url, headers=headers)
    except ApiAdapterError:
        # One device's detected-apps call failing (permissions, transient
        # error) shouldn't abort the whole sync — the device itself still
        # gets an inventory_device row, just with no software.
        return []
    return [
        DeviceSoftwareRecord(
            vendor=app.get("publisher"),
            product=app.get("displayName", ""),
            version=app.get("version"),
        )
        for app in body.get("value", [])
        if app.get("displayName")
    ]
