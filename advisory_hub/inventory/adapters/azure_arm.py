"""Azure Resource Manager adapter — VM inventory, OS type.

Auth: Entra app registration, client-credentials flow, scope
`https://management.azure.com/.default`.

Known limit, stated honestly rather than guessed around: the basic VM list
(`GET .../virtualMachines`) gives `storageProfile.osDisk.osType`
(`Windows`/`Linux`) but not a specific OS *version* — that requires a
per-VM `instanceView` call, which doesn't scale to a full-subscription sync
without either pagination-level throttling or a device cap. Not fetched in
this pass; `os_version` is `None` for every ARM-sourced device. A future
pass can add capped instance-view enrichment.

Required `config`: `base_url` (normally `https://management.azure.com`),
`tenant_id`, `subscription_id`. Required `credential`
(`OAUTH_CLIENT_CREDENTIALS`): `client_id`, `client_secret`. Note that the
Entra token endpoint (`login.microsoftonline.com`) must **also** be on
`OUTBOUND_ALLOWLIST`, not just the ARM host — see docs/inventory-matching.md.
"""

from __future__ import annotations

from ..api_client import (
    ApiAdapterError,
    QueryValue,
    build_client,
    fetch_oauth_client_credentials_token,
    get_json,
)
from .base import DeviceRecord, FetchResult

API_VERSION = "2024-07-01"
GRAPH_SCOPE = "https://management.azure.com/.default"
MAX_PAGES = 20


def test_connection(*, config: dict[str, object], credential: dict[str, str]) -> tuple[bool, str]:
    try:
        result = _fetch(config, credential, max_pages=1)
    except (ApiAdapterError, KeyError) as exc:
        return False, str(exc)
    return True, f"Connected — {len(result.devices)} VM(s) found on the first page."


def fetch(*, config: dict[str, object], credential: dict[str, str]) -> FetchResult:
    return _fetch(config, credential, max_pages=MAX_PAGES)


def _fetch(config: dict[str, object], credential: dict[str, str], *, max_pages: int) -> FetchResult:
    tenant_id = str(config.get("tenant_id", ""))
    subscription_id = str(config.get("subscription_id", ""))
    base_url = str(config.get("base_url") or "https://management.azure.com").rstrip("/")
    client_id = credential.get("client_id", "")
    client_secret = credential.get("client_secret", "")
    if not tenant_id or not subscription_id or not client_id or not client_secret:
        raise ApiAdapterError(
            "tenant_id and subscription_id (config) and client_id/client_secret "
            "(credential) are all required"
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

        url: str | None = (
            f"{base_url}/subscriptions/{subscription_id}/providers/Microsoft.Compute/"
            f"virtualMachines"
        )
        params: dict[str, QueryValue] | None = {"api-version": API_VERSION}
        devices: list[DeviceRecord] = []
        truncated = False

        for page in range(max_pages):
            assert url is not None
            body = get_json(client, url, headers=headers, params=params)
            for vm in body.get("value", []):
                properties = vm.get("properties", {})
                os_type = properties.get("storageProfile", {}).get("osDisk", {}).get("osType")
                devices.append(
                    DeviceRecord(
                        device_identifier=vm.get("id", vm.get("name", "")),
                        hostname=vm.get("name"),
                        os_name=os_type,
                        os_version=None,
                        attributes={"location": vm.get("location")},
                    )
                )
            next_link = body.get("nextLink")
            if not next_link:
                break
            if page == max_pages - 1:
                truncated = True
                break
            url, params = next_link, None

        return FetchResult(
            devices=devices,
            truncated=truncated,
            truncated_reason=(f"stopped after {max_pages} pages" if truncated else None),
        )
