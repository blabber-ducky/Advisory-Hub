"""API-source adapters — mocked HTTP, no live tenant required.

These verify request shape and response mapping against the documented
Azure ARM / MS Graph API contracts. The Desktop Central adapter's contract
is unverified against a live instance — see its module docstring — so its
tests only pin down this adapter's *own* parsing logic against the shape it
assumes, not a vendor guarantee.
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from advisory_hub.inventory.adapters import azure_arm, desktop_central, ms_graph
from advisory_hub.inventory.api_client import ApiAdapterError

CONFIG_AZURE = {
    "base_url": "https://management.azure.com",
    "tenant_id": "tenant-1",
    "subscription_id": "sub-1",
}
CRED_OAUTH = {"client_id": "app-1", "client_secret": "secret-1"}

CONFIG_GRAPH = {"base_url": "https://graph.microsoft.com", "tenant_id": "tenant-1"}

CONFIG_DC = {"base_url": "https://dc.example.invalid"}
CRED_API_KEY = {"api_key": "key-1"}


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


@pytest.fixture(autouse=True)
def _allowlist(monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv(
        "OUTBOUND_ALLOWLIST",
        "management.azure.com,graph.microsoft.com,login.microsoftonline.com,dc.example.invalid",
    )
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _resolves_to(*ips: str):
    return patch(
        "advisory_hub.core.security.ssrf.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (ip, 443)) for ip in ips],
    )


class TestAzureArm:
    def test_fetch_maps_vms_to_devices(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/v2.0/token" in str(request.url):
                return httpx.Response(200, json={"access_token": "tok"})
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "/subscriptions/sub-1/.../vm-1",
                            "name": "vm-1",
                            "location": "eastus",
                            "properties": {
                                "storageProfile": {"osDisk": {"osType": "Linux"}},
                            },
                        }
                    ]
                },
            )

        with (
            _resolves_to("1.1.1.1"),
            patch.object(azure_arm, "build_client", lambda: _mock_client(handler)),
        ):
            result = azure_arm.fetch(config=CONFIG_AZURE, credential=CRED_OAUTH)

        assert len(result.devices) == 1
        device = result.devices[0]
        assert device.device_identifier == "/subscriptions/sub-1/.../vm-1"
        assert device.hostname == "vm-1"
        assert device.os_name == "Linux"
        assert device.os_version is None
        assert not result.truncated

    def test_pagination_follows_next_link(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/v2.0/token" in str(request.url):
                return httpx.Response(200, json={"access_token": "tok"})
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(
                    200,
                    json={
                        "value": [{"id": "vm-1", "name": "vm-1", "properties": {}}],
                        "nextLink": "https://management.azure.com/next-page",
                    },
                )
            return httpx.Response(
                200, json={"value": [{"id": "vm-2", "name": "vm-2", "properties": {}}]}
            )

        with (
            _resolves_to("1.1.1.1"),
            patch.object(azure_arm, "build_client", lambda: _mock_client(handler)),
        ):
            result = azure_arm.fetch(config=CONFIG_AZURE, credential=CRED_OAUTH)

        assert len(result.devices) == 2
        assert not result.truncated

    def test_missing_credential_raises(self) -> None:
        with pytest.raises(ApiAdapterError):
            azure_arm.fetch(config=CONFIG_AZURE, credential={})

    def test_token_failure_is_reported_by_test_connection(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "invalid_client"})

        with (
            _resolves_to("1.1.1.1"),
            patch.object(azure_arm, "build_client", lambda: _mock_client(handler)),
        ):
            ok, message = azure_arm.test_connection(config=CONFIG_AZURE, credential=CRED_OAUTH)

        assert ok is False
        assert "failed" in message.lower() or "401" in message


class TestMsGraph:
    def test_fetch_maps_devices_and_apps(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "oauth2/v2.0/token" in url:
                return httpx.Response(200, json={"access_token": "tok"})
            if "detectedApps" in url:
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "displayName": "Google Chrome",
                                "version": "120.0.6099.109",
                                "publisher": "Google LLC",
                            }
                        ]
                    },
                )
            return httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "dev-1",
                            "deviceName": "LAPTOP-1",
                            "operatingSystem": "Windows",
                            "osVersion": "10.0.19045",
                        }
                    ]
                },
            )

        with (
            _resolves_to("1.1.1.1"),
            patch.object(ms_graph, "build_client", lambda: _mock_client(handler)),
        ):
            result = ms_graph.fetch(config=CONFIG_GRAPH, credential=CRED_OAUTH)

        assert len(result.devices) == 1
        device = result.devices[0]
        assert device.hostname == "LAPTOP-1"
        assert device.os_version == "10.0.19045"
        assert len(device.software) == 1
        assert device.software[0].product == "Google Chrome"
        assert not result.truncated

    def test_detected_apps_failure_does_not_abort_the_sync(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "oauth2/v2.0/token" in url:
                return httpx.Response(200, json={"access_token": "tok"})
            if "detectedApps" in url:
                return httpx.Response(500)
            return httpx.Response(200, json={"value": [{"id": "dev-1", "deviceName": "LAPTOP-1"}]})

        with (
            _resolves_to("1.1.1.1"),
            patch.object(ms_graph, "build_client", lambda: _mock_client(handler)),
        ):
            result = ms_graph.fetch(config=CONFIG_GRAPH, credential=CRED_OAUTH)

        assert len(result.devices) == 1
        assert result.devices[0].software == []

    def test_test_connection_reports_device_count(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "oauth2/v2.0/token" in str(request.url):
                return httpx.Response(200, json={"access_token": "tok"})
            return httpx.Response(200, json={"value": [{"id": "1"}, {"id": "2"}]})

        with (
            _resolves_to("1.1.1.1"),
            patch.object(ms_graph, "build_client", lambda: _mock_client(handler)),
        ):
            ok, message = ms_graph.test_connection(config=CONFIG_GRAPH, credential=CRED_OAUTH)

        assert ok is True
        assert "2" in message


class TestDesktopCentral:
    def test_fetch_maps_computers_and_software(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "installedSoftware" in url:
                return httpx.Response(
                    200,
                    json={
                        "message_response": {
                            "software": [
                                {
                                    "software_name": "7-Zip",
                                    "version": "23.01",
                                    "vendor": "Igor Pavlov",
                                }
                            ]
                        }
                    },
                )
            return httpx.Response(
                200,
                json={
                    "message_response": {
                        "computers": [
                            {
                                "resourceid": "42",
                                "computer_name": "WKS-42",
                                "os_platform": "Windows",
                                "os_version": "11",
                                "domain_name": "corp.local",
                            }
                        ]
                    }
                },
            )

        with (
            _resolves_to("1.1.1.1"),
            patch.object(desktop_central, "build_client", lambda: _mock_client(handler)),
        ):
            result = desktop_central.fetch(config=CONFIG_DC, credential=CRED_API_KEY)

        assert len(result.devices) == 1
        device = result.devices[0]
        assert device.device_identifier == "42"
        assert device.hostname == "WKS-42"
        assert len(device.software) == 1
        assert device.software[0].product == "7-Zip"

    def test_missing_config_raises(self) -> None:
        with pytest.raises(ApiAdapterError):
            desktop_central.fetch(config={}, credential={})

    def test_empty_computer_page_stops_pagination(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message_response": {"computers": []}})

        with (
            _resolves_to("1.1.1.1"),
            patch.object(desktop_central, "build_client", lambda: _mock_client(handler)),
        ):
            result = desktop_central.fetch(config=CONFIG_DC, credential=CRED_API_KEY)

        assert result.devices == []
        assert not result.truncated
