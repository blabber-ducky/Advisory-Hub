"""VirusTotal API v3 client — mocked HTTP, no live calls."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from advisory_hub.core.models.enums import IocType
from advisory_hub.enrich.nvd import RateLimiter
from advisory_hub.enrich.virustotal import (
    VtClient,
    VtRateLimitedError,
    VtUnauthorizedError,
    VtUnsupportedIocTypeError,
    is_supported,
)

MALICIOUS_DOMAIN_PAYLOAD = {
    "data": {
        "id": "evil.example.invalid",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 2,
                "harmless": 60,
                "undetected": 8,
                "timeout": 0,
            },
            "reputation": -45,
            "last_analysis_date": 1_700_000_000,
        },
    }
}


def _transport(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok_handler(payload: dict[str, Any]):
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    return handle


def _fast_client(handler: Any, *, api_key: str | None = "test-key") -> VtClient:
    return VtClient(
        api_key=api_key,
        client=_transport(handler),
        rate_limiter=RateLimiter(max_calls=10_000, window_seconds=0.001),
    )


class TestIsSupported:
    @pytest.mark.parametrize(
        "ioc_type",
        [
            IocType.IPV4,
            IocType.IPV6,
            IocType.DOMAIN,
            IocType.URL,
            IocType.MD5,
            IocType.SHA1,
            IocType.SHA256,
        ],
    )
    def test_lookup_capable_types(self, ioc_type: IocType) -> None:
        assert is_supported(ioc_type) is True

    @pytest.mark.parametrize(
        "ioc_type",
        [
            IocType.EMAIL,
            IocType.FILENAME,
            IocType.FILEPATH,
            IocType.REGISTRY_KEY,
            IocType.MUTEX,
            IocType.USER_AGENT,
            IocType.OTHER,
        ],
    )
    def test_unsupported_types(self, ioc_type: IocType) -> None:
        assert is_supported(ioc_type) is False


class TestVtClient:
    def test_lookup_returns_a_result(self) -> None:
        with _fast_client(_ok_handler(MALICIOUS_DOMAIN_PAYLOAD)) as client:
            result = client.lookup(IocType.DOMAIN, "evil.example.invalid")
        assert result is not None
        assert result.malicious_count == 12
        assert result.suspicious_count == 2
        assert result.harmless_count == 60
        assert result.undetected_count == 8
        assert result.reputation == -45
        assert result.last_analysis_at is not None
        assert "virustotal.com/gui/domain/" in result.permalink

    def test_404_is_not_found_not_an_error(self) -> None:
        with _fast_client(lambda r: httpx.Response(404)) as client:
            assert client.lookup(IocType.DOMAIN, "unknown.example.invalid") is None

    def test_401_raises_unauthorized(self) -> None:
        with (
            _fast_client(lambda r: httpx.Response(401)) as client,
            pytest.raises(VtUnauthorizedError),
        ):
            client.lookup(IocType.DOMAIN, "x.example.invalid")

    def test_no_api_key_raises_unauthorized_before_any_request(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json=MALICIOUS_DOMAIN_PAYLOAD)

        with _fast_client(handler, api_key=None) as client, pytest.raises(VtUnauthorizedError):
            client.lookup(IocType.DOMAIN, "x.example.invalid")
        assert calls["n"] == 0

    def test_429_raises_rate_limited(self) -> None:
        with (
            _fast_client(lambda r: httpx.Response(429)) as client,
            pytest.raises(VtRateLimitedError),
        ):
            client.lookup(IocType.DOMAIN, "x.example.invalid")

    def test_unsupported_ioc_type_raises_before_any_request(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json={})

        with _fast_client(handler) as client, pytest.raises(VtUnsupportedIocTypeError):
            client.lookup(IocType.EMAIL, "attacker@example.invalid")
        assert calls["n"] == 0

    def test_api_key_sent_as_x_apikey_header(self) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(request.headers)
            return httpx.Response(200, json=MALICIOUS_DOMAIN_PAYLOAD)

        with _fast_client(handler, api_key="secret-key-value") as client:
            client.lookup(IocType.DOMAIN, "x.example.invalid")
        assert seen.get("x-apikey") == "secret-key-value"

    def test_hash_lookup_uses_the_hash_directly_as_the_object_id(self) -> None:
        seen_path = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen_path["path"] = request.url.path
            return httpx.Response(200, json=MALICIOUS_DOMAIN_PAYLOAD)

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        with _fast_client(handler) as client:
            client.lookup(IocType.SHA256, sha256)
        assert seen_path["path"] == f"/api/v3/files/{sha256}"

    def test_url_lookup_uses_sha256_of_the_url_as_the_object_id(self) -> None:
        import hashlib

        seen_path = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen_path["path"] = request.url.path
            return httpx.Response(200, json=MALICIOUS_DOMAIN_PAYLOAD)

        url = "http://evil.example.invalid/payload.exe"
        with _fast_client(handler) as client:
            client.lookup(IocType.URL, url)
        expected_id = hashlib.sha256(url.encode()).hexdigest()
        assert seen_path["path"] == f"/api/v3/urls/{expected_id}"

    def test_never_hit_never_analysed_returns_zero_counts_not_none(self) -> None:
        payload = {
            "data": {
                "id": "clean.example.invalid",
                "attributes": {"last_analysis_stats": {}, "reputation": 0},
            }
        }
        with _fast_client(_ok_handler(payload)) as client:
            result = client.lookup(IocType.DOMAIN, "clean.example.invalid")
        assert result is not None
        assert result.malicious_count == 0
        assert result.last_analysis_at is None
