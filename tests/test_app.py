"""Application wiring: config guards, health, security headers, auth redirects."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from advisory_hub.config import INSECURE_SECRET_KEYS, Settings


class TestConfig:
    def test_the_built_in_default_is_treated_as_insecure(self, monkeypatch) -> None:
        """Guards against someone 'fixing' the default to something plausible."""
        monkeypatch.delenv("SECRET_KEY", raising=False)
        assert Settings(_env_file=None).secret_key in INSECURE_SECRET_KEYS

    def test_env_example_placeholder_is_recognised(self) -> None:
        assert "CHANGE_ME_dev_only_do_not_use_in_production" in INSECURE_SECRET_KEYS

    def test_production_refuses_to_start_with_a_placeholder(self, monkeypatch, tmp_path) -> None:
        """The startup guard is the only thing standing between a fresh deploy
        and forgeable session cookies."""
        import asyncio

        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("SECRET_KEY", "CHANGE_ME")
        for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
            monkeypatch.setenv(var, str(tmp_path / var.lower()))

        import advisory_hub.main as main_module
        from advisory_hub.config import get_settings

        get_settings.cache_clear()

        async def _run() -> None:
            async with main_module.lifespan(main_module.create_app()):
                pass

        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            asyncio.run(_run())

        get_settings.cache_clear()

    def test_allowlist_parsing(self) -> None:
        s = Settings(outbound_allowlist=" NVD.nist.gov , example.com ,, ")
        assert s.allowlisted_hosts == ("nvd.nist.gov", "example.com")

    def test_empty_allowlist_denies_everything(self) -> None:
        assert Settings(outbound_allowlist="").allowlisted_hosts == ()


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")

    from advisory_hub.config import get_settings

    get_settings.cache_clear()

    from advisory_hub.main import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


class TestHealth:
    def test_liveness_needs_no_dependencies(self, client: TestClient) -> None:
        assert client.get("/health/live").status_code == 204

    def test_health_reports_each_check_separately(self, client: TestClient) -> None:
        body = client.get("/health").json()
        assert set(body["checks"]) == {"database", "redis", "blob_volume", "inbox"}
        assert body["status"] in {"ok", "degraded"}

    def test_degraded_health_returns_503(self, client: TestClient) -> None:
        """Monitoring must see a non-2xx, not a cheerful 200 with a flag."""
        response = client.get("/health")
        body = response.json()
        if not all(body["checks"].values()):
            assert response.status_code == 503


class TestSecurityHeaders:
    def test_headers_present(self, client: TestClient) -> None:
        headers = client.get("/health/live").headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "same-origin"

    def test_request_id_echoed(self, client: TestClient) -> None:
        r = client.get("/health/live", headers={"x-request-id": "abc123"})
        assert r.headers["x-request-id"] == "abc123"

    def test_request_id_generated_when_absent(self, client: TestClient) -> None:
        assert client.get("/health/live").headers.get("x-request-id")


class TestRequestLogging:
    """Regression: `add_logger_name` + PrintLoggerFactory raised AttributeError
    on every request that actually got logged. Health paths are excluded from
    request logging, so only a non-health route exercises this."""

    @pytest.mark.parametrize("fmt", ["json", "console"])
    def test_non_health_requests_log_without_raising(self, client: TestClient, fmt: str) -> None:
        from advisory_hub.logging import configure_logging

        configure_logging("INFO", fmt)
        assert client.get("/login").status_code == 200


class TestAuthGating:
    def test_root_redirects_anonymous_to_login(self, client: TestClient) -> None:
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_login_page_renders(self, client: TestClient) -> None:
        r = client.get("/login")
        assert r.status_code == 200
        assert "Sign in" in r.text

    def test_openapi_documents_the_api(self, client: TestClient) -> None:
        schema = client.get("/api/openapi.json").json()
        assert schema["info"]["title"] == "Advisory Hub"
        assert "/health" in schema["paths"]
