"""`core.services.system_integrations` — admin-panel-configured global
integrations (NVD, VirusTotal) and the resolution precedence.

Requires TEST_DATABASE_URL.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from advisory_hub.core.models.enums import ActorKind, SystemIntegrationKind
from advisory_hub.core.services import system_integrations as svc
from advisory_hub.core.services.audit import Actor

pytestmark = pytest.mark.integration

ACTOR = Actor(kind=ActorKind.SYSTEM, label="test")


@pytest.fixture(autouse=True)
def _fernet_key(monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clear_env_defaults(monkeypatch):
    """Every test starts from a clean env-var slate — no NVD_API_KEY/
    VT_API_KEY from the surrounding shell leaking into "no DB row" cases."""
    from advisory_hub.config import get_settings

    monkeypatch.setenv("NVD_ENABLED", "true")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setenv("VT_ENABLED", "true")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestResolveCredentialNoDbRow:
    def test_no_row_and_no_env_key_resolves_to_none(self, db) -> None:
        resolved = svc.resolve_credential(db, SystemIntegrationKind.NVD)
        assert resolved.api_key is None
        assert resolved.source == "none"
        assert resolved.enabled is True  # NVD_ENABLED default

    def test_no_row_falls_back_to_env_key(self, db, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("VT_API_KEY", "env-configured-key")
        get_settings.cache_clear()
        resolved = svc.resolve_credential(db, SystemIntegrationKind.VIRUSTOTAL)
        assert resolved.api_key == "env-configured-key"
        assert resolved.source == "environment"

    def test_no_row_respects_env_disabled(self, db, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("NVD_ENABLED", "false")
        get_settings.cache_clear()
        resolved = svc.resolve_credential(db, SystemIntegrationKind.NVD)
        assert resolved.enabled is False


class TestSetApiKey:
    def test_stores_an_encrypted_key_and_enables(self, db) -> None:
        svc.set_api_key(db, SystemIntegrationKind.NVD, api_key="real-nvd-key", actor=ACTOR)
        resolved = svc.resolve_credential(db, SystemIntegrationKind.NVD)
        assert resolved.api_key == "real-nvd-key"
        assert resolved.source == "admin_panel"
        assert resolved.enabled is True

    def test_admin_panel_key_takes_priority_over_env_key(self, db, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("VT_API_KEY", "env-key")
        get_settings.cache_clear()
        svc.set_api_key(db, SystemIntegrationKind.VIRUSTOTAL, api_key="panel-key", actor=ACTOR)
        resolved = svc.resolve_credential(db, SystemIntegrationKind.VIRUSTOTAL)
        assert resolved.api_key == "panel-key"
        assert resolved.source == "admin_panel"

    def test_rotating_replaces_the_previous_key(self, db) -> None:
        svc.set_api_key(db, SystemIntegrationKind.NVD, api_key="first-key", actor=ACTOR)
        svc.set_api_key(db, SystemIntegrationKind.NVD, api_key="second-key", actor=ACTOR)
        resolved = svc.resolve_credential(db, SystemIntegrationKind.NVD)
        assert resolved.api_key == "second-key"

    def test_blank_key_is_rejected(self, db) -> None:
        with pytest.raises(ValueError):
            svc.set_api_key(db, SystemIntegrationKind.NVD, api_key="   ", actor=ACTOR)


class TestSetEnabled:
    def test_disabling_overrides_a_configured_env_key(self, db, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("NVD_API_KEY", "env-key")
        get_settings.cache_clear()
        svc.set_enabled(db, SystemIntegrationKind.NVD, enabled=False, actor=ACTOR)
        resolved = svc.resolve_credential(db, SystemIntegrationKind.NVD)
        assert resolved.enabled is False
        assert resolved.api_key is None

    def test_disabling_overrides_an_admin_panel_key_too(self, db) -> None:
        svc.set_api_key(db, SystemIntegrationKind.VIRUSTOTAL, api_key="a-key", actor=ACTOR)
        svc.set_enabled(db, SystemIntegrationKind.VIRUSTOTAL, enabled=False, actor=ACTOR)
        resolved = svc.resolve_credential(db, SystemIntegrationKind.VIRUSTOTAL)
        assert resolved.enabled is False

    def test_re_enabling_without_a_key_falls_back_to_env(self, db, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("NVD_API_KEY", "env-fallback-key")
        get_settings.cache_clear()
        svc.set_enabled(db, SystemIntegrationKind.NVD, enabled=False, actor=ACTOR)
        svc.set_enabled(db, SystemIntegrationKind.NVD, enabled=True, actor=ACTOR)
        resolved = svc.resolve_credential(db, SystemIntegrationKind.NVD)
        assert resolved.enabled is True
        assert resolved.api_key == "env-fallback-key"
        assert resolved.source == "environment"


class TestListIntegrations:
    def test_returns_every_kind_even_with_no_rows(self, db) -> None:
        rows = svc.list_integrations(db)
        assert set(rows.keys()) == set(SystemIntegrationKind)
        assert all(v is None for v in rows.values())

    def test_configured_kind_returns_its_row(self, db) -> None:
        svc.set_api_key(db, SystemIntegrationKind.NVD, api_key="k", actor=ACTOR)
        rows = svc.list_integrations(db)
        assert rows[SystemIntegrationKind.NVD] is not None
        assert rows[SystemIntegrationKind.VIRUSTOTAL] is None
