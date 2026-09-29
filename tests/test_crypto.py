"""Fernet credential encryption — key rotation and failure modes."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from advisory_hub.core.security.crypto import (
    CredentialEncryptionError,
    decrypt_credential,
    encrypt_credential,
    rotate_credential,
)


@pytest.fixture(autouse=True)
def _fernet_key(monkeypatch):
    from advisory_hub.config import get_settings

    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("FERNET_KEY_PREVIOUS", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestRoundTrip:
    def test_encrypt_then_decrypt_returns_the_original_payload(self) -> None:
        payload = {"api_key": "s3cr3t", "tenant_id": "abc-123"}
        ciphertext = encrypt_credential(payload)
        assert decrypt_credential(ciphertext) == payload

    def test_ciphertext_never_contains_the_plaintext(self) -> None:
        ciphertext = encrypt_credential({"api_key": "extremely-secret-value"})
        assert b"extremely-secret-value" not in ciphertext

    def test_same_payload_encrypts_differently_each_time(self) -> None:
        """Fernet includes a random IV — ciphertext must not be a fingerprint
        of the plaintext (that would leak equality)."""
        a = encrypt_credential({"api_key": "same"})
        b = encrypt_credential({"api_key": "same"})
        assert a != b


class TestKeyRotation:
    def test_previous_key_still_decrypts_after_rotation(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        old_key = Fernet.generate_key().decode()
        monkeypatch.setenv("FERNET_KEY", old_key)
        monkeypatch.delenv("FERNET_KEY_PREVIOUS", raising=False)
        get_settings.cache_clear()

        ciphertext = encrypt_credential({"api_key": "pre-rotation"})

        new_key = Fernet.generate_key().decode()
        monkeypatch.setenv("FERNET_KEY", new_key)
        monkeypatch.setenv("FERNET_KEY_PREVIOUS", old_key)
        get_settings.cache_clear()

        assert decrypt_credential(ciphertext) == {"api_key": "pre-rotation"}

    def test_rotate_credential_re_encrypts_under_the_current_key(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        old_key = Fernet.generate_key().decode()
        monkeypatch.setenv("FERNET_KEY", old_key)
        monkeypatch.delenv("FERNET_KEY_PREVIOUS", raising=False)
        get_settings.cache_clear()
        old_ciphertext = encrypt_credential({"api_key": "value"})

        new_key = Fernet.generate_key().decode()
        monkeypatch.setenv("FERNET_KEY", new_key)
        monkeypatch.setenv("FERNET_KEY_PREVIOUS", old_key)
        get_settings.cache_clear()

        rotated = rotate_credential(old_ciphertext)

        # Now drop the old key entirely — only the rotated ciphertext should
        # still decrypt.
        monkeypatch.delenv("FERNET_KEY_PREVIOUS", raising=False)
        get_settings.cache_clear()
        assert decrypt_credential(rotated) == {"api_key": "value"}
        with pytest.raises(CredentialEncryptionError):
            decrypt_credential(old_ciphertext)

    def test_ciphertext_from_a_dropped_key_fails_cleanly(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
        get_settings.cache_clear()
        ciphertext = encrypt_credential({"api_key": "value"})

        monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
        monkeypatch.delenv("FERNET_KEY_PREVIOUS", raising=False)
        get_settings.cache_clear()

        with pytest.raises(CredentialEncryptionError):
            decrypt_credential(ciphertext)


class TestMisconfiguration:
    def test_missing_fernet_key_raises_a_clear_error(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.delenv("FERNET_KEY", raising=False)
        monkeypatch.delenv("FERNET_KEY_PREVIOUS", raising=False)
        get_settings.cache_clear()

        with pytest.raises(CredentialEncryptionError, match="not configured"):
            encrypt_credential({"api_key": "x"})

    def test_malformed_fernet_key_raises_a_clear_error(self, monkeypatch) -> None:
        from advisory_hub.config import get_settings

        monkeypatch.setenv("FERNET_KEY", "not-a-valid-fernet-key")
        get_settings.cache_clear()

        with pytest.raises(CredentialEncryptionError, match="Invalid FERNET_KEY"):
            encrypt_credential({"api_key": "x"})
