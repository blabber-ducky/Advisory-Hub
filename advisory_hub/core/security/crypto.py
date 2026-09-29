"""Fernet encryption for inventory-integration credentials at rest.

Credentials are write-only from every caller's perspective — no service
returns plaintext or ciphertext to an API/web response, ever (CLAUDE.md
§2.3). This module is the only place that touches either.

Key rotation: `FERNET_KEY` is the active key, used for all new encryption.
`FERNET_KEY_PREVIOUS` (optional) keeps decrypting rows written under the
prior key until `rotate_credential()` has re-encrypted them all. Losing
`FERNET_KEY` without a backup means every stored credential must be
re-entered — there is no recovery path, by design (a recoverable key would
be a second copy of every secret).
"""

from __future__ import annotations

import json

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from ...config import settings


class CredentialEncryptionError(Exception):
    """FERNET_KEY is missing/invalid, or ciphertext matches no configured key."""


def _fernet() -> MultiFernet:
    keys = [k for k in (settings.fernet_key, settings.fernet_key_previous) if k]
    if not keys:
        raise CredentialEncryptionError(
            "FERNET_KEY is not configured. Generate one: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
    try:
        return MultiFernet([Fernet(key.encode()) for key in keys])
    except ValueError as exc:
        raise CredentialEncryptionError(f"Invalid FERNET_KEY: {exc}") from exc


def encrypt_credential(payload: dict[str, str]) -> bytes:
    """Encrypt a credential payload (e.g. `{"api_key": "..."}`) for storage.
    Always encrypts with the primary (first) key."""
    data = json.dumps(payload, sort_keys=True).encode()
    return _fernet().encrypt(data)


def decrypt_credential(ciphertext: bytes) -> dict[str, str]:
    """Decrypt a stored credential, trying the previous key if the primary
    one doesn't match — that's the whole rotation window."""
    try:
        data = _fernet().decrypt(ciphertext)
    except InvalidToken as exc:
        raise CredentialEncryptionError(
            "Credential ciphertext could not be decrypted with any configured key"
        ) from exc
    result: dict[str, str] = json.loads(data)
    return result


def rotate_credential(ciphertext: bytes) -> bytes:
    """Re-encrypt under the current primary key. Used to migrate rows off a
    retiring key before it's removed from `FERNET_KEY_PREVIOUS`."""
    return encrypt_credential(decrypt_credential(ciphertext))
