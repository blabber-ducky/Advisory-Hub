"""Password and token hashing (Argon2id)."""

from __future__ import annotations

import contextlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# OWASP-recommended Argon2id baseline: 19 MiB, 2 iterations, 1 degree of
# parallelism. Tune upward, never downward.
_hasher = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1, hash_len=32, salt_len=16)

#: Verified against this when a user doesn't exist, so that a missing account
#: and a wrong password take the same amount of time.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalisation")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verify a password. Constant-ish time whether or not the hash exists."""
    if not password_hash:
        # Burn the same work so absent accounts aren't detectable by timing.
        with contextlib.suppress(VerifyMismatchError, InvalidHashError):
            _hasher.verify(_DUMMY_HASH, password)
        return False
    try:
        _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    return True


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
