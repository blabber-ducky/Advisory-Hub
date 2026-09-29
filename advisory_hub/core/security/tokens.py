"""API token minting and verification.

Format: ``ah_<prefix>_<secret>``. Only the Argon2id hash of the whole token is
stored; the prefix is kept in clear purely so the UI can identify a token.
The secret is displayed exactly once, at creation.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..models.enums import Role
from .passwords import generate_token, hash_password, verify_password

TOKEN_NAMESPACE = "ah"  # noqa: S105 — token prefix namespace, not a credential
PREFIX_LENGTH = 8
#: The prefix must not contain the separator. `secrets.token_urlsafe` emits
#: `-` and `_` from the base64url alphabet, so a urlsafe prefix would break
#: `split_token` roughly 1 time in 8 — minting a token that can never
#: authenticate. Hex has no such overlap.
_PREFIX_ALPHABET = "0123456789abcdef"


class Scope:
    ADVISORIES_READ = "advisories:read"
    ADVISORIES_WRITE = "advisories:write"
    INVENTORY_READ = "inventory:read"
    INVENTORY_WRITE = "inventory:write"
    SCAN_RUN = "scan:run"
    STATS_READ = "stats:read"
    VT_CHECK = "vt:check"

    @classmethod
    def all(cls) -> tuple[str, ...]:
        return (
            cls.ADVISORIES_READ,
            cls.ADVISORIES_WRITE,
            cls.INVENTORY_READ,
            cls.INVENTORY_WRITE,
            cls.SCAN_RUN,
            cls.STATS_READ,
            cls.VT_CHECK,
        )


#: The minimum role a *session* (browser) user needs to be treated as holding
#: a given scope — see docs/architecture.md §6's role table. API tokens carry
#: scopes explicitly and are checked against this list, not roles; a session
#: user's role is translated into scopes here so the same
#: ``Principal.require_scope()`` call works for both caller kinds.
SCOPE_MIN_ROLE: dict[str, Role] = {
    Scope.ADVISORIES_READ: Role.VIEWER,
    Scope.ADVISORIES_WRITE: Role.ANALYST,
    Scope.INVENTORY_READ: Role.VIEWER,
    Scope.INVENTORY_WRITE: Role.ANALYST,
    Scope.SCAN_RUN: Role.ANALYST,
    Scope.STATS_READ: Role.VIEWER,
    Scope.VT_CHECK: Role.ANALYST,
}


@dataclass(frozen=True, slots=True)
class MintedToken:
    """The only moment the plaintext secret exists."""

    plaintext: str
    prefix: str
    token_hash: str


def mint_token() -> MintedToken:
    prefix = secrets.token_hex(PREFIX_LENGTH // 2)
    secret = generate_token(32)
    plaintext = f"{TOKEN_NAMESPACE}_{prefix}_{secret}"
    return MintedToken(plaintext=plaintext, prefix=prefix, token_hash=hash_password(plaintext))


def split_token(plaintext: str) -> tuple[str, str] | None:
    """Return ``(prefix, plaintext)`` if well-formed, else ``None``.

    ``maxsplit=2`` keeps the secret intact even though it may contain `_`;
    the prefix is validated against the hex alphabet so it never can.
    """
    parts = plaintext.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_NAMESPACE or not parts[2]:
        return None
    prefix = parts[1]
    if len(prefix) != PREFIX_LENGTH or not all(c in _PREFIX_ALPHABET for c in prefix):
        return None
    return prefix, plaintext


def verify_token(plaintext: str, token_hash: str) -> bool:
    return verify_password(plaintext, token_hash)


def has_scope(granted: list[str] | tuple[str, ...], required: str) -> bool:
    return required in granted


def validate_scopes(scopes: list[str]) -> list[str]:
    """Reject unknown scopes rather than silently granting nothing."""
    known = set(Scope.all())
    unknown = [s for s in scopes if s not in known]
    if unknown:
        raise ValueError(f"Unknown scope(s): {', '.join(sorted(unknown))}")
    return sorted(set(scopes))
