"""Append-only audit logging.

Every state change in the system writes one of these. The table has no UPDATE
or DELETE grants — see migration ``0001`` and docs/operations.md.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..models.enums import ActorKind
from ..models.user import AuditLog


@dataclass(frozen=True, slots=True)
class Actor:
    """Who is doing something. Deliberately not a User — API tokens, the MCP
    server, and the ingestion worker are all first-class actors."""

    kind: ActorKind
    user_id: uuid.UUID | None = None
    label: str | None = None
    ip_address: str | None = None

    @classmethod
    def system(cls, label: str = "system") -> Actor:
        return cls(kind=ActorKind.SYSTEM, label=label)


def record(
    session: Session,
    *,
    actor: Actor,
    action: str,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an audit entry. Caller owns the transaction."""
    entry = AuditLog(
        actor_id=actor.user_id,
        actor_kind=actor.kind.value,
        actor_label=actor.label,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail,
        ip_address=actor.ip_address,
    )
    session.add(entry)
    return entry
