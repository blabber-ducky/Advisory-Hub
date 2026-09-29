"""Source registry and sender resolution."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models.advisory import Source

#: Advisories from an unrecognised sender are still ingested — under this
#: source, and flagged. An unknown sender is a security signal, not merely a
#: data-quality one.
UNKNOWN_SOURCE_CODE = "UNKNOWN"


def resolve_source(db: DbSession, sender_email: str | None) -> tuple[Source, bool]:
    """Map a sender onto a source. Returns ``(source, matched)``.

    Patterns are matched most specific first, so a full address beats a domain.
    """
    sources = db.scalars(select(Source).where(Source.is_active.is_(True))).all()
    address = (sender_email or "").strip().lower()

    if address:
        domain = address.rsplit("@", 1)[-1]
        candidates: list[tuple[int, Source]] = []
        for source in sources:
            for pattern in source.sender_patterns or []:
                p = pattern.strip().lower().lstrip("@")
                if not p:
                    continue
                if p == address:
                    candidates.append((100, source))
                elif p == domain or address.endswith(f"@{p}"):
                    candidates.append((50, source))
                elif domain.endswith(f".{p}"):
                    candidates.append((25, source))
        if candidates:
            candidates.sort(key=lambda c: -c[0])
            return candidates[0][1], True

    return get_or_create_unknown(db), False


def get_or_create_unknown(db: DbSession) -> Source:
    source = db.scalar(select(Source).where(Source.short_code == UNKNOWN_SOURCE_CODE))
    if source is None:
        source = Source(
            name="Unknown sender",
            short_code=UNKNOWN_SOURCE_CODE,
            sender_patterns=[],
            is_active=True,
        )
        db.add(source)
        db.flush()
    return source


def get_source(db: DbSession, source_id: uuid.UUID) -> Source | None:
    return db.get(Source, source_id)


def list_sources(db: DbSession) -> list[Source]:
    """All sources, active or not — for the REST API and admin views. The web
    tracker's filter dropdown uses `advisories.sources_for_filter()` instead,
    which excludes inactive ones."""
    return list(db.scalars(select(Source).order_by(Source.name)).all())


def seed_default_sources(db: DbSession) -> list[Source]:
    """Seed the sources we know about. Idempotent."""
    wanted = [
        {
            "name": "Department of Health — Abu Dhabi SOC",
            "short_code": "DOH",
            "sender_patterns": ["cyber.advisory@doh.gov.ae", "doh.gov.ae"],
        },
    ]
    created: list[Source] = []
    for spec in wanted:
        existing = db.scalar(select(Source).where(Source.short_code == spec["short_code"]))
        if existing is None:
            source = Source(**spec, is_active=True)
            db.add(source)
            created.append(source)
    get_or_create_unknown(db)
    db.flush()
    return created
