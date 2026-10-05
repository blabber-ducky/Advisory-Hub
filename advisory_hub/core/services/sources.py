"""Source registry and source resolution (sender, then reference number)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ..models.advisory import Source
from ..models.enums import SourceMethod

if TYPE_CHECKING:
    from ...ingest.message import ParsedMessage

#: Advisories from an unrecognised sender are still ingested — under this
#: source, and flagged. An unknown sender is a security signal, not merely a
#: data-quality one.
UNKNOWN_SOURCE_CODE = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class SourceResolution:
    source: Source
    method: SourceMethod
    #: Whether the *sender* was recognised. False even when the reference
    #: identified the source — an unrecognised sender is a security signal
    #: (possible spoofing) whatever the subject claims, so it stays flagged.
    sender_matched: bool


def resolve_source(
    db: DbSession, sender_email: str | None, external_ref: str | None = None
) -> SourceResolution:
    """Decide an advisory's source, most trustworthy evidence first:

    1. the sender address against each source's ``sender_patterns`` (a full
       address beats a domain beats a subdomain);
    2. the reference prefix against a source's ``short_code`` — "DOH-2026550"
       → DOH — for a forwarded or re-sent advisory;
    3. otherwise the UNKNOWN source.
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
            return SourceResolution(candidates[0][1], SourceMethod.SENDER, sender_matched=True)

    prefix = reference_prefix(external_ref)
    if prefix:
        for source in sources:
            if source.short_code.upper() == prefix and source.short_code != UNKNOWN_SOURCE_CODE:
                return SourceResolution(source, SourceMethod.REFERENCE, sender_matched=False)

    return SourceResolution(get_or_create_unknown(db), SourceMethod.NONE, sender_matched=False)


def unknown_sender_detail(
    message: ParsedMessage, resolution: SourceResolution
) -> dict[str, object]:
    """The UNKNOWN_SENDER flag's detail — says when the reference filed it anyway."""
    detail: dict[str, object] = {"sender": message.sender or "(none)"}
    if resolution.method is SourceMethod.REFERENCE:
        detail["source_from_reference"] = resolution.source.short_code
    return detail


def reference_prefix(external_ref: str | None) -> str | None:
    """ "DOH-2026550" → "DOH"."""
    if not external_ref or "-" not in external_ref:
        return None
    return external_ref.split("-", 1)[0].strip().upper() or None


def assignable_sources(db: DbSession) -> list[Source]:
    """Sources an analyst can pick for an advisory: active, not UNKNOWN."""
    return list(
        db.scalars(
            select(Source)
            .where(Source.is_active.is_(True), Source.short_code != UNKNOWN_SOURCE_CODE)
            .order_by(Source.name)
        )
    )


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
