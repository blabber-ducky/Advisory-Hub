"""Source registry and source resolution (sender, then reference number)."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ..models.advisory import Source
from ..models.enums import Role, SourceMethod
from .audit import record
from .auth import Principal

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


# ─── Admin: managing sources ─────────────────────────────────────────────────


class SourceAdminError(ValueError):
    """A request that breaks a rule; the message is safe to show the admin."""


_CODE = re.compile(r"^[A-Z][A-Z0-9]{1,9}$")
_PATTERN = re.compile(r"^(?:[^@\s]+@)?[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
#: Reference detection ("DOH-2026550") matches prefixes of 2 to 6 letters.
REFERENCE_CODE = re.compile(r"^[A-Z]{2,6}$")


def _clean(
    db: DbSession, name: str, short_code: str, patterns: str, *, exclude: uuid.UUID | None = None
) -> tuple[str, str, list[str]]:
    name = " ".join(name.split())
    code = short_code.strip().upper()
    if not name or len(name) > 200:
        raise SourceAdminError("Enter a name (up to 200 characters).")
    if not _CODE.match(code):
        raise SourceAdminError(
            "Short code: 2 to 10 capital letters or digits, starting with a letter "
            "(e.g. DOH, NCEMA)."
        )
    if code == UNKNOWN_SOURCE_CODE:
        raise SourceAdminError(f"{UNKNOWN_SOURCE_CODE} is reserved.")
    cleaned: list[str] = []
    for line in patterns.replace(",", "\n").splitlines():
        p = line.strip().lower().lstrip("@")
        if not p:
            continue
        if not _PATTERN.match(p):
            raise SourceAdminError(
                f"Sender {line.strip()!r} isn't an email address or a domain (e.g. doh.gov.ae)."
            )
        if p not in cleaned:
            cleaned.append(p)
    for column, value, label in (
        (Source.name, name, "name"),
        (Source.short_code, code, "short code"),
    ):
        clash = db.scalar(select(Source).where(func.lower(column) == value.lower()))
        if clash is not None and clash.id != exclude:
            raise SourceAdminError(f"Another source already has that {label}.")
    return name, code, cleaned


def create_source(
    db: DbSession, principal: Principal, *, name: str, short_code: str, sender_patterns: str
) -> Source:
    principal.require_role(Role.ADMIN)
    name, code, patterns = _clean(db, name, short_code, sender_patterns)
    source = Source(name=name, short_code=code, sender_patterns=patterns, is_active=True)
    db.add(source)
    db.flush()
    record(
        db,
        actor=principal.to_actor(),
        action="source.created",
        entity_type="source",
        entity_id=source.id,
        detail={"name": name, "short_code": code, "sender_patterns": patterns},
    )
    return source


def update_source(
    db: DbSession,
    principal: Principal,
    source_id: uuid.UUID,
    *,
    name: str,
    short_code: str,
    sender_patterns: str,
) -> Source:
    """Rename or re-pattern a source. Advisories already filed under it stay
    there; the new patterns apply to mail from now on (and to a re-parse)."""
    principal.require_role(Role.ADMIN)
    source = _editable(db, source_id)
    name, code, patterns = _clean(db, name, short_code, sender_patterns, exclude=source.id)
    before = {
        "name": source.name,
        "short_code": source.short_code,
        "sender_patterns": list(source.sender_patterns or []),
    }
    source.name, source.short_code, source.sender_patterns = name, code, patterns
    after = {"name": name, "short_code": code, "sender_patterns": patterns}
    record(
        db,
        actor=principal.to_actor(),
        action="source.updated",
        entity_type="source",
        entity_id=source.id,
        detail={k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]},
    )
    return source


def set_source_active(
    db: DbSession, principal: Principal, source_id: uuid.UUID, active: bool
) -> Source:
    """Deactivate instead of delete: advisories keep pointing at it, but it's
    no longer matched, offered in pickers, or shown in the tracker filter."""
    principal.require_role(Role.ADMIN)
    source = _editable(db, source_id)
    if source.is_active is not active:
        source.is_active = active
        record(
            db,
            actor=principal.to_actor(),
            action="source.activated" if active else "source.deactivated",
            entity_type="source",
            entity_id=source.id,
            detail={"short_code": source.short_code},
        )
    return source


def sources_with_counts(db: DbSession) -> list[tuple[Source, int]]:
    """Every source but UNKNOWN, with how many advisories it holds."""
    from ..models.advisory import Advisory

    query = select(Advisory.source_id, func.count()).group_by(Advisory.source_id)
    counts: dict[uuid.UUID, int] = dict(db.execute(query).tuples().all())
    rows = db.scalars(
        select(Source)
        .where(Source.short_code != UNKNOWN_SOURCE_CODE)
        .order_by(Source.is_active.desc(), Source.name)
    )
    return [(s, counts.get(s.id, 0)) for s in rows]


def _editable(db: DbSession, source_id: uuid.UUID) -> Source:
    source = db.get(Source, source_id)
    if source is None:
        raise LookupError(source_id)
    if source.short_code == UNKNOWN_SOURCE_CODE:
        raise SourceAdminError("The Unknown sender source is built in and can't be changed.")
    return source
