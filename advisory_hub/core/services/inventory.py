"""Inventory source CRUD, connectivity checks, and snapshot ingest — both
CSV upload (Phase 2b) and live API sync (Phase 2c).

Credential payloads (API keys, client secrets) are Fernet-encrypted
immediately on write and never stored, logged, or returned in plaintext —
see `core.security.crypto` and CLAUDE.md §2.3. `sync_source()` decrypts a
credential only for the duration of one adapter call; it never returns to
a caller.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ...inventory import csv_parser
from ...inventory.adapters import adapter_for
from ...inventory.api_client import ApiAdapterError
from ...inventory.csv_profiles import profile_for
from ...inventory.normalise import normalise_product, normalise_vendor
from ...inventory.version import normalise_version
from ..models.advisory import Blob
from ..models.base import utcnow
from ..models.enums import (
    CredentialAuthType,
    InventoryItemKind,
    InventoryMode,
    InventorySourceKind,
    SyncStatus,
)
from ..models.inventory import (
    IntegrationCredential,
    InventoryDevice,
    InventoryDeviceSoftware,
    InventorySnapshot,
    InventorySoftware,
    InventorySource,
)
from ..models.user import AuditLog
from ..security.crypto import CredentialEncryptionError, decrypt_credential, encrypt_credential
from ..security.ssrf import SsrfBlockedError, validate_outbound_url
from ..storage.blobs import FilesystemBlobStore
from .audit import Actor, record
from .vendor_alias import load_vendor_alias_map

#: API-kind sources need a `base_url` validated against the SSRF allowlist at
#: config-save time. CSV-kind sources have no live endpoint at all.
API_KINDS = frozenset(
    {
        InventorySourceKind.API_DESKTOP_CENTRAL,
        InventorySourceKind.API_AZURE_ARM,
        InventorySourceKind.API_MS_GRAPH,
    }
)

CSV_KINDS = frozenset(
    {
        InventorySourceKind.CSV_DESKTOP_CENTRAL,
        InventorySourceKind.CSV_LANSWEEPER,
        InventorySourceKind.CSV_AZURE,
    }
)


class SourceNotFoundError(Exception):
    def __init__(self, source_id: uuid.UUID) -> None:
        super().__init__(f"Inventory source {source_id} not found")
        self.source_id = source_id


class DuplicateSourceNameError(Exception):
    def __init__(self, name: str) -> None:
        super().__init__(f"An inventory source named {name!r} already exists")
        self.name = name


class InvalidSourceConfigError(Exception):
    """Config failed kind-specific validation — e.g. a missing `base_url` for
    an API source, or one that fails the SSRF guard."""


class _Unset:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<unset>"


UNSET = _Unset()


def _validate_config(kind: InventorySourceKind, config: dict[str, object]) -> None:
    if kind not in API_KINDS:
        return
    base_url = config.get("base_url")
    if not base_url or not isinstance(base_url, str):
        raise InvalidSourceConfigError("base_url is required for API sources")
    try:
        validate_outbound_url(base_url)
    except SsrfBlockedError as exc:
        raise InvalidSourceConfigError(str(exc)) from exc


def create_source(
    db: DbSession,
    *,
    name: str,
    kind: InventorySourceKind,
    config: dict[str, object] | None = None,
    credential: dict[str, str] | None = None,
    credential_auth_type: CredentialAuthType | None = None,
    schedule_cron: str | None = None,
    actor: Actor,
) -> InventorySource:
    name = name.strip()
    if not name:
        raise InvalidSourceConfigError("name is required")
    if db.scalar(select(InventorySource).where(InventorySource.name == name)):
        raise DuplicateSourceNameError(name)

    config = config or {}
    _validate_config(kind, config)

    credential_row = None
    if credential:
        if credential_auth_type is None:
            raise InvalidSourceConfigError(
                "credential_auth_type is required when a credential is provided"
            )
        credential_row = IntegrationCredential(
            auth_type=credential_auth_type, ciphertext=encrypt_credential(credential)
        )
        db.add(credential_row)
        db.flush()

    source = InventorySource(
        name=name,
        kind=kind,
        mode=kind.mode,
        config=config,
        credential_id=credential_row.id if credential_row else None,
        schedule_cron=schedule_cron,
        is_active=True,
    )
    db.add(source)
    db.flush()
    record(
        db,
        actor=actor,
        action="inventory_source.created",
        entity_type="inventory_source",
        entity_id=source.id,
        detail={"name": name, "kind": kind.value},
    )
    db.flush()
    return source


def update_source(
    db: DbSession,
    source_id: uuid.UUID,
    *,
    config: dict[str, object] | _Unset = UNSET,
    credential: dict[str, str] | _Unset | None = UNSET,
    credential_auth_type: CredentialAuthType | _Unset = UNSET,
    schedule_cron: str | _Unset | None = UNSET,
    is_active: bool | _Unset = UNSET,
    actor: Actor,
) -> InventorySource:
    """PATCH semantics: only fields the caller actually passed are touched.
    `name` and `kind` are immutable after creation — changing either is
    close enough to "a different source" that it should be a new row."""
    source = db.get(InventorySource, source_id)
    if source is None:
        raise SourceNotFoundError(source_id)

    changes: dict[str, object] = {}

    if not isinstance(config, _Unset):
        _validate_config(source.kind, config)
        changes["config"] = "updated"
        source.config = config

    if not isinstance(credential, _Unset):
        if credential is None:
            source.credential_id = None
            changes["credential"] = "cleared"
        else:
            if isinstance(credential_auth_type, _Unset):
                raise InvalidSourceConfigError(
                    "credential_auth_type is required when setting a credential"
                )
            credential_row = IntegrationCredential(
                auth_type=credential_auth_type, ciphertext=encrypt_credential(credential)
            )
            db.add(credential_row)
            db.flush()
            source.credential_id = credential_row.id
            changes["credential"] = "replaced"

    if not isinstance(schedule_cron, _Unset):
        changes["schedule_cron"] = schedule_cron
        source.schedule_cron = schedule_cron

    if not isinstance(is_active, _Unset):
        changes["is_active"] = is_active
        source.is_active = is_active

    if changes:
        record(
            db,
            actor=actor,
            action="inventory_source.updated",
            entity_type="inventory_source",
            entity_id=source.id,
            detail=changes,
        )
        db.flush()
    return source


def get_source(db: DbSession, source_id: uuid.UUID) -> InventorySource | None:
    return db.get(InventorySource, source_id)


def list_sources(db: DbSession, *, active_only: bool = False) -> list[InventorySource]:
    stmt = select(InventorySource).order_by(InventorySource.name)
    if active_only:
        stmt = stmt.where(InventorySource.is_active.is_(True))
    return list(db.scalars(stmt).all())


def latest_snapshots(db: DbSession, *, active_only: bool = True) -> list[InventorySnapshot]:
    """One row per source — its current `is_latest` snapshot. Feeds the
    "Scan inventory" source picker (Phase 2e); a source with no snapshot
    yet contributes nothing."""
    stmt = (
        select(InventorySnapshot)
        .join(InventorySource, InventorySnapshot.source_id == InventorySource.id)
        .where(InventorySnapshot.is_latest.is_(True))
        .order_by(InventorySource.name)
    )
    if active_only:
        stmt = stmt.where(InventorySource.is_active.is_(True))
    return list(db.scalars(stmt).all())


def sync_history(db: DbSession, source_id: uuid.UUID) -> list[AuditLog]:
    """Every create/update/test/sync event for this source, newest first —
    backed by the append-only audit log rather than a dedicated table, since
    `inventory_source` already carries its own `last_sync_*` summary."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.entity_type == "inventory_source", AuditLog.entity_id == source_id)
        .order_by(AuditLog.created_at.desc())
    )
    return list(db.scalars(stmt).all())


@dataclass(slots=True)
class ConnectionTestResult:
    ok: bool
    message: str


def _decrypt_source_credential(db: DbSession, source: InventorySource) -> dict[str, str]:
    if source.credential_id is None:
        raise InvalidSourceConfigError("This source has no credential configured")
    credential_row = db.get(IntegrationCredential, source.credential_id)
    if credential_row is None:
        raise InvalidSourceConfigError("Credential record is missing")
    return decrypt_credential(credential_row.ciphertext)


def test_connection(db: DbSession, source_id: uuid.UUID, *, actor: Actor) -> ConnectionTestResult:
    """SSRF-checks the configured `base_url`, then — for API sources —
    actually calls the adapter's read-only connectivity check."""
    source = db.get(InventorySource, source_id)
    if source is None:
        raise SourceNotFoundError(source_id)

    if source.kind not in API_KINDS:
        result = ConnectionTestResult(
            ok=False, message="CSV sources have no live connection — upload a file to sync."
        )
    else:
        base_url = source.config.get("base_url") if isinstance(source.config, dict) else None
        try:
            if base_url:
                validate_outbound_url(str(base_url))
            credential = _decrypt_source_credential(db, source)
            adapter = adapter_for(source.kind)
            ok, message = adapter.test_connection(config=source.config, credential=credential)
            result = ConnectionTestResult(ok=ok, message=message)
        except SsrfBlockedError as exc:
            result = ConnectionTestResult(ok=False, message=str(exc))
        except (InvalidSourceConfigError, CredentialEncryptionError) as exc:
            result = ConnectionTestResult(ok=False, message=str(exc))
        except ApiAdapterError as exc:
            result = ConnectionTestResult(ok=False, message=str(exc))

    record(
        db,
        actor=actor,
        action="inventory_source.test_connection",
        entity_type="inventory_source",
        entity_id=source.id,
        detail={"ok": result.ok, "message": result.message},
    )
    db.flush()
    return result


def sync_source(db: DbSession, source_id: uuid.UUID, *, actor: Actor) -> InventorySnapshot:
    """Pulls the full inventory via the source's adapter and commits a new
    `DETAILED` snapshot — devices, per-device software, and the aggregate
    `inventory_software` view populated from the same data.

    A failed fetch **never touches `inventory_snapshot`** — the previous
    snapshot stays `is_latest`, and the failure is recorded on the source
    and in the audit log. A degraded (partial/rate-capped) fetch still
    commits, but as `SyncStatus.PARTIAL` with the reason recorded, never
    silently as `OK`."""
    source = db.get(InventorySource, source_id)
    if source is None:
        raise SourceNotFoundError(source_id)
    if source.kind not in API_KINDS:
        raise InvalidSourceConfigError(f"{source.kind.value} is not an API source")

    base_url = source.config.get("base_url") if isinstance(source.config, dict) else None
    if base_url:
        validate_outbound_url(str(base_url))
    credential = _decrypt_source_credential(db, source)
    adapter = adapter_for(source.kind)

    try:
        fetch_result = adapter.fetch(config=source.config, credential=credential)
    except ApiAdapterError as exc:
        source.last_sync_at = utcnow()
        source.last_sync_status = SyncStatus.ERROR
        source.last_sync_error = str(exc)
        record(
            db,
            actor=actor,
            action="inventory_source.sync_failed",
            entity_type="inventory_source",
            entity_id=source.id,
            detail={"error": str(exc)},
        )
        db.flush()
        raise

    db.execute(
        update(InventorySnapshot)
        .where(InventorySnapshot.source_id == source_id, InventorySnapshot.is_latest.is_(True))
        .values(is_latest=False)
    )

    snapshot = InventorySnapshot(
        source_id=source_id,
        taken_at=utcnow(),
        mode=InventoryMode.DETAILED,
        device_count=len(fetch_result.devices),
        software_row_count=0,
        uploaded_by_id=actor.user_id,
        is_latest=True,
    )
    db.add(snapshot)
    db.flush()

    alias_map = load_vendor_alias_map(db)
    aggregate: dict[tuple[str | None, str, str | None, str], int] = defaultdict(int)

    for dev in fetch_result.devices:
        device_row = InventoryDevice(
            snapshot_id=snapshot.id,
            device_identifier=dev.device_identifier,
            hostname=dev.hostname,
            os_name=dev.os_name,
            os_version=dev.os_version,
            attributes=dev.attributes,
        )
        db.add(device_row)
        db.flush()

        for sw in dev.software:
            version_normalized, version_parts = normalise_version(sw.version)
            db.add(
                InventoryDeviceSoftware(
                    device_id=device_row.id,
                    vendor=normalise_vendor(sw.vendor, alias_map),
                    product=normalise_product(sw.product),
                    version_normalized=version_normalized,
                    version_parts=version_parts,
                )
            )
            aggregate[(sw.vendor, sw.product, sw.version, InventoryItemKind.SOFTWARE.value)] += 1

        if dev.os_name:
            aggregate[
                (None, dev.os_name, dev.os_version, InventoryItemKind.OPERATING_SYSTEM.value)
            ] += 1

    for (vendor, product, version, kind), device_count in aggregate.items():
        version_normalized, version_parts = normalise_version(version)
        db.add(
            InventorySoftware(
                snapshot_id=snapshot.id,
                vendor_raw=vendor,
                product_raw=product,
                vendor=normalise_vendor(vendor, alias_map),
                product=normalise_product(product),
                version_raw=version,
                version_normalized=version_normalized,
                version_parts=version_parts,
                kind=InventoryItemKind(kind),
                device_count=device_count,
            )
        )
    snapshot.software_row_count = len(aggregate)

    source.last_sync_at = utcnow()
    source.last_sync_status = SyncStatus.PARTIAL if fetch_result.truncated else SyncStatus.OK
    source.last_sync_error = fetch_result.truncated_reason if fetch_result.truncated else None

    record(
        db,
        actor=actor,
        action="inventory_source.synced",
        entity_type="inventory_source",
        entity_id=source.id,
        detail={
            "snapshot_id": str(snapshot.id),
            "device_count": len(fetch_result.devices),
            "software_rows": len(aggregate),
            "truncated": fetch_result.truncated,
        },
    )
    db.flush()
    return snapshot


# ─── CSV ingest — Phase 2b ───────────────────────────────────────────────────


class CsvBlobNotFoundError(Exception):
    def __init__(self, blob_id: uuid.UUID) -> None:
        super().__init__(f"Uploaded CSV blob {blob_id} not found")
        self.blob_id = blob_id


class CsvTooLargeError(Exception):
    def __init__(self, size_bytes: int, max_bytes: int) -> None:
        super().__init__(f"CSV is {size_bytes} bytes, over the {max_bytes}-byte limit")


@dataclass(slots=True)
class CsvPreview:
    blob_id: uuid.UUID
    headers: list[str]
    mapping: dict[str, str | None]
    #: First 20 successfully parsed rows — enough to sanity-check the
    #: mapping without rendering a 50k-row table.
    preview_rows: list[csv_parser.ParsedRow]
    #: Every row that failed to parse, capped at 50 for the same reason.
    errors: list[csv_parser.RowError]
    total_rows: int
    matched_row_count: int


def _decode_csv(data: bytes) -> str:
    """Real exports are UTF-8 (with or without a BOM) or Windows-1252 —
    tries both rather than guessing silently. Anything else is an honest
    failure, not mojibake in the preview."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252")


def _store_csv_blob(db: DbSession, data: bytes, filename: str) -> Blob:
    store = FilesystemBlobStore(settings.blob_root)
    stored = store.put_bytes(data)
    blob = db.scalar(select(Blob).where(Blob.sha256 == stored.sha256))
    if blob is None:
        blob = Blob(
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            content_type="text/csv",
            original_filename=filename,
        )
        db.add(blob)
        db.flush()
    return blob


def preview_csv(
    db: DbSession, source_id: uuid.UUID, *, file_bytes: bytes, filename: str
) -> CsvPreview:
    """Stores the upload as a blob and parses it for review — writes nothing
    to `inventory_snapshot`/`inventory_software`. The analyst confirms (and
    may edit the mapping) via `commit_csv_snapshot()`."""
    source = db.get(InventorySource, source_id)
    if source is None:
        raise SourceNotFoundError(source_id)
    if source.kind not in CSV_KINDS:
        raise InvalidSourceConfigError(f"{source.kind.value} is not a CSV source")
    if len(file_bytes) > settings.csv_max_bytes:
        raise CsvTooLargeError(len(file_bytes), settings.csv_max_bytes)

    text = _decode_csv(file_bytes)
    headers = csv_parser.sniff_headers(text)

    saved_mapping = source.config.get("column_mapping") if isinstance(source.config, dict) else None
    mapping = (
        dict(saved_mapping)
        if isinstance(saved_mapping, dict)
        else csv_parser.auto_map(headers, profile_for(source.kind))
    )

    blob = _store_csv_blob(db, file_bytes, filename)

    if not mapping.get("product"):
        return CsvPreview(
            blob_id=blob.id,
            headers=headers,
            mapping=mapping,
            preview_rows=[],
            errors=[],
            total_rows=0,
            matched_row_count=0,
        )

    result = csv_parser.parse_rows(
        text, mapping, os_indicator_value=profile_for(source.kind).os_indicator_value
    )
    return CsvPreview(
        blob_id=blob.id,
        headers=headers,
        mapping=mapping,
        preview_rows=result.rows[:20],
        errors=result.errors[:50],
        total_rows=result.total_rows,
        matched_row_count=len(result.rows),
    )


def _aggregate_rows(
    rows: list[csv_parser.ParsedRow],
) -> dict[tuple[str | None, str, str | None, str], int]:
    """Sums `device_count` across rows sharing (vendor, product, version,
    kind) — handles both already-aggregated exports (a count column) and
    raw per-device rows (no count column, each row implicitly one device)
    identically."""
    totals: dict[tuple[str | None, str, str | None, str], int] = defaultdict(int)
    for row in rows:
        key = (row.vendor, row.product, row.version, row.kind)
        totals[key] += row.device_count
    return dict(totals)


def commit_csv_snapshot(
    db: DbSession,
    source_id: uuid.UUID,
    *,
    blob_id: uuid.UUID,
    mapping: dict[str, str | None],
    actor: Actor,
) -> InventorySnapshot:
    """Re-reads the previewed blob, re-parses with the (possibly analyst-
    edited) mapping, and commits a new `inventory_snapshot` — marked latest,
    demoting whichever snapshot held that title before. The mapping is
    persisted onto the source so the next upload defaults to it."""
    source = db.get(InventorySource, source_id)
    if source is None:
        raise SourceNotFoundError(source_id)
    if source.kind not in CSV_KINDS:
        raise InvalidSourceConfigError(f"{source.kind.value} is not a CSV source")

    blob = db.get(Blob, blob_id)
    if blob is None:
        raise CsvBlobNotFoundError(blob_id)

    store = FilesystemBlobStore(settings.blob_root)
    text = _decode_csv(store.get_bytes(blob.sha256))

    try:
        result = csv_parser.parse_rows(
            text, mapping, os_indicator_value=profile_for(source.kind).os_indicator_value
        )
    except csv_parser.MissingMappingError as exc:
        raise InvalidSourceConfigError(str(exc)) from exc

    if not result.rows:
        raise InvalidSourceConfigError("No valid rows to import — check the column mapping")

    aggregated = _aggregate_rows(result.rows)

    db.execute(
        update(InventorySnapshot)
        .where(InventorySnapshot.source_id == source_id, InventorySnapshot.is_latest.is_(True))
        .values(is_latest=False)
    )

    snapshot = InventorySnapshot(
        source_id=source_id,
        taken_at=utcnow(),
        mode=InventoryMode.AGGREGATE,
        software_row_count=len(aggregated),
        uploaded_by_id=actor.user_id,
        raw_file_blob_id=blob.id,
        is_latest=True,
    )
    db.add(snapshot)
    db.flush()

    alias_map = load_vendor_alias_map(db)
    for (vendor, product, version, kind), device_count in aggregated.items():
        version_normalized, version_parts = normalise_version(version)
        db.add(
            InventorySoftware(
                snapshot_id=snapshot.id,
                vendor_raw=vendor,
                product_raw=product,
                vendor=normalise_vendor(vendor, alias_map),
                product=normalise_product(product),
                version_raw=version,
                version_normalized=version_normalized,
                version_parts=version_parts,
                kind=InventoryItemKind(kind),
                device_count=device_count,
            )
        )

    source.last_sync_at = utcnow()
    source.last_sync_status = SyncStatus.OK if not result.errors else SyncStatus.PARTIAL
    source.last_sync_error = (
        f"{len(result.errors)} row(s) failed to parse" if result.errors else None
    )
    source.config = {**(source.config or {}), "column_mapping": mapping}

    record(
        db,
        actor=actor,
        action="inventory_source.csv_imported",
        entity_type="inventory_source",
        entity_id=source.id,
        detail={
            "snapshot_id": str(snapshot.id),
            "software_rows": len(aggregated),
            "parsed_rows": len(result.rows),
            "error_rows": len(result.errors),
        },
    )
    db.flush()
    return snapshot


__all__ = [
    "API_KINDS",
    "CSV_KINDS",
    "UNSET",
    "ConnectionTestResult",
    "CsvBlobNotFoundError",
    "CsvPreview",
    "CsvTooLargeError",
    "DuplicateSourceNameError",
    "InvalidSourceConfigError",
    "SourceNotFoundError",
    "commit_csv_snapshot",
    "create_source",
    "get_source",
    "list_sources",
    "preview_csv",
    "sync_history",
    "sync_source",
    "test_connection",
    "update_source",
]
