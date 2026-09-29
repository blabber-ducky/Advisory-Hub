"""Inventory scans — the matching engine's persistence layer, Phase 2d/2e.

Gathers affected-product specs from an advisory's NVD CPE data, gathers
inventory candidates from the given snapshots, and runs
`inventory.matcher.match_candidates()` — then persists the result as a
`scan_run` with its `scan_match` rows. `run_scan()` is synchronous — see
its own docstring for why. `scan_history()`/`get_scan_run()` back the
Phase 2e "Scan inventory" UI (web `tracker.py`, REST `api/routers/scans.py`);
`coverage_gaps()` is the "not found ≠ not affected" computation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...enrich.cpe import parse_cpe
from ...inventory.matcher import AffectedSpec, InventoryCandidate, match_candidates
from ...inventory.normalise import normalise_product, normalise_vendor
from ..models.advisory import Advisory, CveCpe
from ..models.base import utcnow
from ..models.enums import AdvisoryStatus, MatchConfidence, MatchMethod, ScanStatus, Severity
from ..models.inventory import InventorySnapshot, InventorySoftware, ScanMatch, ScanRun
from .audit import Actor, record
from .vendor_alias import load_vendor_alias_map


class AdvisoryNotFoundError(Exception):
    def __init__(self, advisory_id: uuid.UUID) -> None:
        super().__init__(f"Advisory {advisory_id} not found")
        self.advisory_id = advisory_id


class SnapshotNotFoundError(Exception):
    def __init__(self, snapshot_id: uuid.UUID) -> None:
        super().__init__(f"Inventory snapshot {snapshot_id} not found")
        self.snapshot_id = snapshot_id


class ScanRunNotFoundError(Exception):
    def __init__(self, scan_run_id: uuid.UUID) -> None:
        super().__init__(f"Scan run {scan_run_id} not found")
        self.scan_run_id = scan_run_id


def _affected_specs(
    db: DbSession, advisory: Advisory, alias_map: dict[str, str]
) -> list[AffectedSpec]:
    """NVD CPE specs, plus text-derived specs from `AdvisoryProduct.parsed_range`
    (see `ingest/version_range.py` and D-032) — the two sources are graded
    differently downstream, never `CONFIRMED` for the latter. See
    `inventory.matcher`'s module docstring."""
    specs = _nvd_specs(db, advisory)
    specs.extend(_text_derived_specs(advisory, alias_map))
    return specs


def _nvd_specs(db: DbSession, advisory: Advisory) -> list[AffectedSpec]:
    cve_ids = [row.cve_id for row in advisory.cves]
    if not cve_ids:
        return []

    rows = db.scalars(
        select(CveCpe).where(CveCpe.cve_id.in_(cve_ids), CveCpe.vulnerable.is_(True))
    ).all()

    specs: list[AffectedSpec] = []
    for row in rows:
        exact_version = None
        if row.version_start is None and row.version_end is None:
            parsed = parse_cpe(row.cpe_uri)
            if parsed is not None and parsed.has_explicit_version:
                exact_version = parsed.version
            else:
                # No range and no pinned version — nothing to compare
                # against. Not an error; NVD sometimes ships a bare
                # vendor:product CPE with no version signal at all.
                continue
        specs.append(
            AffectedSpec(
                cve_id=row.cve_id,
                vendor=row.vendor,
                product=row.product,
                min_version=row.version_start,
                min_inclusive=row.version_start_inclusive,
                max_version=row.version_end,
                max_inclusive=row.version_end_inclusive,
                exact_version=exact_version,
            )
        )
    return specs


def _text_derived_specs(advisory: Advisory, alias_map: dict[str, str]) -> list[AffectedSpec]:
    """One spec per `AdvisoryProduct` row with a clean `parsed_range` —
    `cve_id` is always `None` here: a product claim isn't attributed to one
    specific CVE within a (possibly multi-CVE) advisory. Vendor is
    normalised the same way inventory vendors are, so a text-derived spec
    can still match a canonically-spelled inventory row; product is
    normalised at match time in `inventory.matcher`, same as NVD specs."""
    specs: list[AffectedSpec] = []
    for claim in advisory.products:
        if claim.parsed_range is None or not claim.product:
            continue
        pr = claim.parsed_range
        specs.append(
            AffectedSpec(
                cve_id=None,
                vendor=normalise_vendor(claim.vendor, alias_map) or "",
                product=claim.product,
                min_version=pr.get("min_version"),  # type: ignore[arg-type]
                min_inclusive=bool(pr.get("min_inclusive", True)),
                max_version=pr.get("max_version"),  # type: ignore[arg-type]
                max_inclusive=bool(pr.get("max_inclusive", False)),
                exact_version=pr.get("exact_version"),  # type: ignore[arg-type]
                text_derived=True,
            )
        )
    return specs


def _inventory_candidates(db: DbSession, snapshot_ids: list[uuid.UUID]) -> list[InventoryCandidate]:
    rows = db.scalars(
        select(InventorySoftware).where(InventorySoftware.snapshot_id.in_(snapshot_ids))
    ).all()
    return [
        InventoryCandidate(
            snapshot_id=row.snapshot_id,
            vendor=row.vendor_raw,
            product=row.product_raw,
            version=row.version_raw,
            device_count=row.device_count,
        )
        for row in rows
    ]


def run_scan(
    db: DbSession, advisory_id: uuid.UUID, snapshot_ids: list[uuid.UUID], *, actor: Actor
) -> ScanRun:
    """Runs synchronously and returns a `COMPLETE` (or `FAILED`) `ScanRun` —
    there is no background-job queue for this yet (Phase 2e's job, once
    there's a UI to poll it). `affected_device_count` sums `device_count`
    across every match, which can double-count a device affected by more
    than one CVE in the same scan — an intentional, documented
    simplification, not a hidden bug."""
    advisory = db.get(Advisory, advisory_id)
    if advisory is None:
        raise AdvisoryNotFoundError(advisory_id)

    for snapshot_id in snapshot_ids:
        if db.get(InventorySnapshot, snapshot_id) is None:
            raise SnapshotNotFoundError(snapshot_id)

    scan_run = ScanRun(
        advisory_id=advisory_id,
        initiated_by_id=actor.user_id,
        snapshot_ids=snapshot_ids,
        status=ScanStatus.RUNNING,
        started_at=utcnow(),
    )
    db.add(scan_run)
    db.flush()

    try:
        alias_map = load_vendor_alias_map(db)
        specs = _affected_specs(db, advisory, alias_map)
        candidates = _inventory_candidates(db, snapshot_ids)
        matches = match_candidates(specs, candidates, alias_map)

        for match in matches:
            db.add(
                ScanMatch(
                    scan_run_id=scan_run.id,
                    cve_id=match.cve_id,
                    snapshot_id=match.snapshot_id,
                    vendor=match.vendor,
                    product=match.product,
                    matched_version=match.matched_version,
                    affected_range=match.affected_range,
                    device_count=match.device_count,
                    device_ids=match.device_ids,
                    match_method=match.match_method,
                    confidence=match.confidence,
                    rationale=match.rationale,
                )
            )

        scan_run.status = ScanStatus.COMPLETE
        scan_run.finished_at = utcnow()
        scan_run.match_count = len(matches)
        scan_run.affected_device_count = sum(m.device_count for m in matches)
    except Exception as exc:
        scan_run.status = ScanStatus.FAILED
        scan_run.finished_at = utcnow()
        scan_run.error = str(exc)
        db.flush()
        record(
            db,
            actor=actor,
            action="advisory.scan_failed",
            entity_type="advisory",
            entity_id=advisory_id,
            detail={"scan_run_id": str(scan_run.id), "error": str(exc)},
        )
        db.flush()
        raise

    record(
        db,
        actor=actor,
        action="advisory.scanned",
        entity_type="advisory",
        entity_id=advisory_id,
        detail={
            "scan_run_id": str(scan_run.id),
            "match_count": scan_run.match_count,
            "affected_device_count": scan_run.affected_device_count,
            "snapshot_count": len(snapshot_ids),
        },
    )
    db.flush()
    return scan_run


def scan_history(db: DbSession, advisory_id: uuid.UUID) -> list[ScanRun]:
    """Newest first, ordered by `started_at` — not `created_at`. Postgres's
    `now()` (what `created_at`'s `server_default` uses) is transaction-scoped
    and returns the identical value for every row written in one
    transaction, which two scans run back-to-back in the same request/test
    routinely are; `started_at` is a Python-side `utcnow()` call per
    `run_scan()` invocation and so actually distinguishes them."""
    return list(
        db.scalars(
            select(ScanRun)
            .where(ScanRun.advisory_id == advisory_id)
            .order_by(ScanRun.started_at.desc())
        ).all()
    )


def get_scan_run(db: DbSession, scan_run_id: uuid.UUID) -> ScanRun | None:
    return db.get(ScanRun, scan_run_id)


def coverage_gaps(db: DbSession, scan_run: ScanRun) -> list[tuple[str, str]]:
    """`(vendor, product)` pairs this advisory's CVEs affect that no
    candidate in the scanned snapshots matched on vendor+product at all —
    a genuine "we didn't see it" coverage gap, distinct from "present, not
    in the vulnerable range". Recomputed on demand rather than persisted:
    `scan_run`/`scan_match` have no column for it and there's no schema
    reason to add one — every snapshot this project has scanned recomputes
    in well under a second."""
    advisory = db.get(Advisory, scan_run.advisory_id)
    if advisory is None:
        return []

    alias_map = load_vendor_alias_map(db)
    specs = _affected_specs(db, advisory, alias_map)
    candidates = _inventory_candidates(db, scan_run.snapshot_ids)

    covered = {
        (normalise_vendor(c.vendor, alias_map), normalise_product(c.product)) for c in candidates
    }

    seen: set[tuple[str, str]] = set()
    gaps: list[tuple[str, str]] = []
    for spec in specs:
        key = (spec.vendor, normalise_product(spec.product))
        if key in seen or key in covered:
            continue
        seen.add(key)
        gaps.append(key)
    return gaps


@dataclass(slots=True)
class AffectedSoftwareRow:
    advisory_id: uuid.UUID
    advisory_external_ref: str | None
    advisory_severity: Severity | None
    advisory_status: AdvisoryStatus
    vendor: str | None
    product: str
    matched_version: str
    device_count: int
    confidence: MatchConfidence
    match_method: MatchMethod
    rationale: str
    scan_run_id: uuid.UUID
    scanned_at: datetime | None


def _latest_scan_runs(db: DbSession) -> dict[uuid.UUID, ScanRun]:
    """One `ScanRun` per advisory — its most recent `COMPLETE` run. Done as
    a single ordered fetch plus a Python-side first-wins pass rather than a
    self-join on `MAX(started_at)`, which would need an exact timestamp
    match and could pick up more than one row if two runs for the same
    advisory ever land in the same transaction (Postgres's `now()`-backed
    columns can tie — see D-028; `started_at` itself doesn't, but there's
    no reason to rely on that here when this is just as simple)."""
    all_runs = db.scalars(
        select(ScanRun)
        .where(ScanRun.status == ScanStatus.COMPLETE)
        .order_by(ScanRun.advisory_id, ScanRun.started_at.desc())
    ).all()
    latest: dict[uuid.UUID, ScanRun] = {}
    for run in all_runs:
        latest.setdefault(run.advisory_id, run)
    return latest


def list_affected_software(db: DbSession) -> list[AffectedSoftwareRow]:
    """One row per `scan_match` from each advisory's most recent completed
    scan — "what's currently affected in the estate, as of the last time
    each advisory was scanned". An advisory never scanned contributes
    nothing; `refresh_all_scans()` is what keeps this current."""
    latest = _latest_scan_runs(db)
    if not latest:
        return []

    run_ids = [run.id for run in latest.values()]
    advisories = {
        a.id: a
        for a in db.scalars(
            select(Advisory).where(Advisory.id.in_({run.advisory_id for run in latest.values()}))
        )
    }
    matches = db.scalars(select(ScanMatch).where(ScanMatch.scan_run_id.in_(run_ids))).all()
    run_by_id = {run.id: run for run in latest.values()}

    rows: list[AffectedSoftwareRow] = []
    for m in matches:
        run = run_by_id[m.scan_run_id]
        advisory = advisories.get(run.advisory_id)
        if advisory is None:
            continue
        rows.append(
            AffectedSoftwareRow(
                advisory_id=advisory.id,
                advisory_external_ref=advisory.external_ref,
                advisory_severity=advisory.severity,
                advisory_status=advisory.status,
                vendor=m.vendor,
                product=m.product,
                matched_version=m.matched_version,
                device_count=m.device_count,
                confidence=m.confidence,
                match_method=m.match_method,
                rationale=m.rationale,
                scan_run_id=run.id,
                scanned_at=run.finished_at,
            )
        )

    severity_rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    rows.sort(
        key=lambda r: (
            severity_rank.get(r.advisory_severity, len(severity_rank))
            if r.advisory_severity is not None
            else len(severity_rank),
            r.product,
        )
    )
    return rows


@dataclass(slots=True)
class RefreshAllReport:
    refreshed: list[uuid.UUID]
    failed: list[tuple[uuid.UUID, str]]


def refresh_all_scans(db: DbSession, *, actor: Actor) -> RefreshAllReport:
    """Re-scans every advisory that has been scanned at least once before
    (i.e. every advisory `list_affected_software()` currently shows a row
    for), against each active source's *current* latest snapshot — not
    whatever snapshot its last scan happened to use, so a refresh actually
    reflects the newest inventory data.

    Each advisory is scanned and committed independently, mirroring the
    per-source commit discipline `sync_source()`'s scheduled poller already
    established (Phase 2c) — one advisory's failure must not roll back
    every other advisory's already-successful refresh, or block the rest
    of the sweep."""
    from .inventory import latest_snapshots  # local import avoids a cycle

    latest = _latest_scan_runs(db)
    snapshot_ids = [s.id for s in latest_snapshots(db, active_only=True)]

    refreshed: list[uuid.UUID] = []
    failed: list[tuple[uuid.UUID, str]] = []
    for advisory_id in latest:
        try:
            run_scan(db, advisory_id, snapshot_ids, actor=actor)
        except Exception as exc:
            failed.append((advisory_id, str(exc)))
        else:
            refreshed.append(advisory_id)
        finally:
            db.commit()
    return RefreshAllReport(refreshed=refreshed, failed=failed)


__all__ = [
    "AdvisoryNotFoundError",
    "AffectedSoftwareRow",
    "RefreshAllReport",
    "ScanRunNotFoundError",
    "SnapshotNotFoundError",
    "coverage_gaps",
    "get_scan_run",
    "list_affected_software",
    "refresh_all_scans",
    "run_scan",
    "scan_history",
]
