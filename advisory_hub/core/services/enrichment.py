"""NVD enrichment orchestration.

Enrichment is optional and degradable by design (D-004): every outcome is
recorded on the CVE row, and an advisory stays fully usable from parsed content
alone. Failure here must never block ingestion or the UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from ...enrich.cache import MISS, NvdCache
from ...enrich.nvd import NvdClient, NvdError, NvdRecord
from ...logging import get_logger
from ..models.advisory import Advisory, AdvisoryCve, CveCpe
from ..models.base import utcnow
from ..models.enums import SEVERITY_TO_PRIORITY, EnrichmentStatus, Severity, SystemIntegrationKind
from . import system_integrations
from .audit import Actor
from .audit import record as audit_record

log = get_logger(__name__)

#: How long an OK enrichment stays fresh before a refresh is worthwhile.
#: NVD backfills CVSS scores and CPE data days after initial publication.
REFRESH_AFTER = timedelta(days=7)

#: Cap on retries for CVEs that keep erroring, so a permanently broken record
#: doesn't consume the rate-limit budget forever.
MAX_ERROR_AGE = timedelta(days=30)


@dataclass(slots=True)
class EnrichmentReport:
    ok: int = 0
    not_found: int = 0
    errors: int = 0
    skipped: int = 0
    cached: int = 0
    cpe_rows: int = 0
    advisories_rescored: int = 0
    messages: list[str] = field(default_factory=list)

    @property
    def attempted(self) -> int:
        return self.ok + self.not_found + self.errors


def enrich_pending(
    db: DbSession,
    *,
    limit: int | None = None,
    client: NvdClient | None = None,
    cache: NvdCache | None = None,
    force: bool = False,
    actor: Actor | None = None,
) -> EnrichmentReport:
    """Enrich CVE rows that need it.

    With NVD disabled every candidate is marked ``SKIPPED_OFFLINE`` and the
    system degrades to PDF-derived product data — see D-004.

    The API key/enabled state is resolved via `core.services.system_integrations`
    — an admin-panel-configured key takes precedence over `NVD_API_KEY`, and an
    admin explicitly disabling NVD there overrides `NVD_ENABLED` too. See
    docs/decisions.md.
    """
    report = EnrichmentReport()
    actor = actor or Actor.system("enrichment")
    rows = _candidates(db, limit=limit, force=force)
    if not rows:
        return report

    resolved = system_integrations.resolve_credential(db, SystemIntegrationKind.NVD)
    if not resolved.enabled:
        for row in rows:
            row.enrichment_status = EnrichmentStatus.SKIPPED_OFFLINE
            row.last_enriched_at = utcnow()
        report.skipped = len(rows)
        report.messages.append(f"NVD disabled — {len(rows)} CVE(s) marked SKIPPED_OFFLINE")
        return report

    cache = cache or NvdCache()
    owns_client = client is None
    client = client or NvdClient(api_key=resolved.api_key)
    touched_advisories: set[object] = set()

    try:
        # One fetch per distinct CVE, then fan out to every advisory row.
        for cve_id in sorted({row.cve_id for row in rows}):
            fetched = _fetch(client, cache, cve_id, report)
            if fetched is _FETCH_ERROR:
                for row in (r for r in rows if r.cve_id == cve_id):
                    _mark_error(row)
                    report.errors += 1
                continue

            nvd_record: NvdRecord | None = fetched  # type: ignore[assignment]
            if nvd_record is None:
                for row in (r for r in rows if r.cve_id == cve_id):
                    row.enrichment_status = EnrichmentStatus.NOT_FOUND
                    row.last_enriched_at = utcnow()
                    report.not_found += 1
                continue

            report.cpe_rows += _store_cpe_matches(db, nvd_record)
            for row in (r for r in rows if r.cve_id == cve_id):
                _apply(row, nvd_record)
                report.ok += 1
                touched_advisories.add(row.advisory_id)
    finally:
        if owns_client:
            client.close()

    db.flush()
    report.advisories_rescored = sum(
        1 for advisory_id in touched_advisories if _rescore_advisory(db, advisory_id)
    )

    if report.attempted:
        audit_record(
            db,
            actor=actor,
            action="advisory.enriched",
            detail={
                "ok": report.ok,
                "not_found": report.not_found,
                "errors": report.errors,
                "cpe_rows": report.cpe_rows,
                "rescored": report.advisories_rescored,
            },
        )
    return report


class _FetchError:
    """Sentinel distinguishing a transport failure from a genuine 'no record'."""


_FETCH_ERROR = _FetchError()


def _fetch(
    client: NvdClient, cache: NvdCache, cve_id: str, report: EnrichmentReport
) -> NvdRecord | _FetchError | None:
    cached = cache.get(cve_id)
    if cached is not MISS:
        report.cached += 1
        return cached  # type: ignore[return-value]
    try:
        fetched = client.fetch(cve_id)
    except NvdError as exc:
        log.warning("nvd.fetch_failed", cve_id=cve_id, error=str(exc)[:200])
        report.messages.append(f"{cve_id}: {exc}")
        return _FETCH_ERROR
    cache.put(cve_id, fetched)
    return fetched


def _candidates(db: DbSession, *, limit: int | None, force: bool) -> list[AdvisoryCve]:
    stmt = select(AdvisoryCve)
    if not force:
        stale_before = utcnow() - REFRESH_AFTER
        give_up_before = utcnow() - MAX_ERROR_AGE
        stmt = stmt.where(
            (AdvisoryCve.enrichment_status == EnrichmentStatus.PENDING)
            | (AdvisoryCve.enrichment_status == EnrichmentStatus.SKIPPED_OFFLINE)
            | (
                (AdvisoryCve.enrichment_status == EnrichmentStatus.ERROR)
                & (AdvisoryCve.last_enriched_at > give_up_before)
            )
            | (
                (AdvisoryCve.enrichment_status == EnrichmentStatus.OK)
                & (AdvisoryCve.last_enriched_at < stale_before)
            )
        )
    stmt = stmt.order_by(AdvisoryCve.created_at)
    if limit:
        stmt = stmt.limit(limit)
    return list(db.scalars(stmt).all())


def _apply(row: AdvisoryCve, nvd: NvdRecord) -> None:
    v3, v4 = nvd.cvss_v3, nvd.cvss_v4
    if v3:
        row.cvss_v3_score = v3.score
        row.cvss_v3_vector = v3.vector
    if v4:
        row.cvss_v4_score = v4.score
        row.cvss_v4_vector = v4.vector
    row.nvd_description = nvd.description
    row.nvd_published_at = nvd.published
    row.enrichment_status = EnrichmentStatus.OK
    row.last_enriched_at = utcnow()


def _mark_error(row: AdvisoryCve) -> None:
    row.enrichment_status = EnrichmentStatus.ERROR
    row.last_enriched_at = utcnow()


def _store_cpe_matches(db: DbSession, nvd: NvdRecord) -> int:
    """Replace this CVE's CPE rows.

    Keyed by CVE, not advisory: the same CVE appears in several advisories and
    the configuration data is identical. Replace-then-insert keeps the table in
    step with NVD when a configuration is revised.
    """
    if not nvd.cpe_matches:
        return 0
    db.execute(delete(CveCpe).where(CveCpe.cve_id == nvd.cve_id))
    written = 0
    seen: set[tuple[str, str | None, str | None]] = set()
    for match in nvd.cpe_matches:
        key = (match.cpe.uri, match.version_start, match.version_end)
        if key in seen:
            continue
        seen.add(key)
        db.add(
            CveCpe(
                cve_id=nvd.cve_id,
                cpe_uri=match.cpe.uri,
                vendor=match.cpe.vendor,
                product=match.cpe.product,
                version_start=match.version_start,
                version_start_inclusive=match.version_start_inclusive,
                version_end=match.version_end,
                version_end_inclusive=match.version_end_inclusive,
                vulnerable=match.vulnerable,
            )
        )
        written += 1
    return written


def _rescore_advisory(db: DbSession, advisory_id: object) -> bool:
    """Raise an advisory's score/severity to match its worst enriched CVE.

    Only ever raises. The regulator's own severity is an assertion we keep
    (D-019); NVD can add information the regulator's rating missed, but must
    not quietly downgrade a Critical.
    """
    advisory = db.get(Advisory, advisory_id)
    if advisory is None:
        return False

    highest = db.scalar(
        select(func.max(AdvisoryCve.cvss_v3_score)).where(
            AdvisoryCve.advisory_id == advisory.id,
            AdvisoryCve.enrichment_status == EnrichmentStatus.OK,
        )
    )
    if highest is None:
        return False

    changed = False
    if advisory.cvss_score is None or highest > advisory.cvss_score:
        advisory.cvss_score = highest
        changed = True

    derived = _severity_for_score(highest)
    if derived and _rank(derived) > _rank(advisory.severity):
        advisory.severity = derived
        advisory.priority = SEVERITY_TO_PRIORITY[derived]
        _recompute_sla(advisory)
        changed = True
    return changed


def _severity_for_score(score: object) -> Severity | None:
    """CVSS v3.1 qualitative severity bands."""
    value = float(score)  # type: ignore[arg-type]
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0.0:
        return Severity.LOW
    return None


def _rank(severity: Severity | None) -> int:
    if severity is None:
        return -1
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]


def _recompute_sla(advisory: Advisory) -> None:
    """A severity change moves both regulator clocks — see D-018."""
    from ..models.enums import SLA_HOURS, Priority

    if advisory.priority is None:
        return
    ack_hours, resolve_hours = SLA_HOURS[Priority(advisory.priority)]
    advisory.ack_due_at = advisory.received_at + timedelta(hours=ack_hours)
    advisory.resolution_due_at = advisory.received_at + timedelta(hours=resolve_hours)


def enrichment_summary(db: DbSession) -> dict[str, int]:
    rows = db.execute(
        select(AdvisoryCve.enrichment_status, func.count()).group_by(AdvisoryCve.enrichment_status)
    ).all()
    summary = {str(status): count for status, count in rows}
    summary["cve_cpe_rows"] = db.scalar(select(func.count()).select_from(CveCpe)) or 0
    return summary


def stale_cutoff() -> datetime:
    return datetime.now(UTC) - REFRESH_AFTER
