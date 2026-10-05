"""Domain enumerations.

Values are stored as strings in PostgreSQL native enums. Adding a value needs a
migration; removing one needs a data migration first.
"""

from __future__ import annotations

from enum import StrEnum

# ─── Auth ────────────────────────────────────────────────────────────────────


class Role(StrEnum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"

    @property
    def rank(self) -> int:
        return {"VIEWER": 0, "ANALYST": 1, "ADMIN": 2}[self.value]

    def satisfies(self, required: Role) -> bool:
        """Roles are hierarchical: ADMIN satisfies ANALYST satisfies VIEWER."""
        return self.rank >= required.rank


class ActorKind(StrEnum):
    USER = "USER"
    API_TOKEN = "API_TOKEN"  # noqa: S105 — an actor kind, not a credential
    SYSTEM = "SYSTEM"
    MCP = "MCP"


# ─── Advisories ──────────────────────────────────────────────────────────────


class AdvisoryType(StrEnum):
    CVE_ADVISORY = "CVE_ADVISORY"
    SECURITY_BULLETIN = "SECURITY_BULLETIN"
    THREAT_LANDSCAPE = "THREAT_LANDSCAPE"
    OTHER = "OTHER"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Priority(StrEnum):
    """Regulator SLA priority. Derived from severity — see D-018."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class AdvisoryStatus(StrEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    TRIAGED = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    AWAITING_VENDOR = "AWAITING_VENDOR"
    REMEDIATED = "REMEDIATED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CLOSED = "CLOSED"


class AckChannel(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    OTHER = "OTHER"


class FlagKind(StrEnum):
    """Cross-validation findings — see docs/ingestion.md §10."""

    REF_MISMATCH = "REF_MISMATCH"
    SEVERITY_MISMATCH = "SEVERITY_MISMATCH"
    NO_TEXT_LAYER = "NO_TEXT_LAYER"
    UNKNOWN_SENDER = "UNKNOWN_SENDER"
    LOW_TYPE_CONFIDENCE = "LOW_TYPE_CONFIDENCE"
    NO_CVE_FOUND = "NO_CVE_FOUND"
    POSSIBLE_REISSUE = "POSSIBLE_REISSUE"
    PDF_PARSE_FAILED = "PDF_PARSE_FAILED"


class SourceMethod(StrEnum):
    """How an advisory's source was decided — evidence, shown as such."""

    SENDER = "SENDER"  # sender address matched a source's sender patterns
    REFERENCE = "REFERENCE"  # sender unrecognised; reference prefix (DOH-…) matched a short code
    MANUAL = "MANUAL"  # set by an analyst; never overwritten by a re-parse
    NONE = "NONE"  # nothing matched — filed under the UNKNOWN source


class RelationKind(StrEnum):
    POSSIBLE_REISSUE = "POSSIBLE_REISSUE"
    SUPERSEDES = "SUPERSEDES"
    SUPERSEDED_BY = "SUPERSEDED_BY"
    RELATES_TO = "RELATES_TO"


class RelationDetectedBy(StrEnum):
    TITLE_FINGERPRINT = "TITLE_FINGERPRINT"
    MANUAL = "MANUAL"


class ExtractionMethod(StrEnum):
    TEXT_LAYER = "TEXT_LAYER"
    OCR = "OCR"
    FAILED = "FAILED"


class EnrichmentStatus(StrEnum):
    PENDING = "PENDING"
    OK = "OK"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    SKIPPED_OFFLINE = "SKIPPED_OFFLINE"


class IocType(StrEnum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    EMAIL = "EMAIL"
    FILENAME = "FILENAME"
    FILEPATH = "FILEPATH"
    REGISTRY_KEY = "REGISTRY_KEY"
    MUTEX = "MUTEX"
    USER_AGENT = "USER_AGENT"
    OTHER = "OTHER"


class TtpKind(StrEnum):
    THREAT_ACTOR = "THREAT_ACTOR"
    MALWARE_FAMILY = "MALWARE_FAMILY"
    ATTACK_TECHNIQUE = "ATTACK_TECHNIQUE"


class ClaimSource(StrEnum):
    """Where an affected-product claim came from — evidence, not truth."""

    NVD_CPE = "NVD_CPE"
    PDF_TEXT = "PDF_TEXT"
    EMAIL_BODY = "EMAIL_BODY"
    MANUAL = "MANUAL"


# ─── SLA ─────────────────────────────────────────────────────────────────────

#: Regulator SLA, embedded verbatim in all 135 corpus emails. See D-018.
#: priority -> (acknowledge_within_hours, resolve_within_hours)
SLA_HOURS: dict[Priority, tuple[int, int]] = {
    Priority.P1: (8, 24),
    Priority.P2: (16, 48),
    Priority.P3: (72, 120),
    Priority.P4: (72, 120),
}

#: Severity -> priority. LOW and INFO both map to P4.
SEVERITY_TO_PRIORITY: dict[Severity, Priority] = {
    Severity.CRITICAL: Priority.P1,
    Severity.HIGH: Priority.P2,
    Severity.MEDIUM: Priority.P3,
    Severity.LOW: Priority.P4,
    Severity.INFO: Priority.P4,
}


#: Legal status transitions. Every edge additionally requires a comment —
#: enforced in core.services.advisories.change_status(). See architecture §5.
ALLOWED_TRANSITIONS: dict[AdvisoryStatus, frozenset[AdvisoryStatus]] = {
    AdvisoryStatus.NEW: frozenset(
        {
            AdvisoryStatus.ACKNOWLEDGED,
            AdvisoryStatus.TRIAGED,
            AdvisoryStatus.NOT_APPLICABLE,
        }
    ),
    AdvisoryStatus.ACKNOWLEDGED: frozenset(
        {
            AdvisoryStatus.TRIAGED,
            AdvisoryStatus.NOT_APPLICABLE,
        }
    ),
    AdvisoryStatus.TRIAGED: frozenset(
        {
            AdvisoryStatus.IN_PROGRESS,
            AdvisoryStatus.RISK_ACCEPTED,
            AdvisoryStatus.AWAITING_VENDOR,
            AdvisoryStatus.NOT_APPLICABLE,
        }
    ),
    AdvisoryStatus.IN_PROGRESS: frozenset(
        {
            AdvisoryStatus.REMEDIATED,
            AdvisoryStatus.AWAITING_VENDOR,
            AdvisoryStatus.RISK_ACCEPTED,
            AdvisoryStatus.NOT_APPLICABLE,
        }
    ),
    AdvisoryStatus.AWAITING_VENDOR: frozenset(
        {
            AdvisoryStatus.IN_PROGRESS,
            AdvisoryStatus.REMEDIATED,
            AdvisoryStatus.RISK_ACCEPTED,
        }
    ),
    AdvisoryStatus.REMEDIATED: frozenset({AdvisoryStatus.CLOSED, AdvisoryStatus.IN_PROGRESS}),
    AdvisoryStatus.RISK_ACCEPTED: frozenset({AdvisoryStatus.CLOSED, AdvisoryStatus.TRIAGED}),
    AdvisoryStatus.NOT_APPLICABLE: frozenset({AdvisoryStatus.CLOSED, AdvisoryStatus.TRIAGED}),
    # Regulators re-issue advisories — nothing is a dead end.
    AdvisoryStatus.CLOSED: frozenset({AdvisoryStatus.TRIAGED}),
}


# ─── Inventory (Phase 2) ─────────────────────────────────────────────────────


class InventorySourceKind(StrEnum):
    CSV_DESKTOP_CENTRAL = "CSV_DESKTOP_CENTRAL"
    CSV_LANSWEEPER = "CSV_LANSWEEPER"
    CSV_AZURE = "CSV_AZURE"
    API_DESKTOP_CENTRAL = "API_DESKTOP_CENTRAL"
    API_AZURE_ARM = "API_AZURE_ARM"
    API_MS_GRAPH = "API_MS_GRAPH"

    @property
    def mode(self) -> InventoryMode:
        return InventoryMode.AGGREGATE if self.value.startswith("CSV_") else InventoryMode.DETAILED


class InventoryMode(StrEnum):
    #: Counts per product+version only — CSV sources.
    AGGREGATE = "AGGREGATE"
    #: Per-device rows with identifiers — API sources.
    DETAILED = "DETAILED"


class SyncStatus(StrEnum):
    NEVER = "NEVER"
    OK = "OK"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


class CredentialAuthType(StrEnum):
    API_KEY = "API_KEY"
    OAUTH_CLIENT_CREDENTIALS = "OAUTH_CLIENT_CREDENTIALS"
    BASIC = "BASIC"


class InventoryItemKind(StrEnum):
    SOFTWARE = "SOFTWARE"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class MatchMethod(StrEnum):
    CPE_RANGE = "CPE_RANGE"
    CPE_EXACT = "CPE_EXACT"
    TEXT_RANGE = "TEXT_RANGE"
    FUZZY_NAME = "FUZZY_NAME"


class MatchConfidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"


# ─── System integrations (admin panel) ────────────────────────────────────────


class SystemIntegrationKind(StrEnum):
    """Global, singleton API integrations — one row max per kind. Distinct
    from `InventorySourceKind`, which is a user-creatable list of inventory
    sources; NVD and VirusTotal are app-wide, not something an admin adds
    more than one of."""

    NVD = "NVD"
    VIRUSTOTAL = "VIRUSTOTAL"


# ─── IOC remediation tracking ──────────────────────────────────────────────────


class IocRemediationStatus(StrEnum):
    """A per-indicator remediation-tracking status, distinct from
    `AdvisoryStatus`. `AdvisoryIoc.remediation_status` is nullable: `None`
    means "not manually set — follow the advisory's own status" (see
    `ADVISORY_STATUS_TO_IOC_STATUS` below); a non-`None` value is an
    explicit per-IOC override an analyst set independently (e.g. "this one
    specific indicator is blocked pending firewall change access", even
    though the advisory itself is still just `IN_PROGRESS`)."""

    DUE = "DUE"
    BLOCKED = "BLOCKED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


#: The default an IOC's status is *derived* from when nobody has overridden
#: it — every `AdvisoryStatus` maps to exactly one `IocRemediationStatus`,
#: so an IOC's action state always tracks the advisory unless an analyst
#: deliberately steps in.
ADVISORY_STATUS_TO_IOC_STATUS: dict[AdvisoryStatus, IocRemediationStatus] = {
    AdvisoryStatus.NEW: IocRemediationStatus.DUE,
    AdvisoryStatus.ACKNOWLEDGED: IocRemediationStatus.DUE,
    AdvisoryStatus.TRIAGED: IocRemediationStatus.DUE,
    AdvisoryStatus.IN_PROGRESS: IocRemediationStatus.IN_PROGRESS,
    AdvisoryStatus.AWAITING_VENDOR: IocRemediationStatus.BLOCKED,
    AdvisoryStatus.REMEDIATED: IocRemediationStatus.RESOLVED,
    AdvisoryStatus.RISK_ACCEPTED: IocRemediationStatus.RESOLVED,
    AdvisoryStatus.NOT_APPLICABLE: IocRemediationStatus.RESOLVED,
    AdvisoryStatus.CLOSED: IocRemediationStatus.RESOLVED,
}
