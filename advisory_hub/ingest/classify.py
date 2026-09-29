"""Advisory type classification.

Rules-based and deterministic, so every classification can be explained to an
auditor (D-008). Classifies on **structure**, not on the regulator's ``Type``
field: that field is present 135/135 but says ``Vulnerability`` for 128 of them,
including IoT botnet campaigns and quarterly threat-landscape summaries. Section
headings are template-driven and therefore far more stable — see D-017.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal

from ..core.models.enums import AdvisoryType
from .sections import SectionedDocument

#: Below this, the advisory is flagged for analyst review rather than filed.
LOW_CONFIDENCE = Decimal("0.5")

_SECURITY_UPDATE_TITLE = re.compile(
    r"^\s*security\s+updates?\s*[-\u2013\u2014:]|patch\s+(?:tuesday|advisory)|"
    r"\bsecurity\s+(?:updates?|patch)\b.*\b(?:20\d\d|[A-Z][a-z]+\s+20\d\d)\b",
    re.IGNORECASE,
)
_THREAT_WORDS = re.compile(
    r"\b(?:campaign|threat\s+actor|ransomware|backdoor|infostealer|botnet|"
    r"phishing|malware|espionage|apt|intrusion|supply[- ]chain\s+compromise|"
    r"threat\s+landscape|indicators?\s+of\s+compromise)\b",
    re.IGNORECASE,
)
_REGULATOR_THREAT_TYPES = {"campaign", "malware", "phishing", "threat", "incident"}


@dataclass(slots=True)
class Classification:
    type: AdvisoryType
    confidence: Decimal
    signals: list[str] = field(default_factory=list)

    @property
    def is_low_confidence(self) -> bool:
        return self.confidence < LOW_CONFIDENCE


def classify(
    *,
    title: str,
    doc: SectionedDocument | None,
    cve_count: int,
    ioc_count: int,
    has_cvss_vector: bool,
    regulator_type: str | None,
    body_text: str = "",
) -> Classification:
    """Score each candidate type and return the winner with its evidence."""
    scores: dict[AdvisoryType, float] = {
        AdvisoryType.CVE_ADVISORY: 0.0,
        AdvisoryType.SECURITY_BULLETIN: 0.0,
        AdvisoryType.THREAT_LANDSCAPE: 0.0,
        AdvisoryType.OTHER: 0.0,
    }
    signals: list[str] = []

    def add(t: AdvisoryType, weight: float, why: str) -> None:
        scores[t] += weight
        signals.append(f"{why} (+{weight:g} {t.value})")

    # ─── Structural signals: the strongest discriminator (D-017) ─────────────
    # Which headings count as campaign signals is owned by `patterns`, via the
    # Section.is_campaign property — never re-listed here, or the two drift.
    campaign_headings = (
        sorted({s.heading.upper() for s in doc.sections if s.is_campaign}) if doc else []
    )
    if campaign_headings:
        add(AdvisoryType.THREAT_LANDSCAPE, 3.0, f"section {'/'.join(campaign_headings)}")

    if doc and any(s.is_ioc for s in doc.sections):
        add(AdvisoryType.THREAT_LANDSCAPE, 2.0, "IOC section present")
    if ioc_count >= 5:
        add(AdvisoryType.THREAT_LANDSCAPE, 1.5, f"{ioc_count} indicators")
    elif ioc_count > 0:
        add(AdvisoryType.THREAT_LANDSCAPE, 0.5, f"{ioc_count} indicators")

    has_affected = bool(doc and any(s.is_affected_products for s in doc.sections))
    if cve_count and has_affected:
        add(AdvisoryType.CVE_ADVISORY, 3.0, f"{cve_count} CVE(s) + affected-products section")
    elif cve_count:
        add(AdvisoryType.CVE_ADVISORY, 2.0, f"{cve_count} CVE(s)")
    elif has_affected:
        add(AdvisoryType.SECURITY_BULLETIN, 1.5, "affected-products section, no CVE")

    if has_cvss_vector:
        add(AdvisoryType.CVE_ADVISORY, 1.0, "CVSS vector present")

    # ─── Title and prose ────────────────────────────────────────────────────
    if _SECURITY_UPDATE_TITLE.search(title or ""):
        add(AdvisoryType.SECURITY_BULLETIN, 2.5, "title matches vendor-update pattern")
    if cve_count >= 15:
        add(AdvisoryType.SECURITY_BULLETIN, 1.5, f"{cve_count} CVEs — roll-up bulletin")

    threat_hits = len(set(_THREAT_WORDS.findall(f"{title} {body_text[:4000]}")))
    if threat_hits >= 3:
        add(AdvisoryType.THREAT_LANDSCAPE, 2.0, f"{threat_hits} threat-vocabulary terms")
    elif threat_hits:
        add(AdvisoryType.THREAT_LANDSCAPE, 1.0, f"{threat_hits} threat-vocabulary term(s)")

    # Naming no CVE *and* no affected product is itself evidence: whatever this
    # is, it is not a vulnerability advisory. Combined with threat vocabulary
    # that is a positive identification, not merely an absence.
    #
    # Requires `doc`: the absence of a section we never looked for is not
    # evidence of anything. Without this guard an email-only advisory scored
    # 0.71 on the strength of one vocabulary hit.
    if doc is not None and threat_hits and not cve_count and not has_affected:
        add(AdvisoryType.THREAT_LANDSCAPE, 1.5, "no CVE and no affected-products section")

    # ─── The regulator's own label: a weak prior only ───────────────────────
    label = (regulator_type or "").strip().lower()
    if label:
        if any(word in label for word in _REGULATOR_THREAT_TYPES):
            add(AdvisoryType.THREAT_LANDSCAPE, 2.0, f"regulator Type={regulator_type!r}")
        elif "security update" in label:
            add(AdvisoryType.SECURITY_BULLETIN, 1.0, f"regulator Type={regulator_type!r}")
        elif "vulnerab" in label and cve_count:
            # Deliberately weak: 128/135 say this, including campaigns. Only
            # counted when a CVE actually corroborates it.
            add(AdvisoryType.CVE_ADVISORY, 0.5, f"regulator Type={regulator_type!r} (weak prior)")

    # An advisory about CVEs that names no CVE is a contradiction. Without this
    # the regulator's blanket "Vulnerability" label filed IoT botnets and
    # ransomware-affiliate reports as CVE advisories.
    if not cve_count and scores[AdvisoryType.CVE_ADVISORY] > 0:
        scores[AdvisoryType.CVE_ADVISORY] = 0.0
        signals.append("CVE_ADVISORY suppressed: no CVE found")

    total = sum(scores.values())
    if total <= 0:
        return Classification(AdvisoryType.OTHER, Decimal("0.00"), [*signals, "no signals"])

    # Deterministic ordering, so an exact tie never depends on dict insertion
    # order. THREAT_LANDSCAPE outranks the vulnerability types on a tie: a
    # campaign misfiled as a CVE advisory loses the IOC workflow entirely,
    # which is the more expensive error.
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], _TIE_BREAK_ORDER.index(kv[0])))
    best, best_score = ranked[0]
    runner_up_score = ranked[1][1]

    # Confidence combines two independent things, each counted once:
    #   margin   — how clearly the winner beat the runner-up (a two-horse race;
    #              third and fourth places are noise, not competition)
    #   evidence — how much signal there was at all, saturating once we have a
    #              strong structural signal plus corroboration
    # `winner / total` alone rated a single weak prior as 1.00, which is why
    # nothing was ever flagged for review.
    margin = best_score / (best_score + runner_up_score) if runner_up_score else 1.0
    evidence = min(1.0, best_score / _EVIDENCE_SATURATION)
    confidence = Decimal(str(round(margin * evidence, 2)))
    return Classification(type=best, confidence=confidence, signals=signals)


#: Tie-break precedence; see the comment at the call site.
_TIE_BREAK_ORDER = [
    AdvisoryType.THREAT_LANDSCAPE,
    AdvisoryType.SECURITY_BULLETIN,
    AdvisoryType.CVE_ADVISORY,
    AdvisoryType.OTHER,
]

#: Winner score at which evidence is considered full strength — roughly one
#: strong structural signal (3.0) plus light corroboration.
_EVIDENCE_SATURATION = 3.5
