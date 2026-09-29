"""The inventory-vs-advisory matching engine — Phase 2d, extended in
Phase 3 to also match `AdvisoryProduct.parsed_range` (see D-032).

Pure functions: given affected-product specs and inventory candidates,
produce match candidates with a confidence tier and a rationale a human
can check without reading code. Persistence (`scan_run`/`scan_match`) is
`core.services.scan`'s job, mirroring the `ingest/` vs
`core.services.ingestion` split elsewhere in this codebase.

**Two spec sources, deliberately graded differently.** Most specs are
NVD-CPE-sourced (`AffectedSpec.text_derived = False`) — canonical
vendor/product spelling, a structured range straight from NVD. A smaller
set come from `AdvisoryProduct.parsed_range` (`text_derived = True`):
`ingest/version_range.py`'s honest, conservative parse of the regulator's
own free text ("< 17.0.9", "Builds below 16.0.5561.1001"). Both the
version range *and* the vendor/product string on a text-derived spec are
less reliable than NVD's — there's no canonical-naming guarantee, and no
alias table entry means an exact string match is still just an exact
*string* match, not a verified identity. Every text-derived match is
therefore capped at `POSSIBLE`, never `CONFIRMED`/`LIKELY`, regardless of
how clean the version comparison itself was.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from ..core.models.enums import MatchConfidence, MatchMethod
from .normalise import normalise_product, normalise_vendor
from .version import version_in_range


@dataclass(slots=True)
class AffectedSpec:
    """One "this vendor/product in this version range is affected" claim.

    From NVD CPE data by default — `vendor`/`product` are then NVD's own
    canonical (lowercase) spelling, no alias lookup needed on this side.
    When `text_derived` is set, `vendor`/`product` instead come from
    `AdvisoryProduct` (whatever spelling the regulator used) and the range
    from `ingest/version_range.py` — see the module docstring."""

    cve_id: str | None
    vendor: str
    product: str
    min_version: str | None
    min_inclusive: bool
    max_version: str | None
    max_inclusive: bool
    #: A single exact vulnerable version (no range) — from a CPE match
    #: entry with neither a start nor an end bound, or a bare version in
    #: advisory text.
    exact_version: str | None = None
    #: True for a spec built from `AdvisoryProduct.parsed_range` rather
    #: than NVD CPE data — caps confidence at `POSSIBLE` regardless of how
    #: clean the version comparison was. See the module docstring.
    text_derived: bool = False


@dataclass(slots=True)
class InventoryCandidate:
    """One row from `inventory_software` — `vendor`/`product` are raw, as
    the export/adapter wrote them. `snapshot_id` lets a scan span several
    sources at once and still attribute each match to the snapshot it came
    from (`scan_match.snapshot_id` is a single FK, not a list)."""

    snapshot_id: uuid.UUID
    vendor: str | None
    product: str
    version: str | None
    device_count: int
    device_ids: list[uuid.UUID] | None = None


@dataclass(slots=True)
class MatchCandidate:
    #: `None` for a text-derived spec — `AdvisoryProduct` claims aren't
    #: attributed to one specific CVE within a multi-CVE advisory.
    cve_id: str | None
    snapshot_id: uuid.UUID
    vendor: str | None
    product: str
    matched_version: str
    affected_range: str
    device_count: int
    device_ids: list[uuid.UUID] | None
    match_method: MatchMethod
    confidence: MatchConfidence
    rationale: str


def _range_description(spec: AffectedSpec) -> str:
    """Plain text — `rationale`/`affected_range` are stored as-is and
    rendered as-is by both the API (JSON) and the web UI (no
    auto-escaping to undo), so no HTML entities here."""
    if spec.exact_version is not None:
        return f"== {spec.exact_version}"
    parts = []
    if spec.min_version:
        parts.append((">=" if spec.min_inclusive else ">") + f" {spec.min_version}")
    if spec.max_version:
        parts.append(("<=" if spec.max_inclusive else "<") + f" {spec.max_version}")
    return ", ".join(parts) if parts else "(any version)"


def _cve_suffix(spec: AffectedSpec) -> str:
    return f" ({spec.cve_id})" if spec.cve_id else ""


def match_candidates(
    specs: list[AffectedSpec],
    inventory: list[InventoryCandidate],
    alias_map: dict[str, str],
) -> list[MatchCandidate]:
    """No fuzzy product matching in this pass — only exact normalised-string
    product matches. `alias_map` still does real work on the *vendor* side:
    an inventory row whose raw vendor needed an alias to reach the spec's
    canonical form is graded `LIKELY`, not `CONFIRMED` — the match is real,
    but one more inference deep than a direct string match."""
    results: list[MatchCandidate] = []

    for spec in specs:
        spec_product = normalise_product(spec.product)

        for candidate in inventory:
            if normalise_product(candidate.product) != spec_product:
                continue

            raw_vendor_key = (candidate.vendor or "").strip().lower()
            cand_vendor = normalise_vendor(candidate.vendor, alias_map)
            if cand_vendor != spec.vendor:
                continue
            vendor_via_alias = raw_vendor_key in alias_map and raw_vendor_key != spec.vendor

            if not candidate.version:
                if spec.text_derived:
                    no_version_method = MatchMethod.TEXT_RANGE
                elif spec.exact_version:
                    no_version_method = MatchMethod.CPE_EXACT
                else:
                    no_version_method = MatchMethod.CPE_RANGE
                results.append(
                    MatchCandidate(
                        cve_id=spec.cve_id,
                        snapshot_id=candidate.snapshot_id,
                        vendor=candidate.vendor,
                        product=candidate.product,
                        matched_version="(unknown)",
                        affected_range=_range_description(spec),
                        device_count=candidate.device_count,
                        device_ids=candidate.device_ids,
                        match_method=no_version_method,
                        confidence=MatchConfidence.POSSIBLE,
                        rationale=(
                            f"{candidate.product} is installed but no version was recorded — "
                            f"can't check it against {spec.vendor}:{spec_product} "
                            f"{_range_description(spec)}{_cve_suffix(spec)}"
                        ),
                    )
                )
                continue

            if spec.exact_version is not None:
                in_range = version_in_range(
                    candidate.version,
                    min_version=spec.exact_version,
                    min_inclusive=True,
                    max_version=spec.exact_version,
                    max_inclusive=True,
                )
                method = MatchMethod.TEXT_RANGE if spec.text_derived else MatchMethod.CPE_EXACT
            else:
                in_range = version_in_range(
                    candidate.version,
                    min_version=spec.min_version,
                    min_inclusive=spec.min_inclusive,
                    max_version=spec.max_version,
                    max_inclusive=spec.max_inclusive,
                )
                method = MatchMethod.TEXT_RANGE if spec.text_derived else MatchMethod.CPE_RANGE

            if in_range is None:
                results.append(
                    MatchCandidate(
                        cve_id=spec.cve_id,
                        snapshot_id=candidate.snapshot_id,
                        vendor=candidate.vendor,
                        product=candidate.product,
                        matched_version=candidate.version,
                        affected_range=_range_description(spec),
                        device_count=candidate.device_count,
                        device_ids=candidate.device_ids,
                        match_method=method,
                        confidence=MatchConfidence.POSSIBLE,
                        rationale=(
                            f"{candidate.product} {candidate.version} — version format not "
                            f"comparable to range {_range_description(spec)}{_cve_suffix(spec)}"
                        ),
                    )
                )
                continue

            if not in_range:
                continue

            # An open-ended range with no lower bound can't distinguish "just
            # patched" from "always been vulnerable" — real signal, softened
            # confidence, not silently dropped.
            open_ended = spec.exact_version is None and spec.min_version is None

            if spec.text_derived:
                # Advisory-text-derived: vendor/product spelling isn't
                # NVD-canonical and the range came from a regulator's prose,
                # not a structured feed — never more than POSSIBLE, however
                # clean the version comparison itself was.
                confidence = MatchConfidence.POSSIBLE
            elif open_ended:
                confidence = MatchConfidence.POSSIBLE
            elif vendor_via_alias:
                confidence = MatchConfidence.LIKELY
            else:
                confidence = MatchConfidence.CONFIRMED

            source_label = "advisory text" if spec.text_derived else "NVD CPE range"
            rationale = (
                f"{candidate.product} {candidate.version} falls inside {source_label} "
                f"{spec.vendor}:{spec_product} {_range_description(spec)}{_cve_suffix(spec)}"
            )
            if spec.text_derived:
                rationale += " — from the regulator's own text, not NVD-verified"
            if vendor_via_alias:
                rationale += f" — matched via alias {candidate.vendor!r} → {spec.vendor}"
            if open_ended:
                rationale += " — open-ended range with no lower bound, manual check advised"

            results.append(
                MatchCandidate(
                    cve_id=spec.cve_id,
                    snapshot_id=candidate.snapshot_id,
                    vendor=candidate.vendor,
                    product=candidate.product,
                    matched_version=candidate.version,
                    affected_range=_range_description(spec),
                    device_count=candidate.device_count,
                    device_ids=candidate.device_ids,
                    match_method=method,
                    confidence=confidence,
                    rationale=rationale,
                )
            )

    return results
