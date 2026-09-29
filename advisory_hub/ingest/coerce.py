"""Coerce regulator field values onto our enums.

Field values are enums with a small vocabulary, so they are parsed as enums
rather than taken as free text. One corpus message (DOH-2026562) has
``Risk level: High`` immediately followed by a repeated subject line with no
intervening label, so the sliced value is ``"High Security Advisory :: …"``.
Matching a leading known token handles that without special-casing.
"""

from __future__ import annotations

import re

from ..core.models.enums import SEVERITY_TO_PRIORITY, Priority, Severity

_SEVERITY_WORDS: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

_LEADING_WORD = re.compile(r"^\s*([A-Za-z]+)")


def parse_severity(value: str | None) -> Severity | None:
    """Read a severity from the leading token of a field value."""
    if not value:
        return None
    m = _LEADING_WORD.match(value)
    if not m:
        return None
    return _SEVERITY_WORDS.get(m.group(1).lower())


def severity_from_text(text: str | None) -> Severity | None:
    """Find the highest severity mentioned anywhere — used for PDF cover pages."""
    if not text:
        return None
    found = [
        _SEVERITY_WORDS[w] for w in re.findall(r"[A-Za-z]+", text.lower()) if w in _SEVERITY_WORDS
    ]
    return max(found, key=severity_rank) if found else None


def severity_rank(severity: Severity) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]


def higher_severity(a: Severity | None, b: Severity | None) -> Severity | None:
    """Take the more severe of two readings.

    Under-triaging a Critical because a PDF cover page says High is the more
    expensive error — see D-019.
    """
    if a is None:
        return b
    if b is None:
        return a
    return a if severity_rank(a) >= severity_rank(b) else b


def priority_for(severity: Severity | None) -> Priority | None:
    return SEVERITY_TO_PRIORITY.get(severity) if severity else None


def normalise_ref(prefix: str, number: str) -> str:
    return f"{prefix.upper().strip()}-{number.strip()}"


def title_fingerprint(title: str) -> str:
    """Normalised title hash, for re-issue detection (D-020).

    ``DOH-2026550`` and ``DOH-2026552`` carry byte-identical titles eight hours
    apart under different reference numbers; content hashing cannot see that.
    """
    import hashlib

    normalised = re.sub(r"[^a-z0-9]+", "", (title or "").lower())
    return hashlib.sha256(normalised.encode()).hexdigest()
