"""Structured version-range extraction from PDF-parsed advisory text.

`ProductClaim.version_expression`/`.fixed_version` are the raw strings a
regulator writes ("< 17.0.9", "Builds below 16.0.5561.1001", "1.26.1 and
earlier") — always kept verbatim. This module turns the subset that are
genuinely unambiguous into a structured `parsed_range` (the same shape
`inventory.matcher.AffectedSpec` needs), so a scan can compare an
inventory-installed version against it.

**Honest, not clever.** Real advisory text is wildly heterogeneous:
semicolon-separated multi-range lists, comma-separated discrete version
lists, pure prose with no version at all, build-qualified strings with
embedded spaces. Trying to force all of that into one range would mean
guessing — CLAUDE.md §2.2 is explicit that extraction is evidence, not
truth. This parser recognises a handful of single-clause patterns and
returns `None` for everything else, including anything with a `;` or an
ambiguous comma-separated list — no half-parsed, misleading range is ever
produced.
"""

from __future__ import annotations

import re
from typing import TypedDict

#: A chunk this parser is willing to treat as "a version" — must start
#: with a digit. Filters out prose words a looser `[\w.]+` would otherwise
#: catch ("Refer", "your", "Critical").
_VERSION_CHUNK = r"\d[\w.\-]*"

# Real PDF extraction yields several visually-similar dash characters for a
# simple range ("10.3.0" + one of these + "10.3.1") — all normalised to a
# plain hyphen before matching.
_DASH_NORMALISE = re.compile("[‒–—−]|--+")  # noqa: RUF001

_COMPARATOR = re.compile(rf"(<=|>=|<|>)\s*({_VERSION_CHUNK})")
_BELOW_WORDS = re.compile(
    rf"(?i)\b(?:below|prior\s+to|before|earlier\s+than|older\s+than|up\s+to)\s+({_VERSION_CHUNK})"
)
_AND_EARLIER = re.compile(rf"(?i)\b({_VERSION_CHUNK})\s+(?:and|or)\s+(?:earlier|below|prior)\b")
_AND_LATER = re.compile(rf"(?i)\b({_VERSION_CHUNK})\s+(?:and|or)\s+(?:later|above|newer)\b")
#: A leading "Versions"/"Builds"/"Releases" is the same anchor the existing
#: prose-extraction pattern (`ingest/patterns.py`'s `VERSION_RANGE`) already
#: relies on — proven against the real corpus in Phase 1a. Without an
#: anchor, only a bare "X - Y" spanning virtually the whole string is
#: trusted (see the whole-clause check in `_parse_text`).
_SIMPLE_RANGE_ANCHORED = re.compile(
    rf"(?i)\b(?:versions?|builds?|releases?)\s+({_VERSION_CHUNK})\s*(?:-|to|through)\s*({_VERSION_CHUNK})\b"
)
_SIMPLE_RANGE = re.compile(rf"(?i)\b({_VERSION_CHUNK})\s*(?:-|to|through)\s*({_VERSION_CHUNK})\b")
_BARE_VERSION = re.compile(rf"^({_VERSION_CHUNK})$")

#: Two or more comma-separated version-looking chunks with no range
#: operator between them — a discrete list ("7.0, 7.2, 7.4"), not a range.
_COMMA_LIST = re.compile(rf"^{_VERSION_CHUNK}(?:\s*,\s*{_VERSION_CHUNK}){{1,}}$")


class ParsedRange(TypedDict):
    min_version: str | None
    min_inclusive: bool
    max_version: str | None
    max_inclusive: bool
    exact_version: str | None
    #: Which raw field the range was actually derived from — the version
    #: expression, or (only when that yielded nothing) the fixed version.
    source: str


def parse_version_range(
    version_expression: str | None, fixed_version: str | None
) -> ParsedRange | None:
    parsed = _parse_text(version_expression) if version_expression else None
    if parsed is not None:
        return {**parsed, "source": "version_expression"}

    # version_expression didn't yield a clean range — a bare, single fixed
    # version at least tells us "vulnerable if strictly older than this".
    if fixed_version:
        bare = _BARE_VERSION.match(_normalise(fixed_version).strip())
        if bare:
            return _range(max_version=bare.group(1), max_inclusive=False, source="fixed_version")
    return None


def _normalise(text: str) -> str:
    return _DASH_NORMALISE.sub("-", text)


def _parse_text(text: str) -> ParsedRange | None:
    text = _normalise(text).strip()
    if not text or ";" in text:
        return None
    if _COMMA_LIST.match(text):
        return None

    comparator_matches = _COMPARATOR.findall(text)
    if len(comparator_matches) > 1:
        # More than one "< X" / ">= Y" clause — e.g. two separate ranges
        # for two product variants in one cell. Genuinely ambiguous: don't
        # silently pick the first one.
        return None
    if comparator_matches:
        op, version = comparator_matches[0]
        if op == "<":
            return _range(max_version=version, max_inclusive=False)
        if op == "<=":
            return _range(max_version=version, max_inclusive=True)
        if op == ">":
            return _range(min_version=version, min_inclusive=False)
        return _range(min_version=version, min_inclusive=True)  # ">="

    if m := _BELOW_WORDS.search(text):
        return _range(max_version=m.group(1), max_inclusive=False)

    if m := _AND_EARLIER.search(text):
        return _range(max_version=m.group(1), max_inclusive=True)

    if m := _AND_LATER.search(text):
        return _range(min_version=m.group(1), min_inclusive=True)

    if m := _SIMPLE_RANGE_ANCHORED.search(text):
        return _range(
            min_version=m.group(1), min_inclusive=True, max_version=m.group(2), max_inclusive=True
        )

    # Unanchored "X - Y" is only trusted if it's essentially the whole
    # clause — otherwise a longer sentence with an incidental "X to Y"
    # shaped substring could be misread.
    if (m := _SIMPLE_RANGE.search(text)) and m.end() - m.start() >= len(text) - 3:
        return _range(
            min_version=m.group(1),
            min_inclusive=True,
            max_version=m.group(2),
            max_inclusive=True,
        )

    if m := _BARE_VERSION.match(text):
        return _range(exact_version=m.group(1))

    return None


def _range(
    *,
    min_version: str | None = None,
    min_inclusive: bool = True,
    max_version: str | None = None,
    max_inclusive: bool = False,
    exact_version: str | None = None,
    source: str = "version_expression",
) -> ParsedRange:
    return {
        "min_version": min_version,
        "min_inclusive": min_inclusive,
        "max_version": max_version,
        "max_inclusive": max_inclusive,
        "exact_version": exact_version,
        "source": source,
    }
