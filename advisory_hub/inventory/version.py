"""Version normalisation and comparison — the tiered comparator, Phase 2d.

`normalise_version()` (tier 1: digit-run extraction) is what's stored on
every `inventory_software`/`inventory_device_software` row, unchanged since
Phase 2b/2c — it's a storage format, not a comparison, and stays honest
about what it didn't parse.

`compare_versions()` / `version_in_range()` are the actual matching
primitives, added here in 2d:

1. **PEP 440** (`packaging.version.Version`) — tried first, since a large
   share of real-world dotted versions (`120.0.6099.109`) happen to be
   valid PEP 440 too, and PEP 440 gets pre-release ordering right
   (`2.15.0rc1 < 2.15.0`) where naive digit extraction does not.
2. **Numeric tuple** (tier 1, zero-padded to equal length) — used when
   either side isn't PEP-440-shaped.
3. **Give up honestly.** If neither tier parses both sides, the comparison
   returns `None` — recorded as `POSSIBLE` with "version format not
   comparable", never guessed. Java `8u391`, Windows builds, and
   `YYYY CUnn` notation are not special-cased with dedicated handlers: tier
   1's digit-run extraction already recovers a comparable tuple from all
   three in practice (`8u391` → `[8, 391]`, `"2019 CU21"` → `[2019, 21]`),
   so a dedicated "known-format" tier wasn't worth building yet — revisit
   if real scan results show it guessing wrong on those shapes.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

_LEADING_INT_RUN = re.compile(r"\d+")

#: `version_parts` is a Postgres `integer[]` column (32-bit). A real export
#: in this project's `Inventory/` sample data ("Asure ID") carries a
#: corrupted version field with a 195-digit run that overflowed it and
#: crashed the insert — found by actually running real data through this
#: path, not by inspection. No genuine version component is anywhere near
#: this large; treating an implausible one as unparseable is honest, not a
#: guess, and keeps a single dirty CSV row from taking down a whole commit.
_MAX_COMPONENT = 2_147_483_647  # int32 max


def normalise_version(raw: str | None) -> tuple[str | None, list[int] | None]:
    """Returns `(version_normalized, version_parts)`. Both `None` if `raw`
    doesn't contain any digit run at all, or if any run is too large to be
    a plausible version component (see `_MAX_COMPONENT`)."""
    if not raw:
        return None, None
    parts = [int(m) for m in _LEADING_INT_RUN.findall(raw)]
    if not parts or any(p > _MAX_COMPONENT for p in parts):
        return None, None
    return ".".join(str(p) for p in parts), parts


def _parse_pep440(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _pad(a: list[int], b: list[int]) -> tuple[list[int], list[int]]:
    n = max(len(a), len(b))
    return a + [0] * (n - len(a)), b + [0] * (n - len(b))


def compare_versions(a: str, b: str) -> int | None:
    """Returns -1/0/1 (`a<b` / `a==b` / `a>b`), or `None` if the two
    versions can't be compared with confidence."""
    pa, pb = _parse_pep440(a), _parse_pep440(b)
    if pa is not None and pb is not None:
        if pa < pb:
            return -1
        if pa > pb:
            return 1
        return 0

    _, parts_a = normalise_version(a)
    _, parts_b = normalise_version(b)
    if parts_a is None or parts_b is None:
        return None
    padded_a, padded_b = _pad(parts_a, parts_b)
    if padded_a < padded_b:
        return -1
    if padded_a > padded_b:
        return 1
    return 0


def version_in_range(
    version: str,
    *,
    min_version: str | None = None,
    min_inclusive: bool = True,
    max_version: str | None = None,
    max_inclusive: bool = False,
) -> bool | None:
    """`None` means "couldn't compare" — the caller must not treat that as
    either a match or a non-match."""
    if min_version is not None:
        cmp = compare_versions(version, min_version)
        if cmp is None:
            return None
        if cmp < 0 or (cmp == 0 and not min_inclusive):
            return False
    if max_version is not None:
        cmp = compare_versions(version, max_version)
        if cmp is None:
            return None
        if cmp > 0 or (cmp == 0 and not max_inclusive):
            return False
    return True
