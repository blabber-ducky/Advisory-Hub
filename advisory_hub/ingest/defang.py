"""Refanging and defanging of indicators.

The regulator ships IOCs already defanged (``154[.]196[.]162[.]76``,
``hxxps://``). We must **refang before matching** — a plain IPv4 regex over the
corpus found 45 addresses; refanging first found 101 — and **store both forms**,
rendering only the defanged one. See CLAUDE.md §2.3 and D-010.
"""

from __future__ import annotations

import re

# Bracketed/parenthesised/braced dot, with optional surrounding whitespace.
_DOT = re.compile(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", re.IGNORECASE)
_COLON = re.compile(r"[\[\(\{]\s*:\s*[\]\)\}]")
_AT = re.compile(r"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", re.IGNORECASE)
_SCHEME = re.compile(r"\bh(?:xx|XX|\*\*)p(s?)\b")
# "http[s]://" and "http[://]" styles.
_SCHEME_BRACKET = re.compile(r"\bhttp(s?)\s*[\[\(]\s*(?:s?\s*[\]\)]\s*)?:?/*", re.IGNORECASE)

_DEFANG_DOT = re.compile(r"\.")
_DEFANG_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)


def refang(text: str) -> str:
    """Convert defanged notation back to the real value.

    Handles ``[.]``, ``(.)``, ``{.}``, ``[dot]``, ``[:]``, ``[@]``, ``[at]``,
    and ``hxxp``/``hXXp``. Punycode IDNs survive unchanged — the corpus contains
    ``xn--90aguaqgfu[.]xn--p1ai``, which must round-trip.
    """
    if not text:
        return text
    out = _DOT.sub(".", text)
    out = _COLON.sub(":", out)
    out = _AT.sub("@", out)
    return _SCHEME.sub(r"http\1", out)


def defang(value: str) -> str:
    """Render a value safe to display. Never produces a clickable indicator."""
    if not value:
        return value
    out = _DEFANG_SCHEME.sub(r"hxxp\1://", value)
    return _DEFANG_DOT.sub("[.]", out)


def defang_url(value: str) -> str:
    """Defang a URL, also neutering the scheme separator."""
    out = defang(value)
    return out.replace("://", "[://]", 1) if "://" in out else out


def is_defanged(text: str) -> bool:
    return bool(_DOT.search(text) or _SCHEME.search(text) or _COLON.search(text))
