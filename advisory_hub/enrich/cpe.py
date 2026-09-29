"""CPE 2.3 parsing and normalisation.

CPE match data is what makes Phase-2 inventory matching accurate rather than
string-guessing (D-004), so vendor and product are normalised here once, in the
same way the inventory side will normalise them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>:...
_CPE23 = re.compile(
    r"^cpe:2\.3:(?P<part>[aoh\*\-]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):"
    r"(?P<update>[^:]*):(?P<edition>[^:]*):(?P<language>[^:]*):(?P<sw_edition>[^:]*):"
    r"(?P<target_sw>[^:]*):(?P<target_hw>[^:]*):(?P<other>[^:]*)$"
)

#: CPE escapes literals with a backslash: `apache\:doris`, `4\.1`.
_UNESCAPE = re.compile(r"\\(.)")

_ANY = {"*", "-", ""}


@dataclass(frozen=True, slots=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str | None
    target_sw: str | None
    uri: str

    @property
    def is_application(self) -> bool:
        return self.part == "a"

    @property
    def is_os(self) -> bool:
        return self.part == "o"

    @property
    def has_explicit_version(self) -> bool:
        """A pinned version in the URI itself, rather than a range."""
        return self.version is not None


def parse_cpe(uri: str) -> Cpe | None:
    """Parse a CPE 2.3 URI. Returns ``None`` for anything unrecognised.

    Deliberately strict: a mis-parsed CPE produces a wrong inventory match,
    which is worse than no match at all.
    """
    m = _CPE23.match((uri or "").strip())
    if not m:
        return None
    vendor = normalise_component(m.group("vendor"))
    product = normalise_component(m.group("product"))
    if not vendor or not product:
        return None
    version = m.group("version")
    target_sw = m.group("target_sw")
    return Cpe(
        part=m.group("part"),
        vendor=vendor,
        product=product,
        version=None if version in _ANY else _unescape(version),
        target_sw=None if target_sw in _ANY else normalise_component(target_sw),
        uri=uri.strip(),
    )


def normalise_component(value: str) -> str:
    """Canonical form for a vendor or product component.

    Lowercased, unescaped, and with underscores turned into spaces — NVD writes
    ``application_server`` where an inventory export writes ``Application
    Server``. The inventory side normalises identically.
    """
    if value in _ANY:
        return ""
    out = _unescape(value).lower().strip()
    out = out.replace("_", " ")
    return re.sub(r"\s+", " ", out)


def _unescape(value: str) -> str:
    return _UNESCAPE.sub(r"\1", value)
