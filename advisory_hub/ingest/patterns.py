"""Compiled regexes shared across extractors.

Every pattern here was validated against the 135-advisory corpus. Where a
pattern is deliberately permissive, the corpus variant that forced it is named.
"""

from __future__ import annotations

import re

# ─── Subject ─────────────────────────────────────────────────────────────────
#: Matches 135/135. The permissiveness is load-bearing — real variants:
#:   "DOH- 2026550 - Title"   (space after the dash)
#:   "DOH-2026512- Title"     (no space before the title)
#:   "DOH-2026607 Title"      (no separator at all)
#:   "Security Advisory :: "  ("::" is sanitised to "_" in filenames)
SUBJECT = re.compile(
    r"^\s*(?:\[EXTERNAL\]\s*)?Security\s+Advisory\s*(?:::|:|_|-)?\s*"
    r"(?P<prefix>[A-Z]{2,6})\s*-?\s*(?P<number>\d{4,8})\s*[-\u2013\u2014]?\s*(?P<title>.*?)\s*$",
    re.IGNORECASE,
)

#: Reply/forward markers and the gateway's [EXTERNAL] tag, in any order and
#: repeated — "FW: [EXTERNAL] Security Advisory …", "RE: FW: …". Stripped
#: before SUBJECT is matched, so a forwarded advisory keeps its reference.
SUBJECT_PREFIXES = re.compile(
    r"^\s*(?:(?:re|fw|fwd|aw|wg|tr|rv)\s*:\s*|\[external\]\s*)+", re.IGNORECASE
)

#: Fallback when SUBJECT doesn't match: a regulator reference anywhere in the
#: subject ("Urgent - DOH-2026550 patch now"). Uppercase prefix only, and
#: never followed by another "-digits", so CVE-2026-1234 can't match.
REFERENCE_ANYWHERE = re.compile(
    r"(?<![A-Za-z0-9])(?P<prefix>[A-Z]{2,6})\s*-\s*(?P<number>\d{4,8})(?![\d-])"
)
#: Identifier schemes that look like a reference but are never a regulator's.
NOT_A_REFERENCE = frozenset({"CVE", "CWE", "CAPEC", "GHSA", "CVSS", "KB", "MS"})

# ─── Email body labelled fields ──────────────────────────────────────────────
#: Presence across the corpus: Reference/Detected on/Type/Risk level/Action
#: Required 135/135; Description 134; Affected Product 128.
BODY_LABELS: tuple[str, ...] = (
    "Vulnerability/Disclosure Detail",
    "Affected Products",
    "Affected Product",
    "Reference",
    "Detected on",
    "Type",
    "Risk level",
    "Risk Level",
    "Description",
    "Action Required",
    "Impact",
    "Recommendation",
)

BODY_LABEL = re.compile(
    r"(?mi)^[ \t\u00a0]*("
    + "|".join(re.escape(x) for x in BODY_LABELS)
    + r")[ \t\u00a0]*:[ \t\u00a0]*"
)

# ─── PDF structure ───────────────────────────────────────────────────────────
#: Repeats on every page — strip before extraction or matches double-count.
PAGE_HEADER = re.compile(
    r"(?mi)^\s*Advisory\s*Number\s*:\s*[A-Z]{2,6}\s*-?\s*\d{4,8}\s*"
    r"(?:Published\s*on\s*:\s*[^\n]*)?$"
)
ADVISORY_NUMBER = re.compile(
    r"Advisory\s*Number\s*:\s*(?P<prefix>[A-Z]{2,6})\s*-?\s*(?P<number>\d{4,8})", re.IGNORECASE
)
PUBLISHED_ON = re.compile(
    r"Published\s*on\s*:\s*(?P<value>[0-9]{1,2}\s*-\s*[A-Za-z]+\s*-\s*[0-9]{4})", re.IGNORECASE
)
COVER_SEVERITY = re.compile(r"(?mi)^\s*Severity\s*:\s*(?P<value>[A-Za-z]+)\s*$")
CLASSIFICATION = re.compile(r"(?mi)^\s*Classified as .*$")

#: ALL-CAPS heading on its own line. Case-sensitive on purpose: lowercase
#: matching produces false positives from ordinary sentence fragments.
#: Trailing lowercase plural is allowed: the corpus IOC heading is literally
#: "IOCs", and a strict ALL-CAPS pattern silently skipped every one of them.
SECTION_HEADING = re.compile(
    r"(?m)^[ \t]*([A-Z][A-Z0-9 &/()\u2013\u2014.\-']{2,60}?s?)[ \t]*:?[ \t]*$"
)

#: Five spellings observed; match the family rather than enumerate.
AFFECTED_HEADING = re.compile(r"^AFFECTED\s+PRODUCTS?\b|^AFFECTED\s+VERSIONS?\b")
IOC_HEADING = re.compile(
    r"^(?:IOCS?|INDICATORS?(?:\s+OF\s+COMPROMISE)?|IOC\s+LIST)$", re.IGNORECASE
)
REFERENCES_HEADING = re.compile(r"^REFERENCES?$")
#: Structural threat-landscape signals — see D-017. ATTACK VECTOR is
#: deliberately excluded: ordinary CVE advisories describe their attack vector
#: too (DOH-2026551, a SharePoint RCE, has one), so it is not discriminating.
CAMPAIGN_HEADING = re.compile(r"^(?:ATTACK\s+CHAIN\s+OVERVIEW|CAMPAIGN\s+OVERVIEW)$")
ATTACK_VECTOR_HEADING = re.compile(r"^ATTACK\s+VECTORS?$")
#: Boilerplate, discarded.
BOILERPLATE_HEADING = re.compile(
    r"^(?:PLEASE\s+NOTE|ACTION|SECURITY\s+OPERATIONS\s+CENTER|ADVISORY)$"
)

# ─── Entities ────────────────────────────────────────────────────────────────
CVE = re.compile(r"\bCVE[-\u2010-\u2015\s]?(\d{4})[-\u2010-\u2015\s]?(\d{4,7})\b", re.IGNORECASE)
CVSS_VECTOR_V3 = re.compile(r"CVSS:3\.[01]/[A-Z:/]+", re.IGNORECASE)
CVSS_VECTOR_V4 = re.compile(r"CVSS:4\.0/[A-Z:/]+", re.IGNORECASE)
#: "CVSS v3.1: 9.1 (Critical)" — the shape used throughout the corpus.
CVSS_SCORE_V3 = re.compile(
    r"CVSS\s*v?\.?\s*3(?:\.[01])?\s*(?:Base\s*Score)?\s*[:=]?\s*(\d{1,2}\.\d)", re.IGNORECASE
)
CVSS_SCORE_V4 = re.compile(
    r"CVSS\s*v?\.?\s*4(?:\.0)?\s*(?:Base\s*Score)?\s*[:=]?\s*(\d{1,2}\.\d)", re.IGNORECASE
)

IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
URL = re.compile(r"\bhttps?://[^\s\)\]\>,]+", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|xyz|top|info|site|online|ru|cn|uk|ae|gov|edu|"
    r"beer|cyou|lat|sbs|cfd|lol|gg|tr|link|shop|club|live|icu|pw|su|tk|invalid|"
    r"xn--[a-z0-9]+)\b",
    re.IGNORECASE,
)

ATTACK_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
THREAT_ACTOR = re.compile(r"\b(?:APT|UNC|FIN|TA|Storm|DEV)[-\s]?\d{2,5}\b", re.IGNORECASE)

#: "Indicator<whitespace>Type" rows in the PDF IOC table.
IOC_ROW = re.compile(
    r"(?mi)^[ \t]*(?P<value>\S{4,200}?)[ \t]{1,}(?P<type>"
    r"IP\s*Address(?:es)?|IPv4|IPv6|Domains?|URLs?|MD-?5|SHA-?1|SHA-?256|SHA-?512|"
    r"Hash(?:es)?|E-?mails?|File\s*Names?|File\s*Paths?|File\s*Hash(?:es)?|"
    r"Registry[^\n]{0,60}|Mutex(?:es)?|User[-\s]?Agents?|Bitcoin[^\n]{0,40}"
    r")[ \t]*$"
)

#: Header of a CSV/XLSX IOC sidecar. One corpus file used "#,Indicator,Indicator Type".
SIDECAR_HEADER = re.compile(
    r"^\s*(?:#\s*,\s*)?indicators?\s*,\s*(?:indicator\s*)?type", re.IGNORECASE
)

#: Version expressions in affected-product prose.
VERSION_RANGE = re.compile(
    r"(?i)\b(?:versions?|builds?|releases?)\s+(?:"
    r"(?P<below>below|prior\s+to|before|earlier\s+than|older\s+than|up\s+to)\s+(?P<below_v>[\w.\-]+)"
    r"|(?P<through>[\w.\-]+)\s*(?:through|to|-|\u2013)\s*(?P<through_end>[\w.\-]+)"
    r"|(?P<exact>[\w.\-]+)\s+and\s+(?:earlier|below|prior)"
    r")"
)

ARABIC = re.compile(r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]")


def normalise_whitespace(text: str) -> str:
    """Collapse NBSP/ZWSP that HTML-derived bodies are full of."""
    return text.replace("\u00a0", " ").replace("\u200b", "").replace("\ufeff", "")
