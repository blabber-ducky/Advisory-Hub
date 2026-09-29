"""Vendor and product name normalisation — Phase 2d.

Matching only works if both sides (inventory and NVD CPE data) are
normalised the same way. `vendor_alias` maps the many ways a vendor's name
appears across export sources — `"Microsoft Corporation"`,
`"Microsoft Corp"` — onto NVD's canonical lowercase form (`"microsoft"`).
Seeded here with common vendors; extended by admins as mismatches surface,
which the scan UI (Phase 2e) makes easy by showing near-miss names it
*didn't* match.

Product normalisation lowercases, collapses whitespace, and strips common
edition/architecture noise. Deliberately **not** kept as a separate side
field — see docs/inventory-matching.md's "As built" note: the design
sketch called for preserving stripped noise in its own column, but
`inventory_software`/`inventory_device_software` were never given one, and
adding it wasn't worth a migration for data nothing downstream consumes
yet. `product_raw`/`vendor_raw` already keep the untouched original.
"""

from __future__ import annotations

import re

#: (alias as commonly exported, canonical NVD-style lowercase vendor name).
#: Not exhaustive — this is a starting seed, not a claim of completeness.
SEED_VENDOR_ALIASES: list[tuple[str, str]] = [
    ("Microsoft Corporation", "microsoft"),
    ("Microsoft Corp", "microsoft"),
    ("Microsoft", "microsoft"),
    ("Google LLC", "google"),
    ("Google Inc.", "google"),
    ("Google Inc", "google"),
    ("Google", "google"),
    ("Mozilla", "mozilla"),
    ("Mozilla Corporation", "mozilla"),
    ("Mozilla Foundation", "mozilla"),
    ("Adobe Systems", "adobe"),
    ("Adobe Systems Incorporated", "adobe"),
    ("Adobe Systems Inc.", "adobe"),
    ("Adobe Inc.", "adobe"),
    ("Adobe", "adobe"),
    ("Oracle Corporation", "oracle"),
    ("Oracle America, Inc.", "oracle"),
    ("Oracle", "oracle"),
    ("Apple Inc.", "apple"),
    ("Apple Computer, Inc.", "apple"),
    ("Apple", "apple"),
    ("Cisco Systems, Inc.", "cisco"),
    ("Cisco Systems", "cisco"),
    ("Cisco", "cisco"),
    ("VMware, Inc.", "vmware"),
    ("VMware Inc.", "vmware"),
    ("VMware", "vmware"),
    ("Zoom Video Communications, Inc.", "zoom"),
    ("Zoom Video Communications", "zoom"),
    ("Zoom", "zoom"),
    ("Slack Technologies, Inc.", "slack"),
    ("Slack Technologies", "slack"),
    ("Trellix", "trellix"),
    ("McAfee, LLC", "mcafee"),
    ("McAfee LLC", "mcafee"),
    ("McAfee", "mcafee"),
    ("Zoho Corporation Pvt. Ltd.", "zoho"),
    ("Zoho Corporation", "zoho"),
    ("Zoho", "zoho"),
    ("The Apache Software Foundation", "apache"),
    ("Apache Software Foundation", "apache"),
    ("Apache", "apache"),
    ("Docker Inc.", "docker"),
    ("Docker, Inc.", "docker"),
    ("Docker", "docker"),
    ("Wireshark Foundation", "wireshark"),
    ("PuTTY", "putty"),
    ("Igor Pavlov", "7-zip"),  # NVD's own CPE attributes 7-Zip to its author
    ("7-Zip", "7-zip"),
    ("Notepad++ Team", "notepad++"),
    ("Notepad++", "notepad++"),
    ("Amazon Web Services, Inc.", "amazon"),
    ("Amazon.com, Inc.", "amazon"),
    ("Amazon", "amazon"),
    ("IBM Corporation", "ibm"),
    ("IBM", "ibm"),
    ("SAP SE", "sap"),
    ("SAP", "sap"),
    ("RealVNC Ltd", "realvnc"),
    ("RealVNC", "realvnc"),
    ("Citrix Systems, Inc.", "citrix"),
    ("Citrix Systems", "citrix"),
    ("Citrix", "citrix"),
]

_NOISE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\(x64\)",
        r"\(x86\)",
        r"\(64-bit\)",
        r"\(32-bit\)",
        r"\b64-bit\b",
        r"\b32-bit\b",
        r"-\s*en-us\b",
    )
]


def normalise_vendor(raw: str | None, alias_map: dict[str, str]) -> str | None:
    """`alias_map` is keyed by lowercased alias — load it once per operation
    via `load_vendor_alias_map()`, not per row."""
    if not raw:
        return None
    trimmed = raw.strip()
    if not trimmed:
        return None
    hit = alias_map.get(trimmed.lower())
    if hit is not None:
        return hit
    return trimmed.lower()


def normalise_product(raw: str) -> str:
    text = raw.strip().lower()
    for pattern in _NOISE_PATTERNS:
        text = pattern.sub("", text)
    return re.sub(r"\s+", " ", text).strip()
