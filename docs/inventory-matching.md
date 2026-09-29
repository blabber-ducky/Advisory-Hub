# Inventory sources and matching

Phase 2. This is the hardest correctness problem in the system: deciding whether
"Apache Log4j 2.14.1" in a Lansweeper export falls inside "Apache log4j >= 2.0-beta9,
< 2.15.0" from an NVD CPE range. Getting it subtly wrong produces confident,
wrong answers — which is worse than no answer.

## 1. Two modes, deliberately different

| | `AGGREGATE` (CSV) | `DETAILED` (API) |
|---|---|---|
| Sources | Desktop Central, Lansweeper, Azure exports | Desktop Central API, Azure ARM, MS Graph |
| Granularity | Counts per product+version | Per-device rows with identifiers |
| Answers | "**47 endpoints** run Chrome 120.0.6099.109" | "…and here are their device IDs and hostnames" |
| Refresh | Manual upload | Scheduled sync |

Both modes populate `inventory_software` (so counts always work). `DETAILED`
additionally populates `inventory_device` and `inventory_device_software`, which
is what turns a scan result into an actionable ops ticket.

## 2. CSV ingest

### Upload flow

1. Analyst picks a source (or creates one) and uploads a CSV.
2. The file is stored as a blob — the original export is kept.
3. Headers are sniffed and mapped to canonical fields using the source kind's
   built-in profile.
4. **A mapping preview is shown before commit**: detected columns, the first 20
   parsed rows, and any rows that failed to parse. Nothing is written until the
   analyst confirms.
5. On confirm, a new `inventory_snapshot` is created and marked `is_latest`.
   Previous snapshots are retained (scans stay reproducible).

### Built-in column profiles

Profiles are starting points; the mapping is editable per source and saved in
`inventory_source.config`, because every deployment's export columns differ.

| Source | Expected columns (canonical ← common headers) |
|---|---|
| Desktop Central | `product` ← `Software Name`; `version` ← `Software Version`; `device_count` ← `Computer Count` / `Installations`; `vendor` ← `Manufacturer` / `Vendor` |
| Lansweeper | `product` ← `SoftwareName`; `version` ← `SoftwareVersion`; `vendor` ← `Publisher`; `device_count` ← `Count` / `# of Assets` |
| Azure | `product` ← `displayName` / `Name`; `version` ← `version` / `osVersion`; `device_count` ← `count`; OS rows detected by an `osType`/`osName` column |

Rows that don't parse are reported with line numbers, not silently dropped.

### As built (2026-08-21)

Implemented as designed above, with two deliberate simplifications, both
noted in code and both explicitly Phase 2d's job, not skipped:

- **Vendor/product canonicalisation is lowercase-trim only.** The real
  `vendor_alias`-backed normalisation isn't needed until matching exists,
  which is 2d. `InventorySoftware.vendor`/`.product` hold this placeholder
  form for now; `.vendor_raw`/`.product_raw` keep the export's original text.
- **Version normalisation is tier 1 only** (leading-digit-run extraction —
  see §4 below). `version_normalized`/`version_parts` are populated on every
  commit, but the PEP 440 handling and known-format handlers (Java `8u391`,
  Windows builds, `YYYY CUnn`) described in §4 aren't built yet. A version
  that doesn't yield a numeric tuple is stored as `None` — an honest "not
  parsed", never a guess.

Duplicate `(vendor, product, version, kind)` rows within one upload are
summed by `device_count` before storage, so an aggregated export (with a
count column) and a raw per-device export (no count column, one row per
device) produce identical `inventory_software` rows.

### As built (2026-08-22) — corrected against real exports

The table and profiles above were design-stage guesses. Two real exports
(an Endpoint Central "Software Summary" CSV and a Lansweeper "web50" CSV,
placed in `Inventory/`) corrected several columns and revealed a second
OS-row-detection convention:

- **Desktop Central's real headers** are `Software Name` / `Version` /
  `Manufacturer` / `Network Installations` / `Managed Installations` /
  `Software Type` — not the guessed `Software Version` / `Computer Count`.
  OS rows are detected by `Software Type` **equalling** `"Operating
  System"` exactly, reusing the same `product`/`version` columns as regular
  software rows (there's no separate OS-name/version pair, unlike Azure).
- **Lansweeper's real export is semicolon-delimited**, not comma — a
  regional CSV convention the Phase 2b parser hadn't accounted for.
  `csv_parser.py` now sniffs the delimiter
  (`csv.Sniffer().sniff(sample, delimiters=",;\t|")`, falling back to
  comma) instead of assuming one. Headers: `Software` / `Version` /
  `Publisher` / `Total`.
- **`ColumnProfile` gained `os_indicator_value: str | None`** to express
  the two conventions: `None` means "any non-blank value in the indicator
  column signals an OS row, and a separate os-name/os-version column pair
  holds the OS's own name/version" (Azure's convention, unchanged);
  a string means "the indicator column must equal this value exactly, and
  the OS's name/version come from the regular product/version columns"
  (Endpoint Central's convention, new).

**Two real bugs found only by running these files through the actual
pipeline** — not by inspection or synthetic tests. Both are documented in
detail in docs/decisions.md D-026 and D-027:
- A corrupted 195-digit version string overflowed the `version_parts`
  `integer[]` column (int32).
- A genuinely bizarre 245-character Microsoft-Store "app name" (actually a
  conference description) overflowed `vendor`/`product`'s `VARCHAR(200)` —
  which turned out to be a systematic doc-vs-code mismatch: this document
  had always specified `text` (unbounded) for these columns; the Phase 2a
  models used `String(200)`. Fixed by widening all 9 affected columns to
  `Text`, matching the doc.

## 3. API integrations

All configured with: base URL (allowlist-validated), credential (encrypted,
write-only), optional schedule, and a **"Test connection"** action that performs a
read-only call and reports exactly what it found.

| Kind | Auth | Reads | Gives us |
|---|---|---|---|
| `API_DESKTOP_CENTRAL` | API key / OAuth per deployment | Inventory: computers, installed software | Per-device software with resource IDs |
| `API_AZURE_ARM` | Entra app registration, client credentials | ARM resources + VM extensions/instance view | VM inventory, OS versions, resource IDs |
| `API_MS_GRAPH` | Entra app, `DeviceManagementManagedDevices.Read.All` | Intune managed devices + detected apps | Managed device IDs, OS builds, app inventory |

Every outbound call goes through the SSRF guard: host allowlist, no redirects to
new hosts, link-local/loopback/`169.254.169.254` denied outright. Credentials are
Fernet-encrypted at rest and never appear in any response, log line, or error
message.

Sync writes a new immutable snapshot. A failed sync leaves the previous snapshot
as `is_latest` — a broken integration degrades to stale data, never to no data.

### As built (2026-08-21)

Implemented as designed, plus one operational detail and two confidence
notes worth stating explicitly:

- **The Entra OAuth token endpoint (`login.microsoftonline.com`) needs its
  own allowlist entry**, separate from the API host — `core.security.ssrf`
  validates it as a distinct outbound call (the client-credentials flow),
  not part of the ARM/Graph request. See docs/operations.md.
- **Azure ARM and MS Graph are implemented with high confidence** — both
  are stable, versioned, publicly documented Microsoft APIs. One known gap,
  stated rather than silently worked around: the basic ARM VM list gives
  `storageProfile.osDisk.osType` (`Windows`/`Linux`) but not a specific OS
  *version* — that needs a per-VM `instanceView` call, not fetched in this
  pass, so ARM-sourced devices always have `os_version = None`.
- **Desktop Central is implemented with lower confidence.** Unlike ARM/Graph,
  its REST API shape varies across on-prem versions and the newer Endpoint
  Central Cloud product, and this adapter has **not been verified against a
  live instance** — no sandbox was available during development, unlike NVD
  in Phase 1b, which was validated against the real live API. The endpoint
  paths and field names follow commonly documented ManageEngine REST API
  conventions (`/api/1.4/inventory/computers`,
  `/api/1.4/inventory/installedSoftware`, `authtoken` query auth) as a
  reviewed-but-unverified starting point — see
  `inventory/adapters/desktop_central.py`'s module docstring. Expect to
  adjust field mappings against a real deployment's actual responses.
- **Per-device software calls are capped** (`MAX_DEVICES_FOR_APPS` /
  `MAX_DEVICES_FOR_SOFTWARE`, 500 devices) — both MS Graph's `detectedApps`
  and Desktop Central's `installedSoftware` are one call per device, which
  doesn't scale to an unbounded fleet inside one sync. A fleet larger than
  the cap gets device rows for everyone but software only for the first
  500, and the sync is marked `SyncStatus.PARTIAL` with the reason
  recorded — never silently reported as a complete picture.
- **A scheduled sync poller runs in the worker**, checking `schedule_cron`
  via `croniter` every `INVENTORY_SYNC_POLL_SECONDS` (default 5 minutes). A
  source with no `schedule_cron` is never auto-synced.

## 4. Normalisation

Matching only works if both sides are normalised the same way.

### Vendor and product names

Inventory says `Microsoft Corporation` / `Google LLC` / `Mozilla`. NVD says
`microsoft` / `google` / `mozilla`. The `vendor_alias` table maps both directions
onto a canonical lowercase form. It ships seeded with the common vendors and is
extended by admins whenever a mismatch is spotted — which the scan UI makes easy
by showing near-miss names it *didn't* match.

Product normalisation additionally lowercases, collapses whitespace, and strips
edition/architecture noise (`(x64)`, `64-bit`, `- en-US`) into a separate field
rather than deleting it.

### Versions

Versions in the wild are not semver:

| Real example | Shape |
|---|---|
| `120.0.6099.109` | Chrome — 4-part |
| `10.0.19045.3803` | Windows build |
| `17.0.9` | Semver-ish |
| `2019 CU21` | Year + cumulative update |
| `8u391` | Java update notation |
| `2.14.1-rc2` | Pre-release suffix |

The comparator is tiered and never guesses silently:

1. **Numeric tuple** — split on `.`/`-`/`_`, take the leading integer run, compare
   element-wise with missing elements as 0. Covers the large majority.
2. **`packaging.version`** — for PEP 440-compatible strings, handles pre-release
   ordering correctly.
3. **Known-format handlers** — Java `8u391`, Windows builds, `YYYY CUnn`.
4. **Give up honestly.** If none apply, the comparison is not attempted. The
   match is recorded as `POSSIBLE` with rationale "version format not comparable",
   never as a confident yes or no.

`version_parts int[]` is stored alongside `version_normalized` so range filtering
happens in SQL rather than row-by-row in Python.

### As built (2026-08-22)

- **Vendor**: `core/services/vendor_alias.py` seeds ~60 non-exhaustive
  `vendor_alias` rows (`cli.py seed-vendor-aliases`) and loads the whole
  table into an in-memory dict once per operation (`load_vendor_alias_map`)
  — never a per-row query. `inventory/normalise.py`'s `normalise_vendor()`
  looks up the lowercased raw value in that map, falling back to
  lowercase-trim when there's no alias.
- **Product**: `normalise_product()` lowercases, collapses whitespace, and
  strips architecture/edition noise via regex (`(x64)`, `(x86)`,
  `64-bit`/`32-bit`, `- en-US`). **The stripped noise is discarded, not
  preserved in a side field** — the design above says "into a separate
  field", but no such column exists in the schema and nothing downstream
  would consume it; not worth a migration for unused data.
- **Version comparator** (`inventory/version.py`) is tiered, but in the
  opposite order from the design sketch above, and without dedicated
  known-format handlers: **PEP 440 is tried first** (`packaging.version`),
  since most real dotted versions happen to be PEP-440-shaped too and PEP
  440 gets pre-release ordering right (`2.15.0rc1 < 2.15.0`) where naive
  digit extraction does not; the zero-padded numeric-tuple comparison
  (tier 1, already used for storage) is the fallback when either side
  isn't PEP-440-shaped. **No dedicated Java/Windows-build/`YYYY CUnn`
  handlers were built** — tier 1's digit-run extraction already recovers a
  comparable tuple from all three in practice (`8u391` → `[8, 391]`,
  `"2019 CU21"` → `[2019, 21]`), so a third tier wasn't worth building yet.
  Neither tier comparing confidently still means "give up honestly" (`None`),
  exactly as designed.

## 5. The scan

Design: triggered from the expanded advisory, runs as a background job, panel
polls and renders results in place. **The trigger UI is now built (Phase
2e)** — see its own "As built" note below; it does not poll, because the
underlying scan is synchronous, not a background job (also below).

```
for each snapshot in selected sources:
  affected_specs = cve_cpe rows for this advisory's CVEs   (preferred)
                   ∪ advisory_product rows                 (fallback)

  for each spec (vendor, product, version range):
    candidates = inventory_software
                 WHERE snapshot_id = ?
                   AND vendor  = normalise(spec.vendor)
                   AND product = normalise(spec.product)

    for each candidate:
      if version_in_range(candidate.version, spec.range):
        record scan_match(method, confidence, rationale, device_count, device_ids)
```

### As built (2026-08-22)

- **`core.services.scan.run_scan()` runs synchronously** and returns a
  `COMPLETE`/`FAILED` `ScanRun` immediately — there's no background job
  queue for this yet, deliberately deferred to 2e ("once there's a UI to
  poll it"). The 2e route/caller must commit the flushed `FAILED` state
  before or instead of letting an exception propagate uncaught — the same
  discipline D-024 established for `sync_source()` in Phase 2c, documented
  in `scan.py`'s module docstring for whoever writes that caller.
- **NVD CPE data is the primary source; `AdvisoryProduct.parsed_range` is a
  second, distinctly-graded one (added later — see D-032).**
  `AdvisoryProduct.version_expression` is PDF-parsed free text
  (`"< 17.0.9"`); `ingest/version_range.py` conservatively parses the
  minority (28% on the real corpus) that's unambiguous into a structured
  `parsed_range`, and `_text_derived_specs()` turns those into
  `AffectedSpec`s with `text_derived=True`. Every such spec has `cve_id =
  None` (a product claim isn't attributed to one specific CVE within a
  possibly-multi-CVE advisory) and is capped at `POSSIBLE` confidence no
  matter how clean the version comparison is — see docs/ingestion.md's
  "Affected products" section and `inventory.matcher`'s module docstring
  for why both the vendor/product spelling *and* the range are less
  reliable than NVD's. A `parsed_range` that's still `None` (the other 72%)
  contributes no spec at all — never an unbounded "any version" guess.
- **`CveCpe.vulnerable = False` rows are filtered out** before building
  specs — NVD CPE data includes negated-but-kept "context" rows (Phase 1b),
  and a non-vulnerable row must never become an "affected" claim. Tested
  directly: a context row at the exact patched version must not falsely
  match.
- **No fuzzy product-name matching** — `spec.product` and
  `candidate.product` are compared after identical normalisation, exact
  string equality only. `CONFIRMED` requires the vendor to already be
  spelled canonically; matching a vendor **only** via the alias table
  downgrades confidence to `LIKELY`, even if everything else about the
  match is clean.
- **A scan can span multiple snapshots at once** (e.g. two different
  inventory sources) — `ScanMatch.snapshot_id` attributes each individual
  match back to the specific snapshot it came from, verified with a real
  cross-source scan.
- **Verified end-to-end against real data**, not just synthetic fixtures:
  cross-referencing the two real `Inventory/` exports against the
  already-enriched Phase 1 corpus found one genuine overlap (7-Zip, real
  advisory DOH-2026539 / CVE-2026-14266, real installed version `26.02`).
  The CPE range's upper bound is `< 26.02` (exclusive) — the installed
  version is exactly the patched release. `run_scan()` correctly returned
  `match_count == 0`, confirming the boundary comparison doesn't
  off-by-one into a false positive.

### Confidence tiers

Every match carries one. The UI groups by them and never collapses them into a
binary.

| Tier | Meaning |
|---|---|
| `CONFIRMED` | NVD CPE range match, vendor **and** product matched canonically, version parsed cleanly and falls inside the range |
| `LIKELY` | NVD CPE match where the vendor was only reached via the alias table — one more inference deep than a direct string match |
| `POSSIBLE` | Fuzzy product-name match, version format not comparable, an open-ended range with no lower bound, **or the spec is text-derived** (`AdvisoryProduct.parsed_range`, not NVD — see D-032) regardless of how clean that match otherwise is |

Every match stores a `rationale` string: *"Chrome 120.0.6099.109 falls inside NVD
CPE range google:chrome >= 120.0.0.0, < 120.0.6099.130 (CVE-2026-1234)"*. An
analyst must be able to check our work without reading the code.

### Result presentation

```
Scan of 3 sources · snapshot 2026-08-19 14:02 · 4 matches

CONFIRMED   2 products · 47 endpoints
  google:chrome 120.0.6099.109      41 endpoints   CVE-2026-1234   [view devices]
  apache:log4j 2.14.1                6 endpoints   CVE-2021-44228  [view devices]

LIKELY      1 product · 12 endpoints
  oracle:java 8u391                 12 endpoints   CVE-2026-5678
  ↳ matched via alias "Java(TM) SE Runtime Environment" → oracle:java

POSSIBLE    1 product · 3 endpoints
  microsoft:exchange_server "2019 CU21"   3 endpoints
  ↳ version format not comparable to range "< 15.2.1544.9" — manual check needed

NOT FOUND   2 affected products had no inventory match
  fortinet:fortios, cisco:ios_xe
  ↳ no inventory source reports these — coverage gap, not a clean bill of health
```

That last line matters. **"Not found" means "we didn't see it", not "we're not
affected"** — the UI says so explicitly, because the alternative is a false sense
of safety when an inventory source simply doesn't cover a device class.

### As built (2026-08-22) — trigger UI (Phase 2e)

- **The web panel doesn't poll**, because the scan it triggers is
  synchronous (§5 above) — the "Scan inventory" button's `POST` gets the
  finished result back in the same request/response cycle and swaps it in
  directly (`hx-target="#scan-panel"`). Source selection is a checkbox list
  of every active source's current latest snapshot
  (`core.services.inventory.latest_snapshots()`); all are checked by
  default. Reloading the advisory detail page shows the most recent scan's
  results without re-scanning.
- **Result presentation matches the design's grouping** (confidence tier
  sections, a "Not found" coverage-gap block with the same "means we didn't
  see it, not that we're not affected" framing, a scan-history table) —
  device-level "[view devices]" drill-down for `DETAILED` sources is **not
  built**: no `DETAILED`-mode source has been ingested against a real
  device-identifier-bearing export yet to develop it against, and
  `ScanMatch.device_ids` is populated by the matcher but nothing in the UI
  reads it yet. Revisit once a Phase 2c API-synced `DETAILED` source has
  real device data to show.
- **REST API** (`api/routers/scans.py`): `POST /advisories/{id}/scan`
  (defaults to every active source's latest snapshot when `snapshot_ids` is
  omitted), `GET /scans/{run_id}`, `GET /advisories/{id}/scans` — all under
  the `scan:run` scope, matching the design table. See
  docs/api-and-mcp.md's "As built" note for the synchronous-`200`-not-`202`
  divergence and the exception-class-collision bug that surfaced while
  wiring the route.
- **Verified end-to-end against the real dev database**, not just service
  and API tests: logged in as a real session user, opened the real
  DOH-2026539 advisory, checked a temporary snapshot carrying a vulnerable
  7-Zip version, triggered a scan through the actual HTML form, and
  confirmed the rendered result — `POSSIBLE` confidence with the
  "open-ended range, no lower bound, manual check advised" rationale
  (NVD's CVE-2026-14266 CPE row has no `version_start`) — matched exactly
  what the service layer computed; confirmed a VIEWER-role session can read
  the panel but gets `403` attempting to trigger a scan. All temporary
  verification data was removed from the dev database afterward.

## 6. Known limits

Stated up front so nobody over-trusts the output:

- Aggregate CSV sources can tell you *how many*, never *which*. Only API sources
  yield device identifiers.
- Inventory is as fresh as its last sync; every result is stamped with the
  snapshot timestamp.
- NVD CPE data is incomplete for some vendors and lags for very new CVEs.
- Firmware, network appliances, and OT devices are typically absent from all
  three source types — these are permanent coverage gaps, surfaced as such.
- A product present but not in a vulnerable range is reported as **"present, not
  in affected range"** rather than omitted, so analysts can see we checked.
