# Ingestion pipeline

**Grounded in a real corpus.** This design was rewritten on 2026-08-20 after
analysing all 135 messages in `Advisory/` (DOH SOC, 2026-07-13 → 2026-08-19).
Every rule below is backed by a measurement from that corpus, cited inline.

---

## 1. Corpus facts

| Property | Measured |
|---|---|
| Messages | 135 `.msg` (Outlook), **zero `.eml`** |
| Sender | `DoH Cyber Advisory <cyber.advisory@doh.gov.ae>` — **135/135, single sender** |
| Subject pattern match | **135/135** |
| Distinct advisory refs | 131 (`DOH-2026508` … `DOH-2026647`), 9 gaps in the sequence |
| PDF attachments | **exactly 1 per message, 135/135** |
| Inline images | 949 PNG + 139 JPG — signature/logo noise, **must be discarded** |
| Structured IOC sidecars | 2 `.csv` + 2 `.xlsx` |
| PDFs with a text layer | **135/135 — OCR is not required** |
| PDF size | 454 KB – 0.7 MB |
| PDF pages | 3–8 (one outlier at 13) |
| HTML bodies | 135/135 |

**Answers two open questions.** Q1 (samples) — answered, 135 of them. Q2 (scanned
vs text-layer PDFs) — **answered: 100% text layer, OCR is dead weight and should
not be built.**

---

## 2. The single most important finding

The email body is a **summary**. The PDF is the **document of record**.

| Source | Advisories with ≥1 CVE | Distinct CVEs |
|---|---|---|
| Email body only | 47 / 135 | 63 |
| **PDF only** | **92 / 135** | **384** |
| Union (subject + body + PDF) | 92 / 135 | **386** |

PDF parsing recovers **6× more CVEs**. 56 advisories carry CVEs the email body
never mentions — an email-only parser would silently miss them.

But 5 advisories have CVEs in the email that the PDF omits. So the rule is
**union of subject + body + PDF, never either/or**, with provenance recorded per
CVE so an analyst can see where each came from.

---

## 3. The Power Automate contract

The corpus is `.msg`, so `.msg` is the primary format — not the fallback I
assumed before seeing the data. `extract-msg` parses 135/135 with zero errors.

- **One file per email.** `.msg` preferred, `.eml` also accepted.
- **Atomic writes.** Write `<name>.tmp`, then rename to `<name>.msg`. The watcher
  only picks up `.msg`/`.eml`, so a half-written file is never claimed.
- **Filenames are not trusted.** Outlook sanitises `::` → `_` and strips `/`, so
  the filename is a lossy copy of the subject. Parse the subject from the message
  properties, never from the filename.

**Manual upload.** "Upload email" on the tracker page (ANALYST+) follows the
same contract: the file is written into the inbox as `.tmp` + rename (under a
sanitised basename — the upload's filename is user input), then claimed and
processed like any drop, ending in `archive/` or `failed/`. Uploads are
attributed to the uploader in the audit log.

```
/data/inbox/         flow drops here (and tracker-page uploads)
/data/processing/    claimed by a worker; crash-recovered on startup
/data/archive/YYYY-MM-DD/
/data/failed/        + .error.json sidecar
```

---

## 4. Stage 1 — Claim and dedupe

Poll every 30s (survives SMB/network mounts, unlike `inotify`). Claim by atomic
rename into `/data/processing/<worker-id>/`.

`dedupe_hash = sha256(raw bytes)` — exact resends are skipped.

**The corpus proves that is not enough.** Two distinct duplication modes exist:

| Mode | Example | Detection |
|---|---|---|
| Exact resend, same ref | `DOH-2026545` ×2, 19 min apart; `DOH-2026599` ×2 | Content hash — automatic |
| **Re-issue under a new ref** | `DOH-2026550` → `DOH-2026552`, identical title, 8h apart. Also `2026551`→`2026553`, `2026601`→`2026612`, `2026608`→`2026610` | **Hash will not catch this** |

Re-issues get different reference numbers and slightly different bytes, so they
ingest as separate advisories — which is correct, they *are* separate regulator
notifications. But the analyst must see the relationship. On ingest, compute a
normalised-title fingerprint and, on a match within 14 days, create a
`related_advisory` link of kind `POSSIBLE_REISSUE` and surface a banner. Never
auto-merge: only the regulator can supersede its own advisory.

`Message-ID` is stored and indexed as a third signal.

---

## 5. Stage 2 — Store originals, discard signature noise

Raw `.msg` → blob store **before any parsing**. Then every attachment.

Filter aggressively: 1,088 of the 1,223 attachments in this corpus are inline
signature images. Rule — **keep** `.pdf`, `.csv`, `.xlsx`, `.xls`, `.docx`;
**discard** any image part that is `Content-Disposition: inline` *and* referenced
by a `cid:` in the HTML body. Everything kept is content-addressed; the discarded
images are still present inside the archived `.msg`, so nothing is truly lost.

---

## 6. Stage 3 — Parse the email body (labelled field block)

The body is a fixed labelled block. Measured presence across 135:

| Label | Present | Notes |
|---|---|---|
| `Reference:` | **135/135** | Upstream vendor/source, e.g. `Nist`, `Microsoft`, `Cisco` |
| `Detected on:` | **135/135** | `DD-Month-YYYY` |
| `Type:` | **135/135** | Regulator taxonomy |
| `Risk level:` | **135/135** | `Critical` / `High` / `Medium` |
| `Action Required:` | **135/135** | Boilerplate |
| `Description:` | 134/135 | Duplicates the PDF OVERVIEW |
| `Affected Product:` | 128/135 | Free text, product names only — no versions |
| `Vulnerability/Disclosure Detail:` | 109/135 | Section marker |

**Parse by label-scan, not by regex-per-field.** Find every `^Label:` match,
then slice each field from its label to the start of the next. A per-field regex
with a lookahead breaks on the 5 messages where a field runs into the next
without a blank line — that failure mode was observed and is the reason for this
rule.

Normalise `\u00a0` and `\u200b` to spaces first; the body is HTML-derived and
full of both.

### Subject

```
[EXTERNAL] Security Advisory :: DOH- 2026550 - Critical Improper Authentication…
└ prefix ──┘└─── literal ────┘└─┬──┘ └──┬───┘ └┬┘ └───────── title ──────────┘
                            separator  ref   dash
```

```python
SUBJECT = re.compile(
    r"^\s*(?:\[EXTERNAL\]\s*)?Security\s+Advisory\s*(?:::|:|_|-)?\s*"
    r"DOH\s*-?\s*(?P<ref>\d{4,8})\s*[-–—]?\s*(?P<title>.*?)\s*$",
    re.I,
)
```

Matches **135/135**. The permissiveness is all load-bearing — real variants
observed: `DOH- 2026550` (space after dash), `DOH-2026512-` (no space before
title), `DOH-2026607 Multiple…` (**no separator at all**), and `–` en-dash inside
titles. The `_` seen in filenames is Outlook sanitising `::`.

### Field value vocabularies

`Risk level` — `Critical` 79 · `High` 39 · `Medium` 16. **`Low` never observed**;
accept it, don't assume it.

`Type` — `Vulnerability` 128 · `Campaign` 3 · `Malware` 2 · `Phishing` 1 ·
`Security Updates` 1.

---

## 7. Stage 4 — Parse the PDF (fixed section template)

Sandboxed subprocess, no network, caps on bytes/pages/decompression/wall-clock.
Corpus maxima (0.7 MB, 13 pages) mean the caps in `operations.md` are generous by
~70×, which is the right side to err on.

### Cover page

```
Classified as Restricted by Department of Health
SECURITY OPERATIONS CENTER
ADVISORY
Critical Improper Authentication Vulnerability in Apache Doris
Severity: Critical
```

`Severity:` is present on **135/135**.

### Page header (pages 2+)

```
Advisory Number: DOH- 2026550    Published on: 23-July-2026
```

Found on 134/135; `Published on` on 126/135. This header repeats on every page —
**strip it before running any extractor**, or every regex double-counts.

### Section skeleton — measured frequency

| Heading | Count | Use |
|---|---|---|
| `OVERVIEW` | **135** | → `advisory.description` |
| `TECHNICAL DETAILS` | **135** | → body text, CVE extraction |
| `PLEASE NOTE` | **135** | Boilerplate — **discard** |
| `ACTION` | **135** | Boilerplate — **discard** |
| `REFERENCES` | 134 | → reference URLs. **Not IOCs.** |
| `RECOMMENDATIONS` | 132 | → remediation guidance |
| `AFFECTED PRODUCTS…` (5 spellings) | 58 | → `advisory_product` |
| `IMPACT` | 20 | → body text |
| `ATTACK CHAIN OVERVIEW` | 17 | **threat-landscape signal** |
| `ADDITIONAL DETAILS` | 14 | → body text |
| `ATTACK VECTOR` | 12 | *Not* a threat signal — see the note below |
| `CAMPAIGN OVERVIEW` | 7 | **threat-landscape signal** |
| `IOCs` / `INDICATORS OF COMPROMISE` / `IOC` | 15 | → `advisory_ioc`. **Note the lowercase `s`** |

Headings are ALL-CAPS on their own line, with or without a trailing colon.
Match case-sensitively — lowercase matching produces false positives from
sentence fragments — but **allow a trailing lowercase plural**: the IOC heading
is literally `IOCs`, and a strict ALL-CAPS pattern silently skips every one of
them. (This was a real bug: all IOCs were coming from CSV/XLSX sidecars until it
was fixed, costing 39 indicators.)

**`ATTACK VECTOR` is deliberately *not* a threat-landscape signal.** Ordinary
CVE advisories describe their attack vector too — `DOH-2026551`, a SharePoint
RCE, has one — so scoring it misfiles plain vulnerability advisories. Only
`ATTACK CHAIN OVERVIEW` and `CAMPAIGN OVERVIEW` imply a campaign narrative.

**Affected-products heading has five observed spellings**: `AFFECTED PRODUCTS &
VERSIONS`, `AFFECTED PRODUCT & VERSIONS`, `AFFECTED PRODUCTS AND FIXES`,
`AFFECTED PRODUCTS & FIXED VERSIONS`, `AFFECTED PRODUCT AND VERSIONS`. Match the
family with `^AFFECTED PRODUCTS?\b.*$` rather than enumerating — a sixth spelling
is a matter of time.

### Extraction is section-scoped, never document-wide

This is the rule that matters most for precision. A document-wide URL regex over
this corpus returns **216 URLs, the overwhelming majority of which are REFERENCES
citations, not indicators**. Scope every extractor:

| Extractor | Scoped to |
|---|---|
| CVE / CVSS | Whole document minus page headers and `PLEASE NOTE`/`ACTION` |
| IOCs | **`IOCs` section only**, plus CSV/XLSX sidecars |
| Reference URLs | `REFERENCES` section only |
| Products/versions | `AFFECTED PRODUCTS…` section only |
| Recommendations | `RECOMMENDATIONS` section only |

### Arabic text

Cover and last pages carry Arabic that `pdfplumber` emits in reversed logical
order (`تامولعملا نمأ تايلمع زكرم`). It is bilingual boilerplate with no unique
content. Detect the Arabic Unicode block and exclude those runs from
`body_text` and from the search vector — do not attempt to reorder it.

---

## 8. Stage 5 — Entity extraction

### CVEs — union with provenance

`CVE-\d{4}-\d{4,7}`, case-insensitive, uppercased, deduped. Run over subject,
body, **and PDF**; store the union with a `found_in` provenance field.

Volume is real: max **63 CVEs in one advisory** (`DOH-2026593`, Chrome), then 40
(SAP), 21 (Atlassian), 21 (Microsoft Patch Tuesday). The detail panel must
paginate or group CVEs — a flat list of 63 is unusable.

### CVSS

Observed inline as `CVSS v3.1: 9.1 (Critical)` in bullet lists. Extract
`CVSS\s*v?3\.[01]\s*:?\s*(\d{1,2}\.\d)` and the full vector `CVSS:3\.[01]/[A-Z:/]+`
when present. **Parse the base score from the vector when both exist** — the
prose number is what a human typed.

### IOCs — three sources, in precedence order

**1. CSV/XLSX sidecar (highest confidence).** Header is `Indicator,Type` with an
optional `Description`. Already defanged. One file used `#,Indicator,Indicator Type`
— match the header family, not an exact string.

**2. PDF `IOCs` section table.** Two logical columns, `Indicator | Type`:

```
154[.]196[.]162[.]76      IP Address
about[.]blsouqs[.]com     Domain
082d49ef9f14e6811d68c7e0e82e5069   MD5
7b9efc7ef8957411cdd22582ce4bfb3a5f76d9c91cdb7e36bf85c9785a2480e9   SHA256
```

`extract_tables()` returns padded 6-column rows with empties (spacer columns), so
**coalesce non-empty cells left-to-right** rather than trusting column indices.
The line-oriented regex `^(\S{4,120}?)\s{2,}(TYPE)$` is more reliable here and
should be the primary path, with table extraction as the cross-check.

**3. Regex fallback** over the IOC section only, when neither above parses.

**The type is given — do not infer it.** Observed vocabulary: `IP Address` (18),
`Domain` (17), `URL` (13), `MD5` (12), `Email` (6), `SHA256` (6), `SHA-256` (5),
`IPv4` (2), `SHA1` (1), plus free-text `Registry …` variants. Normalise to the
`advisory_ioc.ioc_type` enum; map unknown strings to `OTHER` and keep the raw
label rather than dropping the row.

**Refang before matching, store both forms.** The regulator ships IOCs
pre-defanged (`154[.]196[.]162[.]76`, `hxxps://`). A naive IPv4 regex found 45
across the corpus; refanging first found **101**. Refanging must handle `[.]`,
`(.)`, `{.}`, `[:]`, `hxxp`/`hXXp`, and punycode IDNs (`xn--90aguaqgfu[.]xn--p1ai`
appears in the corpus and must survive the round trip).

Volume is modest — 15/135 advisories have an IOC section, 84 labelled rows total.
IOC handling is a real feature, not a dominant one.

### Affected products — version_expression, fixed_version, and parsed_range

`extract_products_from_table()`/`extract_products_from_prose()` (unchanged since
Phase 1a) capture the regulator's affected-version and fixed-version text
**verbatim**, into `advisory_product.version_expression`/`.fixed_version`. That
raw text is always kept, however messy — it's what an analyst reads.

`ingest/version_range.py` (added later, see D-032) additionally tries to turn
that text into a **structured** `advisory_product.parsed_range` — the same
shape `inventory.matcher.AffectedSpec` needs, so a scan can compare it against
an inventory-installed version. Measured against the real corpus: **only
28% of rows with a `version_expression` parse cleanly** (35/124). That is
expected, not a shortfall — the parser is deliberately conservative and never
guesses at the other 72%, which is genuinely ambiguous: semicolon-separated
multi-range lists ("10.3.0-10.3.1 (LTS); 10.2.0-10.2.5 (LTS); …"),
comma-separated discrete version lists, pure prose with no version at all,
build-qualified strings with embedded spaces. Patterns it *does* trust:

| Shape | Example |
|---|---|
| Comparator | `< 17.0.9`, `<= 29.0`, `>= 2.0` |
| "below/prior to/before/up to X" | `Builds below 16.0.5561.1001` |
| "X and earlier/below" (inclusive) | `1.26.1 and earlier` |
| "X and later/above" (inclusive min) | `2.0.0 and later` |
| Simple range, `versions`/`builds`/`releases`-anchored | `versions 1.2.68 through 1.2.83` |
| Simple range, no other text | `3.4.0 - 3.4.5` |
| Bare version | `4.0.0` (→ `exact_version`) |

A single comparator clause is still trusted even embedded in a longer sentence
("Vulnerable builds compiled with Foo < 1.1.0"); **two** comparator clauses in
one string (two ranges for two variants) is rejected outright, not
first-match-wins. When `version_expression` yields nothing but `fixed_version`
alone is a bare version, that's used as an implied exclusive upper bound (a
device is vulnerable if strictly older than the fix) — recorded with
`"source": "fixed_version"` in the JSONB so the provenance is never lost.

See docs/inventory-matching.md §5 for how `parsed_range` feeds the scan engine
(as `MatchMethod.TEXT_RANGE`, always capped at `POSSIBLE` confidence).

---

## 9. Stage 6 — Classification

**The regulator's `Type` field is present 135/135 and is not reliable enough to
use alone.** It reports `Vulnerability` for 128 of 135, including advisories that
are unambiguously threat-landscape by content:

- `DOH-2026563 — JADEPUFFER Evolves with Ransomware Targeting AI Models` → `Vulnerability`
- `DOH-2026582 — Microsoft Email Threat Landscape Q2 2026` → `Vulnerability`
- `DOH-2026638 — Dysphoria Expands IoT Botnet into DDoS Network` → `Vulnerability`

Classify on **content signals, using the regulator field only as a prior**:

| Signal | Weight | Toward |
|---|---|---|
| `Type` ∈ {`Campaign`, `Malware`, `Phishing`} | Strong | `THREAT_LANDSCAPE` |
| `ATTACK CHAIN OVERVIEW` / `CAMPAIGN OVERVIEW` / `ATTACK VECTOR` section present | **Strong** | `THREAT_LANDSCAPE` |
| `IOCs` section or IOC sidecar present | Strong | `THREAT_LANDSCAPE` |
| ≥1 CVE **and** an `AFFECTED PRODUCTS…` section | Strong | `CVE_ADVISORY` |
| CVSS vector present | Moderate | `CVE_ADVISORY` |
| Title matches `Security Updates?\s*[-–]` | Moderate | `SECURITY_BULLETIN` |
| `Type: Vulnerability` | **Weak prior only** | `CVE_ADVISORY` |

The section-heading signals are the discriminator, and they're structural rather
than lexical — which is why they beat both keyword-spotting and the regulator's
own label. Keep the regulator's raw value in `advisory.source_type_raw`
regardless — it is what the regulator asserted, and an auditor may ask.

Two rules the corpus forced:

- **`CVE_ADVISORY` cannot win with zero CVEs.** An advisory about CVEs that
  names none is a contradiction; without this guard the regulator's blanket
  `Vulnerability` label filed IoT botnets and ransomware-affiliate reports as
  CVE advisories.
- **Confidence must reflect evidence mass, not just the split.** `winner/total`
  rated a single weak prior as 1.00, so nothing was ever flagged. Confidence is
  now a two-horse margin against the runner-up, scaled by how much signal there
  was at all. On the corpus this flags 20/135 for review.

**As built (2026-08-20):** 135/135 classify without error —
72 `CVE_ADVISORY`, 39 `THREAT_LANDSCAPE`, 20 `SECURITY_BULLETIN`, 4 `OTHER`.
All 11 IOC-bearing advisories classify as `THREAT_LANDSCAPE`. The 4 `OTHER`
carry no CVE, no affected-products section, and no threat vocabulary — genuinely
undecidable, and flagged as such rather than guessed.

---

## 10. Stage 7 — Cross-validation (new stage, driven by the data)

The corpus contains genuine regulator data-entry errors. Detect, don't correct.

| Check | Result | Rule |
|---|---|---|
| Subject ref == PDF `Advisory Number` | **132/135** | Trust the **subject** (routing key). Flag `REF_MISMATCH`. Observed: subject `DOH-2026515` vs PDF `DOH2026516`; subject `DOH-2026532` vs PDF `DOH2026531` |
| Email `Risk level` == PDF `Severity` | **130/134** | Take the **higher** severity, flag `SEVERITY_MISMATCH`. Observed: Critical/High ×2, Medium/Critical ×1, High/Critical ×1 |
| PDF text length | 135/135 non-trivial | Empty → `NO_TEXT_LAYER` warning |
| CVE sets differ between email and PDF | 56 + 5 advisories | Union; record provenance |

Each mismatch writes an `advisory_flag` row rendered as a badge in the detail
panel. Taking the higher severity is deliberate: under-triaging a Critical
because a PDF cover page says High is the more expensive error.

---

## 11. Stage 8 — SLA clocks

**The email body embeds the regulator's SLA table in all 135 messages**, and
demands two distinct responses:

> 1. **Acknowledgement** — by email or phone call.
> 2. **Resolution** — confirmation of resolution, or a definite timeline.

| Priority | Risk level | Acknowledge within | Resolve within |
|---|---|---|---|
| P1 | Critical | **8 h** | **24 h** |
| P2 | High | **16 h** | **48 h** |
| P3 | Medium | 72 h (3 working days) | 120 h (5 working days) |
| P4 | Low | 72 h (3 working days) | 120 h (5 working days) |

This **answers open question 3** and changes the status model: acknowledgement is
a separate, earlier clock than remediation, with an 8-hour fuse on Criticals. See
`docs/architecture.md` §5 for the revised statuses and `docs/data-model.md` for
`acknowledged_at` / `ack_due_at` / `resolution_due_at`.

Both clocks start at `received_at`. P3/P4 are expressed in working days, so the
resolution clock needs a working-calendar (UAE week, Sat–Sun weekend) — captured
as a follow-up question rather than assumed.

---

## 12. Stage 9 — Enrich from NVD

Unchanged in shape, but now correctly sized: **386 distinct CVEs across ~5 weeks
(~77/week)**. Well inside NVD's rate limit even without an API key; with one, not
close to a constraint.

`Reference:` in the email names the upstream source (`Nist` 14, `Microsoft` 8,
`Cisco` 4, `Github`/`IBM`/`Fortiguard` 3 each, …). Store it — it tells an analyst
where the regulator got this, and it is a useful enrichment-routing hint later.

**As built (2026-08-20).** Verified against the live API:

- Only `cvssMetric*` keys are read from `metrics`. Real payloads also carry
  `ssvcV203`, which has no `cvssData` and a null score — iterating blindly
  yields junk rows.
- Where several metrics share a CVSS version, `type: "Primary"` from
  `nvd@nist.gov` wins over secondary sources.
- NVD timestamps carry **no timezone**; they are UTC and are normalised as such.
- Negated configuration nodes are **skipped, not inverted** — inverting would
  invent affected products NVD never asserted.
- **CVSS v4.0 vectors exceed 170 characters** when they carry threat and
  environmental metrics. Both vector columns are `TEXT`; a bounded column
  failed on live data (migration `f9d471469add`).
- Enrichment may **raise** an advisory's severity and both SLA clocks when NVD
  scores a CVE higher than the regulator did. It never lowers them — D-019.

---

## 13. Failure handling

| Failure | Behaviour |
|---|---|
| `.msg` unparseable | `failed/` + sidecar; admin alert |
| PDF timeout / bomb | Advisory still created from email; attachment `FAILED`; UI warning |
| No text layer | `FAILED` + `NO_TEXT_LAYER` (not expected — 0/135) |
| Ref mismatch | Ingested on the **subject** ref, flagged |
| Severity mismatch | Higher value used, flagged |
| Unknown sender | `UNKNOWN` source, flagged — a security signal, not just data quality |
| Duplicate hash | Skipped, original archived |
| Probable re-issue | Ingested separately, linked, banner shown |

---

## 14. Test fixtures

The corpus gives us a real regression suite. Priority fixtures:

| Fixture | Why |
|---|---|
| `DOH-2026550` Apache Doris | Canonical single-CVE vulnerability |
| `DOH-2026585` OctLurk/SilkLurk | 38-row IOC table, defanged, 6 pages |
| `DOH-2026593` Chrome | **63 CVEs** — pagination and performance |
| `DOH-2026551` SharePoint | Multi-column affected-products table with KB numbers |
| `DOH-2026558` Check Point | Prose version list, `R81.10` vendor-prefixed versions |
| `DOH-2026577` BlueDash | `.xlsx` IOC sidecar with Description column |
| `DOH-2026627` ErrTraffic | 73-row `.csv` IOC sidecar |
| `DOH-2026515` / `DOH-2026532` | **Ref mismatch** — assert the flag fires |
| `DOH-2026545` ×2 | Exact resend — assert dedupe |
| `DOH-2026550`/`552` | Re-issue pair — assert link, assert **no** merge |
| `DOH-2026607` | No subject separator — regex edge case |
| `DOH-2026562` | Field bleed — asserts label-scan beats per-field regex |

All redacted before committing. Plus synthetic hostile PDFs (zip bomb, 10k pages)
where the assertion is that the sandbox kills them cleanly.

---

## 15. Re-parsing

`parser_version` is stamped on every advisory. Re-parse reads from blobs and
regenerates derived fields; it **never** touches `status`, `assignee`, comments,
acknowledgement, or status history.

```bash
docker compose exec app python -m advisory_hub.cli reparse \
    --since 2026-07-01 --parser-version-below 3 --dry-run
```

Because this corpus is already archived, every parser improvement can be
regression-tested against all 135 real advisories before deployment.
