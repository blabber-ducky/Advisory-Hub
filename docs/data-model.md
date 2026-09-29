# Data model

PostgreSQL 16. All tables have `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`,
`created_at TIMESTAMPTZ NOT NULL DEFAULT now()`, and where mutable,
`updated_at TIMESTAMPTZ`. Only distinguishing columns are listed below.

---

## Phase 1 — advisories

### `source`
The regulator or body that sends advisories.

| Column | Type | Notes |
|---|---|---|
| `name` | text unique | e.g. "National CERT" |
| `short_code` | text unique | e.g. `NCERT` — used in the UI table |
| `sender_patterns` | text[] | Sender addresses/domains that map to this source |
| `default_type_hint` | enum nullable | Bias for the classifier when this source is known to send one kind |
| `is_active` | bool | |

### `blob`
Content-addressed immutable storage index. The bytes live on the volume at
`/data/blobs/<sha256[0:2]>/<sha256>`.

| Column | Type | Notes |
|---|---|---|
| `sha256` | text unique | Also the filename |
| `size_bytes` | bigint | |
| `content_type` | text | Sniffed, not trusted from the email |
| `original_filename` | text nullable | |

### `advisory`
The core record.

| Column | Type | Notes |
|---|---|---|
| `source_id` | fk → source | |
| `external_ref` | text nullable | Regulator's own advisory number, if parseable |
| `type` | enum | `CVE_ADVISORY`, `SECURITY_BULLETIN`, `THREAT_LANDSCAPE`, `OTHER` |
| `type_confidence` | numeric(3,2) | Classifier confidence 0.00–1.00 |
| `title` | text | From subject or PDF title |
| `description` | text | Short summary shown in the table |
| `body_text` | text | Full normalised text (email body + all PDF text) |
| `severity` | enum nullable | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` — max across CVEs, or parsed |
| `cvss_score` | numeric(3,1) nullable | Highest across linked CVEs |
| `status` | enum | See architecture §5. Default `NEW` |
| `assignee_id` | fk → user nullable | |
| `priority` | enum | `P1`–`P4`, derived from `severity` per the regulator's SLA table |
| `acknowledged_at` | timestamptz nullable | Stops the acknowledgement clock |
| `acknowledged_by_id` | fk → user nullable | |
| `ack_channel` | enum nullable | `EMAIL` or `PHONE` — the regulator accepts either |
| `ack_due_at` | timestamptz | `received_at` + 8/16/72/72 h by priority |
| `resolution_due_at` | timestamptz | `received_at` + 24/48/120/120 h by priority |
| `source_type_raw` | text | The regulator's own `Type:` value, kept verbatim |
| `published_at` | timestamptz nullable | PDF `Published on:` |
| `detected_on` | date nullable | Email `Detected on:` |
| `upstream_reference` | text nullable | Email `Reference:` — e.g. `Nist`, `Microsoft` |
| `received_at` | timestamptz | Email `Date` header |
| `ingested_at` | timestamptz | When we processed it |
| `dedupe_hash` | text unique | sha256 of raw message; the idempotency key |
| `message_id` | text nullable, indexed | RFC 5322 `Message-ID` |
| `parser_version` | text | Which parser produced the derived fields |
| `raw_email_blob_id` | fk → blob | The untouched original |
| `search_vector` | tsvector, GIN | `title` + `description` + `body_text` |

Indexes: `(status, severity)`, `(source_id, received_at DESC)`, `(type)`,
GIN on `search_vector`.

### `advisory_attachment`

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `blob_id` | fk → blob | |
| `filename` | text | |
| `page_count` | int nullable | PDFs |
| `extracted_text_blob_id` | fk → blob nullable | Text layer, stored separately |
| `extraction_method` | enum | `TEXT_LAYER`, `OCR`, `FAILED` |
| `extraction_error` | text nullable | |

### `advisory_cve`
One row per CVE mentioned, enriched from NVD.

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `cve_id` | text | `CVE-YYYY-NNNN+`, indexed |
| `found_in` | text[] | Provenance: any of `SUBJECT`, `EMAIL_BODY`, `PDF`. The union rule means this matters |
| `cvss_v3_score` / `cvss_v3_vector` | numeric / text | From NVD |
| `cvss_v4_score` / `cvss_v4_vector` | numeric / text nullable | |
| `nvd_description` | text nullable | |
| `nvd_published_at` | timestamptz nullable | |
| `enrichment_status` | enum | `PENDING`, `OK`, `NOT_FOUND`, `ERROR`, `SKIPPED_OFFLINE` |
| `last_enriched_at` | timestamptz nullable | |

Unique on `(advisory_id, cve_id)`.

### `cve_cpe`
NVD configuration data — **this is what makes inventory matching accurate rather
than string-guessing.** Shared across advisories, keyed by CVE not advisory.

| Column | Type | Notes |
|---|---|---|
| `cve_id` | text, indexed | |
| `cpe_uri` | text | Full CPE 2.3 URI |
| `vendor` | text | Normalised lowercase |
| `product` | text | Normalised lowercase |
| `version_start` | text nullable | |
| `version_start_inclusive` | bool | |
| `version_end` | text nullable | |
| `version_end_inclusive` | bool | |
| `vulnerable` | bool | NVD's `vulnerable` flag; non-vulnerable rows are context only |

### `advisory_ioc`
Threat-landscape indicators.

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `ioc_type` | enum | `IPV4`, `IPV6`, `DOMAIN`, `URL`, `MD5`, `SHA1`, `SHA256`, `EMAIL`, `FILEPATH`, `REGISTRY_KEY` |
| `value` | text | Refanged/canonical form |
| `defanged_value` | text | **What the UI renders** |
| `context` | text nullable | Surrounding sentence, for analyst judgement |
| `first_seen_page` | int nullable | Where in the PDF |
| `remediation_status` | enum nullable | `DUE`, `BLOCKED`, `IN_PROGRESS`, `RESOLVED` (`IocRemediationStatus`). `NULL` = "not manually overridden — follow the advisory's own status"; see `core.services.iocs.effective_status()` and D-034 |

Unique on `(advisory_id, ioc_type, value)`.

**Effective remediation status** (the IOC tab's "Status" column, and the
matching column on the advisory detail page) is never a second stored
value — it's `remediation_status` if set, otherwise derived on read from
the parent advisory's own `AdvisoryStatus` via a fixed mapping:

| `AdvisoryStatus` | Effective `IocRemediationStatus` |
|---|---|
| `NEW`, `ACKNOWLEDGED`, `TRIAGED` | `DUE` |
| `IN_PROGRESS` | `IN_PROGRESS` |
| `AWAITING_VENDOR` | `BLOCKED` |
| `REMEDIATED`, `RISK_ACCEPTED`, `NOT_APPLICABLE`, `CLOSED` | `RESOLVED` |

### `vt_lookup`
A cached VirusTotal reputation check — analyst-triggered, per indicator
(see docs/decisions.md D-030). Keyed globally by `(ioc_type, value)`, **not**
by `advisory_ioc.id`: the same indicator often appears across several
advisories, and one check result serves all of them.

| Column | Type | Notes |
|---|---|---|
| `ioc_type` | enum | Same `IocType` enum as `advisory_ioc` |
| `value` | text | The raw indicator — never returned by any API response |
| `status` | enum | `PENDING`, `OK`, `NOT_FOUND`, `ERROR`, `SKIPPED_OFFLINE` — reuses `EnrichmentStatus` |
| `checked_at` | timestamptz nullable | When *we* last asked VT |
| `checked_by_id` | fk → user_account, nullable | Who triggered it |
| `malicious_count` / `suspicious_count` / `harmless_count` / `undetected_count` | int nullable | VT's `last_analysis_stats` |
| `reputation` | int nullable | VT's community reputation score |
| `last_analysis_at` | timestamptz nullable | When *VT's own engines* last scanned it — distinct from `checked_at` |
| `permalink` | text nullable | Link to VT's GUI report page — safe to render as a real link (VT's own domain, not the indicator itself) |
| `error` | text nullable | Populated only for `status = ERROR` |

Unique on `(ioc_type, value)`.

### `advisory_flag`
Cross-validation findings and parser warnings. Rendered as badges in the detail
panel. Added after corpus analysis found genuine regulator data-entry errors.

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `kind` | enum | `REF_MISMATCH`, `SEVERITY_MISMATCH`, `NO_TEXT_LAYER`, `UNKNOWN_SENDER`, `LOW_TYPE_CONFIDENCE`, `NO_CVE_FOUND`, `POSSIBLE_REISSUE` |
| `detail` | jsonb | Both conflicting values, so an analyst can judge |
| `resolved_at` / `resolved_by_id` | timestamptz / fk nullable | Analyst dismissal |

### `related_advisory`
Links re-issues and supersessions. **Never auto-merges** — only the regulator can
supersede its own advisory.

| Column | Type | Notes |
|---|---|---|
| `advisory_id` / `related_advisory_id` | fk → advisory | |
| `kind` | enum | `POSSIBLE_REISSUE`, `SUPERSEDES`, `SUPERSEDED_BY`, `RELATES_TO` |
| `detected_by` | enum | `TITLE_FINGERPRINT`, `MANUAL` |
| `confidence` | numeric(3,2) nullable | |

### `advisory_ttp`
Threat-group and technique references.

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `kind` | enum | `THREAT_ACTOR`, `MALWARE_FAMILY`, `ATTACK_TECHNIQUE` |
| `value` | text | e.g. `APT29`, `T1566.001` |

### `advisory_product`
Affected products as stated by the advisory text, independent of NVD.

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `vendor` / `product` | text | Normalised |
| `version_expression` | text | Raw, as written: `"< 17.0.9"`, `"2019 CU21"` |
| `parsed_range` | jsonb nullable | Structured form when parseable |
| `source_of_claim` | enum | `NVD_CPE`, `PDF_TEXT`, `EMAIL_BODY`, `MANUAL` |

### `comment`

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `author_id` | fk → user | |
| `body` | text | Non-empty enforced by CHECK constraint |
| `is_status_change` | bool | Convenience flag for rendering |

### `status_change`
The audit trail. **`comment_id` is `NOT NULL` — the schema itself enforces the
mandatory comment.**

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `from_status` | enum nullable | Null on the initial `NEW` |
| `to_status` | enum | |
| `actor_id` | fk → user | |
| `comment_id` | fk → comment **NOT NULL** | |

`advisory.last_comment` for the table column is read as the most recent `comment`
by `created_at` — no denormalised copy to drift.

### `audit_log`
Append-only. No update or delete grants on this table.

| Column | Type | Notes |
|---|---|---|
| `actor_id` | fk → user nullable | Null for system actions |
| `actor_kind` | enum | `USER`, `API_TOKEN`, `SYSTEM`, `MCP` |
| `action` | text | `advisory.status_changed`, `inventory.source_created`, … |
| `entity_type` / `entity_id` | text / uuid | |
| `detail` | jsonb | Before/after where relevant |
| `ip_address` | inet nullable | |

### `user`, `api_token`

| `user` | Type | Notes |
|---|---|---|
| `email` | text unique | |
| `display_name` | text | |
| `password_hash` | text nullable | Null once SSO-provisioned |
| `role` | enum | `VIEWER`, `ANALYST`, `ADMIN` |
| `is_active` | bool | |
| `external_subject` | text nullable | OIDC `sub`, for the future SSO swap |

| `api_token` | Type | Notes |
|---|---|---|
| `name` | text | |
| `token_prefix` | text indexed | First 8 chars, shown in the UI |
| `token_hash` | text | Argon2id of the full token |
| `scopes` | text[] | |
| `created_by_id` | fk → user | |
| `expires_at` / `last_used_at` / `revoked_at` | timestamptz nullable | |

---

## Phase 2 — inventory

### `inventory_source`

| Column | Type | Notes |
|---|---|---|
| `name` | text unique | |
| `kind` | enum | `CSV_DESKTOP_CENTRAL`, `CSV_LANSWEEPER`, `CSV_AZURE`, `API_DESKTOP_CENTRAL`, `API_AZURE_ARM`, `API_MS_GRAPH` |
| `mode` | enum | `AGGREGATE` (counts only — CSV) or `DETAILED` (per-device — API) |
| `config` | jsonb | Non-secret: base URL, tenant/subscription IDs, column mappings |
| `credential_id` | fk → integration_credential nullable | |
| `schedule_cron` | text nullable | API sources only |
| `is_active` | bool | |
| `last_sync_at` | timestamptz nullable | |
| `last_sync_status` | enum | `NEVER`, `OK`, `PARTIAL`, `ERROR` |
| `last_sync_error` | text nullable | |

### `integration_credential`
**Never returned by any API.** Write-only from the caller's perspective.

| Column | Type | Notes |
|---|---|---|
| `auth_type` | enum | `API_KEY`, `OAUTH_CLIENT_CREDENTIALS`, `BASIC` |
| `ciphertext` | bytea | Fernet-encrypted JSON payload |
| `key_version` | int | Supports rotation |
| `last_rotated_at` | timestamptz | |

### `system_integration`
Admin-panel-configured global integrations — NVD and VirusTotal. At most one
row per `kind`; distinct from `inventory_source`, which is a user-creatable
list. Reuses `integration_credential` for the encrypted key (see
docs/decisions.md).

| Column | Type | Notes |
|---|---|---|
| `kind` | enum | `NVD`, `VIRUSTOTAL` |
| `enabled` | bool | Explicitly disabling here overrides the equivalent env var — see `core.services.system_integrations.resolve_credential()` |
| `credential_id` | fk → integration_credential, nullable | Absent means "fall back to the env var" |
| `updated_by_id` | fk → user nullable | |

Unique on `kind`.

### `inventory_snapshot`
Each sync or CSV upload creates one. Snapshots are immutable; scans always run
against a named snapshot so results are reproducible.

| Column | Type | Notes |
|---|---|---|
| `source_id` | fk → inventory_source | |
| `taken_at` | timestamptz | |
| `mode` | enum | Copied from source at capture time |
| `device_count` | int nullable | `DETAILED` only |
| `software_row_count` | int | |
| `uploaded_by_id` | fk → user nullable | CSV uploads |
| `raw_file_blob_id` | fk → blob nullable | The uploaded CSV, kept |
| `is_latest` | bool | Partial unique index per source |

### `inventory_software`
The aggregate view — "how many endpoints run product X version Y". Populated by
both CSV and API sources.

| Column | Type | Notes |
|---|---|---|
| `snapshot_id` | fk → inventory_snapshot | |
| `vendor_raw` / `product_raw` | text | Exactly as the export said |
| `vendor` / `product` | text | Normalised via `vendor_alias` |
| `version_raw` | text | |
| `version_normalized` | text | Canonical dotted form |
| `version_parts` | int[] | For fast range comparison in SQL |
| `kind` | enum | `SOFTWARE` or `OPERATING_SYSTEM` |
| `device_count` | int | |

Index: `(snapshot_id, vendor, product)`.

### `inventory_device`
`DETAILED` (API) sources only.

| Column | Type | Notes |
|---|---|---|
| `snapshot_id` | fk → inventory_snapshot | |
| `device_identifier` | text | Source-native ID — **the thing you hand to ops** |
| `hostname` | text nullable | |
| `os_name` / `os_version` | text nullable | |
| `last_seen_at` | timestamptz nullable | |
| `attributes` | jsonb | Owner, OU, location, tags — whatever the source gives |

### `inventory_device_software`

| Column | Type | Notes |
|---|---|---|
| `device_id` | fk → inventory_device | |
| `vendor` / `product` / `version_normalized` / `version_parts` | as above | |

### `vendor_alias`
Maps the ten ways every vendor writes its own name to one canonical form.
Seeded, then extended by admins as mismatches surface.

| Column | Type | Notes |
|---|---|---|
| `alias` | text unique | `"Microsoft Corporation"`, `"microsoft corp"` |
| `canonical_vendor` | text | `"microsoft"` |
| `canonical_product` | text nullable | For product-level aliases too |

### `scan_run`

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | fk → advisory | |
| `initiated_by_id` | fk → user nullable | |
| `snapshot_ids` | uuid[] | Exactly which snapshots were scanned |
| `status` | enum | `QUEUED`, `RUNNING`, `COMPLETE`, `FAILED` |
| `started_at` / `finished_at` | timestamptz | |
| `match_count` | int | |
| `affected_device_count` | int nullable | |
| `error` | text nullable | |

### `scan_match`

| Column | Type | Notes |
|---|---|---|
| `scan_run_id` | fk → scan_run | |
| `cve_id` | text nullable | Null for non-CVE product matches |
| `snapshot_id` | fk → inventory_snapshot | |
| `vendor` / `product` | text | |
| `matched_version` | text | The version found in inventory |
| `affected_range` | text | The range it fell inside |
| `device_count` | int | |
| `device_ids` | uuid[] nullable | `DETAILED` sources — capped, full list paginated |
| `match_method` | enum | `CPE_RANGE`, `CPE_EXACT`, `TEXT_RANGE`, `FUZZY_NAME` |
| `confidence` | enum | `CONFIRMED`, `LIKELY`, `POSSIBLE` |
| `rationale` | text | Human-readable "why we think this matched" |

---

## Retention

| Data | Retention |
|---|---|
| Advisories, comments, status changes, audit log | Forever |
| Blobs (emails, attachments) | Forever |
| `inventory_snapshot` and children | 13 months rolling, latest per source always kept |
| `scan_run` / `scan_match` | 13 months |
| NVD cache (Redis) | 24h for found, 1h for not-found |
