"""Raise an Ivanti ITSM ticket (Service Request) for an advisory (D-050).

An analyst chooses Service → Category → Sub-category → Team from lists read
live from Ivanti — each narrowing the next — and the ticket is created with
those values plus a subject and description built from the advisory. The
advisory keeps a link to it. One-way: nothing is read back afterwards.

Settings live in ``system_integration`` (kind ``IVANTI_ITSM``): the tenant URL
and an encrypted, write-only API key; the rest ("Advanced") has defaults and
is checked by **Test**, which must pass before the integration can be enabled.
"""

from __future__ import annotations

import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import quote, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ...integrations.ivanti import IvantiClient, IvantiError, http_client
from ..models.advisory import Advisory, AdvisoryTicket, Blob
from ..models.base import utcnow
from ..models.enums import CredentialAuthType, SystemIntegrationKind
from ..models.inventory import IntegrationCredential
from ..models.system import SystemIntegration
from ..security.crypto import decrypt_credential, encrypt_credential
from ..storage.blobs import FilesystemBlobStore
from .audit import Actor, record
from .system_integrations import get_integration, set_enabled

KIND = SystemIntegrationKind.IVANTI_ITSM
LEVELS = ("service", "category", "subcategory", "team")
LEVEL_LABELS = {
    "service": "Service",
    "category": "Category",
    "subcategory": "Sub-category",
    "team": "Team",
}
CACHE_SECONDS = 600
ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024
#: An identical request this soon after a ticket was created returns that
#: ticket instead of creating a second one (double-click guard).
DUPLICATE_WINDOW = timedelta(minutes=2)
#: Test checks a cascading list under this many values of the level above.
PARENTS_TRIED = 10

PLACEHOLDERS = (
    "ref", "title", "severity", "priority", "type", "cves", "products",
    "description", "source", "received", "ack_due", "resolve_due", "url", "requested_by",
)  # fmt: skip

#: Ivanti's usual names; the admin's Test confirms them against the tenant and
#: they're editable under Advanced. Each level: the field set on the ticket,
#: the business object the list comes from, the field shown, and the field of
#: that object that must equal the previous level's choice ("" = no filter).
DEFAULT_LEVELS: dict[str, dict[str, str]] = {
    "service": {"field": "Service", "bo": "CI#Service", "display": "Name", "parent": ""},
    "category": {"field": "Category", "bo": "Category#", "display": "Name", "parent": "Service"},
    "subcategory": {
        "field": "Subcategory",
        "bo": "Subcategory#",
        "display": "Name",
        "parent": "Category",
    },
    "team": {"field": "OwnerTeam", "bo": "StandardUserTeam#", "display": "Team", "parent": ""},
}
DEFAULTS: dict[str, Any] = {
    "object_type": "ServiceReq#",
    "number_field": "ServiceReqNumber",
    "subject_field": "Subject",
    "description_field": "Symptom",
    "subject_template": "{ref} - {title}",
    "description_template": (
        "Security advisory {ref} from {source}\n"
        "Severity: {severity} · Priority: {priority} · Type: {type}\n"
        "CVEs: {cves}\n"
        "Affected products: {products}\n"
        "Acknowledge by: {ack_due} · Resolve by: {resolve_due}\n\n"
        "{description}\n\n"
        "Advisory Hub: {url}"
    ),
    "extra_fields": "",
    "attach_pdfs": True,
    "link_template": (
        "{base}/HEAT/Default.aspx?Scope=ObjectWorkspace&CommandId=Search"
        "&ObjectType={object_type_q}&CommandData=RecId,%3D,0,{recid},string,AND|"
    ),
}


class TicketError(ValueError):
    """A refused or failed request; the message is safe to show."""


@dataclass(frozen=True, slots=True)
class IvantiSettings:
    enabled: bool
    base_url: str
    tenant_id: str
    has_key: bool
    tested_at: str
    advanced: dict[str, Any]

    @property
    def levels(self) -> dict[str, dict[str, str]]:
        return dict(self.advanced["levels"])

    def missing(self) -> list[str]:
        gaps = [] if self.base_url else ["tenant URL"]
        if not self.has_key:
            gaps.append("API key")
        if not self.tested_at:
            gaps.append("a successful Test")
        return gaps


def get_settings(db: DbSession) -> IvantiSettings:
    row = get_integration(db, KIND)
    config: dict[str, Any] = dict(row.config) if row else {}
    advanced = {**DEFAULTS, **{k: v for k, v in config.items() if k in DEFAULTS}}
    levels = {
        lvl: {**DEFAULT_LEVELS[lvl], **(config.get("levels") or {}).get(lvl, {})} for lvl in LEVELS
    }
    advanced["levels"] = levels
    base_url = str(config.get("base_url", ""))
    return IvantiSettings(
        enabled=bool(row and row.enabled),
        base_url=base_url,
        tenant_id=str(config.get("tenant_id") or urlparse(base_url).hostname or ""),
        has_key=bool(row and row.credential_id),
        tested_at=str(config.get("tested_at", "")),
        advanced=advanced,
    )


def is_enabled(db: DbSession) -> bool:
    s = get_settings(db)
    return s.enabled and not s.missing()


def save_settings(
    db: DbSession,
    *,
    base_url: str,
    api_key: str | None,
    advanced: dict[str, Any] | None,
    actor: Actor,
) -> IvantiSettings:
    """Validate and store. A blank ``api_key`` keeps the current one. Any
    change to where or what is queried clears the last Test, so the admin
    must Test again (and the integration is switched off until they do)."""
    base_url = base_url.strip().rstrip("/")
    parsed = urlparse(base_url)
    if base_url and (parsed.scheme != "https" or not parsed.hostname or parsed.path):
        raise TicketError(
            "Tenant URL must be the https:// address only, e.g. https://example.ivanticloud.com"
        )
    current = get_settings(db)
    merged = dict(current.advanced)
    if advanced is not None:
        merged.update({k: v for k, v in advanced.items() if k in DEFAULTS or k == "levels"})
        sent_levels = advanced.get("levels") or {}
        merged["levels"] = {
            lvl: {
                key: str(sent_levels.get(lvl, {}).get(key, current.levels[lvl][key])).strip()
                for key in ("field", "bo", "display", "parent")
            }
            for lvl in LEVELS
        }
    _validate_advanced(merged)
    tenant_id = str((advanced or {}).get("tenant_id") or "").strip()

    row = get_integration(db, KIND)
    if row is None:
        row = SystemIntegration(kind=KIND, enabled=False, config={})
        db.add(row)
    previous = dict(row.config or {})
    config: dict[str, Any] = {**{k: merged[k] for k in DEFAULTS}, "levels": merged["levels"]}
    config["base_url"] = base_url
    config["tenant_id"] = tenant_id or previous.get("tenant_id", "")
    key = (api_key or "").strip()
    if key:
        credential = IntegrationCredential(
            auth_type=CredentialAuthType.API_KEY, ciphertext=encrypt_credential({"api_key": key})
        )
        db.add(credential)
        db.flush()
        row.credential_id = credential.id
    query_keys = ("base_url", "tenant_id", "levels", "object_type")
    changed_query = key or any(previous.get(k) != config.get(k) for k in query_keys)
    config["tested_at"] = "" if changed_query else previous.get("tested_at", "")
    if changed_query:
        row.enabled = False
        clear_cache()
    row.config = config
    row.updated_by_id = actor.user_id
    db.flush()
    record(
        db,
        actor=actor,
        action="system_integration.config_set",
        entity_type="system_integration",
        entity_id=row.id,
        detail={
            "kind": KIND.value,
            "changed": sorted(k for k in config if previous.get(k) != config.get(k)),
            "api_key": "rotated" if key else "unchanged",
        },
    )
    return get_settings(db)


def set_ivanti_enabled(db: DbSession, *, enabled: bool, actor: Actor) -> IvantiSettings:
    current = get_settings(db)
    if enabled and current.missing():
        raise TicketError("Before enabling: " + ", ".join(current.missing()) + ".")
    set_enabled(db, KIND, enabled=enabled, actor=actor)
    return get_settings(db)


def _validate_advanced(advanced: dict[str, Any]) -> None:
    for name in ("subject_template", "description_template"):
        _check_template(str(advanced[name]), PLACEHOLDERS, name.replace("_", " "))
    _check_template(
        str(advanced["link_template"]),
        ("base", "recid", "number", "object_type_q"),
        "ticket link template",
    )
    for level, cfg in advanced["levels"].items():
        if not cfg["field"] or not cfg["bo"] or not cfg["display"]:
            raise TicketError(
                f"{LEVEL_LABELS[level]}: field, list object and display field are required."
            )
    _parse_extra_fields(str(advanced["extra_fields"]))


def _check_template(template: str, allowed: tuple[str, ...], label: str) -> None:
    try:
        names = {f for _, f, _, _ in string.Formatter().parse(template) if f is not None}
    except ValueError:
        raise TicketError(f"The {label} has an unmatched {{ or }}.") from None
    unknown = sorted(n for n in names if n not in allowed)
    if unknown:
        raise TicketError(
            f"Unknown placeholder(s) in the {label}: {', '.join(unknown)}. "
            f"Available: {', '.join('{' + a + '}' for a in allowed)}"
        )


def _parse_extra_fields(text: str) -> dict[str, str]:
    """``Name=Value`` per line → fields always set on the ticket."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        name, sep, value = line.partition("=")
        if not sep or not name.strip():
            raise TicketError(f"Extra fields: '{line.strip()}' isn't Name=Value.")
        out[name.strip()] = value.strip()
    return out


# ─── Talking to Ivanti ───────────────────────────────────────────────────────


def _client(db: DbSession, s: IvantiSettings) -> IvantiClient:
    row = get_integration(db, KIND)
    if row is None or row.credential is None or not s.base_url:
        raise TicketError("Ivanti isn't configured.")
    api_key = decrypt_credential(row.credential.ciphertext).get("api_key", "")
    try:
        return IvantiClient(s.base_url, s.tenant_id, api_key, _http_client())
    except IvantiError as exc:
        raise TicketError(str(exc)) from None


def _http_client() -> Any:
    return http_client()


_cache: dict[tuple[str, ...], tuple[float, list[str]]] = {}


def clear_cache() -> None:
    _cache.clear()


def options(db: DbSession, level: str, parent: str | None = None) -> list[str]:
    """The choices for ``level``, narrowed by the previous level's choice
    (``parent``) when that level is configured to be. Cached 10 minutes."""
    if level not in LEVELS:
        raise TicketError(f"Unknown level {level!r}.")
    s = get_settings(db)
    cfg = s.levels[level]
    if cfg["parent"] and not parent:
        return []
    key = (s.base_url, s.tenant_id, level, cfg["bo"], cfg["display"], cfg["parent"], parent or "")
    hit = _cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    where = [(cfg["parent"], parent)] if cfg["parent"] and parent else []
    try:
        records = _client(db, s).search(cfg["bo"], [cfg["display"]], where)
    except IvantiError as exc:
        raise TicketError(str(exc)) from None
    values = sorted({r.get(cfg["display"], "").strip() for r in records} - {""}, key=str.lower)
    _cache[key] = (time.monotonic() + CACHE_SECONDS, values)
    return values


def parent_level(level: str) -> str | None:
    index = LEVELS.index(level)
    return LEVELS[index - 1] if index > 0 else None


@dataclass(slots=True)
class TestStep:
    label: str
    ok: bool
    detail: str


@dataclass(slots=True)
class TestReport:
    ok: bool
    steps: list[TestStep] = field(default_factory=list)


def run_test(db: DbSession, *, actor: Actor) -> TestReport:
    """Read-only: authenticate, read the ticket's schema, and walk the four
    lists (first service → its categories → first category's sub-categories;
    teams). Records success so the integration can be enabled."""
    s = get_settings(db)
    report = TestReport(ok=False)
    if not s.base_url or not s.has_key:
        report.steps.append(
            TestStep("Settings", False, "Set the tenant URL and API key, then Save.")
        )
        return report
    clear_cache()
    try:
        client = _client(db, s)
        client.authenticate()
        report.steps.append(TestStep("API key", True, f"Signed in to tenant {s.tenant_id}."))
    except (TicketError, IvantiError) as exc:
        report.steps.append(TestStep("API key", False, str(exc)))
        return report

    adv = s.advanced
    try:
        schema = client.schema_fields(str(adv["object_type"]))
    except IvantiError as exc:
        schema = {}
        report.steps.append(TestStep("Ticket fields", False, str(exc)))
    if schema:
        wanted = [cfg["field"] for cfg in s.levels.values()]
        wanted += [str(adv["subject_field"]), str(adv["description_field"])]
        wanted += list(_parse_extra_fields(str(adv["extra_fields"])))
        absent = [f for f in wanted if f not in schema]
        uncovered = sorted(f for f, req in schema.items() if req and f not in wanted)
        detail = f"{adv['object_type']} has {len(schema)} fields."
        if absent:
            detail += f" Not found: {', '.join(absent)}."
        if uncovered:
            detail += f" Required by the schema but not set here: {', '.join(uncovered[:12])}."
        report.steps.append(TestStep("Ticket fields", not absent, detail))
    elif not any(step.label == "Ticket fields" for step in report.steps):
        report.steps.append(
            TestStep("Ticket fields", True, "Schema not readable — skipped (lists checked below).")
        )

    # Each cascading level is tried under up to PARENTS_TRIED of the previous
    # level's values (some services have no categories); the first parent with
    # children becomes the parent for the next level.
    candidates: list[str] = []
    for level in LEVELS:
        cfg = s.levels[level]
        label = f"{LEVEL_LABELS[level]} list ({cfg['bo']})"
        parents: list[str | None] = list(candidates[:PARENTS_TRIED]) if cfg["parent"] else [None]
        if not parents:
            report.steps.append(TestStep(label, False, "No values above it to narrow by."))
            candidates = []
            continue
        values: list[str] = []
        used: str | None = None
        try:
            for parent in parents:
                values = options(db, level, parent)
                if values:
                    used = parent
                    break
        except TicketError as exc:
            report.steps.append(TestStep(label, False, str(exc)))
            candidates = []
            continue
        if values:
            scope = f" for {used!r}" if used else ""
            sample = ", ".join(values[:3]) + ("…" if len(values) > 3 else "")
            report.steps.append(TestStep(label, True, f"{len(values)} value(s){scope}: {sample}"))
        else:
            tried = f" (tried under {len(parents)} value(s) above)" if cfg["parent"] else ""
            report.steps.append(TestStep(label, False, f"No values{tried}."))
        if level != "team":
            candidates = values

    report.ok = all(step.ok for step in report.steps)
    row = get_integration(db, KIND)
    if row is not None:
        config = dict(row.config or {})
        config["tested_at"] = utcnow().isoformat() if report.ok else ""
        row.config = config
        if not report.ok:
            row.enabled = False
    record(
        db,
        actor=actor,
        action="system_integration.tested",
        entity_type="system_integration",
        entity_id=row.id if row else None,
        detail={"kind": KIND.value, "ok": report.ok},
    )
    return report


# ─── Creating a ticket ───────────────────────────────────────────────────────


def placeholder_values(advisory: Advisory, requested_by: str) -> dict[str, str]:
    def when(value: Any) -> str:
        return value.strftime("%Y-%m-%d %H:%M UTC") if value else "—"

    url = (
        f"{settings.public_base_url.rstrip('/')}/advisories/{advisory.id}"
        if settings.public_base_url
        else ""
    )
    products = sorted({f"{p.vendor or ''} {p.product}".strip() for p in advisory.products})
    return {
        "ref": advisory.external_ref or "(no reference)",
        "title": advisory.title,
        "severity": advisory.severity.value.title() if advisory.severity else "—",
        "priority": advisory.priority.value if advisory.priority else "—",
        "type": advisory.type.value.replace("_", " ").title().replace("Cve ", "CVE "),
        "cves": ", ".join(sorted(c.cve_id for c in advisory.cves)) or "—",
        "products": ", ".join(products) or "—",
        "description": advisory.description or "",
        "source": advisory.source.name if advisory.source else "—",
        "received": when(advisory.received_at),
        "ack_due": when(advisory.ack_due_at),
        "resolve_due": when(advisory.resolution_due_at),
        "url": url,
        "requested_by": requested_by,
    }


def draft(db: DbSession, advisory: Advisory, requested_by: str) -> tuple[str, str]:
    """Subject and description to pre-fill the dialog with."""
    adv = get_settings(db).advanced
    values = placeholder_values(advisory, requested_by)
    return (
        str(adv["subject_template"]).format_map(values)[:250],
        str(adv["description_template"]).format_map(values),
    )


def tickets_for(db: DbSession, advisory_id: uuid.UUID) -> list[AdvisoryTicket]:
    return list(
        db.scalars(
            select(AdvisoryTicket)
            .where(AdvisoryTicket.advisory_id == advisory_id)
            .order_by(AdvisoryTicket.created_at.desc())
        )
    )


@dataclass(slots=True)
class CreateResult:
    ticket: AdvisoryTicket
    reused: bool = False


def create_ticket(
    db: DbSession,
    advisory_id: uuid.UUID,
    *,
    choices: dict[str, str],
    subject: str,
    description: str,
    actor: Actor,
) -> CreateResult:
    """Create the ticket in Ivanti and link it. Every choice must be one of
    the values Ivanti offers for it, given the choice before (re-checked here,
    so a tampered form can't send arbitrary values)."""
    s = get_settings(db)
    if not (s.enabled and not s.missing()):
        raise TicketError("The Ivanti integration isn't enabled.")
    advisory = db.scalar(select(Advisory).where(Advisory.id == advisory_id).with_for_update())
    if advisory is None:
        raise LookupError(advisory_id)

    chosen = {lvl: (choices.get(lvl) or "").strip() for lvl in LEVELS}
    missing = [LEVEL_LABELS[lvl] for lvl in LEVELS if not chosen[lvl]]
    if missing:
        raise TicketError("Choose a " + ", ".join(missing) + ".")
    subject, description = subject.strip(), description.strip()
    if not subject:
        raise TicketError("The subject can't be empty.")

    recent = db.scalar(
        select(AdvisoryTicket).where(
            AdvisoryTicket.advisory_id == advisory.id,
            AdvisoryTicket.service == chosen["service"],
            AdvisoryTicket.category == chosen["category"],
            AdvisoryTicket.subcategory == chosen["subcategory"],
            AdvisoryTicket.team == chosen["team"],
            AdvisoryTicket.created_at >= utcnow() - DUPLICATE_WINDOW,
        )
    )
    if recent is not None:
        return CreateResult(recent, reused=True)

    for level in LEVELS:
        cfg = s.levels[level]
        prev = parent_level(level)
        parent = chosen[prev] if cfg["parent"] and prev else None
        if chosen[level] not in options(db, level, parent):
            scope = f" under {parent!r}" if parent else ""
            raise TicketError(f"{chosen[level]!r} isn't a {LEVEL_LABELS[level]} in Ivanti{scope}.")

    adv = s.advanced
    object_type = str(adv["object_type"])
    values = {
        **_parse_extra_fields(str(adv["extra_fields"])),
        **{s.levels[lvl]["field"]: chosen[lvl] for lvl in LEVELS},
        str(adv["subject_field"]): subject[:250],
        str(adv["description_field"]): description,
    }
    client = _client(db, s)
    try:
        rec_id, created = client.create(object_type, values)
    except IvantiError as exc:
        raise TicketError(str(exc)) from None

    number_field = str(adv["number_field"])
    number = created.get(number_field) or None
    warnings: list[str] = []
    if number is None:
        try:
            number = client.find(object_type, rec_id).get(number_field) or None
        except IvantiError:
            warnings.append("Couldn't read the ticket number back.")

    attached = 0
    if adv["attach_pdfs"]:
        blobs = FilesystemBlobStore(settings.blob_root)
        for att in advisory.attachments:
            if not att.filename.lower().endswith(".pdf"):
                continue
            blob = db.get(Blob, att.blob_id)
            if blob is None or blob.size_bytes > ATTACHMENT_MAX_BYTES:
                warnings.append(f"{att.filename} not attached (over 10 MB).")
                continue
            try:
                client.add_attachment(
                    object_type, rec_id, att.filename, blobs.get_bytes(blob.sha256)
                )
                attached += 1
            except (IvantiError, OSError) as exc:
                warnings.append(f"{att.filename} not attached: {exc}")

    url = str(adv["link_template"]).format(
        base=s.base_url, recid=quote(rec_id), number=quote(number or ""),
        object_type_q=quote(object_type, safe=""),
    )  # fmt: skip
    ticket = AdvisoryTicket(
        advisory_id=advisory.id,
        system="IVANTI",
        object_type=object_type,
        number=number,
        rec_id=rec_id,
        url=url,
        service=chosen["service"],
        category=chosen["category"],
        subcategory=chosen["subcategory"],
        team=chosen["team"],
        created_by_id=actor.user_id,
        attachment_count=attached,
        warning=" ".join(warnings) or None,
    )
    db.add(ticket)
    db.flush()
    record(
        db,
        actor=actor,
        action="advisory.ticket_created",
        entity_type="advisory",
        entity_id=advisory.id,
        detail={
            "system": "IVANTI",
            "number": number,
            "rec_id": rec_id,
            **chosen,
            "attachments": attached,
        },
    )
    return CreateResult(ticket)
