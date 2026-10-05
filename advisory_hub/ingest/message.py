"""Parse ``.msg`` and ``.eml`` messages into a normalised structure.

``.msg`` is the primary format — the entire 135-message corpus is Outlook
``.msg``, and ``extract-msg`` parses all of them with zero errors (D-014).
Filenames are never parsed: Outlook sanitises ``::`` to ``_`` and strips ``/``,
so the filename is a lossy copy of the subject.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from . import patterns

#: Attachment types worth keeping. 1,088 of the corpus's 1,223 attachments are
#: inline signature images — see §5 of docs/ingestion.md.
KEEP_EXTENSIONS = frozenset({".pdf", ".csv", ".xlsx", ".xls", ".docx", ".doc", ".txt"})
MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024


@dataclass(slots=True)
class Attachment:
    filename: str
    data: bytes
    content_type: str | None = None

    @property
    def extension(self) -> str:
        return Path(self.filename).suffix.lower()

    @property
    def is_pdf(self) -> bool:
        return self.extension == ".pdf"

    @property
    def is_sidecar(self) -> bool:
        return self.extension in {".csv", ".xlsx", ".xls"}


@dataclass(slots=True)
class ParsedMessage:
    raw_bytes: bytes
    dedupe_hash: str
    subject: str
    sender: str | None
    sender_email: str | None
    recipients: str | None
    sent_at: datetime | None
    message_id: str | None
    body_text: str
    attachments: list[Attachment] = field(default_factory=list)
    fields: dict[str, str] = field(default_factory=dict)
    discarded_attachments: int = 0

    # ─── Derived from the subject ────────────────────────────────────────────
    @property
    def external_ref(self) -> str | None:
        return subject_parts(self.subject)[0]

    @property
    def title(self) -> str:
        return subject_parts(self.subject)[1]

    @property
    def pdfs(self) -> list[Attachment]:
        return [a for a in self.attachments if a.is_pdf]

    @property
    def sidecars(self) -> list[Attachment]:
        return [a for a in self.attachments if a.is_sidecar]


def subject_parts(subject: str | None) -> tuple[str | None, str]:
    """``(external_ref, title)`` from a subject line.

    Reply/forward markers and [EXTERNAL] are stripped first. The strict
    corpus pattern (``patterns.SUBJECT``) wins; failing that, a reference
    anywhere in the subject is still picked up, and the title is the
    stripped subject.
    """
    cleaned = patterns.SUBJECT_PREFIXES.sub("", patterns.normalise_whitespace(subject or ""))
    m = patterns.SUBJECT.match(cleaned)
    if m:
        title = re.sub(r"\s+", " ", m.group("title")).strip()
        ref = f"{m.group('prefix').upper()}-{m.group('number')}"
        return ref, title or cleaned.strip() or "(untitled)"
    loose = next(
        (
            f"{found.group('prefix')}-{found.group('number')}"
            for found in patterns.REFERENCE_ANYWHERE.finditer(cleaned)
            if found.group("prefix") not in patterns.NOT_A_REFERENCE
        ),
        None,
    )
    return loose, cleaned.strip() or "(untitled)"


class MessageParseError(Exception):
    pass


def parse_message(path: Path) -> ParsedMessage:
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".msg":
        return _parse_msg(path, raw)
    if suffix in {".eml", ".mime"}:
        return _parse_eml(raw)
    raise MessageParseError(f"Unsupported message format: {suffix}")


# ─── Outlook .msg ────────────────────────────────────────────────────────────


def _parse_msg(path: Path, raw: bytes) -> ParsedMessage:
    try:
        # extract-msg logs a warning per message for benign header variations
        # ("Header found, but 'to' is not included"). At corpus scale that is
        # hundreds of lines of noise that drowns real ingestion errors.
        import logging as _logging

        import extract_msg

        _logging.getLogger("extract_msg").setLevel(_logging.ERROR)
    except ImportError as exc:  # pragma: no cover
        raise MessageParseError("extract-msg is not installed") from exc

    try:
        msg = extract_msg.Message(str(path))  # type: ignore[no-untyped-call]
    except Exception as exc:
        raise MessageParseError(f"Could not open .msg: {exc}") from exc

    try:
        attachments, discarded = _collect_msg_attachments(msg)
        body = patterns.normalise_whitespace(msg.body or "")
        sender = (msg.sender or "").strip() or None
        return ParsedMessage(
            raw_bytes=raw,
            dedupe_hash=hashlib.sha256(raw).hexdigest(),
            subject=(msg.subject or "").strip(),
            sender=sender,
            sender_email=_extract_address(sender),
            recipients=(msg.to or "").strip() or None,
            sent_at=_coerce_datetime(msg.date),
            message_id=(msg.messageId or "").strip() or None,
            body_text=body,
            attachments=attachments,
            fields=parse_body_fields(body),
            discarded_attachments=discarded,
        )
    finally:
        with _Suppressed():
            msg.close()


def _collect_msg_attachments(msg: Any) -> tuple[list[Attachment], int]:
    kept: list[Attachment] = []
    discarded = 0
    for att in msg.attachments:
        name = (
            getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or ""
        ).strip()
        if not name or Path(name).suffix.lower() not in KEEP_EXTENSIONS:
            discarded += 1
            continue
        data = getattr(att, "data", None)
        if not isinstance(data, bytes) or not data:
            discarded += 1
            continue
        if len(data) > MAX_ATTACHMENT_BYTES:
            discarded += 1
            continue
        kept.append(Attachment(filename=Path(name).name, data=data))
    return kept, discarded


# ─── RFC 5322 .eml ───────────────────────────────────────────────────────────


def _parse_eml(raw: bytes) -> ParsedMessage:
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    body = ""
    plain = msg.get_body(preferencelist=("plain",))
    if plain is not None:
        body = plain.get_content()
    else:
        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            body = _html_to_text(html_part.get_content())

    attachments: list[Attachment] = []
    discarded = 0
    for part in msg.iter_attachments():
        name = part.get_filename()
        if not name or Path(name).suffix.lower() not in KEEP_EXTENSIONS:
            discarded += 1
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_ATTACHMENT_BYTES:
            discarded += 1
            continue
        attachments.append(
            Attachment(filename=Path(name).name, data=payload, content_type=part.get_content_type())
        )

    sender = (msg.get("From") or "").strip() or None
    body = patterns.normalise_whitespace(body)
    return ParsedMessage(
        raw_bytes=raw,
        dedupe_hash=hashlib.sha256(raw).hexdigest(),
        subject=(msg.get("Subject") or "").strip(),
        sender=sender,
        sender_email=_extract_address(sender),
        recipients=(msg.get("To") or "").strip() or None,
        sent_at=_parse_header_date(msg.get("Date")),
        message_id=(msg.get("Message-ID") or "").strip() or None,
        body_text=body,
        attachments=attachments,
        fields=parse_body_fields(body),
        discarded_attachments=discarded,
    )


def _html_to_text(html: str) -> str:
    """Minimal, dependency-free HTML → text. Sanitisation for *rendering* is a
    separate concern handled at display time."""
    out = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    out = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", out)
    out = re.sub(r"(?i)</t[dh]>", "\t", out)
    out = re.sub(r"<[^>]+>", "", out)
    import html as html_mod

    return re.sub(r"\n{3,}", "\n\n", html_mod.unescape(out))


# ─── Body field block ────────────────────────────────────────────────────────


def parse_body_fields(body: str) -> dict[str, str]:
    """Extract the labelled field block by label-scan.

    Deliberately not a regex per field with a lookahead: five corpus messages
    run one field into the next without a blank line, and a per-field regex
    swallows the remainder of the message. Scanning for every label and slicing
    between them is robust to that.
    """
    text = patterns.normalise_whitespace(body or "")
    marks = [(m.start(), m.end(), m.group(1).lower()) for m in patterns.BODY_LABEL.finditer(text)]
    fields: dict[str, str] = {}
    for i, (_start, end, label) in enumerate(marks):
        stop = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        value = re.sub(r"\s+", " ", text[end:stop]).strip()
        # First occurrence wins: the block appears once, but the words can recur.
        fields.setdefault(_canonical_label(label), value)
    return fields


def _canonical_label(label: str) -> str:
    return {"risk level": "risk_level", "detected on": "detected_on"}.get(
        label, label.replace("/", "_").replace(" ", "_")
    )


# ─── Value coercion ──────────────────────────────────────────────────────────

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
#: Observed shapes: "23-July-2026", "4-Aug-2026", "04- Aug-2026".
_DATE = re.compile(r"^\s*(\d{1,2})\s*-\s*([A-Za-z]{3,9})\s*-\s*(\d{4})\s*$")


def parse_advisory_date(value: str | None) -> date | None:
    if not value:
        return None
    m = _DATE.match(value.strip())
    if not m:
        return None
    month = _MONTHS.get(m.group(2)[:3].lower())
    if month is None:
        return None
    try:
        return date(int(m.group(3)), month, int(m.group(1)))
    except ValueError:
        return None


def _extract_address(sender: str | None) -> str | None:
    if not sender:
        return None
    m = patterns.EMAIL.search(sender)
    return m.group(0).lower() if m else None


def _coerce_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        return _parse_header_date(value)
    return None


def _parse_header_date(value: str | None) -> datetime | None:
    if not value:
        return None
    from email.utils import parsedate_to_datetime

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class _Suppressed:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return True
