"""Mailbox-folder sync: Microsoft Graph → the inbox (D-049).

Each new message in the configured folder is downloaded as MIME (.eml) and
**deposited into the inbox**, exactly like a Power Automate drop — so it goes
through the same sandboxed parser, duplicate gates (D-048), archive/failed
handling and audit. This module only moves bytes; it decides nothing about
the advisory.

Read-only: the mailbox is never written to. Position is kept with a Graph
delta link in ``mailbox_sync_state``; changing the mailbox or folder starts
over (and the duplicate gates stop anything already imported).

Never raises for a sync failure: the error is stored on the state row and
shown on /admin, and the next cycle tries again.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ...ingest.graph_mailbox import (
    GRAPH_SCOPE,
    DeltaExpiredError,
    GraphMailbox,
    MailboxError,
)
from ...ingest.watcher import Inbox
from ...inventory.api_client import ApiAdapterError, fetch_oauth_client_credentials_token
from ...logging import get_logger
from ..models.base import utcnow
from ..models.enums import SystemIntegrationKind
from ..models.system import MailboxSyncState
from ..security.ssrf import SsrfBlockedError
from .system_integrations import (
    MAILBOX_POLL_DEFAULT,
    EntraApp,
    entra_app,
    entra_client_secret,
)

log = get_logger(__name__)

HTTP_TIMEOUT_SECONDS = 60.0
#: Serialises sync runs (worker poller vs "Sync now").
_SYNC_LOCK_KEY = 0x4D_42_58_53  # "MBXS"


@dataclass(slots=True)
class SyncReport:
    status: str  # ok | error | disabled | busy
    fetched: int = 0
    skipped_too_large: int = 0
    message: str = ""
    deposited: list[str] = field(default_factory=list)


def poll_seconds(db: DbSession) -> int:
    app = entra_app(db, SystemIntegrationKind.MAILBOX_SYNC)
    value = app.config.get("poll_seconds", "")
    return int(value) if value.isdigit() else MAILBOX_POLL_DEFAULT


def state(db: DbSession) -> MailboxSyncState | None:
    return db.scalar(select(MailboxSyncState).order_by(MailboxSyncState.created_at).limit(1))


def _http_client() -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False)


def _connect(db: DbSession, app: EntraApp, client: httpx.Client) -> GraphMailbox:
    secret = entra_client_secret(db, SystemIntegrationKind.MAILBOX_SYNC) or ""
    try:
        token = fetch_oauth_client_credentials_token(
            client,
            tenant_id=app.tenant_id,
            client_id=app.client_id,
            client_secret=secret,
            scope=GRAPH_SCOPE,
        )
    except SsrfBlockedError as exc:
        raise MailboxError(
            f"{exc.reason}. Add login.microsoftonline.com to OUTBOUND_ALLOWLIST."
        ) from None
    except ApiAdapterError as exc:
        raise MailboxError(f"Couldn't get a token from Entra: {exc}") from None
    return GraphMailbox(client, token, app.config["mailbox"])


def check_connection(db: DbSession) -> tuple[bool, str]:
    """For the admin panel's Test button: token, mailbox, folder."""
    app = entra_app(db, SystemIntegrationKind.MAILBOX_SYNC)
    if missing := app.missing():
        return False, "Set these first: " + ", ".join(missing)
    with _http_client() as client:
        try:
            mailbox = _connect(db, app, client)
            _, count = mailbox.resolve_folder(app.config["folder"])
        except MailboxError as exc:
            return False, str(exc)
    shown = f"{count} message(s)" if count is not None else "found"
    return True, f"Connected — {app.config['mailbox']} / {app.config['folder']}: {shown}."


def run_sync(db: DbSession, *, inbox: Inbox | None = None) -> SyncReport:
    """One sync cycle. The caller commits (the state row records the outcome)."""
    app = entra_app(db, SystemIntegrationKind.MAILBOX_SYNC)
    if not app.enabled or app.missing():
        return SyncReport("disabled", message="Mailbox sync is off.")
    if not db.scalar(select(func.pg_try_advisory_xact_lock(_SYNC_LOCK_KEY))):
        return SyncReport("busy", message="A sync is already running.")

    target = f"{app.config['mailbox'].lower()}|{app.config['folder']}"
    row = state(db)
    if row is None:
        row = MailboxSyncState(target=target)
        db.add(row)
    elif row.target != target:
        # Different mailbox or folder: start over (counters too).
        row.target, row.folder_id, row.delta_link = target, None, None
        row.fetched_total = row.skipped_too_large_total = 0

    inbox = inbox or Inbox()
    report = SyncReport("ok")
    with _http_client() as client:
        try:
            mailbox = _connect(db, app, client)
            if row.folder_id is None:
                row.folder_id, _ = mailbox.resolve_folder(app.config["folder"])
            try:
                _pull(mailbox, row, inbox, report)
            except DeltaExpiredError:
                row.delta_link = None
                _pull(mailbox, row, inbox, report)
        except MailboxError as exc:
            report.status, report.message = "error", str(exc)
            if "not found" in str(exc).lower():
                row.folder_id = None  # renamed/moved: look it up again next time

    row.last_sync_at = utcnow()
    row.last_status = report.status
    row.last_error = report.message if report.status == "error" else None
    row.fetched_total += report.fetched
    row.skipped_too_large_total += report.skipped_too_large
    if report.status == "ok":
        report.message = f"{report.fetched} new message(s) imported" + (
            f", {report.skipped_too_large} too large to import" if report.skipped_too_large else ""
        )
    log.info(
        "mailbox.sync",
        status=report.status,
        fetched=report.fetched,
        skipped_too_large=report.skipped_too_large,
        error=row.last_error,
    )
    return report


def _pull(mailbox: GraphMailbox, row: MailboxSyncState, inbox: Inbox, report: SyncReport) -> None:
    assert row.folder_id is not None
    for page in mailbox.delta(row.folder_id, row.delta_link):
        for message_id in page.message_ids:
            mime = mailbox.download_mime(message_id, settings.upload_max_bytes)
            if mime is None:
                report.skipped_too_large += 1
                log.warning("mailbox.message_too_large", graph_id=message_id[-24:])
                continue
            # Graph ids are long and full of symbols; a hash makes a clean,
            # stable filename (the inbox never overwrites — see Inbox.deposit).
            name = f"mailbox-{hashlib.sha256(message_id.encode()).hexdigest()[:20]}.eml"
            report.deposited.append(inbox.deposit(name, mime).name)
            report.fetched += 1
        if page.delta_link:
            # Only the last page carries it; saved once every page is in.
            row.delta_link = page.delta_link
