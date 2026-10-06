"""Microsoft Graph, read-only, for one mailbox folder (D-049).

App-only token (client credentials). The app may read only the one mailbox:
Exchange RBAC for Applications grants it the "Application Mail.Read" role
scoped to that mailbox — *not* an Entra-consented Mail.Read, which would open
every mailbox (operations.md). Nothing here writes to the mailbox.

Every URL is SSRF-checked, redirects are off, and the bearer token is only
ever sent to ``graph.microsoft.com`` — paging links come back from the server,
so they're checked too.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ..core.security.ssrf import SsrfBlockedError, validate_outbound_url

GRAPH = "https://graph.microsoft.com"
GRAPH_HOST = "graph.microsoft.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
#: Folders Graph knows by a fixed name in any mailbox language.
WELL_KNOWN = {"inbox", "archive", "junkemail", "deleteditems", "drafts", "sentitems"}
MAX_PAGES = 200
PAGE_SIZE = 50


class MailboxError(Exception):
    """A Graph call failed; ``str()`` is safe to show an admin."""


class DeltaExpiredError(MailboxError):
    """Graph no longer accepts the stored delta link (HTTP 410): start over.
    Re-imported messages are stopped by the duplicate gates (D-048)."""


@dataclass(frozen=True, slots=True)
class DeltaPage:
    message_ids: list[str]
    next_link: str | None
    delta_link: str | None


class GraphMailbox:
    def __init__(self, client: httpx.Client, token: str, mailbox: str) -> None:
        self._client = client
        self._headers = {"Authorization": f"Bearer {token}"}
        self._base = f"{GRAPH}/v1.0/users/{quote(mailbox)}"

    # ─── Folders ─────────────────────────────────────────────────────────────

    def resolve_folder(self, path: str) -> tuple[str, int | None]:
        """``"Inbox/Security Advisories"`` → (folder id, total item count).

        The first segment may be a well-known name (``Inbox``) or a top-level
        folder's display name; later segments are child folders, matched
        case-insensitively."""
        parts = [p for p in path.split("/") if p.strip()]
        if not parts:
            raise MailboxError("No folder set.")
        first = parts[0].strip()
        if first.lower().replace(" ", "") in WELL_KNOWN:
            folder = self._get(f"{self._base}/mailFolders/{first.lower().replace(' ', '')}")
        else:
            folder = self._child(f"{self._base}/mailFolders", first, "the mailbox")
        for name in parts[1:]:
            parent = folder.get("displayName", "?")
            folder = self._child(
                f"{self._base}/mailFolders/{folder['id']}/childFolders", name, parent
            )
        count = folder.get("totalItemCount")
        return str(folder["id"]), int(count) if isinstance(count, int) else None

    def _child(self, url: str, name: str, parent: str) -> dict[str, Any]:
        wanted = name.strip().lower()
        next_url: str | None = f"{url}?$top=100&$select=id,displayName,totalItemCount"
        seen = 0
        while next_url and seen < MAX_PAGES:
            page = self._get(next_url)
            for folder in page.get("value", []):
                if str(folder.get("displayName", "")).strip().lower() == wanted:
                    return dict(folder)
            next_url = page.get("@odata.nextLink")
            seen += 1
        raise MailboxError(f"Folder {name!r} not found under {parent}.")

    # ─── Messages ────────────────────────────────────────────────────────────

    def delta(self, folder_id: str, delta_link: str | None) -> Iterator[DeltaPage]:
        """Pages of message ids added since ``delta_link`` (all, if none). The
        last page carries the new delta link. Removals are ignored — the
        tool never deletes."""
        url: str | None = delta_link or (
            f"{self._base}/mailFolders/{folder_id}/messages/delta?$select=id"
        )
        pages = 0
        while url:
            pages += 1
            if pages > MAX_PAGES:
                raise MailboxError(f"Stopped after {MAX_PAGES} pages; will continue next cycle.")
            page = self._get(url, prefer=f"odata.maxpagesize={PAGE_SIZE}")
            ids = [str(m["id"]) for m in page.get("value", []) if "id" in m and "@removed" not in m]
            next_link = page.get("@odata.nextLink")
            yield DeltaPage(ids, next_link, page.get("@odata.deltaLink"))
            url = next_link

    def download_mime(self, message_id: str, max_bytes: int) -> bytes | None:
        """The message as RFC 822 (.eml) bytes, attachments included — or
        ``None`` if it's larger than ``max_bytes`` (download stops there)."""
        url = f"{self._base}/messages/{quote(message_id, safe='')}/$value"
        self._check(url)
        try:
            with self._client.stream("GET", url, headers=self._headers) as response:
                self._raise_for(response, url)
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        return None
                    chunks.append(chunk)
                return b"".join(chunks)
        except httpx.HTTPError as exc:
            raise MailboxError(f"Downloading a message failed: {exc}") from None

    # ─── HTTP ────────────────────────────────────────────────────────────────

    def _check(self, url: str) -> None:
        if urlparse(url).hostname != GRAPH_HOST:
            # Never hand the token to another host, even an allowlisted one.
            raise MailboxError(f"Refusing to send the token to {urlparse(url).hostname!r}.")
        try:
            validate_outbound_url(url)
        except SsrfBlockedError as exc:
            raise MailboxError(f"{exc.reason}. Add {GRAPH_HOST} to OUTBOUND_ALLOWLIST.") from None

    def _get(self, url: str, *, prefer: str | None = None) -> dict[str, Any]:
        self._check(url)
        headers = dict(self._headers)
        if prefer:
            headers["Prefer"] = prefer
        try:
            response = self._client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise MailboxError(f"Graph request failed: {exc}") from None
        self._raise_for(response, url)
        return dict(response.json())

    @staticmethod
    def _raise_for(response: httpx.Response, url: str) -> None:
        if response.status_code < 400:
            return
        if response.status_code in (401, 403):
            raise MailboxError(
                f"Access denied by Microsoft Graph (HTTP {response.status_code}). Check that "
                "Exchange lets this app read this mailbox (RBAC for Applications: the "
                "'Application Mail.Read' role scoped to it) — see operations.md."
            )
        if response.status_code == 404:
            raise MailboxError("Mailbox or folder not found (HTTP 404) — check the address.")
        if response.status_code == 410:
            raise DeltaExpiredError("The sync position expired; starting over.")
        raise MailboxError(f"Graph returned HTTP {response.status_code}.")
