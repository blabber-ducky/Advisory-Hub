"""Shared HTTP plumbing for API-source adapters.

Every outbound call is SSRF-validated **immediately before use**, not only
at config-save time — DNS can rebind between the two moments, so
config-time validation alone isn't a guarantee (see
`core.security.ssrf`). Redirects are never followed, so a redirect to a
blocked host can't be used to bypass the guard either.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core.security.ssrf import validate_outbound_url

REQUEST_TIMEOUT_SECONDS = 30.0


class ApiAdapterError(Exception):
    """Transport, auth, or protocol failure talking to an inventory API."""


def build_client() -> httpx.Client:
    return httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False)


QueryValue = str | int | float | bool | None


def get_json(
    client: httpx.Client,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, QueryValue] | None = None,
) -> Any:
    validate_outbound_url(url)
    try:
        response = client.get(url, headers=headers, params=params)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ApiAdapterError(f"GET {url} failed: {exc}") from exc
    return response.json()


def fetch_oauth_client_credentials_token(
    client: httpx.Client, *, tenant_id: str, client_id: str, client_secret: str, scope: str
) -> str:
    """Entra ID (Azure AD) OAuth2 client-credentials flow — shared by the
    Azure ARM and MS Graph adapters, which differ only in `scope`."""
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    validate_outbound_url(token_url)
    try:
        response = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            },
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ApiAdapterError(f"Token request failed: {exc}") from exc
    token = response.json().get("access_token")
    if not token:
        raise ApiAdapterError("Token response did not contain an access_token")
    return str(token)
