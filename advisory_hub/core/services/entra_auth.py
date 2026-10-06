"""Microsoft Entra ID sign-in — OIDC authorization code flow with PKCE.

Entra is used **only to prove who someone is**. Whether they may sign in and
what they may do come from the local ``user_account`` row: no group or role
claim is requested or read (D-049). Rules:

- Single tenant: the ID token's ``tid`` and issuer must be the configured
  tenant. No ``common``/``organizations`` endpoint.
- The ID token is signature-verified (RS256, tenant JWKS) and its ``aud``,
  ``iss``, ``nonce``, ``exp``/``nbf`` checked, even though it arrives directly
  from the token endpoint over TLS.
- Matching: a user already linked to this Entra object (``tid:oid`` in
  ``external_subject``); else an *unlinked* user whose email equals the
  token's ``preferred_username``/``email``, which links it; else refused. An
  admin must have added the user first. Deactivated users are refused.
- Every refusal is audited with the real reason; the person sees one generic
  message, so nothing about account state leaks.

All HTTP goes through ``validate_outbound_url`` (SSRF guard, allowlist) with
redirects off. No refresh token is requested or stored.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from ...config import settings
from ..models.base import utcnow
from ..models.enums import ActorKind, SystemIntegrationKind
from ..models.user import User
from ..security.ssrf import SsrfBlockedError, validate_outbound_url
from .audit import Actor, record
from .system_integrations import EntraApp, entra_app, entra_client_secret

LOGIN_HOST = "https://login.microsoftonline.com"
SCOPES = "openid profile email"
CALLBACK_PATH = "/auth/entra/callback"
#: Seconds of clock skew tolerated on exp/nbf/iat.
LEEWAY_SECONDS = 120
JWKS_TTL_SECONDS = 3600
HTTP_TIMEOUT_SECONDS = 15.0

#: Shown to the person for every refusal. The audit log has the reason.
REFUSED_MESSAGE = (
    "Your Microsoft account can't sign in to Advisory Hub. "
    "Ask an administrator to add you, then try again."
)


class EntraLoginError(Exception):
    """Sign-in refused or failed. ``user_message`` is safe to display;
    ``reason`` is for the audit log and logs only."""

    def __init__(self, reason: str, user_message: str = REFUSED_MESSAGE) -> None:
        super().__init__(reason)
        self.reason = reason
        self.user_message = user_message


@dataclass(frozen=True, slots=True)
class LoginFlow:
    """What the callback must check, carried in a short-lived signed cookie."""

    state: str
    nonce: str
    code_verifier: str

    def to_dict(self) -> dict[str, str]:
        return {"state": self.state, "nonce": self.nonce, "code_verifier": self.code_verifier}

    @classmethod
    def from_dict(cls, data: object) -> LoginFlow | None:
        if not isinstance(data, dict):
            return None
        try:
            return cls(str(data["state"]), str(data["nonce"]), str(data["code_verifier"]))
        except KeyError:
            return None


def _http_client() -> httpx.Client:
    """Redirects off: a redirect could otherwise bypass the SSRF guard."""
    return httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False)


def redirect_uri() -> str:
    return settings.public_base_url.rstrip("/") + CALLBACK_PATH


def enabled_app(db: DbSession) -> EntraApp | None:
    """The sign-in app if it's switched on and complete, else ``None``."""
    app = entra_app(db, SystemIntegrationKind.ENTRA_SSO)
    return app if app.enabled and not app.missing() else None


def start_login(app: EntraApp) -> tuple[str, LoginFlow]:
    """The Microsoft authorize URL to redirect to, and the flow to remember."""
    flow = LoginFlow(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        code_verifier=secrets.token_urlsafe(64),
    )
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(flow.code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    query = urlencode(
        {
            "client_id": app.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri(),
            "response_mode": "query",
            "scope": SCOPES,
            "state": flow.state,
            "nonce": flow.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{LOGIN_HOST}/{app.tenant_id}/oauth2/v2.0/authorize?{query}", flow


def complete_login(
    db: DbSession,
    *,
    code: str,
    state: str,
    flow: LoginFlow | None,
    ip_address: str | None = None,
    client: httpx.Client | None = None,
) -> User:
    """Validate the callback, verify the ID token, and return the local user.

    Raises ``EntraLoginError`` (already audited) on any refusal.
    """
    app = enabled_app(db)
    if app is None:
        raise EntraLoginError("sso_disabled", "Microsoft sign-in isn't enabled.")
    if flow is None or not secrets.compare_digest(flow.state, state or ""):
        # Expired/missing flow cookie, or a forged/replayed callback.
        _refuse(db, "state_mismatch", {}, ip_address)
    secret = entra_client_secret(db, SystemIntegrationKind.ENTRA_SSO)
    assert flow is not None and secret is not None  # checked above / by missing()

    owns_client = client is None
    client = client or _http_client()
    try:
        id_token = _exchange_code(client, app, secret, code, flow)
        claims = _verify_id_token(client, app, id_token, flow.nonce)
    except EntraLoginError as exc:
        _refuse(db, exc.reason, {}, ip_address)
    finally:
        if owns_client:
            client.close()
    return _resolve_user(db, claims, ip_address)


# ─── Token exchange and verification ─────────────────────────────────────────


def _exchange_code(
    client: httpx.Client, app: EntraApp, secret: str, code: str, flow: LoginFlow
) -> str:
    url = f"{LOGIN_HOST}/{app.tenant_id}/oauth2/v2.0/token"
    try:
        validate_outbound_url(url)
        response = client.post(
            url,
            data={
                "grant_type": "authorization_code",
                "client_id": app.client_id,
                "client_secret": secret,
                "code": code,
                "redirect_uri": redirect_uri(),
                "code_verifier": flow.code_verifier,
                "scope": SCOPES,
            },
        )
    except (httpx.HTTPError, SsrfBlockedError) as exc:
        raise EntraLoginError(f"token_request_failed: {exc}") from None
    if response.status_code != 200:
        # Entra's error body names the problem (e.g. AADSTS7000215 bad secret).
        detail = _error_code(response)
        raise EntraLoginError(f"token_endpoint_{response.status_code}: {detail}")
    id_token = response.json().get("id_token")
    if not isinstance(id_token, str):
        raise EntraLoginError("no_id_token")
    return id_token


def _error_code(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return "unparseable error body"
    codes = body.get("error_codes") or []
    return f"{body.get('error')} {codes[:3]}"


_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _jwks(client: httpx.Client, tenant_id: str, *, refresh: bool = False) -> dict[str, Any]:
    cached = _jwks_cache.get(tenant_id)
    if cached and not refresh and cached[0] > time.monotonic():
        return cached[1]
    url = f"{LOGIN_HOST}/{tenant_id}/discovery/v2.0/keys"
    try:
        validate_outbound_url(url)
        response = client.get(url)
        response.raise_for_status()
        keys = response.json()
    except (httpx.HTTPError, SsrfBlockedError, ValueError) as exc:
        raise EntraLoginError(f"jwks_fetch_failed: {exc}") from None
    _jwks_cache[tenant_id] = (time.monotonic() + JWKS_TTL_SECONDS, keys)
    return dict(keys)


def _signing_key(client: httpx.Client, tenant_id: str, kid: str) -> Any:
    for refresh in (False, True):  # keys rotate: one refetch on an unknown kid
        for key in _jwks(client, tenant_id, refresh=refresh).get("keys", []):
            if key.get("kid") == kid:
                return jwt.PyJWK(key).key
    raise EntraLoginError("unknown_signing_key")


def _verify_id_token(
    client: httpx.Client, app: EntraApp, id_token: str, nonce: str
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise EntraLoginError("malformed_id_token") from None
    if header.get("alg") != "RS256":
        raise EntraLoginError(f"unexpected_alg_{header.get('alg')}")
    key = _signing_key(client, app.tenant_id, str(header.get("kid", "")))
    try:
        claims: dict[str, Any] = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=app.client_id,
            issuer=f"{LOGIN_HOST}/{app.tenant_id}/v2.0",
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise EntraLoginError(f"id_token_invalid: {type(exc).__name__}") from None
    if str(claims.get("tid", "")).lower() != app.tenant_id.lower():
        raise EntraLoginError("wrong_tenant")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise EntraLoginError("nonce_mismatch")
    if not claims.get("oid"):
        raise EntraLoginError("no_oid_claim")
    return claims


# ─── Matching the local account ──────────────────────────────────────────────


def subject_for(tenant_id: str, oid: str) -> str:
    return f"{tenant_id.lower()}:{oid.lower()}"


def _resolve_user(db: DbSession, claims: dict[str, Any], ip_address: str | None) -> User:
    subject = subject_for(str(claims["tid"]), str(claims["oid"]))
    upn = str(claims.get("preferred_username") or claims.get("email") or "").strip().lower()
    who = {"oid": str(claims["oid"]), "upn": upn or None}

    user = db.scalar(select(User).where(User.external_subject == subject))
    if user is None and upn:
        candidate = db.scalar(select(User).where(func.lower(User.email) == upn))
        if candidate is not None and candidate.external_subject not in (None, subject):
            # The email belongs to an account linked to a *different* Entra
            # object — a re-created Entra user, or a takeover attempt. An admin
            # must unlink it first.
            _refuse(db, "email_linked_to_other_entra_object", who, ip_address)
        if candidate is not None:
            user = candidate
            if user.is_active:
                user.external_subject = subject
                record(
                    db,
                    actor=Actor(ActorKind.USER, user.id, user.display_name, ip_address),
                    action="user.entra_linked",
                    entity_type="user",
                    entity_id=user.id,
                    detail=who,
                )
    if user is None:
        _refuse(db, "no_matching_user", who, ip_address)
    assert user is not None
    if not user.is_active:
        _refuse(db, "user_deactivated", {**who, "user_id": str(user.id)}, ip_address)
    user.last_login_at = utcnow()
    return user


def _refuse(db: DbSession, reason: str, detail: dict[str, Any], ip_address: str | None) -> None:
    record(
        db,
        actor=Actor(ActorKind.SYSTEM, None, "entra-sso", ip_address),
        action="auth.entra_refused",
        entity_type="user",
        detail={"reason": reason, **detail},
    )
    db.commit()  # the refusal must be on record even though the request fails
    raise EntraLoginError(reason)


def check_configuration(app: EntraApp, client: httpx.Client | None = None) -> tuple[bool, str]:
    """For the admin panel: does the tenant's OIDC metadata and key set load?"""
    owns = client is None
    client = client or _http_client()
    url = f"{LOGIN_HOST}/{app.tenant_id}/v2.0/.well-known/openid-configuration"
    try:
        validate_outbound_url(url)
        response = client.get(url)
        if response.status_code != 200:
            return (
                False,
                f"Tenant metadata returned HTTP {response.status_code} — check the tenant ID.",
            )
        issuer = response.json().get("issuer", "")
        keys = _jwks(client, app.tenant_id, refresh=True).get("keys", [])
    except SsrfBlockedError as exc:
        return False, f"{exc.reason}. Add login.microsoftonline.com to OUTBOUND_ALLOWLIST."
    except (httpx.HTTPError, EntraLoginError, ValueError) as exc:
        return False, f"Couldn't reach Microsoft: {exc}"
    finally:
        if owns:
            client.close()
    return True, (
        f"Tenant found ({issuer}); {len(keys)} signing key(s). "
        f"Redirect URI to register: {redirect_uri()}"
    )
