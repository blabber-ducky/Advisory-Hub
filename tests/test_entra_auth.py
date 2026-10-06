"""Microsoft Entra ID sign-in (D-049): authentication only, roles from the app.

No network: an httpx MockTransport plays login.microsoftonline.com, and a
test RSA key signs the ID tokens it returns.
"""

from __future__ import annotations

import json
import time
import uuid
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from advisory_hub.core.models.enums import ActorKind, Role, SystemIntegrationKind
from advisory_hub.core.models.user import AuditLog, User
from advisory_hub.core.services import entra_auth as entra
from advisory_hub.core.services.audit import Actor

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KID = "test-key-1"
OTHER_GUID = "ffffffff-0000-0000-0000-000000000000"
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks() -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_KEY.public_key()))
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}


def _id_token(nonce: str, *, key=_KEY, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT,
        "tid": TENANT,
        "oid": "99999999-0000-0000-0000-000000000001",
        "sub": "pairwise-sub",
        "preferred_username": "ana@contoso.example",
        "nonce": nonce,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        # Never consulted — roles come from the app (D-049).
        "groups": ["Global Administrators"],
        "roles": ["Admin"],
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


class FakeEntra:
    """The token endpoint returns whatever ``next_token`` builds."""

    def __init__(self) -> None:
        self.token_status = 200
        self.make_token = lambda nonce: _id_token(nonce)
        self.last_token_form: dict[str, list[str]] = {}
        self.nonce = ""

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/discovery/v2.0/keys"):
            return httpx.Response(200, json=_jwks())
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200, json={"issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0"}
            )
        if path.endswith("/oauth2/v2.0/token"):
            self.last_token_form = parse_qs(request.content.decode())
            if self.token_status != 200:
                return httpx.Response(
                    self.token_status, json={"error": "invalid_client", "error_codes": [7000215]}
                )
            return httpx.Response(200, json={"id_token": self.make_token(self.nonce)})
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def fake(monkeypatch) -> FakeEntra:
    from cryptography.fernet import Fernet

    from advisory_hub.config import get_settings

    monkeypatch.setenv("PUBLIC_BASE_URL", "https://hub.example")
    monkeypatch.setenv("FERNET_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()
    monkeypatch.setattr(entra, "validate_outbound_url", lambda url: None)
    entra._jwks_cache.clear()
    f = FakeEntra()
    monkeypatch.setattr(entra, "_http_client", f.client)
    yield f
    get_settings.cache_clear()


@pytest.fixture
def sso(db, fake):
    from advisory_hub.core.services.system_integrations import (
        save_entra_settings,
        set_entra_enabled,
    )

    actor = Actor.system("test")
    save_entra_settings(
        db,
        SystemIntegrationKind.ENTRA_SSO,
        config={"tenant_id": TENANT, "client_id": CLIENT},
        client_secret="s3cret",
        actor=actor,
    )
    set_entra_enabled(db, SystemIntegrationKind.ENTRA_SSO, enabled=True, actor=actor)
    db.flush()
    return fake


def _user(db, email="ana@contoso.example", role=Role.ANALYST, **kw) -> User:
    user = User(email=email, display_name="Ana", role=role, **kw)
    db.add(user)
    db.flush()
    return user


def _login(db, fake: FakeEntra, **kw) -> User:
    app = entra.enabled_app(db)
    assert app is not None
    _, flow = entra.start_login(app)
    fake.nonce = flow.nonce
    return entra.complete_login(db, code="the-code", state=flow.state, flow=flow, **kw)


def _refusals(db) -> list[str]:
    return [
        e.detail["reason"]
        for e in db.scalars(select(AuditLog).where(AuditLog.action == "auth.entra_refused"))
    ]


@pytest.mark.integration
class TestFlow:
    def test_authorize_url(self, db, sso) -> None:
        url, flow = entra.start_login(entra.enabled_app(db))
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        assert urlparse(url).netloc == "login.microsoftonline.com"
        assert urlparse(url).path == f"/{TENANT}/oauth2/v2.0/authorize"
        assert q["client_id"] == CLIENT and q["state"] == flow.state and q["nonce"] == flow.nonce
        assert q["redirect_uri"] == "https://hub.example/auth/entra/callback"
        assert q["code_challenge_method"] == "S256" and q["scope"] == "openid profile email"

    def test_token_request_sends_pkce_and_secret(self, db, sso) -> None:
        _user(db)
        _login(db, sso)
        form = sso.last_token_form
        assert form["grant_type"] == ["authorization_code"]
        assert form["client_secret"] == ["s3cret"] and form["code_verifier"][0]

    def test_disabled_or_incomplete_means_no_button(self, db, fake) -> None:
        assert entra.enabled_app(db) is None


@pytest.mark.integration
class TestMatching:
    def test_pre_added_user_is_linked_on_first_sign_in(self, db, sso) -> None:
        user = _user(db)
        assert _login(db, sso).id == user.id
        assert user.external_subject == f"{TENANT}:99999999-0000-0000-0000-000000000001"
        assert db.scalar(select(AuditLog).where(AuditLog.action == "user.entra_linked"))

    def test_then_matched_by_object_id_even_if_the_email_changes(self, db, sso) -> None:
        user = _user(db)
        _login(db, sso)
        sso.make_token = lambda n: _id_token(n, preferred_username="ana.renamed@contoso.example")
        assert _login(db, sso).id == user.id

    def test_role_comes_from_the_app_not_the_token(self, db, sso) -> None:
        user = _user(db, role=Role.VIEWER)
        assert _login(db, sso).role is Role.VIEWER  # token says groups/roles: Admin
        assert user.role is Role.VIEWER

    def test_email_match_is_case_insensitive(self, db, sso) -> None:
        user = _user(db, email="ana@contoso.example")
        sso.make_token = lambda n: _id_token(n, preferred_username="Ana@Contoso.Example")
        assert _login(db, sso).id == user.id

    def test_unknown_person_is_refused_and_audited(self, db, sso) -> None:
        with pytest.raises(entra.EntraLoginError) as exc:
            _login(db, sso)
        assert exc.value.user_message == entra.REFUSED_MESSAGE
        assert _refusals(db) == ["no_matching_user"]

    def test_deactivated_user_is_refused_and_not_linked(self, db, sso) -> None:
        user = _user(db, is_active=False)
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert user.external_subject is None
        assert _refusals(db) == ["user_deactivated"]

    def test_email_already_linked_to_another_entra_object_is_refused(self, db, sso) -> None:
        _user(db, external_subject=f"{TENANT}:someone-else")
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert _refusals(db) == ["email_linked_to_other_entra_object"]


@pytest.mark.integration
class TestTokenChecks:
    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            ({"aud": OTHER_GUID}, "id_token_invalid: InvalidAudienceError"),
            ({"iss": f"https://login.microsoftonline.com/{OTHER_GUID}/v2.0"},
             "id_token_invalid: InvalidIssuerError"),
            ({"exp": int(time.time()) - 3600}, "id_token_invalid: ExpiredSignatureError"),
            ({"tid": OTHER_GUID}, "wrong_tenant"),
            ({"oid": None}, "no_oid_claim"),
        ],
    )  # fmt: skip
    def test_bad_claims(self, db, sso, overrides, reason) -> None:
        _user(db)
        sso.make_token = lambda n: _id_token(n, **overrides)
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert _refusals(db) == [reason]

    def test_wrong_nonce(self, db, sso) -> None:
        _user(db)
        sso.make_token = lambda n: _id_token("not-the-nonce")
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert _refusals(db) == ["nonce_mismatch"]

    def test_signed_by_another_key(self, db, sso) -> None:
        _user(db)
        sso.make_token = lambda n: _id_token(n, key=_OTHER_KEY)
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert _refusals(db) == ["id_token_invalid: InvalidSignatureError"]

    def test_unsigned_token(self, db, sso) -> None:
        _user(db)
        sso.make_token = lambda n: jwt.encode({"nonce": n}, None, algorithm="none")
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert _refusals(db) == ["unexpected_alg_none"]

    def test_state_mismatch_never_calls_microsoft(self, db, sso) -> None:
        _user(db)
        _, flow = entra.start_login(entra.enabled_app(db))
        with pytest.raises(entra.EntraLoginError):
            entra.complete_login(db, code="c", state="forged", flow=flow)
        with pytest.raises(entra.EntraLoginError):
            entra.complete_login(db, code="c", state=flow.state, flow=None)
        assert sso.last_token_form == {}
        assert _refusals(db) == ["state_mismatch", "state_mismatch"]

    def test_bad_client_secret(self, db, sso) -> None:
        _user(db)
        sso.token_status = 401
        with pytest.raises(entra.EntraLoginError):
            _login(db, sso)
        assert _refusals(db)[0].startswith("token_endpoint_401: invalid_client")


@pytest.mark.integration
class TestPasswordRule:
    def test_linked_user_cannot_use_a_password(self, db, sso) -> None:
        from advisory_hub.core.security.passwords import hash_password
        from advisory_hub.core.services.auth import AuthError, LocalAuthProvider

        user = _user(db, password_hash=hash_password("a-long-enough-password"))
        provider = LocalAuthProvider()
        assert provider.authenticate(db, identifier=user.email, secret="a-long-enough-password")
        _login(db, sso)  # links
        with pytest.raises(AuthError):
            provider.authenticate(db, identifier=user.email, secret="a-long-enough-password")


# ─── Web ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def client(db, sso, tmp_path, monkeypatch):
    for var in ("BLOB_ROOT", "INBOX_PATH", "PROCESSING_PATH", "ARCHIVE_PATH", "FAILED_PATH"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-a-placeholder-value")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    from fastapi.testclient import TestClient

    from advisory_hub.api.deps import db_session
    from advisory_hub.config import get_settings
    from advisory_hub.main import create_app

    get_settings.cache_clear()
    app = create_app()

    def _override():
        yield db

    app.dependency_overrides[db_session] = _override
    return TestClient(app, follow_redirects=False, client=("127.0.0.1", 51001))


@pytest.mark.integration
class TestWeb:
    def test_login_page_offers_microsoft(self, client) -> None:
        assert 'href="/auth/entra/login"' in client.get("/login").text

    def test_full_round_trip(self, db, client, sso) -> None:
        user = _user(db, role=Role.ANALYST)
        start = client.get("/auth/entra/login")
        assert start.status_code == 303
        q = parse_qs(urlparse(start.headers["location"]).query)
        sso.nonce = q["nonce"][0]

        done = client.get("/auth/entra/callback", params={"code": "c", "state": q["state"][0]})
        assert done.status_code == 303 and done.headers["location"] == "/"
        page = client.get("/")
        assert page.status_code == 200 and "Ana · ANALYST" in page.text
        assert user.external_subject is not None

    def test_callback_without_the_flow_cookie_is_refused(self, db, client) -> None:
        _user(db)
        r = client.get("/auth/entra/callback", params={"code": "c", "state": "s"})
        assert r.status_code == 403 and "can&#39;t sign in" in r.text
        assert client.get("/").status_code == 303  # no session

    def test_microsoft_error_is_shown(self, client) -> None:
        r = client.get("/auth/entra/callback", params={"error": "access_denied"})
        assert r.status_code == 401 and "access_denied" in r.text

    def test_unknown_user_round_trip(self, db, client, sso) -> None:
        start = client.get("/auth/entra/login")
        q = parse_qs(urlparse(start.headers["location"]).query)
        sso.nonce = q["nonce"][0]
        r = client.get("/auth/entra/callback", params={"code": "c", "state": q["state"][0]})
        assert r.status_code == 403
        assert _refusals(db) == ["no_matching_user"]


# ─── User administration with Entra ──────────────────────────────────────────


def _admin(db) -> object:
    from advisory_hub.core.services.auth import Principal

    return Principal(
        kind=ActorKind.USER,
        user=_user(db, email=f"adm-{uuid.uuid4().hex[:6]}@x.example", role=Role.ADMIN),
    )


@pytest.mark.integration
class TestUserAdmin:
    def test_password_required_while_sso_is_off(self, db, fake) -> None:
        from advisory_hub.core.services import users

        with pytest.raises(users.UserAdminError, match="Microsoft sign-in isn't enabled"):
            users.add_user(
                db, _admin(db), email="b@contoso.example", display_name="B",
                role=Role.VIEWER, password="",
            )  # fmt: skip

    def test_microsoft_only_user_then_links_on_first_sign_in(self, db, sso) -> None:
        from advisory_hub.core.services import users

        added = users.add_user(
            db, _admin(db), email="ana@contoso.example", display_name="Ana",
            role=Role.ANALYST, password="",
        )  # fmt: skip
        assert added.password_hash is None
        assert _login(db, sso).id == added.id

    def test_no_password_reset_for_linked_users_and_unlink(self, db, sso) -> None:
        from advisory_hub.core.services import users
        from advisory_hub.core.services.auth import start_session

        admin = _admin(db)
        user = _user(db)
        _login(db, sso)
        session = start_session(db, user)
        with pytest.raises(users.UserAdminError, match="signs in with Microsoft"):
            users.reset_password(db, admin, user.id, "a-long-enough-password")

        users.unlink_entra(db, admin, user.id)
        db.flush()
        db.refresh(session)
        assert user.external_subject is None
        assert session.revoked_at is not None
        assert db.scalar(select(AuditLog).where(AuditLog.action == "user.entra_unlinked"))
        users.reset_password(db, admin, user.id, "a-long-enough-password")  # allowed again
