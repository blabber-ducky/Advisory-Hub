"""The app's own HTTPS: certificate generation, validation, and the
launcher's uvicorn options. No database needed."""

from __future__ import annotations

import ipaddress
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from advisory_hub.core.security import tls

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "certs" / "server.crt", tmp_path / "certs" / "server.key"


def _provided_cert(
    tmp_path: Path, *, names: list[str], days: int = 365, encrypt: bool = False
) -> tuple[Path, Path]:
    """A certificate as if issued by someone else (not our self-signed one)."""
    cert_path, key_path = _paths(tmp_path)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Corp Issuing CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    encryption = (
        serialization.BestAvailableEncryption(b"secret")
        if encrypt
        else serialization.NoEncryption()
    )
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    )
    return cert_path, key_path


def _san(cert_path: Path) -> set[str]:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return set(san.get_values_for_type(x509.DNSName)) | {
        str(ip) for ip in san.get_values_for_type(x509.IPAddress)
    }


class TestGenerate:
    def test_generates_when_neither_file_exists(self, tmp_path: Path) -> None:
        cert_path, key_path = _paths(tmp_path)
        status = tls.ensure_certificate(
            cert_path, key_path, ["advisoryhub.corp", "10.0.4.20"], now=NOW
        )
        assert status.generated and status.self_signed
        assert _san(cert_path) == {"advisoryhub.corp", "10.0.4.20", "localhost", "127.0.0.1"}
        # IPs go in as IP SANs (browsers ignore an IP written as a DNS name)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        ips = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert ipaddress.ip_address("10.0.4.20") in ips.get_values_for_type(x509.IPAddress)

    def test_private_key_is_owner_only(self, tmp_path: Path) -> None:
        cert_path, key_path = _paths(tmp_path)
        tls.ensure_certificate(cert_path, key_path, [], now=NOW)
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert not list(cert_path.parent.glob(".incoming-*"))

    def test_reuses_an_existing_one_instead_of_regenerating(self, tmp_path: Path) -> None:
        cert_path, key_path = _paths(tmp_path)
        tls.ensure_certificate(cert_path, key_path, [], now=NOW)
        first = cert_path.read_bytes()
        status = tls.ensure_certificate(cert_path, key_path, [], now=NOW + timedelta(days=10))
        assert not status.generated
        assert cert_path.read_bytes() == first

    def test_own_self_signed_cert_is_renewed_near_expiry(self, tmp_path: Path) -> None:
        cert_path, key_path = _paths(tmp_path)
        tls.ensure_certificate(cert_path, key_path, [], now=NOW)
        first = cert_path.read_bytes()
        later = NOW + timedelta(days=tls.VALIDITY_DAYS - 10)
        status = tls.ensure_certificate(cert_path, key_path, [], now=later)
        assert status.generated
        assert cert_path.read_bytes() != first

    def test_changed_hostnames_on_a_kept_cert_are_flagged(self, tmp_path: Path) -> None:
        cert_path, key_path = _paths(tmp_path)
        tls.ensure_certificate(cert_path, key_path, ["old.corp"], now=NOW)
        status = tls.ensure_certificate(cert_path, key_path, ["new.corp"], now=NOW)
        assert any("delete server.crt and server.key" in w for w in status.warnings)


class TestProvided:
    def test_used_as_is_and_never_rewritten(self, tmp_path: Path) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["advisoryhub.corp"])
        before = (cert_path.read_bytes(), key_path.read_bytes())
        status = tls.ensure_certificate(cert_path, key_path, ["advisoryhub.corp"], now=NOW)
        assert not status.generated and not status.self_signed
        assert (cert_path.read_bytes(), key_path.read_bytes()) == before

    def test_near_expiry_warns_but_is_not_replaced(self, tmp_path: Path) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["a.corp"], days=10)
        before = cert_path.read_bytes()
        status = tls.ensure_certificate(cert_path, key_path, [], now=NOW)
        assert any("expires" in w for w in status.warnings)
        assert cert_path.read_bytes() == before

    def test_expired_is_refused(self, tmp_path: Path) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["a.corp"], days=10)
        with pytest.raises(tls.TlsConfigError, match="expired"):
            tls.ensure_certificate(cert_path, key_path, [], now=NOW + timedelta(days=11))

    def test_hostname_not_covered_is_flagged(self, tmp_path: Path) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["a.corp"])
        status = tls.ensure_certificate(cert_path, key_path, ["b.corp"], now=NOW)
        assert any("doesn't cover: b.corp" in w for w in status.warnings)

    def test_mismatched_key_is_refused(self, tmp_path: Path) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["a.corp"])
        other = ec.generate_private_key(ec.SECP256R1())
        key_path.write_bytes(
            other.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        with pytest.raises(tls.TlsConfigError, match="does not match"):
            tls.ensure_certificate(cert_path, key_path, [], now=NOW)

    def test_passphrase_protected_key_is_refused_with_a_fix(self, tmp_path: Path) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["a.corp"], encrypt=True)
        with pytest.raises(tls.TlsConfigError, match="passphrase"):
            tls.ensure_certificate(cert_path, key_path, [], now=NOW)

    def test_garbage_is_refused(self, tmp_path: Path) -> None:
        cert_path, key_path = _paths(tmp_path)
        cert_path.parent.mkdir(parents=True)
        cert_path.write_text("not a certificate")
        key_path.write_text("not a key")
        with pytest.raises(tls.TlsConfigError, match="PEM certificate"):
            tls.ensure_certificate(cert_path, key_path, [], now=NOW)


class TestHalfPresent:
    @pytest.mark.parametrize("keep", ["crt", "key"])
    def test_one_file_alone_is_refused_and_left_untouched(self, tmp_path: Path, keep: str) -> None:
        cert_path, key_path = _provided_cert(tmp_path, names=["a.corp"])
        survivor = cert_path if keep == "crt" else key_path
        (key_path if keep == "crt" else cert_path).unlink()
        before = survivor.read_bytes()
        with pytest.raises(tls.TlsConfigError, match="Refusing to generate"):
            tls.ensure_certificate(cert_path, key_path, [], now=NOW)
        assert survivor.read_bytes() == before


class TestServeOptions:
    def _settings(self, monkeypatch, tmp_path: Path, **env: str) -> None:
        from advisory_hub.config import get_settings

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()

    def test_http_by_default(self, monkeypatch, tmp_path: Path) -> None:
        from advisory_hub import serve
        from advisory_hub.config import get_settings

        self._settings(monkeypatch, tmp_path, HTTPS_ENABLED="false")
        try:
            options = serve.uvicorn_options()
        finally:
            get_settings.cache_clear()
        assert "ssl_certfile" not in options
        assert options["port"] == 8000 and options["proxy_headers"] is True

    def test_https_generates_and_passes_the_certificate(self, monkeypatch, tmp_path: Path) -> None:
        from advisory_hub import serve
        from advisory_hub.config import get_settings

        cert_path, key_path = _paths(tmp_path)
        self._settings(
            monkeypatch,
            tmp_path,
            HTTPS_ENABLED="true",
            TLS_CERT_FILE=str(cert_path),
            TLS_KEY_FILE=str(key_path),
            TLS_HOSTNAMES="advisoryhub.corp, 10.0.4.20",
            FORWARDED_ALLOW_IPS="10.0.0.10",
        )
        try:
            options = serve.uvicorn_options()
        finally:
            get_settings.cache_clear()
        assert options["ssl_certfile"] == str(cert_path)
        assert options["ssl_keyfile"] == str(key_path)
        assert options["forwarded_allow_ips"] == "10.0.0.10"
        assert {"advisoryhub.corp", "10.0.4.20"} <= _san(cert_path)

    def test_unusable_setup_stops_start_up(self, monkeypatch, tmp_path: Path, capsys) -> None:
        from advisory_hub import serve
        from advisory_hub.config import get_settings

        cert_path, key_path = _paths(tmp_path)
        cert_path.parent.mkdir(parents=True)
        cert_path.write_text("half")
        self._settings(
            monkeypatch,
            tmp_path,
            HTTPS_ENABLED="true",
            TLS_CERT_FILE=str(cert_path),
            TLS_KEY_FILE=str(key_path),
        )
        try:
            assert serve.main() == 1
        finally:
            get_settings.cache_clear()
        assert "can't start" in capsys.readouterr().err
