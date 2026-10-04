"""The certificate the app serves HTTPS with, when ``HTTPS_ENABLED`` is on.

Two cases, decided by what's in the certificate folder at start-up:

* **Both files present** — used as-is: parsed, the key checked against the
  certificate, expiry checked. Never modified. If it's a self-signed one
  *this module generated* and it's close to expiry, it's regenerated —
  provided certificates are never touched, only warned about.
* **Neither present** — a self-signed certificate is generated for the
  names in ``TLS_HOSTNAMES`` and written there, to be reused next time.

Exactly one of the two present is refused outright: it's probably half of
a real certificate copied in by hand, and generating over it would destroy
the other half's partner.

Generated with ``cryptography`` (already a dependency for Fernet), so the
image needs no OpenSSL CLI. See docs/operations.md §7 and D-045.
"""

from __future__ import annotations

import ipaddress
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

#: Subject Organisation marking a certificate as one this module made —
#: the only kind it will ever replace.
GENERATED_ORG = "Advisory Hub (self-signed)"
VALIDITY_DAYS = 397
RENEW_WITHIN_DAYS = 30
WARN_WITHIN_DAYS = 30


class TlsConfigError(Exception):
    """The certificate setup can't be used; message says how to fix it."""


@dataclass(frozen=True, slots=True)
class CertificateStatus:
    cert_path: Path
    key_path: Path
    generated: bool  # made (or remade) just now
    self_signed: bool
    names: tuple[str, ...]
    not_after: datetime
    warnings: tuple[str, ...] = ()


def _names(hostnames: list[str]) -> list[str]:
    out: list[str] = []
    for raw in [*hostnames, "localhost", "127.0.0.1"]:
        name = raw.strip()
        if name and name not in out:
            out.append(name)
    return out


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for name in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def _write_private(path: Path, data: bytes, mode: int) -> None:
    """Atomic write with the final permissions set before the rename, so a
    key is never briefly readable by others."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".incoming-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def generate_self_signed(
    cert_path: Path, key_path: Path, hostnames: list[str], *, now: datetime | None = None
) -> None:
    now = now or datetime.now(UTC)
    names = _names(hostnames)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, GENERATED_ORG),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=VALIDITY_DAYS))
        .add_extension(_san(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    _write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    _write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)


def _load(cert_path: Path, key_path: Path) -> tuple[x509.Certificate, bool]:
    try:
        certs = x509.load_pem_x509_certificates(cert_path.read_bytes())
    except (ValueError, OSError) as exc:
        raise TlsConfigError(f"{cert_path} is not a readable PEM certificate ({exc})") from exc
    if not certs:
        raise TlsConfigError(f"{cert_path} contains no certificate")
    leaf = certs[0]
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except TypeError as exc:
        raise TlsConfigError(
            f"{key_path} is passphrase-protected — the server can't prompt for it. "
            f"Decrypt it: openssl pkey -in {key_path.name} -out server.key"
        ) from exc
    except (ValueError, OSError) as exc:
        raise TlsConfigError(f"{key_path} is not a readable PEM private key ({exc})") from exc

    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(
        serialization.Encoding.PEM, pub
    ) != leaf.public_key().public_bytes(serialization.Encoding.PEM, pub):
        raise TlsConfigError(f"{key_path} does not match the certificate in {cert_path}")
    orgs = leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    ours = any(o.value == GENERATED_ORG for o in orgs) and leaf.issuer == leaf.subject
    return leaf, ours


def _cert_names(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(
        [*san.get_values_for_type(x509.DNSName)]
        + [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    )


def ensure_certificate(
    cert_path: Path, key_path: Path, hostnames: list[str], *, now: datetime | None = None
) -> CertificateStatus:
    """Make sure a usable certificate is at ``cert_path``/``key_path``,
    generating a self-signed one only when neither file exists (or when the
    existing one is our own self-signed one about to expire)."""
    now = now or datetime.now(UTC)
    have_cert, have_key = cert_path.exists(), key_path.exists()
    if have_cert != have_key:
        present, missing = (cert_path, key_path) if have_cert else (key_path, cert_path)
        raise TlsConfigError(
            f"Found {present} but not {missing}. Provide both files, or remove "
            f"{present.name} to have a self-signed certificate generated. "
            "(Refusing to generate over half of what may be a real certificate.)"
        )

    generated = False
    if not have_cert:
        generate_self_signed(cert_path, key_path, hostnames, now=now)
        generated = True

    cert, ours = _load(cert_path, key_path)
    if ours and cert.not_valid_after_utc - now < timedelta(days=RENEW_WITHIN_DAYS):
        generate_self_signed(cert_path, key_path, hostnames, now=now)
        cert, ours = _load(cert_path, key_path)
        generated = True

    if cert.not_valid_after_utc <= now:
        raise TlsConfigError(
            f"The certificate in {cert_path} expired on "
            f"{cert.not_valid_after_utc:%Y-%m-%d}. Replace server.crt and server.key."
        )
    warnings: list[str] = []
    if cert.not_valid_after_utc - now < timedelta(days=WARN_WITHIN_DAYS):
        warnings.append(f"Certificate expires {cert.not_valid_after_utc:%Y-%m-%d} — renew it soon")
    names = _cert_names(cert)
    wanted = [h.strip() for h in hostnames if h.strip()]
    missing_names = [h for h in wanted if h not in names]
    if missing_names and not ours:
        warnings.append(
            "TLS_HOSTNAMES lists names the provided certificate doesn't cover: "
            + ", ".join(missing_names)
        )
    if missing_names and ours and not generated:
        warnings.append(
            "TLS_HOSTNAMES changed since the self-signed certificate was made — delete "
            "server.crt and server.key to regenerate it for: " + ", ".join(missing_names)
        )
    return CertificateStatus(
        cert_path=cert_path,
        key_path=key_path,
        generated=generated,
        self_signed=cert.issuer == cert.subject,
        names=names,
        not_after=cert.not_valid_after_utc,
        warnings=tuple(warnings),
    )
