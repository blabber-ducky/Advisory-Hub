"""Start the web app — over HTTPS when ``HTTPS_ENABLED`` is on.

    python -m advisory_hub.serve

The image's default command and the production compose file both run this
instead of calling uvicorn directly, so the certificate is in place (found,
validated, or generated) before the server binds. With HTTPS off it starts
exactly the plain-HTTP server it always did.

Settings read here: HTTPS_ENABLED, TLS_CERT_FILE, TLS_KEY_FILE, TLS_HOSTNAMES,
and — as before — WEB_CONCURRENCY and FORWARDED_ALLOW_IPS.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from .config import settings
from .core.security.tls import TlsConfigError, ensure_certificate
from .logging import configure_logging, get_logger

log = get_logger(__name__)

PORT = 8000


def uvicorn_options() -> dict[str, Any]:
    """Everything uvicorn needs, certificate included. Raises
    ``TlsConfigError`` if HTTPS is on and the certificate setup is unusable."""
    options: dict[str, Any] = {
        "host": "0.0.0.0",  # noqa: S104 — inside the container; the host decides exposure
        "port": PORT,
        "proxy_headers": True,
        "forwarded_allow_ips": os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        "server_header": False,
        "workers": int(os.environ.get("WEB_CONCURRENCY", "1")),
    }
    if settings.https_enabled:
        status = ensure_certificate(
            settings.tls_cert_file, settings.tls_key_file, settings.tls_hostname_list
        )
        log.info(
            "tls.certificate",
            path=str(status.cert_path),
            generated=status.generated,
            self_signed=status.self_signed,
            names=list(status.names),
            expires=status.not_after.date().isoformat(),
        )
        for warning in status.warnings:
            log.warning("tls.certificate_warning", message=warning)
        options["ssl_certfile"] = str(status.cert_path)
        options["ssl_keyfile"] = str(status.key_path)
    return options


def main() -> int:
    configure_logging(settings.log_level, settings.log_format)
    try:
        options = uvicorn_options()
    except TlsConfigError as exc:
        log.error("tls.unusable", message=str(exc))
        print(f"HTTPS is enabled but can't start: {exc}", file=sys.stderr)
        return 1

    import uvicorn

    log.info(
        "serve.starting",
        scheme="https" if settings.https_enabled else "http",
        port=PORT,
        workers=options["workers"],
    )
    uvicorn.run("advisory_hub.main:app", **options)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
