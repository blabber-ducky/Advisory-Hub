"""PDF extraction — the parent half of the sandbox.

Spawns ``pdf_worker`` in its own process group, enforces a wall-clock timeout,
and kills the whole group on expiry so a wedged native library cannot linger.
A failure here is never fatal to ingestion: the advisory is still created from
the email, and the attachment is recorded as ``FAILED`` with a reason.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..config import settings
from ..core.models.enums import ExtractionMethod
from ..logging import get_logger

log = get_logger(__name__)

#: Below this, the document has no usable text layer. All 135 corpus PDFs are
#: far above it (D-015), so tripping this is a real signal, not a tuning knob.
MIN_TEXT_CHARS = 200


@dataclass(slots=True)
class PdfExtraction:
    method: ExtractionMethod
    text: str = ""
    tables: list[list[list[str | None]]] = field(default_factory=list)
    page_count: int | None = None
    truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.method is not ExtractionMethod.FAILED


def extract_pdf(
    data: bytes,
    *,
    max_bytes: int | None = None,
    max_pages: int | None = None,
    timeout_seconds: int | None = None,
) -> PdfExtraction:
    """Extract text and tables from PDF bytes in a resource-capped subprocess."""
    max_bytes = max_bytes or settings.pdf_max_bytes
    max_pages = max_pages or settings.pdf_max_pages
    timeout_seconds = timeout_seconds or settings.pdf_timeout_seconds

    if not data:
        return PdfExtraction(ExtractionMethod.FAILED, error="EMPTY_FILE")
    if len(data) > max_bytes:
        return PdfExtraction(
            ExtractionMethod.FAILED,
            error=f"FILE_TOO_LARGE: {len(data)} bytes exceeds limit {max_bytes}",
        )
    if not data.startswith(b"%PDF"):
        return PdfExtraction(ExtractionMethod.FAILED, error="NOT_A_PDF: missing %PDF header")

    with tempfile.TemporaryDirectory(prefix="advhub-pdf-") as tmpdir:
        target = Path(tmpdir) / "document.pdf"
        target.write_bytes(data)
        return _run_worker(target, max_bytes, max_pages, timeout_seconds)


def _run_worker(path: Path, max_bytes: int, max_pages: int, timeout_seconds: int) -> PdfExtraction:
    cmd = [
        sys.executable,
        "-m",
        "advisory_hub.ingest.pdf_worker",
        str(path),
        str(max_bytes),
        str(max_pages),
        str(timeout_seconds),
    ]
    # Strip proxy variables so nothing in the child can be coaxed into egress.
    env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "ftp_proxy"}
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    try:
        proc = subprocess.Popen(  # noqa: S603 — fixed argv, no shell
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,  # own process group, so we can kill it all
        )
    except OSError as exc:
        return PdfExtraction(ExtractionMethod.FAILED, error=f"SPAWN_FAILED: {exc}")

    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.communicate()
        log.warning("pdf.timeout", timeout_seconds=timeout_seconds)
        return PdfExtraction(ExtractionMethod.FAILED, error=f"TIMEOUT: exceeded {timeout_seconds}s")

    if proc.returncode != 0 and not stdout:
        detail = (stderr or b"").decode("utf-8", "replace").strip()[-300:]
        if proc.returncode < 0:
            sig = signal.Signals(-proc.returncode).name
            return PdfExtraction(ExtractionMethod.FAILED, error=f"KILLED_BY_{sig}")
        return PdfExtraction(
            ExtractionMethod.FAILED, error=f"WORKER_FAILED[{proc.returncode}]: {detail}"
        )

    try:
        payload = json.loads(stdout.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError:
        return PdfExtraction(ExtractionMethod.FAILED, error="WORKER_OUTPUT_UNPARSEABLE")

    if not payload.get("ok"):
        return PdfExtraction(
            ExtractionMethod.FAILED, error=str(payload.get("error", "UNKNOWN"))[:500]
        )

    text = payload.get("text", "") or ""
    if len(text.strip()) < MIN_TEXT_CHARS:
        # Not expected: the corpus is 100% text-layer. OCR is not built (D-015).
        return PdfExtraction(
            ExtractionMethod.FAILED,
            text=text,
            page_count=payload.get("page_count"),
            error="NO_TEXT_LAYER: document appears to be scanned; OCR is not enabled",
        )

    return PdfExtraction(
        method=ExtractionMethod.TEXT_LAYER,
        text=text,
        tables=payload.get("tables", []),
        page_count=payload.get("page_count"),
        truncated=bool(payload.get("truncated")),
    )


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with _Ignore():
            proc.kill()


class _Ignore:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return True
