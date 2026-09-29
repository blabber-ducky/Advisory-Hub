"""Sandboxed PDF extraction worker.

Runs as its own process so a hostile PDF cannot take the ingestion worker with
it. Reads a file path on argv, writes one JSON object to stdout.

Limits applied before opening the document: address space, CPU seconds, and
file size (the parent additionally enforces a wall-clock timeout and kills the
process group). This process performs no network I/O — pdfplumber does not
fetch remote resources, and no JavaScript in the PDF is ever executed.

Never import this from application code; the parent invokes it via ``-m``.
"""

from __future__ import annotations

import json
import sys
from typing import Any

EXIT_OK = 0
EXIT_LIMIT = 3
EXIT_ERROR = 4


def _apply_limits(max_bytes: int, cpu_seconds: int) -> None:
    try:
        import resource
    except ImportError:  # pragma: no cover — non-POSIX
        return
    address_space = max(max_bytes * 8, 512 * 1024 * 1024)
    for res, limit in (
        (getattr(resource, "RLIMIT_AS", None), address_space),
        (getattr(resource, "RLIMIT_CPU", None), cpu_seconds),
        (getattr(resource, "RLIMIT_FSIZE", None), max_bytes * 4),
        (getattr(resource, "RLIMIT_NOFILE", None), 256),
    ):
        if res is None:
            continue
        try:
            _soft, hard = resource.getrlimit(res)
            ceiling = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
            resource.setrlimit(res, (ceiling, hard))
        except (ValueError, OSError):
            continue


def extract(path: str, max_pages: int) -> dict[str, Any]:
    import pdfplumber

    pages: list[str] = []
    tables: list[list[list[str | None]]] = []
    truncated = False

    with pdfplumber.open(path) as doc:
        total = len(doc.pages)
        for index, page in enumerate(doc.pages):
            if index >= max_pages:
                truncated = True
                break
            pages.append(page.extract_text() or "")
            for table in page.extract_tables() or []:
                if table and len(table) > 1:
                    tables.append([list(row) for row in table])

    return {
        "ok": True,
        "page_count": total,
        "pages_extracted": len(pages),
        "truncated": truncated,
        "text": "\n".join(pages),
        "tables": tables,
    }


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        json.dump(
            {"ok": False, "error": "usage: pdf_worker PATH MAX_BYTES MAX_PAGES CPU"}, sys.stdout
        )
        return EXIT_ERROR

    path, max_bytes, max_pages = argv[1], int(argv[2]), int(argv[3])
    cpu_seconds = int(argv[4]) if len(argv) > 4 else 60

    _apply_limits(max_bytes, cpu_seconds)

    try:
        result = extract(path, max_pages)
    except MemoryError:
        json.dump({"ok": False, "error": "memory limit exceeded", "limit": True}, sys.stdout)
        return EXIT_LIMIT
    except Exception as exc:
        json.dump({"ok": False, "error": f"{type(exc).__name__}: {exc}"[:500]}, sys.stdout)
        return EXIT_ERROR

    json.dump(result, sys.stdout)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
