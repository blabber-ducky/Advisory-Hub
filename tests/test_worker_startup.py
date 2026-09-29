"""Worker start-up: the background pollers must survive their first import.

The inbox, enrichment and inventory-sync pollers each start on their own
thread at the same moment. When each thread performed the *first* import of
``advisory_hub.core.models`` itself, the imports raced — ``ImportError:
cannot import name 'ApiToken' from partially initialized module`` — and the
inbox and inventory-sync threads died on start-up while the worker stayed
"healthy". Reproduced in 14/15 fresh interpreters before the fix.

Each check runs in a fresh interpreter: in this test process the modules
are already imported, which would hide the race entirely.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

POLLER_IMPORTS = (
    "advisory_hub.ingest.pipeline",
    "advisory_hub.core.models.base",
    "advisory_hub.core.services.enrichment",
    "advisory_hub.core.services.inventory",
    "advisory_hub.core.services.audit",
    "advisory_hub.inventory.api_client",
    "advisory_hub.db",
)


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — fixed argv, test-authored code, no shell
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_preload_imports_every_poller_dependency() -> None:
    result = _run(
        f"""
        import sys
        from advisory_hub.worker.__main__ import _preload_poller_dependencies
        _preload_poller_dependencies()
        missing = [m for m in {POLLER_IMPORTS!r} if m not in sys.modules]
        assert not missing, missing
        """
    )
    assert result.returncode == 0, result.stderr


def test_concurrent_poller_imports_after_preload_do_not_race() -> None:
    # Five fresh interpreters: without the preload this failed ~14 times in 15.
    for _ in range(5):
        result = _run(
            f"""
            import importlib, sys, threading
            from advisory_hub.worker.__main__ import _preload_poller_dependencies
            _preload_poller_dependencies()

            errors = []
            barrier = threading.Barrier({len(POLLER_IMPORTS)})
            def load(name):
                barrier.wait()
                try:
                    importlib.import_module(name)
                except Exception as exc:
                    errors.append(repr(exc))
            threads = [threading.Thread(target=load, args=(m,)) for m in {POLLER_IMPORTS!r}]
            for t in threads: t.start()
            for t in threads: t.join()
            sys.exit(1 if errors else 0)
            """
        )
        assert result.returncode == 0, result.stderr
