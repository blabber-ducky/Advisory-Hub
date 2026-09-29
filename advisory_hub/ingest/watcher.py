"""Inbox watcher.

Polls rather than using ``inotify``: the drop directory is typically an SMB or
network mount, where inotify does not fire. Claiming is an atomic rename into a
per-worker directory, so two workers can never take the same file.

`inbox` and `processing` are not guaranteed to be on the same filesystem —
e.g. `INBOX_HOST_PATH` bind-mounts `inbox` to a real host folder while
`processing` stays an internal Docker volume. A plain ``os.rename`` cannot
cross that boundary (``OSError: Invalid cross-device link``); ``claim()``
falls back to a same-filesystem claim-in-place rename followed by a
cross-device copy — see its docstring.
"""

from __future__ import annotations

import errno
import os
import shutil
from collections.abc import Iterator
from datetime import date
from pathlib import Path

from ..config import settings
from ..logging import get_logger

log = get_logger(__name__)

#: Only these are claimed. Power Automate must write `<name>.tmp` and rename,
#: so a half-written file is never picked up.
MESSAGE_EXTENSIONS = frozenset({".msg", ".eml", ".mime"})


class Inbox:
    def __init__(
        self,
        *,
        inbox: Path | None = None,
        processing: Path | None = None,
        archive: Path | None = None,
        failed: Path | None = None,
        worker_id: str | None = None,
    ) -> None:
        self.inbox = Path(inbox or settings.inbox_path)
        self.processing_root = Path(processing or settings.processing_path)
        self.archive = Path(archive or settings.archive_path)
        self.failed = Path(failed or settings.failed_path)
        self.worker_id = worker_id or f"w{os.getpid()}"
        self.processing = self.processing_root / self.worker_id
        for path in (self.inbox, self.processing, self.archive, self.failed):
            path.mkdir(parents=True, exist_ok=True)

    # ─── Discovery ───────────────────────────────────────────────────────────

    def pending(self) -> list[Path]:
        if not self.inbox.is_dir():
            return []
        return sorted(
            (p for p in self.inbox.iterdir() if p.is_file() and _is_message(p)),
            key=lambda p: p.stat().st_mtime,
        )

    def claim(self, path: Path) -> Path | None:
        """Atomically claim a file. Returns ``None`` if another worker won."""
        target = self.processing / path.name
        target = _unique(target)
        try:
            os.rename(path, target)
            return target
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                return None
            return self._claim_cross_device(path, target)

    def _claim_cross_device(self, path: Path, target: Path) -> Path | None:
        """`inbox` and `processing` are on different filesystems — see the
        module docstring. Claims same-filesystem first (an in-``inbox``
        rename into a hidden per-worker staging dir; still atomic, still
        correctly loses the race if another worker already claimed it),
        then does the unavoidable cross-device copy into ``processing/`` on
        a file this worker already exclusively owns."""
        staging_dir = self.inbox / ".claiming" / self.worker_id
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged = staging_dir / path.name
        try:
            os.rename(path, staged)
        except (FileNotFoundError, OSError):
            return None
        try:
            shutil.move(str(staged), str(target))
        except OSError:
            # Left staged rather than lost — recover_orphans() sweeps this
            # directory too, so a crash here is still recovered on restart.
            return None
        return target

    def claim_batch(self, limit: int = 50) -> Iterator[Path]:
        for path in self.pending()[:limit]:
            claimed = self.claim(path)
            if claimed is not None:
                yield claimed

    def recover_orphans(self) -> list[Path]:
        """Return files this worker left in ``processing/`` — or, for a
        cross-device inbox, its ``inbox/.claiming/<worker_id>/`` staging
        dir — after a crash."""
        orphans: list[Path] = []
        if self.processing.is_dir():
            orphans += [p for p in self.processing.iterdir() if p.is_file() and _is_message(p)]
        staging_dir = self.inbox / ".claiming" / self.worker_id
        if staging_dir.is_dir():
            for p in staging_dir.iterdir():
                if not (p.is_file() and _is_message(p)):
                    continue
                target = _unique(self.processing / p.name)
                try:
                    shutil.move(str(p), str(target))
                except OSError:
                    continue
                orphans.append(target)
        if orphans:
            log.warning("inbox.recovered_orphans", count=len(orphans), worker_id=self.worker_id)
        return sorted(orphans)

    # ─── Disposition ─────────────────────────────────────────────────────────

    def archive_file(self, path: Path, *, on: date | None = None) -> Path:
        day = (on or date.today()).isoformat()
        destination = _unique(self.archive / day / path.name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(destination))
        return destination

    def fail_file(self, path: Path, error: dict[str, object]) -> Path:
        """Move to ``failed/`` with a sidecar. Nothing here is auto-deleted —
        it is a queue for a human."""
        import json

        destination = _unique(self.failed / path.name)
        shutil.move(str(path), str(destination))
        destination.with_suffix(destination.suffix + ".error.json").write_text(
            json.dumps(error, indent=2, default=str), encoding="utf-8"
        )
        log.error(
            "inbox.failed", file=destination.name, **{k: str(v)[:200] for k, v in error.items()}
        )
        return destination

    def failed_count(self) -> int:
        if not self.failed.is_dir():
            return 0
        return sum(1 for p in self.failed.iterdir() if p.is_file() and _is_message(p))


def _is_message(path: Path) -> bool:
    return path.suffix.lower() in MESSAGE_EXTENSIONS


def _unique(path: Path) -> Path:
    """Never overwrite. Regulators resend, and filenames repeat."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for n in range(1, 1000):
        candidate = path.with_name(f"{stem}.{n}{suffix}")
        if not candidate.exists():
            return candidate
    import uuid

    return path.with_name(f"{stem}.{uuid.uuid4().hex[:8]}{suffix}")
