"""Content-addressed blob storage.

Originals are stored by SHA-256 and never mutated or deleted — they are
compliance artefacts and the input to every future re-parse. See D-007.

Layout: ``<root>/<sha[0:2]>/<sha[2:4]>/<sha>``. Two levels of fan-out keeps
directory sizes sane at corpus scale.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

CHUNK = 1024 * 1024


@dataclass(frozen=True, slots=True)
class StoredBlob:
    sha256: str
    size_bytes: int
    #: False when an identical blob already existed — ingestion idempotency.
    created: bool


class BlobStore(Protocol):
    def put_bytes(self, data: bytes) -> StoredBlob: ...
    def put_stream(self, stream: BinaryIO) -> StoredBlob: ...
    def get_bytes(self, sha256: str) -> bytes: ...
    def open(self, sha256: str) -> BinaryIO: ...
    def exists(self, sha256: str) -> bool: ...
    def path_for(self, sha256: str) -> Path: ...


class FilesystemBlobStore:
    """Filesystem-backed store. Swappable for S3-compatible storage later."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def path_for(self, sha256: str) -> Path:
        _validate_digest(sha256)
        return self.root / sha256[0:2] / sha256[2:4] / sha256

    def exists(self, sha256: str) -> bool:
        return self.path_for(sha256).is_file()

    def put_bytes(self, data: bytes) -> StoredBlob:
        digest = hashlib.sha256(data).hexdigest()
        target = self.path_for(digest)
        if target.is_file():
            return StoredBlob(digest, target.stat().st_size, created=False)
        self._atomic_write(target, data)
        return StoredBlob(digest, len(data), created=True)

    def put_stream(self, stream: BinaryIO) -> StoredBlob:
        """Stream to a temp file while hashing, then rename into place.

        Never loads the whole object into memory — attachments can be large and
        arrive from outside the organisation.
        """
        hasher = hashlib.sha256()
        size = 0
        self.root.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=self.root, prefix=".incoming-")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := stream.read(CHUNK):
                    hasher.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
            digest = hasher.hexdigest()
            target = self.path_for(digest)
            if target.is_file():
                tmp.unlink(missing_ok=True)
                return StoredBlob(digest, target.stat().st_size, created=False)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, target)
            target.chmod(0o440)  # immutable by convention
            return StoredBlob(digest, size, created=True)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def get_bytes(self, sha256: str) -> bytes:
        return self.path_for(sha256).read_bytes()

    def open(self, sha256: str) -> BinaryIO:
        return self.path_for(sha256).open("rb")

    def _atomic_write(self, target: Path, data: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".incoming-")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
            os.replace(tmp, target)
            target.chmod(0o440)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def healthcheck(self) -> bool:
        """Verify the volume is present and writable."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            probe = self.root / ".healthcheck"
            probe.write_bytes(b"ok")
            probe.unlink()
        except OSError:
            return False
        return True


def _validate_digest(sha256: str) -> None:
    """Reject anything that isn't a hex digest — these become path segments."""
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        raise ValueError(f"Not a lowercase hex SHA-256 digest: {sha256!r}")
