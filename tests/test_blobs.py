"""Blob store: content addressing, idempotency, and path-traversal refusal."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from advisory_hub.core.storage.blobs import FilesystemBlobStore


def test_put_bytes_is_content_addressed(blob_root: Path) -> None:
    store = FilesystemBlobStore(blob_root)
    data = b"advisory content"
    result = store.put_bytes(data)

    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.size_bytes == len(data)
    assert result.created is True
    assert store.get_bytes(result.sha256) == data


def test_identical_content_is_stored_once(blob_root: Path) -> None:
    """Ingestion idempotency depends on this — see D-007."""
    store = FilesystemBlobStore(blob_root)
    first = store.put_bytes(b"same bytes")
    second = store.put_bytes(b"same bytes")

    assert first.sha256 == second.sha256
    assert first.created is True
    assert second.created is False
    assert len(list(blob_root.rglob("*"))) == 3  # 2 dirs + 1 file


def test_put_stream_matches_put_bytes(blob_root: Path) -> None:
    store = FilesystemBlobStore(blob_root)
    payload = b"x" * (3 * 1024 * 1024)  # larger than one chunk

    streamed = store.put_stream(io.BytesIO(payload))

    assert streamed.sha256 == hashlib.sha256(payload).hexdigest()
    assert streamed.size_bytes == len(payload)
    assert store.get_bytes(streamed.sha256) == payload


def test_stream_leaves_no_temp_files(blob_root: Path) -> None:
    store = FilesystemBlobStore(blob_root)
    store.put_stream(io.BytesIO(b"payload"))
    assert not list(blob_root.glob(".incoming-*"))


def test_blobs_are_written_read_only(blob_root: Path) -> None:
    store = FilesystemBlobStore(blob_root)
    result = store.put_bytes(b"immutable")
    mode = store.path_for(result.sha256).stat().st_mode & 0o777
    assert mode == 0o440


@pytest.mark.parametrize(
    "bad",
    [
        "../../etc/passwd",
        "not-a-digest",
        "",
        "A" * 64,  # uppercase is not our canonical form
        "g" * 64,  # not hex
        "a" * 63,  # too short
    ],
)
def test_rejects_non_digest_paths(blob_root: Path, bad: str) -> None:
    """Digests become path segments — anything else must not be accepted."""
    store = FilesystemBlobStore(blob_root)
    with pytest.raises(ValueError, match="hex SHA-256"):
        store.path_for(bad)


def test_healthcheck_reports_writability(blob_root: Path) -> None:
    assert FilesystemBlobStore(blob_root).healthcheck() is True
    assert FilesystemBlobStore(Path("/proc/nonexistent/blobs")).healthcheck() is False
