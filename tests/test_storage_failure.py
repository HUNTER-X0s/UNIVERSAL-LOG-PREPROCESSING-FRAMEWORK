"""Phase 7 Test: Storage Failure Mode.

Verifies:
- Rule D8: Object storage failure raises meaningful error (not silent drop)
- Rule B8: Checksum mismatch detected on retrieval
- Rule B9: Path traversal attempts are rejected
"""

from pathlib import Path

import pytest
from ulpf_storage.object_store import (
    ChecksumMismatchError,
    FilesystemObjectStore,
    ObjectNotFoundError,
    PathTraversalError,
)


@pytest.fixture()
def store(tmp_path: Path) -> FilesystemObjectStore:
    return FilesystemObjectStore(tmp_path)


def test_put_and_get_roundtrip(store: FilesystemObjectStore) -> None:
    data = b"hello storage layer"
    meta = store.put("events/raw/evt-001.bin", data)
    assert meta.sha256 is not None
    assert meta.size_bytes == len(data)

    retrieved_meta, retrieved_data = store.get("events/raw/evt-001.bin")
    assert retrieved_data == data
    assert retrieved_meta.sha256 == meta.sha256


def test_object_not_found_raises(store: FilesystemObjectStore) -> None:
    with pytest.raises(ObjectNotFoundError):
        store.get("does/not/exist.bin")


def test_checksum_mismatch_detected(store: FilesystemObjectStore, tmp_path: Path) -> None:
    """Tampered object data is detected on retrieval."""
    data = b"original content"
    store.put("tamper/test.bin", data)

    # Tamper the stored file directly
    stored_path = tmp_path / "tamper" / "test.bin"
    stored_path.write_bytes(b"tampered content")

    with pytest.raises(ChecksumMismatchError):
        store.get("tamper/test.bin")


def test_path_traversal_rejected(store: FilesystemObjectStore) -> None:
    with pytest.raises(PathTraversalError):
        store.put("../../etc/passwd", b"evil")


def test_path_traversal_in_get_rejected(store: FilesystemObjectStore) -> None:
    with pytest.raises(PathTraversalError):
        store.get("../../../etc/shadow")


def test_exists_before_and_after_put(store: FilesystemObjectStore) -> None:
    assert not store.exists("key/does/not/exist.bin")
    store.put("key/does/not/exist.bin", b"data")
    assert store.exists("key/does/not/exist.bin")


def test_delete_removes_object(store: FilesystemObjectStore) -> None:
    store.put("obj/to/delete.bin", b"data")
    assert store.exists("obj/to/delete.bin")
    store.delete("obj/to/delete.bin")
    assert not store.exists("obj/to/delete.bin")


def test_list_keys_returns_all_objects(store: FilesystemObjectStore) -> None:
    store.put("a/1.bin", b"1")
    store.put("a/2.bin", b"2")
    store.put("b/3.bin", b"3")
    keys = store.list_keys()
    assert len(keys) == 3


def test_list_keys_with_prefix(store: FilesystemObjectStore) -> None:
    store.put("raw/001.bin", b"x")
    store.put("raw/002.bin", b"y")
    store.put("semantic/001.bin", b"z")
    raw_keys = store.list_keys("raw/")
    assert len(raw_keys) == 2
    assert all(k.startswith("raw/") for k in raw_keys)


def test_dotdot_in_key_neutralized(store: FilesystemObjectStore) -> None:
    """.. in key components are sanitized (DOTDOT replacement), not traversing."""
    # This should not raise PathTraversalError, but sanitize the key
    store.put("safe/../sanitized.bin", b"data")
    # The key is stored with DOTDOT replacement, so exists under sanitized path
