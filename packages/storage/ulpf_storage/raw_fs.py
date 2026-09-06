"""Filesystem-backed raw evidence repository for ULPF Phase 6.

Enforces:
- Rule 2: Raw evidence remains immutable
- Rule 9: Do not silently overwrite raw evidence
- Rule 36: Forensic evidence chain with cryptographic verification
- Path safety: Validates against path traversal / directory escapes
"""

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ulpf_runtime.errors import PersistenceError, StorageIntegrityError

from ulpf_storage.interfaces import RawEvidenceRecord, RawEvidenceRepository


class FilesystemRawEvidenceRepository(RawEvidenceRepository):
    """Stores raw evidence on filesystem in a structured, hashed layout:

    {base_dir}/raw/{date}/{source}/{hash_prefix}/{event_id}.raw
    with a corresponding sidecar metadata JSON file.
    """

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _sanitize_path_segment(self, segment: str) -> str:
        """Prevent path traversal and invalid characters."""
        clean = "".join(c for c in segment if c.isalnum() or c in ("-", "_", "."))
        return clean.strip(".").replace("..", "") or "default"

    def _compute_path(self, raw_event_id: str, source_id: str, sha256_hex: str) -> Path:
        date_str = datetime.now(UTC).strftime("%Y-%m-%d")
        safe_source = self._sanitize_path_segment(source_id)
        safe_id = self._sanitize_path_segment(raw_event_id)
        prefix = sha256_hex[:4]

        rel = Path("raw") / date_str / safe_source / prefix / f"{safe_id}.raw"
        full = (self.base_dir / rel).resolve()

        # Strict containment check to prevent directory traversal
        if not str(full).startswith(str(self.base_dir)):
            raise PersistenceError(f"Path traversal detected: {raw_event_id}")

        return full

    def put(
        self,
        raw_event_id: str,
        payload: bytes,
        source_id: str,
        format_str: str,
        metadata: dict[str, Any] | None = None,
    ) -> RawEvidenceRecord:
        sha256_hex = hashlib.sha256(payload).hexdigest()
        file_path = self._compute_path(raw_event_id, source_id, sha256_hex)
        meta_path = file_path.with_suffix(".json")

        with self._lock:
            if file_path.exists():
                raise PersistenceError(
                    f"Raw evidence {raw_event_id} already exists. Overwrite forbidden.",
                    details={"raw_event_id": raw_event_id, "path": str(file_path)},
                )

            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(payload)

            record = RawEvidenceRecord(
                raw_event_id=raw_event_id,
                sha256=sha256_hex,
                captured_at=datetime.now(UTC).isoformat(),
                source_id=source_id,
                format=format_str,
                byte_length=len(payload),
                storage_path=str(file_path.relative_to(self.base_dir)),
                metadata=metadata or {},
            )

            meta_content = {
                "raw_event_id": record.raw_event_id,
                "sha256": record.sha256,
                "captured_at": record.captured_at,
                "source_id": record.source_id,
                "format": record.format,
                "byte_length": record.byte_length,
                "storage_path": record.storage_path,
                "metadata": record.metadata,
            }
            meta_path.write_text(json.dumps(meta_content, indent=2), encoding="utf-8")
            return record

    def get(self, raw_event_id: str) -> tuple[RawEvidenceRecord, bytes]:
        meta = self.get_metadata(raw_event_id)
        if not meta:
            raise PersistenceError(f"Raw evidence {raw_event_id} not found")

        full_path = (self.base_dir / meta.storage_path).resolve()
        if not full_path.exists():
            raise PersistenceError(f"Raw evidence file missing at {meta.storage_path}")

        payload = full_path.read_bytes()
        actual_sha = hashlib.sha256(payload).hexdigest()
        if actual_sha != meta.sha256:
            raise StorageIntegrityError(
                f"Integrity check failed for {raw_event_id}",
                details={"expected": meta.sha256, "actual": actual_sha},
            )

        return meta, payload

    def exists(self, raw_event_id: str) -> bool:
        return self.get_metadata(raw_event_id) is not None

    def verify(self, raw_event_id: str) -> bool:
        try:
            self.get(raw_event_id)
            return True
        except (PersistenceError, StorageIntegrityError):
            return False

    def get_metadata(self, raw_event_id: str) -> RawEvidenceRecord | None:
        safe_id = self._sanitize_path_segment(raw_event_id)
        # Search for the sidecar json matching the event id
        matches = list(self.base_dir.glob(f"raw/*/*/*/{safe_id}.json"))
        if not matches:
            return None

        try:
            data = json.loads(matches[0].read_text(encoding="utf-8"))
            return RawEvidenceRecord(
                raw_event_id=data["raw_event_id"],
                sha256=data["sha256"],
                captured_at=data["captured_at"],
                source_id=data["source_id"],
                format=data["format"],
                byte_length=data["byte_length"],
                storage_path=data["storage_path"],
                metadata=data.get("metadata", {}),
            )
        except Exception:
            return None
