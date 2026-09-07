"""ULPF Phase 7 — Backup Manager.

Generates encrypted, checksummed, versioned backups of:
- Database (SQLite dump)
- Mappings and source profiles
- Audit records

Backup format:
- Each backup is a directory with a manifest JSON and per-component
  content files. Each file has an accompanying SHA-256 sidecar.
- Encryption: XOR-stream with key derived from PBKDF2-HMAC-SHA256
  (lightweight symmetric cipher suitable for air-gap; can be replaced
  with AES-GCM if PyCryptodome is available in the environment).

Enforces:
- Rule D1: Encrypted, checksummed, versioned backups
- Rule D2: Backup includes database, mappings, profiles, audit
- Rule D3: Backup manifest contains schema version and component checksums
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class BackupError(Exception):
    """Raised when a backup operation fails."""


class BackupManifest:
    """Manifest for a single backup snapshot."""

    def __init__(
        self,
        backup_id: str,
        schema_version: int,
        created_at: str,
        components: dict[str, str],  # component_name → sha256
        total_size_bytes: int,
    ) -> None:
        self.backup_id = backup_id
        self.schema_version = schema_version
        self.created_at = created_at
        self.components = components
        self.total_size_bytes = total_size_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "components": self.components,
            "total_size_bytes": self.total_size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupManifest:
        return cls(
            backup_id=data["backup_id"],
            schema_version=data["schema_version"],
            created_at=data["created_at"],
            components=data["components"],
            total_size_bytes=data["total_size_bytes"],
        )


def _derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive a 32-byte encryption key using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR-stream encryption (deterministic for a given key stream)."""
    # Expand key to data length using HMAC-SHA256 counter mode
    result = bytearray(len(data))
    block_size = 32
    for i in range(0, len(data), block_size):
        counter = struct.pack(">Q", i // block_size)
        keystream = hmac.new(key, counter, hashlib.sha256).digest()
        block = data[i : i + block_size]
        for j, b in enumerate(block):
            result[i + j] = b ^ keystream[j % block_size]
    return bytes(result)


# XOR is symmetric
_xor_decrypt = _xor_encrypt


class BackupManager:
    """Generates and restores encrypted, versioned backups."""

    def __init__(
        self,
        backup_root: str | Path,
        encryption_password: str,
    ) -> None:
        self._root = Path(backup_root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._password = encryption_password

    def create_backup(
        self,
        components: dict[str, bytes],  # component_name → raw bytes
        schema_version: int,
        backup_id: str | None = None,
    ) -> BackupManifest:
        """Create a new versioned, encrypted, checksummed backup.

        Args:
            components: Mapping of component name to raw bytes to back up.
            schema_version: Current schema version to embed in manifest.
            backup_id: Optional explicit ID; auto-generated if not provided.

        Returns:
            BackupManifest with component checksums and metadata.
        """
        ts = datetime.now(UTC).isoformat()
        bid = backup_id or f"backup-{ts.replace(':', '-').replace('.', '-')}"
        backup_dir = self._root / bid
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Salt: deterministic per backup_id for reproducibility in tests
        salt = hashlib.sha256(bid.encode("utf-8")).digest()[:16]
        key = _derive_key(self._password, salt)

        component_checksums: dict[str, str] = {}
        total_size = 0

        for name, raw_data in components.items():
            # Checksum of plaintext
            sha256 = hashlib.sha256(raw_data).hexdigest()
            component_checksums[name] = sha256

            # Encrypt
            encrypted = _xor_encrypt(raw_data, key)
            total_size += len(encrypted)

            # Write encrypted file
            enc_path = backup_dir / f"{name}.enc"
            enc_path.write_bytes(encrypted)

            # Write plaintext checksum sidecar
            (backup_dir / f"{name}.sha256").write_text(sha256, encoding="utf-8")

        # Write manifest
        manifest = BackupManifest(
            backup_id=bid,
            schema_version=schema_version,
            created_at=ts,
            components=component_checksums,
            total_size_bytes=total_size,
        )
        manifest_path = backup_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest.to_dict(), indent=2), encoding="utf-8"
        )

        return manifest

    def restore_backup(
        self, backup_id: str
    ) -> tuple[BackupManifest, dict[str, bytes]]:
        """Restore and verify a backup by ID.

        Returns the manifest and a dict of component_name → decrypted bytes.
        Raises BackupError if checksum verification fails.
        """
        backup_dir = self._root / backup_id
        if not backup_dir.exists():
            raise BackupError(f"Backup '{backup_id}' not found at {backup_dir}")

        manifest_path = backup_dir / "manifest.json"
        if not manifest_path.exists():
            raise BackupError(f"Backup '{backup_id}' missing manifest.json")

        manifest = BackupManifest.from_dict(
            json.loads(manifest_path.read_text(encoding="utf-8"))
        )

        salt = hashlib.sha256(backup_id.encode("utf-8")).digest()[:16]
        key = _derive_key(self._password, salt)

        restored: dict[str, bytes] = {}
        for name, expected_sha256 in manifest.components.items():
            enc_path = backup_dir / f"{name}.enc"
            if not enc_path.exists():
                raise BackupError(f"Missing encrypted component '{name}' in backup '{backup_id}'")

            encrypted = enc_path.read_bytes()
            raw_data = _xor_decrypt(encrypted, key)

            actual_sha256 = hashlib.sha256(raw_data).hexdigest()
            if actual_sha256 != expected_sha256:
                raise BackupError(
                    f"Checksum mismatch for component '{name}' in backup '{backup_id}': "
                    f"expected={expected_sha256} actual={actual_sha256}"
                )

            restored[name] = raw_data

        return manifest, restored

    def list_backups(self) -> list[str]:
        """List all available backup IDs, sorted by creation time."""
        backups = []
        for d in sorted(self._root.iterdir()):
            if d.is_dir() and (d / "manifest.json").exists():
                backups.append(d.name)
        return backups

    def delete_backup(self, backup_id: str) -> None:
        """Delete a backup directory and all its files."""
        import shutil

        backup_dir = self._root / backup_id
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
