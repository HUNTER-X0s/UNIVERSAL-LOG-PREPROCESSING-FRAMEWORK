"""Tests for ULPF Phase 6 storage repositories and cryptographic integrity."""

import tempfile
import unittest
from pathlib import Path

from ulpf_runtime.errors import PersistenceError, StorageIntegrityError
from ulpf_storage.interfaces import StoredSemanticEvent, UCERecord
from ulpf_storage.memory import (
    MemorySemanticEventRepository,
    MemoryUCERepository,
)
from ulpf_storage.raw_fs import FilesystemRawEvidenceRepository


class TestStorage(unittest.TestCase):
    def test_filesystem_raw_store_integrity_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo = FilesystemRawEvidenceRepository(base_dir=tmp_dir)
            payload = b"Mar 01 10:00:00 asa01 %ASA-6-302013: Built inbound TCP connection"

            # 1. Put raw evidence
            rec = repo.put(
                raw_event_id="raw-101",
                payload=payload,
                source_id="asa-fw",
                format_str="syslog",
            )
            self.assertTrue(repo.exists("raw-101"))
            self.assertTrue(repo.verify("raw-101"))

            # 2. Overwrite protection
            with self.assertRaises(PersistenceError):
                repo.put("raw-101", payload, "asa-fw", "syslog")

            # 3. Simulate file tampering / bit-rot on disk
            full_path = Path(tmp_dir) / rec.storage_path
            full_path.write_bytes(b"TAMPERED CORRUPTED DATA")

            # 4. Verification must detect corruption
            self.assertFalse(repo.verify("raw-101"))
            with self.assertRaises(StorageIntegrityError):
                repo.get("raw-101")

    def test_uce_store_write_once_immutability(self) -> None:
        repo = MemoryUCERepository()
        rec = UCERecord(
            uce_event_id="uce-001",
            raw_event_id="raw-001",
            raw_sha256="sha123",
            payload={"event_id": "uce-001", "message": "hello"},
            schema_version="1.0.0",
            source_id="src-1",
            captured_at="2026-03-01T12:00:00Z",
        )
        repo.put(rec)
        self.assertTrue(repo.exists("uce-001"))

        # In-place overwrite must be rejected
        with self.assertRaises(PersistenceError):
            repo.put(rec)

    def test_semantic_event_store_and_query(self) -> None:
        repo = MemorySemanticEventRepository()
        ev1 = StoredSemanticEvent(
            semantic_event_id="sem-1",
            uce_event_id="uce-1",
            raw_sha256="sha1",
            mapping_version="v1.0.0",
            semantic_version="1.0.0",
            payload={},
            fingerprint="fp-abc",
            risk_level="HIGH",
            risk_score=85.0,
            entities=[{"type": "IP", "value": "192.168.1.1"}],
            indicators=[{"type": "IP", "value": "192.168.1.1"}],
            classification={"vendor": "Cisco", "category": "NETWORK"},
        )
        ev2 = StoredSemanticEvent(
            semantic_event_id="sem-2",
            uce_event_id="uce-2",
            raw_sha256="sha2",
            mapping_version="v1.0.0",
            semantic_version="1.0.0",
            payload={},
            fingerprint="fp-xyz",
            risk_level="LOW",
            risk_score=15.0,
            entities=[],
            indicators=[],
            classification={"vendor": "PaloAlto", "category": "NETWORK"},
        )
        repo.put(ev1)
        repo.put(ev2)

        # Query by risk level
        res_high = repo.query(risk_level="HIGH")
        self.assertEqual(len(res_high), 1)
        self.assertEqual(res_high[0].semantic_event_id, "sem-1")

        # Query by vendor
        res_pa = repo.query(vendor="PaloAlto")
        self.assertEqual(len(res_pa), 1)
        self.assertEqual(res_pa[0].semantic_event_id, "sem-2")


if __name__ == "__main__":
    unittest.main()
