"""Tests for ULPF Phase 6 historical replay coordinator."""

import unittest

from ulpf_runtime.errors import ReplayError
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_runtime.replay import ReplayRequest, RuntimeReplayCoordinator
from ulpf_storage.memory import (
    MemoryAuditRepository,
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)


class TestReplayRuntime(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_store = MemoryRawEvidenceRepository()
        self.uce_store = MemoryUCERepository()
        self.semantic_store = MemorySemanticEventRepository()
        self.audit_repo = MemoryAuditRepository()

        self.pipeline = RuntimePipeline(
            raw_store=self.raw_store,
            uce_store=self.uce_store,
            semantic_store=self.semantic_store,
        )

        self.coordinator = RuntimeReplayCoordinator(
            pipeline=self.pipeline,
            raw_store=self.raw_store,
            uce_store=self.uce_store,
            audit_repo=self.audit_repo,
        )

        # Ingest an initial event to generate raw evidence
        self.init_res = self.pipeline.process_event(
            raw_payload="test raw evidence log",
            source_id="asa-01",
        )

    def test_replay_with_pinned_version_and_audit(self) -> None:
        req = ReplayRequest(
            job_id="job-101",
            target_stage="RAW",
            mapping_version="v1.2.0",  # Explicitly pinned
            event_ids=[self.init_res.raw_event_id],
            reason="Forensic Review",
            requested_by="security-auditor",
        )

        result = self.coordinator.execute_replay(req)
        self.assertEqual(result.processed_count, 1)
        self.assertEqual(result.failed_count, 0)
        self.assertEqual(result.mapping_version, "v1.2.0")

        # Verify audit trail records
        actions = self.audit_repo.list_actions()
        self.assertGreaterEqual(len(actions), 2)  # START and COMPLETE
        action_names = [a.action for a in actions]
        self.assertIn("REPLAY_START", action_names)
        self.assertIn("REPLAY_COMPLETE", action_names)

    def test_replay_without_mapping_version_raises_error(self) -> None:
        # Pinned mapping version is strictly mandatory
        req = ReplayRequest(
            job_id="job-invalid",
            target_stage="RAW",
            mapping_version="",  # Empty / missing pinning
            event_ids=[self.init_res.raw_event_id],
        )
        with self.assertRaises(ReplayError):
            self.coordinator.execute_replay(req)


if __name__ == "__main__":
    unittest.main()
