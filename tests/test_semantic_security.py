"""Security and boundary resistance tests for ULPF Phase 4 Semantic Engine."""

import unittest

from ulpf_semantic.models import SemanticEvent
from ulpf_semantic.projections.base import BaseProjection, ProjectionResult, ProjectionStatus
from ulpf_semantic.projections.registry import ProjectionRegistry
from ulpf_semantic.service import SemanticService


class FaultyProjection(BaseProjection):
    """Mock projection simulating unexpected exceptions."""

    projection_id = "faulty.v1"
    version = "1.0.0"

    def project(self, semantic_event: SemanticEvent, uce_event: dict) -> ProjectionResult:
        raise RuntimeError("Simulated projection engine failure")


class TestSemanticSecurity(unittest.TestCase):
    def test_projection_failure_isolation(self) -> None:
        """A crashing projection must never invalidate UCE or SemanticEvent."""
        reg = ProjectionRegistry()
        reg.register(FaultyProjection())
        service = SemanticService(projection_registry=reg)

        uce = {
            "event_id": "evt_iso_01",
            "event": {
                "category": "security",
                "type": "firewall",
                "action": "drop",
                "metadata": {"vendor": "Cisco"},
            },
            "unmapped_fields": {},
        }
        sem_event = service.process_uce(uce)

        self.assertIsNotNone(sem_event)
        self.assertEqual(sem_event.semantic_triple.category, "SECURITY")
        self.assertIn("faulty.v1", sem_event.projections)
        self.assertEqual(sem_event.projections["faulty.v1"]["status"], ProjectionStatus.FAILED.value)

    def test_oversized_unmapped_residue(self) -> None:
        """Verify engine tolerates very large attribute dictionaries safely."""
        huge_unmapped = {f"custom_key_{i}": f"custom_val_{i}" * 5 for i in range(1000)}
        uce = {
            "event_id": "evt_huge_01",
            "event": {
                "category": "security",
                "type": "firewall",
                "action": "drop",
                "metadata": {"vendor": "Palo Alto Networks"},
            },
            "unmapped_fields": huge_unmapped,
        }
        service = SemanticService()
        sem_event = service.process_uce(uce)

        self.assertEqual(len(sem_event.unmapped_semantic_fields), 1000)
        self.assertEqual(sem_event.semantic_triple.type_name, "firewall.deny")

    def test_unicode_and_special_character_resilience(self) -> None:
        """Verify engine handles Unicode, control characters, and SQL injection strings safely."""
        malicious_input = "'; DROP TABLE logs; -- \x00\x1f \U0001f525"
        uce = {
            "event_id": "evt_injection_01",
            "event": {
                "category": "security",
                "type": "firewall",
                "action": "drop",
                "identity": {"user": {"name": malicious_input}},
                "metadata": {"vendor": malicious_input},
            },
            "unmapped_fields": {"threat": malicious_input},
        }
        service = SemanticService()
        sem_event = service.process_uce(uce)

        self.assertIsNotNone(sem_event)
        user_ent = next((e for e in sem_event.entities if e.role == "actor"), None)
        self.assertIsNotNone(user_ent)
        self.assertEqual(user_ent.value, malicious_input)


if __name__ == "__main__":
    unittest.main()
