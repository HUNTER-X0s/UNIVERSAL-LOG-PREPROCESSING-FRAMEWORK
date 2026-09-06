"""Unit tests for ULPF Phase 4 Entities, Relationships, Indicators, and Risk Modeling."""

import unittest

from ulpf_semantic.analytics.fingerprint import EventFingerprinter
from ulpf_semantic.entities.extractor import EntityExtractor
from ulpf_semantic.indicators.extractor import IndicatorExtractor
from ulpf_semantic.models import SemanticTriple
from ulpf_semantic.relationships.builder import RelationshipBuilder
from ulpf_semantic.risk.evaluator import RiskEvaluator


class TestSemanticEntities(unittest.TestCase):
    def test_entity_extraction(self) -> None:
        uce = {
            "event": {
                "source": {"ip": "192.168.1.50", "port": 54321},
                "destination": {"ip": "10.0.0.5", "port": 80},
                "identity": {"user": {"name": "admin"}},
                "device": {"hostname": "SRV-DC-01"},
            },
            "unmapped_fields": {
                "resourceId": "vol-0123456789abcdef0",
            },
        }
        entities = EntityExtractor.extract_entities(uce)
        types = [e.entity_type for e in entities]
        self.assertIn("IP", types)
        self.assertIn("USER", types)
        self.assertIn("HOST", types)
        self.assertIn("CLOUD_RESOURCE", types)

        src_ip = next(e for e in entities if e.role == "source")
        self.assertEqual(src_ip.value, "192.168.1.50")
        self.assertEqual(src_ip.normalized_value, "192.168.1.50")

    def test_relationship_building(self) -> None:
        uce = {
            "event": {
                "source": {"ip": "10.0.0.2"},
                "destination": {"ip": "10.0.0.3"},
                "identity": {"user": {"name": "bob"}},
                "device": {"hostname": "host-a"},
            },
            "unmapped_fields": {},
        }
        entities = EntityExtractor.extract_entities(uce)
        rels = RelationshipBuilder.build_relationships(entities, uce, action="allow")
        predicates = [r.predicate for r in rels]
        self.assertIn("communicated_with", predicates)
        self.assertIn("accessed_host", predicates)

    def test_indicator_extraction(self) -> None:
        uce = {
            "event": {
                "source": {"ip": "8.8.8.8"},  # Globally routable public IP (Google DNS)
                "destination": {"ip": "192.168.1.1"},  # Private IP — not extracted
            },
            "unmapped_fields": {
                "query": "malicious.example.com",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        }
        indicators = IndicatorExtractor.extract_indicators(uce)
        ind_types = [i.indicator_type for i in indicators]
        self.assertIn("IP", ind_types)
        self.assertIn("DOMAIN", ind_types)
        self.assertIn("HASH_SHA256", ind_types)

    def test_risk_evaluation(self) -> None:
        risk_high = RiskEvaluator.evaluate(
            severity=9,
            action="drop",
            result_status="DENIED",
            is_security_event=True,
            has_public_indicators=True,
            uce_event={},
        )
        self.assertEqual(risk_high.risk_level, "CRITICAL")
        self.assertGreaterEqual(risk_high.risk_score, 80.0)

        # severity=2 → base_score=20.0 → risk_level="LOW" (threshold ≥20)
        risk_low = RiskEvaluator.evaluate(
            severity=2,
            action="allow",
            result_status="SUCCESS",
            is_security_event=False,
            has_public_indicators=False,
            uce_event={},
        )
        self.assertEqual(risk_low.risk_level, "LOW")

    def test_event_fingerprinting(self) -> None:
        triple = SemanticTriple("SECURITY", "Firewall", "firewall.deny")
        uce = {
            "event": {
                "source": {"ip": "192.168.1.1"},
                "destination": {"ip": "10.0.0.1"},
                "network": {"protocol": "TCP"},
            },
            "unmapped_fields": {"session_id": "sess-99"},
        }
        entities = EntityExtractor.extract_entities(uce)
        ctx1 = EventFingerprinter.build_correlation_context(triple, "deny", "DENIED", entities, uce)
        ctx2 = EventFingerprinter.build_correlation_context(triple, "deny", "DENIED", entities, uce)
        self.assertEqual(ctx1.equivalence_key, ctx2.equivalence_key)
        self.assertEqual(ctx1.event_fingerprint, ctx2.event_fingerprint)
        self.assertTrue(ctx1.equivalence_key.startswith("eq:"))
        self.assertTrue(ctx1.event_fingerprint.startswith("fp:"))


if __name__ == "__main__":
    unittest.main()
