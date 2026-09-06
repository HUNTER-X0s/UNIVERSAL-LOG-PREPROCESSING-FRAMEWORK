"""Semantic Mapping Engine for ULPF Phase 4.

Transforms Phase 3 Universal Canonical Event (UCE) structures into
fully interpreted, explainable SemanticEvent models.
"""

import uuid
from typing import Any

from ulpf_semantic.analytics.fingerprint import EventFingerprinter
from ulpf_semantic.classification.classifier import SemanticClassifier
from ulpf_semantic.entities.extractor import EntityExtractor
from ulpf_semantic.indicators.extractor import IndicatorExtractor
from ulpf_semantic.mapping.residue import SemanticResidueManager
from ulpf_semantic.models import (
    MitreAttackRef,
    SecurityContext,
    SemanticEvent,
    SemanticStatus,
)
from ulpf_semantic.relationships.builder import RelationshipBuilder
from ulpf_semantic.risk.evaluator import RiskEvaluator
from ulpf_semantic.taxonomy.actions import map_action
from ulpf_semantic.taxonomy.results import derive_result


class SemanticMapper:
    """Core mapping engine coordinating semantic interpretation of UCE records."""

    def __init__(self, mapping_version: str = "1.0.0", registry: Any = None) -> None:
        self.mapping_version = mapping_version
        self.registry = registry
        self.classifier = SemanticClassifier(mapping_version=mapping_version, registry=registry)

    def map_uce_to_semantic(self, uce_event: dict[str, Any]) -> SemanticEvent:
        """Transform a UCE event into an explainable SemanticEvent."""
        ev_id = uce_event.get("event_id", f"evt_{uuid.uuid4().hex[:16]}")
        raw_id = uce_event.get("raw_event_id", f"raw_{uuid.uuid4().hex[:16]}")
        sem_id = f"sem_{uuid.uuid4().hex[:16]}"
        event_body = uce_event.get("event", {})
        unmapped = uce_event.get("unmapped_fields", {})
        timestamp = event_body.get("time") or uce_event.get("processing", {}).get(
            "processed_at", ""
        )
        severity = int(event_body.get("severity", 1))

        # 1. Deterministic Classification & Decision Trace
        triple, confidence, trace = self.classifier.classify(uce_event, unmapped_fields=unmapped)

        # 2. Action & Result Semantics
        raw_action = event_body.get("action")
        sem_action = map_action(original=raw_action, normalized=raw_action)
        status_code = None
        if "status_code" in unmapped:
            try:
                status_code = int(unmapped["status_code"])
            except (ValueError, TypeError):
                pass
        sem_result = derive_result(action=sem_action, status_code=status_code)

        # 3. Entity & Relationship Extraction
        entities = EntityExtractor.extract_entities(uce_event)
        relationships = RelationshipBuilder.build_relationships(
            entities=entities,
            uce_event=uce_event,
            action=sem_action.semantic,
        )

        # 4. Indicators Extraction
        indicators = IndicatorExtractor.extract_indicators(uce_event)

        # 5. Security Context
        meta = event_body.get("metadata", {})
        threat_val = unmapped.get("threat") or unmapped.get("threat_name") or unmapped.get("msg")
        rule_val = unmapped.get("rule") or unmapped.get("rule_name") or unmapped.get("rulename")
        sig_val = unmapped.get("signature") or unmapped.get("sig_id") or unmapped.get("event_id")

        mitre_list: list[MitreAttackRef] = []
        if "mitre_technique" in unmapped:
            mitre_list.append(
                MitreAttackRef(
                    technique_id=str(unmapped["mitre_technique"]),
                    evidence="Source field 'mitre_technique'",
                )
            )

        security_ctx = SecurityContext(
            threat=str(threat_val) if threat_val else None,
            alert=str(unmapped.get("alert")) if "alert" in unmapped else None,
            rule=str(rule_val) if rule_val else None,
            signature=str(sig_val) if sig_val else None,
            attack_phase=str(unmapped.get("attack_phase")) if "attack_phase" in unmapped else None,
            policy=str(unmapped.get("policy")) if "policy" in unmapped else None,
            detection_source=str(meta.get("parser_id")) if meta.get("parser_id") else None,
            mitre_attack=tuple(mitre_list),
        )

        # 6. Risk Evaluation
        is_sec = triple.category == "SECURITY"
        has_ext_ind = any(i.indicator_type == "IP" for i in indicators)
        risk_ctx = RiskEvaluator.evaluate(
            severity=severity,
            action=sem_action.semantic,
            result_status=sem_result.status,
            is_security_event=is_sec,
            has_public_indicators=has_ext_ind,
            uce_event=uce_event,
        )

        # 7. Correlation Context & Fingerprint
        corr_ctx = EventFingerprinter.build_correlation_context(
            triple=triple,
            action=sem_action.semantic,
            result_status=sem_result.status,
            entities=entities,
            uce_event=uce_event,
        )

        # 8. Residue Management
        semantic_residue = SemanticResidueManager.preserve_residue(
            uce_unmapped=unmapped,
        )

        # Determine semantic quality status from confidence
        if confidence.score >= 0.90:
            sem_status = SemanticStatus.FULL
        elif confidence.score >= 0.70:
            sem_status = SemanticStatus.PARTIAL
        else:
            sem_status = SemanticStatus.UNKNOWN

        return SemanticEvent(
            contract_version="1.0.0",
            semantic_event_id=sem_id,
            uce_event_id=ev_id,
            raw_event_id=raw_id,
            timestamp=str(timestamp),
            semantic_triple=triple,
            action=sem_action,
            result=sem_result,
            confidence=confidence,
            decision_trace=trace,
            severity=severity,
            status=sem_status,
            entities=entities,
            relationships=relationships,
            indicators=indicators,
            security_context=security_ctx,
            risk_context=risk_ctx,
            correlation_context=corr_ctx,
            projections={},
            unmapped_semantic_fields=semantic_residue,
        )
