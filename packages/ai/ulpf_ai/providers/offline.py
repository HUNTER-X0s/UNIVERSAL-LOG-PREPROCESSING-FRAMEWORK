"""Offline Deterministic AI Advisor for ULPF Phase 5.

Operates 100% offline with zero external model calls, providing rule-based
candidate suggestions and field semantic matching derived from physical evidence.
"""

import hashlib
import json
import uuid
from typing import Any

from ulpf_ai.interfaces import AISemanticAdvisor
from ulpf_ai.models import AIConfidenceBreakdown, AISuggestion, FieldSemanticsSuggestion


class OfflineDeterministicAdvisor(AISemanticAdvisor):
    """Offline, deterministic advisor using statistical heuristics and dictionaries."""

    FIELD_TARGET_HEURISTICS: dict[str, tuple[str, str, float]] = {
        "src_ip": ("event.source.ip", "ip", 0.95),
        "source_ip": ("event.source.ip", "ip", 0.95),
        "srcaddr": ("event.source.ip", "ip", 0.95),
        "src": ("event.source.ip", "ip", 0.90),
        "dst_ip": ("event.destination.ip", "ip", 0.95),
        "dest_ip": ("event.destination.ip", "ip", 0.95),
        "dstaddr": ("event.destination.ip", "ip", 0.95),
        "dst": ("event.destination.ip", "ip", 0.90),
        "sport": ("event.source.port", "integer", 0.90),
        "src_port": ("event.source.port", "integer", 0.95),
        "dport": ("event.destination.port", "integer", 0.90),
        "dst_port": ("event.destination.port", "integer", 0.95),
        "proto": ("event.network.protocol", "string", 0.90),
        "protocol": ("event.network.protocol", "string", 0.95),
        "username": ("event.identity.user.name", "string", 0.90),
        "user": ("event.identity.user.name", "string", 0.85),
        "hostname": ("event.device.hostname", "string", 0.90),
        "host": ("event.device.hostname", "string", 0.85),
        "act": ("event.action", "string", 0.90),
        "action": ("event.action", "string", 0.95),
    }

    @property
    def provider_id(self) -> str:
        return "offline.deterministic.v1"

    @property
    def model_version(self) -> str:
        return "heuristic.1.0.0"

    def infer_field_semantics(
        self,
        field_name: str,
        sample_values: list[Any],
        context: dict[str, Any] | None = None,
    ) -> FieldSemanticsSuggestion:
        """Deterministically infer target canonical field and type."""
        fn_clean = field_name.strip().lower().replace("-", "_")
        if fn_clean in self.FIELD_TARGET_HEURISTICS:
            target, f_type, conf = self.FIELD_TARGET_HEURISTICS[fn_clean]
            return FieldSemanticsSuggestion(
                source_field=field_name,
                target_canonical_field=target,
                inferred_type=f_type,
                confidence=conf,
                evidence=(f"heuristic_alias_match:{fn_clean}->{target}",),
                reasoning=(
                    f"Field name '{field_name}' matches known network/security telemetry alias."
                ),
            )

        return FieldSemanticsSuggestion(
            source_field=field_name,
            target_canonical_field=f"unmapped.{field_name}",
            inferred_type="string",
            confidence=0.50,
            evidence=("fallback_unmapped",),
            reasoning=(
                f"No high-confidence semantic match found for "
                f"'{field_name}'. Forwarded as unmapped residue."
            ),
        )

    def suggest_mapping(
        self,
        sample_events: list[dict[str, Any]],
        source_hint: dict[str, Any] | None = None,
    ) -> AISuggestion:
        """Generate candidate mapping definition from sample logs deterministically."""
        s_id = f"sug_{uuid.uuid4().hex[:12]}"
        sample_hash = hashlib.sha256(
            json.dumps(sample_events[:5], sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

        vendor = "Generic"
        product = "Telemetry"
        if source_hint:
            vendor = source_hint.get("vendor", vendor)
            product = source_hint.get("product", product)

        # Inspect first sample for action / category hints
        first_ev = sample_events[0] if sample_events else {}
        action_val = "access"
        category = "NETWORK"
        class_name = "Network Activity"
        type_name = "network.flow"

        # Check for deny/drop
        str_repr = json.dumps(first_ev).lower()
        match_action = str(first_ev.get("action", first_ev.get("act", "access")))
        if "deny" in str_repr or "drop" in str_repr or "block" in str_repr:
            action_val = "deny"
            category = "SECURITY"
            class_name = "Firewall"
            type_name = "firewall.deny"
        elif "alert" in str_repr or "attack" in str_repr or "threat" in str_repr:
            action_val = "alert"
            category = "SECURITY"
            class_name = "Intrusion Detection"
            type_name = "ids.alert"

        candidate_mapping = {
            "schema_version": "1.0.0",
            "mapping_id": f"{vendor.lower()}.{product.lower()}.{action_val}",
            "version": "1.0.0",
            "vendor": vendor,
            "product": product,
            "priority": 150,
            "confidence": 0.88,
            "lifecycle_state": "DRAFT",
            "provenance": "AI_SUGGESTED",
            "match": {
                "vendor": vendor,
                "product": product,
                "conditions": [{"field": "action", "op": "equals", "value": match_action}],
            },
            "semantic": {
                "category": category,
                "class": class_name,
                "type": type_name,
                "action": action_val,
                "result": "DENIED" if action_val == "deny" else "UNKNOWN",
            },
            "metadata": {
                "suggested_by": self.provider_id,
                "model_version": self.model_version,
            },
        }

        conf_breakdown = AIConfidenceBreakdown(
            rule_match_strength=0.85,
            schema_match_strength=0.90,
            evidence_strength=0.88,
            model_confidence=0.88,
            composite_confidence=0.88,
        )

        return AISuggestion(
            suggestion_id=s_id,
            provider_id=self.provider_id,
            model_version=self.model_version,
            candidate_mapping=candidate_mapping,
            confidence_breakdown=conf_breakdown,
            evidence=[f"keyword_analysis:action={action_val}", f"vendor_hint:{vendor}"],
            uncertainties=["Requires human review to verify policy semantics."],
            explanation=(
                f"Deterministically inferred {category} {class_name} mapping based on "
                f"'{action_val}' action keyword."
            ),
            requires_human_review=True,
            input_sample_hash=sample_hash,
        )

    def explain_suggestion(self, candidate_mapping: dict[str, Any]) -> str:
        """Provide detailed human rationale for candidate mapping."""
        m_id = candidate_mapping.get("mapping_id", "unknown")
        sem = candidate_mapping.get("semantic", {})
        return (
            f"Mapping '{m_id}' maps events to canonical {sem.get('category')}:{sem.get('class')} "
            f"({sem.get('type')}). Rule was derived using offline deterministic field analysis."
        )
