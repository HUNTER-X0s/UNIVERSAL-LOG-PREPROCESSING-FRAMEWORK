"""Deterministic Semantic Event Classifier for ULPF Phase 4.

Resolves UCE telemetry into explainable (Category, Class, Type) semantic triples
with complete evidence references and confidence scoring.
"""

from typing import Any

from ulpf_semantic.explainability.trace import DecisionTraceBuilder
from ulpf_semantic.models import (
    ConfidenceLevel,
    DecisionTrace,
    SemanticConfidence,
    SemanticProvenance,
    SemanticTriple,
)
from ulpf_semantic.taxonomy.categories import EventCategory, EventClass, EventType


class SemanticClassifier:
    """Deterministic, rule-based classification engine for UCE records."""

    def __init__(self, mapping_version: str = "1.0.0", registry: Any = None) -> None:
        self.mapping_version = mapping_version
        self.mapping_id = f"ulpf.classifier:{mapping_version}"
        self.registry = registry

    def classify(
        self,
        uce_event: dict[str, Any],
        unmapped_fields: dict[str, Any] | None = None,
    ) -> tuple[SemanticTriple, SemanticConfidence, DecisionTrace]:
        """Classify a UCE event into an explainable semantic triple."""
        # 0. Check active compiled mappings from registry if present
        if self.registry is not None:
            matches = self.registry.lookup(uce_event)
            if matches:
                top_match = matches[0]
                target = top_match.semantic
                triple = SemanticTriple(
                    category=target.category,
                    class_name=target.class_name,
                    type_name=target.type_name,
                )
                conf = SemanticConfidence(
                    level=ConfidenceLevel.HIGH
                    if top_match.confidence >= 0.85
                    else ConfidenceLevel.MEDIUM,
                    score=top_match.confidence,
                    explanation=f"Compiled mapping '{top_match.mapping_id}' matched.",
                )
                prov_val = getattr(top_match.provenance, "value", str(top_match.provenance))
                prov_type = (
                    SemanticProvenance[prov_val]
                    if hasattr(SemanticProvenance, prov_val)
                    else SemanticProvenance.DERIVED
                )
                trace = DecisionTraceBuilder.build(
                    rule_id=top_match.mapping_id,
                    rule_version=top_match.version,
                    mapping_id=f"map.{top_match.mapping_id}:{top_match.version}",
                    provenance_type=prov_type,
                    evidence=(
                        f"mapping_pack:{top_match.mapping_id}",
                        f"priority:{top_match.priority}",
                    ),
                    explanation=(
                        f"Matched configuration-driven rule '{top_match.mapping_id}' "
                        f"(priority={top_match.priority})"
                    ),
                )
                return triple, conf, trace

        event_body = uce_event.get("event", {})
        meta = event_body.get("metadata", {})
        vendor = str(meta.get("vendor", "")).strip()
        product = str(meta.get("product", "")).strip()
        parser_id = str(meta.get("parser_id", "")).strip()
        category = str(event_body.get("category", "")).lower()
        ev_type = str(event_body.get("type", "")).lower()
        action = str(event_body.get("action", "")).lower()

        evidence: list[str] = []
        if vendor:
            evidence.append(f"vendor:{vendor}")
        if product:
            evidence.append(f"product:{product}")
        if parser_id:
            evidence.append(f"parser_id:{parser_id}")
        if action:
            evidence.append(f"action:{action}")
        if ev_type:
            evidence.append(f"raw_type:{ev_type}")

        # 1. Firewall / Perimeter Packet Filtering
        is_firewall = (
            "firewall" in parser_id
            or "panos" in parser_id
            or "fortigate" in parser_id
            or "cisco" in parser_id
            or "opnsense" in parser_id
            or vendor in ("Palo Alto Networks", "Fortinet", "Cisco", "OPNsense", "pfSense")
            or ev_type in ("firewall", "traffic", "filterlog")
        )

        if is_firewall:
            if action in ("deny", "drop", "reject", "block"):
                triple = SemanticTriple(
                    category=EventCategory.SECURITY.value,
                    class_name=EventClass.FIREWALL.value,
                    type_name=EventType.FIREWALL_DENY.value,
                )
                conf = SemanticConfidence(
                    level=ConfidenceLevel.EXACT,
                    score=0.99,
                    explanation=(
                        f"Firewall restrictive action '{action}' detected from "
                        f"{vendor or parser_id}"
                    ),
                )
                trace = DecisionTraceBuilder.build(
                    rule_id="rule.firewall.deny",
                    rule_version=self.mapping_version,
                    mapping_id=self.mapping_id,
                    provenance_type=SemanticProvenance.DERIVED,
                    evidence=tuple(evidence),
                    explanation=conf.explanation,
                )
                return triple, conf, trace

            # Allowed / Permitted firewall traffic
            triple = SemanticTriple(
                category=EventCategory.NETWORK.value,
                class_name=EventClass.FIREWALL.value,
                type_name=EventType.FIREWALL_ALLOW.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.HIGH,
                score=0.95,
                explanation=(
                    f"Firewall permit/forward action '{action}' detected from {vendor or parser_id}"
                ),
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.firewall.allow",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # 2. IDS / IPS Alerts
        is_ids = (
            "suricata" in parser_id
            or "snort" in parser_id
            or ev_type in ("alert", "ids", "ips")
            or "alert" in action
        )
        if is_ids:
            triple = SemanticTriple(
                category=EventCategory.SECURITY.value,
                class_name=EventClass.DETECTION_FINDING.value,
                type_name=EventType.IDS_ALERT.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.EXACT,
                score=0.98,
                explanation=f"Intrusion detection alert matched from {parser_id}",
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.ids.alert",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # 3. DNS Telemetry
        is_dns = (
            "dns" in parser_id
            or ev_type == "dns"
            or (event_body.get("destination", {}).get("port") == 53)
        )
        if is_dns:
            triple = SemanticTriple(
                category=EventCategory.NETWORK.value,
                class_name=EventClass.DNS_ACTIVITY.value,
                type_name=EventType.DNS_QUERY.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.HIGH,
                score=0.92,
                explanation="DNS telemetry matched on port 53 / DNS activity type",
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.network.dns",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # 4. Web Access & HTTP
        is_http = (
            "web.access" in parser_id
            or "w3c" in parser_id
            or ev_type in ("http", "web", "access")
            or "http" in parser_id
        )
        if is_http:
            triple = SemanticTriple(
                category=EventCategory.WEB.value,
                class_name=EventClass.HTTP_ACTIVITY.value,
                type_name=EventType.HTTP_REQUEST.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.HIGH,
                score=0.94,
                explanation=f"HTTP web access matched from {parser_id}",
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.web.http_access",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # 5. Network Flow / Connection (e.g. Zeek, VPC Flow)
        is_flow = (
            "zeek" in parser_id
            or "flow" in ev_type
            or (
                bool(event_body.get("source", {}).get("ip"))
                and bool(event_body.get("destination", {}).get("ip"))
            )
        )
        if is_flow and category in ("network", "telemetry"):
            triple = SemanticTriple(
                category=EventCategory.NETWORK.value,
                class_name=EventClass.NETWORK_ACTIVITY.value,
                type_name=EventType.NETWORK_FLOW.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.MEDIUM,
                score=0.85,
                explanation="Network IP communication flow detected",
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.network.flow",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # 6. Cloud Audit & API Calls
        is_cloud = (
            "cloud_audit" in parser_id or vendor in ("AWS", "Azure", "GCP") or "cloud" in ev_type
        )
        if is_cloud:
            triple = SemanticTriple(
                category=EventCategory.CLOUD.value,
                class_name=EventClass.CLOUD_API.value,
                type_name=EventType.CLOUD_API_CALL.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.HIGH,
                score=0.90,
                explanation=f"Cloud control plane audit event matched from {vendor or parser_id}",
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.cloud.audit",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # 7. Identity & Authentication
        is_auth = (
            "auth" in ev_type
            or "login" in action
            or "logon" in action
            or category in ("identity", "authentication")
        )
        if is_auth:
            triple = SemanticTriple(
                category=EventCategory.IDENTITY.value,
                class_name=EventClass.AUTHENTICATION.value,
                type_name=EventType.USER_AUTHENTICATION.value,
            )
            conf = SemanticConfidence(
                level=ConfidenceLevel.HIGH,
                score=0.91,
                explanation="User authentication telemetry matched",
            )
            trace = DecisionTraceBuilder.build(
                rule_id="rule.identity.authentication",
                rule_version=self.mapping_version,
                mapping_id=self.mapping_id,
                provenance_type=SemanticProvenance.DERIVED,
                evidence=tuple(evidence),
                explanation=conf.explanation,
            )
            return triple, conf, trace

        # Fallback: Generic Telemetry
        triple = SemanticTriple(
            category=EventCategory.OTHER.value,
            class_name=EventClass.UNKNOWN.value,
            type_name=EventType.GENERIC_TELEMETRY.value,
        )
        conf = SemanticConfidence(
            level=ConfidenceLevel.LOW,
            score=0.50,
            explanation=f"Generic fallback classification for category '{category}'",
        )
        trace = DecisionTraceBuilder.build(
            rule_id="rule.generic.fallback",
            rule_version=self.mapping_version,
            mapping_id=self.mapping_id,
            provenance_type=SemanticProvenance.INFERRED,
            evidence=tuple(evidence),
            explanation=conf.explanation,
        )
        return triple, conf, trace
