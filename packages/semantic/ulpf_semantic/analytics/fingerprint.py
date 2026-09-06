"""Deterministic Event Fingerprinting and Equivalence Keys for ULPF Phase 4.

Provides stable event hashing and deduplication keys based strictly on immutable
semantic and header attributes.
"""

import hashlib
from typing import Any

from ulpf_semantic.models import CorrelationContext, Entity, EntityType, SemanticTriple


class EventFingerprinter:
    """Generates deterministic hashes and correlation contexts for events."""

    @staticmethod
    def build_correlation_context(
        triple: SemanticTriple,
        action: str,
        result_status: str,
        entities: list[Entity],
        uce_event: dict[str, Any],
    ) -> CorrelationContext:
        """Construct deterministic equivalence key and fingerprint."""
        event_body = uce_event.get("event", {})
        net = event_body.get("network", {})
        proto = str(net.get("protocol", "")).upper()

        src_ip: str | None = None
        dst_ip: str | None = None
        user: str | None = None
        host: str | None = None

        for ent in entities:
            if ent.entity_type == EntityType.IP.value:
                if ent.role == "source" and not src_ip:
                    src_ip = ent.normalized_value or ent.value
                elif ent.role == "destination" and not dst_ip:
                    dst_ip = ent.normalized_value or ent.value
            elif ent.entity_type == EntityType.USER.value and not user:
                user = ent.normalized_value or ent.value
            elif ent.entity_type == EntityType.HOST.value and not host:
                host = ent.normalized_value or ent.value

        unmapped = uce_event.get("unmapped_fields", {})
        session_id = unmapped.get("session_id") or unmapped.get("sessionid") or unmapped.get("uid")
        trace_id = unmapped.get("trace_id") or unmapped.get("traceId")
        span_id = unmapped.get("span_id") or unmapped.get("spanId")

        # Equivalence key: coarse grouping for correlation/dedup
        equiv_components = [
            triple.type_name,
            action,
            result_status,
            src_ip or "-",
            dst_ip or "-",
            proto or "-",
            user or "-",
        ]
        equiv_raw = "|".join(equiv_components)
        equiv_key = f"eq:{hashlib.sha256(equiv_raw.encode('utf-8')).hexdigest()[:16]}"

        # Event fingerprint: stable unique semantic hash
        fp_components = [
            triple.category,
            triple.class_name,
            triple.type_name,
            action,
            result_status,
            src_ip or "",
            dst_ip or "",
            proto or "",
            user or "",
            host or "",
            str(session_id or ""),
        ]
        fp_raw = "|".join(fp_components)
        event_fp = f"fp:{hashlib.sha256(fp_raw.encode('utf-8')).hexdigest()}"

        return CorrelationContext(
            equivalence_key=equiv_key,
            event_fingerprint=event_fp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            user=user,
            host=host,
            session_id=str(session_id) if session_id else None,
            trace_id=str(trace_id) if trace_id else None,
            span_id=str(span_id) if span_id else None,
        )
