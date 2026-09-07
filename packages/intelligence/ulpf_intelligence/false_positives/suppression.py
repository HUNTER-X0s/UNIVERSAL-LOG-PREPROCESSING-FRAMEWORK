"""Auditable False Positive Suppression Engine for ULPF Phase 8."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.events import SuppressionRecord


class SuppressionEngine:
    """Evaluates detections against auditable suppression rules and known-good allowlists."""

    def __init__(self) -> None:
        # suppression_id -> SuppressionRecord
        self._suppressions: dict[str, SuppressionRecord] = {}
        # known_good_entities: set of "entity_type:value"
        self._known_good: set[str] = set()
        self._lock = threading.Lock()

    def add_suppression(
        self,
        reason: str = "",
        created_by: str = "secops",
        rule_id: str | None = None,
        target_entity: str | None = None,
        expires_at: str | None = None,
        tenant_id: str | None = None,
        author: str | None = None,
        conditions: dict[str, Any] | None = None,
    ) -> SuppressionRecord:
        """Add an auditable suppression rule."""
        rec = SuppressionRecord(
            suppression_id=f"sup-{uuid.uuid4().hex[:12]}",
            reason=reason,
            created_by=author or created_by,
            created_at=datetime.now(UTC).isoformat(),
            expires_at=expires_at,
            rule_id=rule_id,
            target_entity=target_entity,
            tenant_id=tenant_id,
            conditions=conditions or {},
        )
        with self._lock:
            self._suppressions[rec.suppression_id] = rec
            return rec

    def add_known_good_entity(self, entity_str: str) -> None:
        with self._lock:
            self._known_good.add(entity_str.lower().strip())

    def is_suppressed(
        self,
        rule_id: str,
        entities: tuple[str, ...] | str | None = None,
        tenant_id: str | None = None,
        event_payload: dict[str, Any] | None = None,
    ) -> tuple[bool, Any]:
        """Check if a detection is suppressed by active rule or allowlisted entity."""
        now_iso = datetime.now(UTC).isoformat()

        # Normalize if called as is_suppressed(rule_id="..", tenant_id="..", event_payload={...})
        if isinstance(entities, str) and tenant_id is None and event_payload is None:
            # Shifted args
            tenant_id = entities
            entities = ()
        elif isinstance(entities, dict):
            event_payload = entities
            entities = ()

        ents = tuple(entities or ())

        with self._lock:
            # Check known-good allowlist
            for ent in ents:
                if ent.lower().strip() in self._known_good:
                    return True, f"Entity '{ent}' is present in known-good allowlist"

            # Check active suppressions
            for sup in self._suppressions.values():
                if sup.expires_at and sup.expires_at < now_iso:
                    continue  # Expired

                if sup.tenant_id is not None and tenant_id is not None and sup.tenant_id != tenant_id:
                    continue  # Tenant mismatch

                # Match rule_id if specified
                rule_match = (sup.rule_id is None) or (sup.rule_id == rule_id)

                # Match target_entity if specified
                entity_match = (sup.target_entity is None) or any(
                    sup.target_entity.lower() in e.lower() for e in ents
                )

                # Match condition payload if specified
                payload_match = True
                if sup.conditions and event_payload:
                    for k, v in sup.conditions.items():
                        if str(event_payload.get(k, "")).lower() != str(v).lower():
                            payload_match = False
                            break
                elif sup.conditions and not event_payload:
                    payload_match = False

                if rule_match and entity_match and payload_match:
                    object.__setattr__(sup, "hit_count", sup.hit_count + 1)
                    return True, sup

        return False, None
