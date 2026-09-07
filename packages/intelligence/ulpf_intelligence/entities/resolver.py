"""Entity Intelligence and Alias Resolver for ULPF Phase 8."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.models.events import EntityRecord
from ulpf_intelligence.models.provenance import _ProvenanceFactory


class EntityResolver:
    """Manages canonical entity identities, alias mapping, and entity risk aggregation."""

    def __init__(self) -> None:
        # canonical_id -> EntityRecord
        self._entities: dict[str, EntityRecord] = {}
        # alias_string -> canonical_id
        self._alias_map: dict[str, str] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self,
        identifier: str,
        entity_type: str,
        tenant_id: str | None = None,
    ) -> EntityRecord:
        """Convenience alias for resolve_or_create."""
        return self.resolve_or_create(
            entity_type=entity_type,
            name=identifier,
            tenant_id=tenant_id,
        )

    def add_alias(
        self,
        canonical_id: str,
        alias: str,
        entity_type: str = "HOST",
    ) -> None:
        """Convenience alias for link_alias."""
        self.link_alias(canonical_id=canonical_id, alias_name=alias, entity_type=entity_type)

    def resolve(self, identifier: str, tenant_id: str | None = None) -> str | None:
        """Resolve identifier to canonical ID."""
        clean = identifier.strip().lower()
        with self._lock:
            for key, cid in self._alias_map.items():
                if ":" in key:
                    _, val = key.split(":", 1)
                    if val == clean:
                        return cid
                if key == clean:
                    return cid
            if identifier in self._entities:
                return identifier
        return None

    def resolve_or_create(
        self,
        entity_type: str,
        name: str,
        first_seen: str | None = None,
        tenant_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> EntityRecord:
        """Deterministically resolve an entity name or alias to its canonical record."""
        clean_name = name.strip()
        alias_key = f"{entity_type.upper()}:{clean_name.lower()}"
        now_iso = datetime.now(UTC).isoformat()
        ts = first_seen or now_iso

        with self._lock:
            canonical_id = self._alias_map.get(alias_key)

            if canonical_id and canonical_id in self._entities:
                existing = self._entities[canonical_id]
                # Update last seen timestamp
                updated = EntityRecord(
                    entity_id=existing.entity_id,
                    entity_type=existing.entity_type,
                    canonical_name=existing.canonical_name,
                    aliases=existing.aliases,
                    first_seen=existing.first_seen,
                    last_seen=now_iso,
                    risk_score=existing.risk_score,
                    confidence=existing.confidence,
                    tenant_id=existing.tenant_id,
                    provenance=existing.provenance,
                    attributes={**existing.attributes, **(attributes or {})},
                )
                self._entities[canonical_id] = updated
                return updated

            # Create new canonical record
            new_id = f"{entity_type.lower()}:{clean_name}"
            record = EntityRecord(
                entity_id=new_id,
                entity_type=entity_type.upper(),
                canonical_name=clean_name,
                aliases=(clean_name,),
                first_seen=ts,
                last_seen=ts,
                risk_score=0.0,
                confidence=1.0,
                tenant_id=tenant_id,
                provenance=_ProvenanceFactory.DERIVED,
                attributes=attributes or {},
            )
            self._entities[new_id] = record
            self._alias_map[alias_key] = new_id
            return record

    def link_alias(self, canonical_id: str, alias_name: str, entity_type: str) -> None:
        """Link an additional alias (e.g. hostname) to an existing canonical entity."""
        alias_key = f"{entity_type.upper()}:{alias_name.strip().lower()}"
        with self._lock:
            if canonical_id not in self._entities:
                return

            existing = self._entities[canonical_id]
            if alias_name not in existing.aliases:
                new_aliases = (*existing.aliases, alias_name.strip())
                self._entities[canonical_id] = EntityRecord(
                    entity_id=existing.entity_id,
                    entity_type=existing.entity_type,
                    canonical_name=existing.canonical_name,
                    aliases=new_aliases,
                    first_seen=existing.first_seen,
                    last_seen=existing.last_seen,
                    risk_score=existing.risk_score,
                    confidence=existing.confidence,
                    tenant_id=existing.tenant_id,
                    provenance=existing.provenance,
                    attributes=existing.attributes,
                )
            self._alias_map[alias_key] = canonical_id

    def update_risk(self, canonical_id: str, new_risk: float) -> None:
        """Update risk score for an entity."""
        with self._lock:
            existing = self._entities.get(canonical_id)
            if existing:
                self._entities[canonical_id] = EntityRecord(
                    entity_id=existing.entity_id,
                    entity_type=existing.entity_type,
                    canonical_name=existing.canonical_name,
                    aliases=existing.aliases,
                    first_seen=existing.first_seen,
                    last_seen=existing.last_seen,
                    risk_score=round(max(existing.risk_score, new_risk), 2),
                    confidence=existing.confidence,
                    tenant_id=existing.tenant_id,
                    provenance=existing.provenance,
                    attributes=existing.attributes,
                )

    def get_entity(self, canonical_id: str) -> EntityRecord | None:
        with self._lock:
            return self._entities.get(canonical_id)

    def get_all_entities(self, tenant_id: str | None = None) -> list[EntityRecord]:
        with self._lock:
            if tenant_id:
                return [e for e in self._entities.values() if e.tenant_id == tenant_id]
            return list(self._entities.values())
