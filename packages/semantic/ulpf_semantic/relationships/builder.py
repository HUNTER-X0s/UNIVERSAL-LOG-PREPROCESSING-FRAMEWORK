"""Deterministic Entity Relationship Builder for ULPF Phase 4.

Builds directed graph edges between entities where supported by concrete
telemetry evidence.
"""

from typing import Any

from ulpf_semantic.models import Entity, EntityRelationship, EntityType


class RelationshipBuilder:
    """Constructs verifiable relationship edges between extracted entities."""

    @staticmethod
    def build_relationships(
        entities: list[Entity],
        uce_event: dict[str, Any],
        action: str,
    ) -> list[EntityRelationship]:
        """Infer deterministic entity relationships from extracted entities and event context."""
        relationships: list[EntityRelationship] = []

        # Find entities by type/role
        src_ips = [
            e for e in entities if e.entity_type == EntityType.IP.value and e.role == "source"
        ]
        dst_ips = [
            e for e in entities if e.entity_type == EntityType.IP.value and e.role == "destination"
        ]
        users = [e for e in entities if e.entity_type == EntityType.USER.value]
        hosts = [e for e in entities if e.entity_type == EntityType.HOST.value]
        cloud_res = [e for e in entities if e.entity_type == EntityType.CLOUD_RESOURCE.value]

        # 1. Network communication edge: Source IP -> communicated_with -> Destination IP
        if src_ips and dst_ips:
            for s in src_ips:
                for d in dst_ips:
                    rel_id = f"rel:net:{s.value}->{d.value}"
                    predicate = (
                        "communicated_with"
                        if action in ("allow", "accept")
                        else "attempted_connection_to"
                    )
                    relationships.append(
                        EntityRelationship(
                            relationship_id=rel_id,
                            subject=s.entity_id,
                            predicate=predicate,
                            object_ref=d.entity_id,
                            confidence=0.95,
                            provenance="DERIVED",
                        )
                    )

        # 2. Authentication / Access edge: User -> authenticated_to -> Host
        if users and hosts:
            for u in users:
                for h in hosts:
                    rel_id = f"rel:auth:{u.value}->{h.value}"
                    relationships.append(
                        EntityRelationship(
                            relationship_id=rel_id,
                            subject=u.entity_id,
                            predicate="accessed_host",
                            object_ref=h.entity_id,
                            confidence=0.90,
                            provenance="DERIVED",
                        )
                    )

        # 3. Cloud principal edge: User -> invoked -> Cloud Resource
        if users and cloud_res:
            for u in users:
                for cr in cloud_res:
                    rel_id = f"rel:cloud:{u.value}->{cr.value[:32]}"
                    relationships.append(
                        EntityRelationship(
                            relationship_id=rel_id,
                            subject=u.entity_id,
                            predicate="invoked_resource",
                            object_ref=cr.entity_id,
                            confidence=0.90,
                            provenance="DERIVED",
                        )
                    )

        return relationships
