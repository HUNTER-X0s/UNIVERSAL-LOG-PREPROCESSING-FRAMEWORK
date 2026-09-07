"""Relationship Graph Abstraction for ULPF Phase 8."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_intelligence.errors import GraphDepthExceededError
from ulpf_intelligence.models.events import EntityRecord, EntityRelationship
from ulpf_intelligence.models.provenance import IntelligenceProvenance


class RelationshipGraph:
    """In-memory graph representing directional, evidence-linked relationships between entities."""

    def __init__(self, max_traversal_depth: int = 5, max_visited_nodes: int = 1000) -> None:
        self.max_traversal_depth = max_traversal_depth
        self.max_visited_nodes = max_visited_nodes
        # entity_id -> EntityRecord
        self._nodes: dict[str, EntityRecord] = {}
        # source_id -> list of EntityRelationship
        self._out_edges: dict[str, list[EntityRelationship]] = {}
        # target_id -> list of EntityRelationship
        self._in_edges: dict[str, list[EntityRelationship]] = {}
        # relationship_id -> EntityRelationship
        self._edges: dict[str, EntityRelationship] = {}
        self._lock = threading.Lock()

    def add_node(self, entity: EntityRecord) -> None:
        with self._lock:
            self._nodes[entity.entity_id] = entity

    def add_entity(self, entity: EntityRecord) -> None:
        """Convenience alias for add_node."""
        self.add_node(entity)

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relation_type: str | None = None,
        confidence: float = 1.0,
        weight: float = 1.0,
        source_event_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        relationship_type: str | None = None,
    ) -> EntityRelationship:
        """Add or update an evidence-based directional edge between two entities."""
        r_type = relationship_type or relation_type or "RELATED_TO"
        now_iso = datetime.now(UTC).isoformat()
        rel_id = f"rel-{uuid.uuid4().hex[:12]}"
        events = (source_event_id,) if source_event_id else ()
        meta = {**(metadata or {}), "weight": weight}

        rel = EntityRelationship(
            relationship_id=rel_id,
            source_entity_id=source_id,
            target_entity_id=target_id,
            relation_type=r_type,
            confidence=confidence,
            first_observed=now_iso,
            last_observed=now_iso,
            source_event_ids=events,
            provenance=IntelligenceProvenance.DERIVED,
            metadata=meta,
        )

        with self._lock:
            self._edges[rel_id] = rel
            self._out_edges.setdefault(source_id, []).append(rel)
            self._in_edges.setdefault(target_id, []).append(rel)
            return rel

    def get_neighbors(
        self,
        entity_id: str,
        direction: str = "both",
    ) -> list[tuple[EntityRelationship, str]]:
        """Return (relationship, neighbor_id) pairs for an entity."""
        with self._lock:
            results: list[tuple[EntityRelationship, str]] = []
            if direction in ("out", "both"):
                for edge in self._out_edges.get(entity_id, []):
                    results.append((edge, edge.target_entity_id))
            if direction in ("in", "both"):
                for edge in self._in_edges.get(entity_id, []):
                    results.append((edge, edge.source_entity_id))
            return results

    def get_subgraph(
        self,
        entity_id: str,
        max_depth: int = 2,
    ) -> tuple[list[EntityRecord], list[EntityRelationship]]:
        """Convenience method returning (nodes, edges) tuple."""
        res = self.get_connected_subgraph(entity_id, max_depth=max_depth)
        return res["nodes"], res["edges"]

    def get_connected_subgraph(
        self,
        start_entity_id: str,
        max_depth: int | None = None,
    ) -> dict[str, Any]:
        """Perform bounded BFS traversal from start_entity_id, returning nodes and edges."""
        if max_depth is not None and max_depth > self.max_traversal_depth:
            raise GraphDepthExceededError(
                f"Requested depth {max_depth} exceeds maximum allowable {self.max_traversal_depth}"
            )
        depth_limit = max_depth or self.max_traversal_depth

        with self._lock:
            visited_nodes: set[str] = {start_entity_id}
            included_edges: list[EntityRelationship] = []
            queue: list[tuple[str, int]] = [(start_entity_id, 0)]

            while queue:
                curr_id, curr_depth = queue.pop(0)
                if curr_depth >= depth_limit:
                    continue

                # Explore out edges
                for edge in self._out_edges.get(curr_id, []):
                    target = edge.target_entity_id
                    included_edges.append(edge)
                    if target not in visited_nodes:
                        if len(visited_nodes) >= self.max_visited_nodes:
                            raise GraphDepthExceededError(
                                f"Graph traversal exceeded node limit of {self.max_visited_nodes}"
                            )
                        visited_nodes.add(target)
                        queue.append((target, curr_depth + 1))

                # Explore in edges
                for edge in self._in_edges.get(curr_id, []):
                    source = edge.source_entity_id
                    included_edges.append(edge)
                    if source not in visited_nodes:
                        if len(visited_nodes) >= self.max_visited_nodes:
                            raise GraphDepthExceededError(
                                f"Graph traversal exceeded node limit of {self.max_visited_nodes}"
                            )
                        visited_nodes.add(source)
                        queue.append((source, curr_depth + 1))

            # Retrieve node records
            nodes = [self._nodes[nid] for nid in visited_nodes if nid in self._nodes]
            # Deduplicate edges by relationship_id
            unique_edges = {e.relationship_id: e for e in included_edges}

            return {
                "root_id": start_entity_id,
                "node_count": len(nodes),
                "edge_count": len(unique_edges),
                "nodes": nodes,
                "edges": list(unique_edges.values()),
            }
