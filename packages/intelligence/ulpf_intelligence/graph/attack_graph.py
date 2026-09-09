"""ULPF Phase 14 — Attack Path Graph, Bounded Traversal & Explainable Risk Propagation.

Fulfills Phase 14 Workstreams S, T, and U:
- Attack path graph supporting assets, accounts, processes, IPs, domains, services, detections
- Bounded traversal to prevent graph explosions and recursive DoS
- Explainable risk propagation across relationships (lateral movement, shared credentials)
- Composite attack chain confidence calculation
"""

from __future__ import annotations

import collections
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    ASSET = "ASSET"
    ACCOUNT = "ACCOUNT"
    PROCESS = "PROCESS"
    IP = "IP"
    DOMAIN = "DOMAIN"
    SERVICE = "SERVICE"
    DETECTION = "DETECTION"


class EdgeRelation(str, Enum):
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    SPAWNED = "SPAWNED"
    RESOLVED_TO = "RESOLVED_TO"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    SHARED_CREDENTIAL = "SHARED_CREDENTIAL"
    TRIGGERED = "TRIGGERED"


@dataclass
class AttackNode:
    """A verified entity node in the mission attack path graph."""

    node_id: str
    node_type: NodeType
    label: str
    base_risk: float = 0.0          # 0.0 to 100.0
    propagated_risk: float = 0.0    # 0.0 to 100.0
    evidence_ids: set[str] = field(default_factory=set)
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def total_risk(self) -> float:
        return min(100.0, round(self.base_risk + self.propagated_risk, 1))


@dataclass(frozen=True)
class AttackEdge:
    """Directed connection between two attack nodes."""

    source_node_id: str
    target_node_id: str
    relation: EdgeRelation
    confidence: float = 1.0         # 0.0 to 1.0
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    propagation_weight: float = 0.5  # Decay factor for risk


@dataclass
class PropagationAudit:
    """Audit record explaining how risk propagated between entities."""

    from_node_id: str
    to_node_id: str
    relation: str
    applied_rule: str
    source_risk: float
    added_risk: float
    confidence: float
    evidence_ids: list[str]


class AttackPathGraph:
    """In-memory directed attack graph with bounded depth traversal."""

    def __init__(self, max_nodes: int = 10_000, max_edges_per_node: int = 250) -> None:
        self.max_nodes = max_nodes
        self.max_edges_per_node = max_edges_per_node
        self.nodes: dict[str, AttackNode] = {}
        # source_node_id -> list of AttackEdge
        self.edges_out: dict[str, list[AttackEdge]] = collections.defaultdict(list)
        self.edges_in: dict[str, list[AttackEdge]] = collections.defaultdict(list)

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str,
        base_risk: float = 0.0,
        evidence_ids: list[str] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> AttackNode:
        if len(self.nodes) >= self.max_nodes and node_id not in self.nodes:
            raise OverflowError(f"Attack graph max node capacity ({self.max_nodes}) breached")

        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.base_risk = max(node.base_risk, base_risk)
            if evidence_ids:
                node.evidence_ids.update(evidence_ids)
            if properties:
                node.properties.update(properties)
            return node

        node = AttackNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            base_risk=base_risk,
            evidence_ids=set(evidence_ids or []),
            properties=properties or {},
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: EdgeRelation,
        confidence: float = 1.0,
        evidence_ids: list[str] | None = None,
        propagation_weight: float = 0.5,
    ) -> AttackEdge:
        if source_id not in self.nodes or target_id not in self.nodes:
            raise KeyError("Both source and target nodes must exist before adding edge")

        if len(self.edges_out[source_id]) >= self.max_edges_per_node:
            # Drop or bound edge to prevent fanout DoS
            return self.edges_out[source_id][0]

        edge = AttackEdge(
            source_node_id=source_id,
            target_node_id=target_id,
            relation=relation,
            confidence=confidence,
            evidence_ids=tuple(evidence_ids or []),
            propagation_weight=propagation_weight,
        )
        self.edges_out[source_id].append(edge)
        self.edges_in[target_id].append(edge)
        return edge

    def traverse_bounded(
        self,
        start_node_id: str,
        max_depth: int = 3,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Perform bounded breadth-first traversal from a starting entity."""
        if start_node_id not in self.nodes:
            return {"nodes": [], "edges": [], "truncated": False}

        visited_nodes: set[str] = set()
        collected_edges: list[AttackEdge] = []
        queue = collections.deque([(start_node_id, 0)])

        truncated = False
        while queue:
            curr_id, depth = queue.popleft()
            if curr_id in visited_nodes:
                continue
            visited_nodes.add(curr_id)

            if len(visited_nodes) >= max_results:
                truncated = True
                break

            if depth < max_depth:
                for edge in self.edges_out.get(curr_id, []):
                    collected_edges.append(edge)
                    if edge.target_node_id not in visited_nodes:
                        queue.append((edge.target_node_id, depth + 1))

        return {
            "nodes": [self.nodes[nid] for nid in visited_nodes if nid in self.nodes],
            "edges": collected_edges,
            "truncated": truncated,
            "traversal_depth": max_depth,
        }

    def propagate_risk(self, max_iterations: int = 3) -> list[PropagationAudit]:
        """Propagate risk from high-risk nodes to neighboring connected assets."""
        audits: list[PropagationAudit] = []

        for _ in range(max_iterations):
            for u_id, edges in list(self.edges_out.items()):
                u_node = self.nodes.get(u_id)
                if not u_node or u_node.total_risk < 10.0:
                    continue

                for edge in edges:
                    v_node = self.nodes.get(edge.target_node_id)
                    if not v_node:
                        continue

                    # Transferred risk = source_risk * propagation_weight * confidence
                    added = u_node.total_risk * edge.propagation_weight * edge.confidence * 0.5
                    if added > 1.0 and (v_node.propagated_risk + added) <= 100.0:
                        v_node.propagated_risk = round(v_node.propagated_risk + added, 1)
                        audits.append(
                            PropagationAudit(
                                from_node_id=u_id,
                                to_node_id=edge.target_node_id,
                                relation=edge.relation.value,
                                applied_rule=f"GraphRiskPropagation({edge.relation.value})",
                                source_risk=u_node.total_risk,
                                added_risk=added,
                                confidence=edge.confidence,
                                evidence_ids=list(edge.evidence_ids),
                            )
                        )
        return audits


class AttackChainConfidenceScorer:
    """Computes a multi-dimensional confidence score for attack stories."""

    @classmethod
    def calculate_confidence(
        cls,
        event_confidences: list[float],
        temporal_coherence: float,   # 0.0 to 1.0 (temporal consistency of progression)
        evidence_count: int,         # number of distinct raw evidence items
        cross_source_count: int,     # number of distinct sources confirming the attack
    ) -> float:
        if not event_confidences:
            return 0.0

        mean_event_conf = sum(event_confidences) / len(event_confidences)
        # Evidence density bonus: 1-2 items = 0.0, 3-5 = +0.1, 6+ = +0.15
        density_bonus = min(0.15, max(0.0, (evidence_count - 1) * 0.03))
        # Multi-source corroboration bonus: >=2 sources = +0.10
        source_bonus = 0.10 if cross_source_count >= 2 else 0.0

        base = (mean_event_conf * 0.5) + (temporal_coherence * 0.25) + density_bonus + source_bonus
        return min(1.0, max(0.1, round(base, 2)))
