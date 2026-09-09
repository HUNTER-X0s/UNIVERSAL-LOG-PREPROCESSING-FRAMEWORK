"""ULPF Phase 14 — Investigation Context Graph & Case Workflow Governance.

Fulfills Phase 14 Workstreams Z, AA, and AB:
- Investigation context object linking cases, alerts, entities, evidence, and notes
- 7-state case workflow: NEW, TRIAGED, INVESTIGATING, CONTAINMENT_RECOMMENDED,
  RESOLVED, CLOSED, REOPENED
- Audited analyst collaboration and evidence annotations
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CaseState(str, Enum):
    """The 7 explicit lifecycle states for a security case."""

    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


@dataclass(frozen=True)
class AnalystAnnotation:
    """Immutable analyst note or evidence tag."""

    annotation_id: str
    author: str
    target_type: str  # "EVENT", "ENTITY", "EVIDENCE", "CASE"
    target_id: str
    content: str
    timestamp: str


@dataclass
class InvestigationContext:
    """Coherent operational context object for incident investigation."""

    case_id: str
    title: str
    severity: str                   # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    state: CaseState = CaseState.NEW
    assigned_analyst: str = "unassigned"
    created_at: str = ""
    updated_at: str = ""
    entities: set[str] = field(default_factory=set)
    alert_ids: list[str] = field(default_factory=list)
    raw_evidence_ids: list[str] = field(default_factory=list)
    annotations: list[AnalystAnnotation] = field(default_factory=list)
    mitre_techniques: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "severity": self.severity,
            "state": self.state.value,
            "assigned_analyst": self.assigned_analyst,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "entities": sorted(self.entities),
            "alert_ids": self.alert_ids,
            "raw_evidence_ids": self.raw_evidence_ids,
            "annotation_count": len(self.annotations),
            "mitre_techniques": sorted(self.mitre_techniques),
        }


class CaseWorkflowManager:
    """Governs case state transitions with auditable authorization."""

    ALLOWED_CASE_TRANSITIONS: dict[CaseState, set[CaseState]] = {
        CaseState.NEW: {CaseState.TRIAGED, CaseState.CLOSED},
        CaseState.TRIAGED: {CaseState.INVESTIGATING, CaseState.CLOSED},
        CaseState.INVESTIGATING: {CaseState.CONTAINMENT_RECOMMENDED, CaseState.RESOLVED, CaseState.CLOSED},
        CaseState.CONTAINMENT_RECOMMENDED: {CaseState.INVESTIGATING, CaseState.RESOLVED, CaseState.CLOSED},
        CaseState.RESOLVED: {CaseState.CLOSED, CaseState.REOPENED},
        CaseState.CLOSED: {CaseState.REOPENED},
        CaseState.REOPENED: {CaseState.INVESTIGATING, CaseState.CLOSED},
    }

    def __init__(self) -> None:
        self.cases: dict[str, InvestigationContext] = {}
        self.transition_log: list[dict[str, Any]] = []

    def create_case(
        self,
        case_id: str,
        title: str,
        severity: str,
        analyst: str = "unassigned",
        entities: list[str] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> InvestigationContext:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ctx = InvestigationContext(
            case_id=case_id,
            title=title,
            severity=severity,
            state=CaseState.NEW,
            assigned_analyst=analyst,
            created_at=now,
            updated_at=now,
            entities=set(entities or []),
            raw_evidence_ids=list(evidence_ids or []),
        )
        self.cases[case_id] = ctx
        return ctx

    def transition_state(
        self,
        case_id: str,
        target_state: CaseState,
        actor: str,
        rationale: str,
    ) -> bool:
        ctx = self.cases.get(case_id)
        if not ctx:
            raise KeyError(f"Case '{case_id}' does not exist")

        current = ctx.state
        if target_state not in self.ALLOWED_CASE_TRANSITIONS[current]:
            raise ValueError(f"Disallowed case transition: {current.value} -> {target_state.value}")

        ctx.state = target_state
        ctx.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        self.transition_log.append({
            "case_id": case_id,
            "from_state": current.value,
            "to_state": target_state.value,
            "actor": actor,
            "rationale": rationale,
            "timestamp": ctx.updated_at,
        })
        return True

    def add_annotation(
        self,
        case_id: str,
        author: str,
        target_type: str,
        target_id: str,
        content: str,
    ) -> AnalystAnnotation:
        ctx = self.cases.get(case_id)
        if not ctx:
            raise KeyError(f"Case '{case_id}' does not exist")

        ann_id = f"ANN-{len(ctx.annotations)+1:03d}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ann = AnalystAnnotation(
            annotation_id=ann_id,
            author=author,
            target_type=target_type,
            target_id=target_id,
            content=content,
            timestamp=now,
        )
        ctx.annotations.append(ann)
        ctx.updated_at = now
        return ann
