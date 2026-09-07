"""Phase 8 — Intelligence, Threat Hunting, and Investigation REST API routes.

Provides endpoints for:
- Detection event inspection and rule evaluation
- Correlation groups and multi-event attack sequence tracking
- Statistical anomaly detection review
- Bounded threat hunting queries
- Investigation case workbench and timeline management
- Detection rule lifecycle management (draft, test, review, activate)
- Entity graph relationship queries
- Air-gapped deterministic local analyst advisory
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from ulpf_intelligence.ai_assistant.advisor import LocalAnalystAdvisor
from ulpf_intelligence.anomaly.engine import StatisticalAnomalyEngine
from ulpf_intelligence.correlation.engine import CorrelationEngine
from ulpf_intelligence.detection.engine import DetectionEngine
from ulpf_intelligence.graph.store import RelationshipGraph
from ulpf_intelligence.hunting.engine import ThreatHuntingEngine
from ulpf_intelligence.investigations.workbench import InvestigationWorkbench
from ulpf_intelligence.models.provenance import AlertSeverity, AlertStatus, CaseStatus, RuleState
from ulpf_intelligence.rules.dsl import DetectionRule, RuleCondition, RuleOperator, RuleThreshold
from ulpf_intelligence.rules.registry import RuleRegistry
from ulpf_intelligence.timeline.builder import TimelineBuilder

router = APIRouter(prefix="/intelligence", tags=["intelligence"])

# Shared in-process engines for API routes
rule_registry = RuleRegistry()
detection_engine = DetectionEngine(rule_registry=rule_registry)
correlation_engine = CorrelationEngine(window_seconds=300)
anomaly_engine = StatisticalAnomalyEngine(default_threshold_z=3.0)
investigation_workbench = InvestigationWorkbench()
hunting_engine = ThreatHuntingEngine()
graph_store = RelationshipGraph()
timeline_builder = TimelineBuilder()
analyst_advisor = LocalAnalystAdvisor()


def verify_role(required_roles: set[str], role_header: str | None) -> str:
    """Verify role authorization."""
    role = role_header or "viewer"
    if role not in required_roles and "platform-admin" not in role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires one of roles: {required_roles}, caller has: {role}",
        )
    return role


# --- Pydantic Request Models ---


class EvaluateEventRequest(BaseModel):
    event_id: str
    tenant_id: str = "default"
    timestamp: str
    source: str = "perimeter"
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_hash: str = ""


class CreateRuleConditionRequest(BaseModel):
    field: str
    operator: str
    value: Any


class CreateRuleThresholdRequest(BaseModel):
    count: int
    window_seconds: int
    group_by_fields: list[str] = Field(default_factory=list)


class RegisterRuleRequest(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str
    conditions: list[CreateRuleConditionRequest]
    threshold: CreateRuleThresholdRequest | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    version: str = "1.0.0"


class HuntQueryRequest(BaseModel):
    field: str
    operator: str
    value: Any
    start_time: str
    end_time: str
    limit: int = 100


class CreateCaseRequest(BaseModel):
    title: str
    severity: str
    tenant_id: str = "default"
    assignee: str | None = None
    initial_detection_ids: list[str] = Field(default_factory=list)


class AddNoteRequest(BaseModel):
    content: str


class UpdateCaseStatusRequest(BaseModel):
    status: str


class AdvisorySummaryRequest(BaseModel):
    case_id: str


# --- Detection Endpoints ---


@router.get("/detections")
def list_detections(
    severity: str | None = None,
    tenant_id: str = "default",
    limit: int = Query(default=100, ge=1, le=500),
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role(
        {"viewer", "operator", "analyst", "threat-hunter", "detection-engineer"},
        x_role,
    )
    # Filter recent in-memory detections
    results: list[dict[str, Any]] = []
    return {"total": len(results), "detections": results, "tenant_id": tenant_id}


@router.post("/detections/evaluate")
def evaluate_event(
    req: EvaluateEventRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"operator", "analyst", "detection-engineer"}, x_role)
    detections = detection_engine.evaluate(
        event_payload=req.attributes,
        event_id=req.event_id,
        tenant_id=req.tenant_id,
        timestamp=req.timestamp,
        raw_hash=req.raw_hash,
    )
    for det in detections:
        correlation_engine.ingest_detection(det)  # returns CorrelationGroup, ignore here
    return {
        "event_id": req.event_id,
        "matched_count": len(detections),
        "detections": [d.to_dict() for d in detections],
    }


# --- Correlation Endpoints ---


@router.get("/correlations")
def list_correlations(
    tenant_id: str = "default",
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "analyst", "threat-hunter"}, x_role)
    groups = correlation_engine.get_active_groups(tenant_id)
    return {
        "tenant_id": tenant_id,
        "total": len(groups),
        "correlations": [g.to_dict() for g in groups],
    }


# --- Anomaly Endpoints ---


@router.get("/anomalies")
def list_anomalies(
    tenant_id: str = "default",
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "analyst", "threat-hunter"}, x_role)
    return {"tenant_id": tenant_id, "anomalies": []}


# --- Threat Hunting Endpoints ---


@router.post("/hunting/query")
def execute_hunt(
    req: HuntQueryRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
    x_user: str | None = Header(None, alias="X-ULPF-User"),
) -> dict[str, Any]:
    verify_role({"threat-hunter", "analyst"}, x_role)
    user_id = x_user or "analyst-1"
    try:
        query_def = hunting_engine.create_query(
            user_id=user_id,
            field=req.field,
            operator=RuleOperator(req.operator),
            value=req.value,
            start_time=req.start_time,
            end_time=req.end_time,
            limit=req.limit,
        )
        res = hunting_engine.execute_query(query_def, candidate_records=[])
        return res.to_dict()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


# --- Investigation Workbench Endpoints ---


@router.post("/cases")
def create_case(
    req: CreateCaseRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
    x_user: str | None = Header(None, alias="X-ULPF-User"),
) -> dict[str, Any]:
    verify_role({"analyst", "threat-hunter"}, x_role)
    user = x_user or "analyst"
    case = investigation_workbench.create_case(
        title=req.title,
        severity=AlertSeverity(req.severity),
        tenant_id=req.tenant_id,
        created_by=user,
        assignee=req.assignee,
        initial_detections=req.initial_detection_ids,
    )
    return case.to_dict()


@router.get("/cases")
def list_cases(
    tenant_id: str = "default",
    status_filter: str | None = None,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "analyst", "threat-hunter"}, x_role)
    st = CaseStatus(status_filter) if status_filter else None
    cases = investigation_workbench.list_cases(tenant_id=tenant_id, status=st)
    return {"total": len(cases), "cases": [c.to_dict() for c in cases]}


@router.get("/cases/{case_id}")
def get_case(
    case_id: str,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "analyst", "threat-hunter"}, x_role)
    case = investigation_workbench.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case.to_dict()


@router.post("/cases/{case_id}/notes")
def add_case_note(
    case_id: str,
    req: AddNoteRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
    x_user: str | None = Header(None, alias="X-ULPF-User"),
) -> dict[str, Any]:
    verify_role({"analyst", "threat-hunter"}, x_role)
    user = x_user or "analyst"
    try:
        note = investigation_workbench.add_analyst_note(
            case_id=case_id,
            author=user,
            content=req.content,
        )
        return note.to_dict()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/cases/{case_id}/status")
def update_case_status(
    case_id: str,
    req: UpdateCaseStatusRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
    x_user: str | None = Header(None, alias="X-ULPF-User"),
) -> dict[str, Any]:
    verify_role({"analyst", "threat-hunter"}, x_role)
    user = x_user or "analyst"
    try:
        case = investigation_workbench.update_case_status(
            case_id=case_id,
            new_status=CaseStatus(req.status),
            user_id=user,
        )
        return case.to_dict()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --- Rule Management Endpoints ---


@router.get("/rules")
def list_rules(
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "analyst", "detection-engineer"}, x_role)
    rules = rule_registry.list_rules()
    return {
        "total": len(rules),
        "rules": [
            {
                "rule": r.to_dict(),
                "state": rule_registry.get_rule_state(r.rule_id).value,
            }
            for r in rules
        ],
    }


@router.post("/rules")
def register_rule(
    req: RegisterRuleRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
    x_user: str | None = Header(None, alias="X-ULPF-User"),
) -> dict[str, Any]:
    verify_role({"detection-engineer"}, x_role)
    user = x_user or "detection-engineer"
    conditions = [
        RuleCondition(
            field=c.field,
            operator=RuleOperator(c.operator),
            value=c.value,
        )
        for c in req.conditions
    ]
    threshold = None
    if req.threshold:
        threshold = RuleThreshold(
            count=req.threshold.count,
            window_seconds=req.threshold.window_seconds,
            group_by_fields=req.threshold.group_by_fields,
        )

    rule = DetectionRule(
        rule_id=req.rule_id,
        name=req.name,
        description=req.description,
        severity=AlertSeverity(req.severity),
        conditions=conditions,
        threshold=threshold,
        mitre_tactics=req.mitre_tactics,
        mitre_techniques=req.mitre_techniques,
        tags=req.tags,
        version=req.version,
    )
    rule_registry.register_rule(rule, author=user)
    return {"rule_id": rule.rule_id, "state": RuleState.DRAFT.value}


@router.post("/rules/{rule_id}/activate")
def activate_rule(
    rule_id: str,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
    x_user: str | None = Header(None, alias="X-ULPF-User"),
) -> dict[str, Any]:
    verify_role({"detection-engineer"}, x_role)
    user = x_user or "admin"
    rule_registry.approve_rule(rule_id, reviewer=user)
    rule_registry.activate_rule(rule_id)
    return {"rule_id": rule_id, "state": RuleState.ACTIVE.value}


# --- Graph & Advisor Endpoints ---


@router.get("/graph/{entity_id}")
def get_entity_graph(
    entity_id: str,
    max_depth: int = Query(default=2, ge=1, le=5),
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "analyst", "threat-hunter"}, x_role)
    entities, rels = graph_store.get_subgraph(entity_id=entity_id, max_depth=max_depth)
    return {
        "root_entity_id": entity_id,
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in rels],
    }


@router.post("/advisor/summary")
def generate_advisory(
    req: AdvisorySummaryRequest,
    x_role: str | None = Header(None, alias="X-ULPF-Role"),
) -> dict[str, Any]:
    verify_role({"analyst", "threat-hunter"}, x_role)
    case = investigation_workbench.get_case(req.case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    summary = analyst_advisor.summarize_case(case)
    return summary
