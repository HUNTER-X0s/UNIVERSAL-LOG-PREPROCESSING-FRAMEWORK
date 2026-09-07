"""Phase 10 — Mission Operations Plane REST API routes.

Provides endpoints for:
- Security posture & risk trends
- Pre-incident early-warning intelligence
- Multi-source signal fusion
- Detection coverage matrix, gap analysis & source reliability
- Purple-team attack scenario validation harness & analytical differentials
- Response playbook dry-run simulations
- Offline AI analyst copilot summaries with prompt injection defense
- 12-subsystem operational health state machine
- Measured SLA metrics (MTTD/MTTA/MTTR, latency distributions)
- Mission pipeline execution & deterministic simulation
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field
from ulpf_mission.copilot.advisor import AIAnalystCopilot
from ulpf_mission.coverage.gap_analyzer import DetectionGapAnalyzer
from ulpf_mission.coverage.matrix import DetectionCoverageMatrix
from ulpf_mission.coverage.reliability import SourceReliabilityCalculator
from ulpf_mission.cross_domain.analytics import CrossDomainAnalytics
from ulpf_mission.early_warning.engine import EarlyWarningEngine
from ulpf_mission.fusion.engine import SignalFusionEngine
from ulpf_mission.health.model import MissionHealthModel
from ulpf_mission.metrics.sla import OperationalMetricsTracker
from ulpf_mission.orchestration.pipeline import MissionAnalysisPipeline
from ulpf_mission.playbooks.engine import ResponsePlaybookEngine
from ulpf_mission.posture.engine import RiskTrendAnalytics, SecurityPostureEngine
from ulpf_mission.replay.lab import ReplayLab
from ulpf_mission.scenarios.definitions import ALL_SCENARIOS
from ulpf_mission.scenarios.differential import AnalyticalDifferentialEngine
from ulpf_mission.scenarios.harness import DetectionValidationHarness
from ulpf_mission.simulation.engine import MissionSimulationEngine

router = APIRouter(prefix="/mission", tags=["mission"])

# ---------------------------------------------------------------------------
# In-process singletons for Mission Plane
# ---------------------------------------------------------------------------
_health_model = MissionHealthModel()
_health_model.mark_all_healthy()
_posture_engine = SecurityPostureEngine()
_trend_analytics = RiskTrendAnalytics()
_early_warning_engine = EarlyWarningEngine()
_fusion_engine = SignalFusionEngine()
_cross_domain = CrossDomainAnalytics()
_coverage_matrix = DetectionCoverageMatrix()
_gap_analyzer = DetectionGapAnalyzer()
_reliability_calc = SourceReliabilityCalculator()
_scenario_harness = DetectionValidationHarness()
_differential_engine = AnalyticalDifferentialEngine()
_copilot = AIAnalystCopilot()
_playbook_engine = ResponsePlaybookEngine()
_metrics_tracker = OperationalMetricsTracker()
_replay_lab = ReplayLab()
_sim_engine = MissionSimulationEngine()
_pipeline = MissionAnalysisPipeline(
    health_model=_health_model,
    posture_engine=_posture_engine,
    early_warning_engine=_early_warning_engine,
    fusion_engine=_fusion_engine,
    cross_domain_analytics=_cross_domain,
    coverage_matrix=_coverage_matrix,
    gap_analyzer=_gap_analyzer,
    copilot=_copilot,
    playbook_engine=_playbook_engine,
    metrics_tracker=_metrics_tracker,
)


def _require_role(required: set[str], role_header: str | None) -> str:
    """Enforce RBAC for mission endpoints."""
    role = role_header or "viewer"
    if role not in required and "platform-admin" not in role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires one of: {sorted(required)}, caller has: {role}",
        )
    return role


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class PostureCalculateRequest(BaseModel):
    critical_alert_count: int = Field(0, ge=0)
    active_campaign_count: int = Field(0, ge=0)
    anomaly_event_count: int = Field(0, ge=0)
    total_event_count: int = Field(1, ge=1)
    ti_match_count: int = Field(0, ge=0)
    unhealthy_source_fraction: float = Field(0.0, ge=0.0, le=1.0)


class SignalFusionRequest(BaseModel):
    entity_id: str = Field(..., description="Target entity ID (host, user, ip)")
    entity_type: str = Field("host", description="Entity type: host, user, ip, service")
    raw_signals: list[dict[str, Any]] = Field(..., description="List of raw signals to fuse")


class PlaybookDryRunRequest(BaseModel):
    parameters: dict[str, Any] = Field(default_factory=dict)
    user_permissions: list[str] = Field(
        default_factory=lambda: ["firewall:write", "ad:write", "edr:isolate", "notification:send"]
    )


class CopilotSummaryRequest(BaseModel):
    case_id: str = Field(..., description="Case identifier")
    severity: str = Field("HIGH", description="Incident severity: CRITICAL, HIGH, MEDIUM, LOW")
    description: str = Field(..., description="Case description")
    affected_assets: list[str] = Field(default_factory=list)
    involved_users: list[str] = Field(default_factory=list)
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)
    detection_rule_ids: list[str] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)


class PipelineRunRequest(BaseModel):
    events: list[dict[str, Any]] = Field(..., description="Events to process through pipeline")


class SimulationRunRequest(BaseModel):
    attack_type: str = Field("BRUTE_FORCE", description="Attack scenario type to simulate")
    event_count: int = Field(
        50, ge=5, le=500, description="Total events including background noise"
    )
    noise_ratio: float = Field(
        0.7, ge=0.0, le=0.95, description="Fraction of events that are benign noise"
    )
    seed: int = Field(42, description="RNG seed for deterministic generation")


# ---------------------------------------------------------------------------
# Mission REST Endpoints
# ---------------------------------------------------------------------------

@router.get("/health", summary="12-subsystem unified health state")
def get_mission_health(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Retrieve current operational health status across all 12 platform subsystems."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    report = _health_model.report()
    return {
        "status": report.overall_state.value,
        "healthy_count": report.healthy_count,
        "degraded_count": report.degraded_count,
        "failed_count": report.failed_count,
        "subsystems": [
            {
                "subsystem": s.subsystem,
                "state": s.state.value,
                "latency_ms": s.latency_ms,
                "throughput_eps": s.throughput_eps,
                "error_message": s.error_message,
                "last_checked": s.last_checked,
            }
            for s in report.subsystems
        ],
    }


@router.get("/posture", summary="Current security posture and risk state")
def get_security_posture(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Get current security posture score, level, and factor breakdown."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    state = _posture_engine.calculate(
        critical_alert_count=2,
        active_campaign_count=1,
        anomaly_event_count=15,
        total_event_count=1000,
        ti_match_count=4,
        unhealthy_source_fraction=0.0,
    )
    return {
        "level": state.level.value,
        "risk_score": state.risk_score,
        "rationale": state.rationale,
        "recommendations": state.recommendations,
        "factors": {
            "critical_alert": state.critical_alert_factor,
            "campaign_volume": state.campaign_volume_factor,
            "anomaly_rate": state.anomaly_rate_factor,
            "ti_match": state.ti_match_factor,
            "source_health": state.source_health_factor,
        },
        "is_urgent": state.is_urgent,
        "timestamp": state.timestamp,
    }


@router.post("/posture/calculate", summary="Calculate custom security posture")
def calculate_security_posture(
    body: PostureCalculateRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Compute security posture from explicit input counters."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    state = _posture_engine.calculate(
        critical_alert_count=body.critical_alert_count,
        active_campaign_count=body.active_campaign_count,
        anomaly_event_count=body.anomaly_event_count,
        total_event_count=body.total_event_count,
        ti_match_count=body.ti_match_count,
        unhealthy_source_fraction=body.unhealthy_source_fraction,
    )
    return {
        "level": state.level.value,
        "risk_score": state.risk_score,
        "rationale": state.rationale,
        "recommendations": state.recommendations,
        "is_urgent": state.is_urgent,
    }


@router.get("/early-warning", summary="Pre-incident threat acceleration early warning")
def get_early_warning(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Evaluate pre-incident threat acceleration indicators."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    assessment = _early_warning_engine.analyze(
        current_failure_rate=0.18,
        baseline_failure_rate=0.04,
        current_source_count=42,
        baseline_source_count=12,
        current_dest_count=8,
        baseline_dest_count=6,
        current_ti_velocity=5,
        baseline_ti_velocity=1,
        current_anomaly_count=14,
        baseline_anomaly_count=3,
        privilege_escalation_events=2,
        baseline_priv_events=0,
        lateral_movement_events=1,
        baseline_lateral_events=0,
    )
    return {
        "threat_acceleration_detected": assessment.threat_acceleration_detected,
        "threat_level": assessment.threat_level,
        "acceleration_factor": assessment.acceleration_factor,
        "rationale": assessment.rationale,
        "signal_count": len(assessment.signals),
        "signals": [
            {
                "indicator_type": s.indicator_type.value,
                "observed_value": s.observed_value,
                "baseline_value": s.baseline_value,
                "ratio": s.ratio,
                "confidence": s.confidence,
                "rationale": s.rationale,
            }
            for s in assessment.signals
        ],
    }


@router.post("/fusion", summary="Multi-source evidence signal fusion")
def fuse_signals(
    body: SignalFusionRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Fuse multiple detection signals into a unified entity risk score."""
    _require_role({"mission:execute", "mission:write", "platform-admin"}, x_role)
    fused = _fusion_engine.fuse(
        entity_id=body.entity_id,
        entity_type=body.entity_type,
        raw_signals=body.raw_signals,
    )
    return {
        "entity_id": fused.entity_id,
        "entity_type": fused.entity_type,
        "fused_risk_score": fused.fused_risk_score,
        "confidence": fused.confidence,
        "is_high_risk": fused.is_high_risk,
        "rationale": fused.rationale,
        "contributions": [
            {
                "source": c.source.value,
                "weight": c.weight,
                "raw_risk": c.raw_risk,
                "confidence": c.confidence,
                "description": c.description,
            }
            for c in fused.contributions
        ],
    }


@router.get("/coverage", summary="Detection coverage matrix across MITRE ATT&CK tactics")
def get_coverage_matrix(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Return MITRE ATT&CK tactics coverage matrix for active log sources."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    report = _coverage_matrix.generate_report()
    return {
        "overall_coverage_pct": report.overall_coverage_pct,
        "total_cells": report.total_cells,
        "covered_cells": report.covered_cells,
        "partially_covered_cells": report.partially_covered_cells,
        "uncovered_cells": report.uncovered_cells,
        "sources": report.sources,
        "tactics": report.tactics,
        "matrix": report.matrix,
    }


@router.get("/coverage/gaps", summary="Detection gap analysis and recommendations")
def get_coverage_gaps(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Analyze coverage matrix for detection blind spots and generate recommendations."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    cov_report = _coverage_matrix.generate_report()
    gap_report = _gap_analyzer.analyze(cov_report)
    return {
        "critical_gaps": gap_report.critical_gaps,
        "high_gaps": gap_report.high_gaps,
        "medium_gaps": gap_report.medium_gaps,
        "recommendations": gap_report.recommendations,
        "gaps": [
            {
                "tactic": g.tactic,
                "source_type": g.source_type,
                "severity": g.severity,
                "impact": g.impact,
                "remediation": g.remediation,
            }
            for g in gap_report.gaps
        ],
    }


@router.get("/scenarios", summary="List standard purple-team attack scenarios")
def list_scenarios(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """List all registered deterministic purple-team attack scenarios."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    return {
        "count": len(ALL_SCENARIOS),
        "scenarios": [
            {
                "scenario_id": s.scenario_id,
                "name": s.name,
                "description": s.description,
                "mitre_technique": s.mitre_technique,
                "step_count": len(s.steps),
                "expected_min_score": s.expected_min_score,
            }
            for s in ALL_SCENARIOS
        ],
    }


@router.post(
    "/scenarios/{scenario_id}/validate",
    summary="Execute purple-team scenario validation harness",
)
def validate_scenario(
    scenario_id: str,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Inject synthetic scenario events and validate detection effectiveness."""
    _require_role({"mission:execute", "mission:write", "platform-admin"}, x_role)
    scenario = next((s for s in ALL_SCENARIOS if s.scenario_id == scenario_id), None)
    if not scenario:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Scenario '{scenario_id}' not found. "
                f"Available: {[s.scenario_id for s in ALL_SCENARIOS]}"
            ),
        )

    result = _scenario_harness.run_scenario(scenario)
    return {
        "scenario_id": result.scenario_id,
        "scenario_name": result.scenario_name,
        "status": result.status.value,
        "detection_rate": result.detection_rate,
        "max_risk_score": result.max_risk_score,
        "duration_ms": result.duration_ms,
        "failure_reasons": result.failure_reasons,
        "step_results": [
            {
                "step_number": st.step_number,
                "name": st.step_name,
                "fired": st.detection_fired,
                "matched_rules": st.matched_rule_ids,
                "risk_score": st.risk_score,
            }
            for st in result.step_results
        ],
    }


@router.post("/playbooks/{playbook_id}/dry-run", summary="Simulate playbook in safe dry-run mode")
def dry_run_playbook(
    playbook_id: str,
    body: PlaybookDryRunRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Simulate execution of an automated response playbook without state mutation."""
    _require_role({"mission:execute", "mission:write", "platform-admin"}, x_role)
    result = _playbook_engine.dry_run(
        playbook_id,
        user_permissions=body.user_permissions,
        parameters=body.parameters,
    )
    return {
        "playbook_id": result.playbook_id,
        "playbook_name": result.playbook_name,
        "status": result.status.value,
        "steps_simulated": result.steps_simulated,
        "blocking_issues": result.blocking_issues,
        "projected_impact": result.projected_impact,
        "dry_run_timestamp": result.dry_run_timestamp,
        "step_results": [
            {
                "step_id": s.step_id,
                "name": s.name,
                "type": s.step_type.value,
                "status": s.status.value,
                "action": s.action,
                "impact": s.projected_impact,
                "error": s.error_message,
            }
            for s in result.step_results
        ],
    }


@router.post("/copilot/summary", summary="AI Analyst Copilot structured case summary")
def get_copilot_summary(
    body: CopilotSummaryRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Generate 5W case summary and hunt queries with prompt injection defense."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    summary = _copilot.summarise_case(
        case_id=body.case_id,
        severity=body.severity,
        description=body.description,
        affected_assets=body.affected_assets,
        involved_users=body.involved_users,
        timeline_events=body.timeline_events,
        detection_rule_ids=body.detection_rule_ids,
        kill_chain_phases=body.kill_chain_phases,
    )
    return {
        "case_id": summary.case_id,
        "severity": summary.severity,
        "what": summary.what,
        "when": summary.when,
        "where": summary.where,
        "who": summary.who,
        "why": summary.why,
        "recommended_actions": summary.recommended_actions,
        "hunt_queries": summary.hunt_queries,
        "confidence_note": summary.confidence_note,
        "data_limitations": summary.data_limitations,
    }


@router.get("/metrics", summary="Operational SLA metrics")
def get_sla_metrics(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Return measured operational SLA metrics (MTTD/MTTA/MTTR, latency percentiles)."""
    _require_role({"mission:read", "viewer", "platform-admin"}, x_role)
    snap = _metrics_tracker.snapshot()
    return {
        "mttd_s": snap.mttd_s,
        "mtta_s": snap.mtta_s,
        "mttr_s": snap.mttr_s,
        "timestamp": snap.timestamp,
        "ingest_latency": {
            "p50_ms": snap.ingest_latency.p50_ms if snap.ingest_latency else 0.0,
            "p95_ms": snap.ingest_latency.p95_ms if snap.ingest_latency else 0.0,
            "p99_ms": snap.ingest_latency.p99_ms if snap.ingest_latency else 0.0,
            "samples": snap.ingest_latency.sample_count if snap.ingest_latency else 0,
        },
        "detection_latency": {
            "p50_ms": snap.detection_latency.p50_ms if snap.detection_latency else 0.0,
            "p95_ms": snap.detection_latency.p95_ms if snap.detection_latency else 0.0,
            "p99_ms": snap.detection_latency.p99_ms if snap.detection_latency else 0.0,
            "samples": snap.detection_latency.sample_count if snap.detection_latency else 0,
        },
    }


@router.post("/pipeline/run", summary="Execute end-to-end Mission Analysis Pipeline")
def run_pipeline(
    body: PipelineRunRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Execute end-to-end telemetry ingestion and multi-factor intelligence pipeline."""
    _require_role({"mission:execute", "mission:write", "platform-admin"}, x_role)
    result = _pipeline.run(body.events)
    return {
        "total_events": result.total_events,
        "processed_events": result.processed_events,
        "failed_events": result.failed_events,
        "operational_state": result.operational_state.value,
        "posture": {
            "level": result.posture.level.value,
            "risk_score": result.posture.risk_score,
            "rationale": result.posture.rationale,
        },
        "early_warning": {
            "threat_acceleration_detected": (
                result.early_warning.threat_acceleration_detected
                if result.early_warning else False
            ),
            "threat_level": result.early_warning.threat_level if result.early_warning else "LOW",
        },
        "fused_signals_count": len(result.fused_signals),
        "stage_errors": result.stage_errors,
        "execution_duration_ms": result.execution_duration_ms,
    }


@router.post("/simulation/run", summary="Generate deterministic simulation dataset")
def run_simulation(
    body: SimulationRunRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Generate deterministic synthetic telemetry with labeled attack & benign noise events."""
    _require_role({"mission:execute", "mission:write", "platform-admin"}, x_role)
    sim_run = _sim_engine.generate(
        attack_type=body.attack_type,
        event_count=body.event_count,
        noise_ratio=body.noise_ratio,
        seed=body.seed,
    )
    return {
        "run_id": sim_run.run_id,
        "attack_type": sim_run.attack_type,
        "total_events": sim_run.total_events,
        "attack_events": sim_run.attack_events,
        "benign_events": sim_run.benign_events,
        "seed": sim_run.seed,
        "sample_events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "is_attack": e.is_attack,
                "source": e.source,
                "payload": e.payload,
            }
            for e in sim_run.events[:10]
        ],
    }
