"""Phase 9 — Advanced Security Analytics Plane REST API routes.

Provides endpoints for:
- Local threat intelligence feed ingestion and indicator lookup
- Alert triage classification
- Alert deduplication groups and flood control status
- SOC operational overview (real data only, no fabrication)
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from ulpf_advanced_intelligence.models.threat_intel import (
    ObservableType,
    ThreatIntelConfidence,
    ThreatIntelIndicator,
    ThreatIntelLifecycleState,
    ThreatIntelStatus,
)
from ulpf_advanced_intelligence.threat_intel.lifecycle import ThreatIntelLifecycleManager
from ulpf_advanced_intelligence.ti_matching.engine import ThreatIntelMatchingEngine
from ulpf_advanced_intelligence.triage.classifier import AlertTriageClassifier
from ulpf_advanced_intelligence.triage.deduplication import AlertDeduplicator
from ulpf_advanced_intelligence.triage.flood_control import AlertFloodController

router = APIRouter(prefix="/advanced-intelligence", tags=["advanced-intelligence"])

# ---------------------------------------------------------------------------
# Shared in-process singletons for API routes
# ---------------------------------------------------------------------------
_ti_lifecycle = ThreatIntelLifecycleManager()
_ti_engine = ThreatIntelMatchingEngine(lifecycle_manager=_ti_lifecycle)
_deduplicator = AlertDeduplicator()
_flood_controller = AlertFloodController()


def _require_role(required: set[str], role_header: str | None) -> str:
    """Enforce RBAC for Phase 9 endpoints."""
    role = role_header or "viewer"
    if role not in required and "platform-admin" not in role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires one of: {sorted(required)}, caller has: {role}",
        )
    return role


# ---------------------------------------------------------------------------
# Pydantic Request / Response Models
# ---------------------------------------------------------------------------


class IngestIndicatorRequest(BaseModel):
    type: str = Field(..., description="Observable type: IPV4, DOMAIN, HASH, URL, etc.")
    normalized_value: str = Field(..., description="Normalized observable value")
    source: str = Field(..., description="Intelligence feed source name")
    source_version: str = Field("1.0.0")
    status: str = Field("OBSERVED")
    lifecycle_state: str = Field("ACTIVE")
    description: str = Field("")
    tags: list[str] = Field(default_factory=list)
    tenant_id: str | None = Field(None)
    confidence_source: float = Field(0.8, ge=0.0, le=1.0)
    confidence_indicator: float = Field(0.8, ge=0.0, le=1.0)
    risk_contribution: float = Field(25.0, ge=0.0, le=100.0)


class MatchEventRequest(BaseModel):
    event: dict[str, Any] = Field(..., description="Event dictionary to scan against TI")
    tenant_id: str | None = Field(None)


class TriageClassifyRequest(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0)
    has_critical_ti: bool = False
    asset_criticality: str = "MEDIUM"
    is_external_facing: bool = False
    is_multi_stage: bool = False


class FloodCheckRequest(BaseModel):
    source_id: str
    tenant_id: str | None = None


class SOCOverviewResponse(BaseModel):
    active_indicators: int
    alert_dedup_groups: int
    flood_control_rate_1m: int
    flood_control_total_suppressed: int
    last_updated: str
    tenant_id: str | None


# ---------------------------------------------------------------------------
# Threat Intelligence Endpoints
# ---------------------------------------------------------------------------


@router.post("/ti/indicators", summary="Ingest a local TI indicator")
def ingest_indicator(
    body: IngestIndicatorRequest,
    x_role: str | None = Header(None),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Ingest a Threat Intelligence indicator from a local feed and register it in the lifecycle manager."""
    _require_role({"intelligence:write", "platform-admin"}, x_role)
    tenant_id = body.tenant_id or x_tenant_id

    try:
        obs_type = ObservableType(body.type.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown observable type: {body.type}") from None

    try:
        ti_status = ThreatIntelStatus(body.status.upper())
        lifecycle_state = ThreatIntelLifecycleState(body.lifecycle_state.upper())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    indicator_id = f"ind-{uuid.uuid4().hex[:12]}"
    confidence = ThreatIntelConfidence(
        source_confidence=body.confidence_source,
        indicator_confidence=body.confidence_indicator,
        match_confidence=1.0,
        risk_contribution=body.risk_contribution,
    )
    indicator = ThreatIntelIndicator(
        indicator_id=indicator_id,
        type=obs_type,
        normalized_value=body.normalized_value.lower().strip(),
        source=body.source,
        source_version=body.source_version,
        confidence=confidence,
        status=ti_status,
        lifecycle_state=lifecycle_state,
        description=body.description,
        tags=tuple(body.tags),
        tenant_id=tenant_id,
        created_at=datetime.now(UTC).isoformat(),
    )
    _ti_lifecycle.register_indicator(indicator)

    # If lifecycle_state is ACTIVE, also activate (builds lookup index)
    if lifecycle_state == ThreatIntelLifecycleState.ACTIVE:
        with contextlib.suppress(Exception):
            _ti_lifecycle.activate_indicator(indicator_id)

    return {"indicator_id": indicator_id, "integrity_hash": indicator.integrity_hash, "status": "REGISTERED"}


@router.get("/ti/indicators/{indicator_id}", summary="Get a specific TI indicator")
def get_indicator(
    indicator_id: str,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Retrieve a specific threat intelligence indicator by ID."""
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)
    indicator = _ti_lifecycle.get_indicator(indicator_id)
    if not indicator:
        raise HTTPException(status_code=404, detail=f"Indicator not found: {indicator_id}")
    return indicator.to_dict()


@router.post("/ti/indicators/{indicator_id}/activate", summary="Activate a TI indicator")
def activate_indicator(
    indicator_id: str,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Promote a registered TI indicator to ACTIVE lifecycle state."""
    _require_role({"intelligence:write", "platform-admin"}, x_role)
    try:
        updated = _ti_lifecycle.activate_indicator(indicator_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"indicator_id": indicator_id, "lifecycle_state": updated.lifecycle_state.value, "status": "ACTIVATED"}


@router.post("/ti/indicators/{indicator_id}/revoke", summary="Revoke a TI indicator")
def revoke_indicator(
    indicator_id: str,
    reason: str = Query(""),
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Revoke a TI indicator immediately, removing it from active matching."""
    _require_role({"intelligence:write", "platform-admin"}, x_role)
    try:
        updated = _ti_lifecycle.revoke_indicator(indicator_id, reason=reason)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"indicator_id": indicator_id, "lifecycle_state": updated.lifecycle_state.value, "status": "REVOKED"}


@router.get("/ti/stats", summary="TI engine statistics")
def ti_stats(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Get current threat intelligence engine statistics."""
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)
    return {
        "active_indicator_count": _ti_lifecycle.get_active_count(),
        "provenance": "LOCAL_OFFLINE_TI_ENGINE",
    }


@router.post("/ti/match", summary="Match an event against local TI")
def match_event(
    body: MatchEventRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Scan an event's observable fields against active local TI indicators (deterministic, non-blocking)."""
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)
    assessment = _ti_engine.match_event(body.event, tenant_id=body.tenant_id)
    return assessment.to_dict()


# ---------------------------------------------------------------------------
# Alert Triage Endpoints
# ---------------------------------------------------------------------------


@router.post("/alerts/triage/classify", summary="Classify alert triage severity")
def classify_alert(
    body: TriageClassifyRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Apply deterministic multi-factor triage classification to produce an explainable severity tier."""
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)
    severity, reason = AlertTriageClassifier.classify(
        risk_score=body.risk_score,
        has_critical_ti=body.has_critical_ti,
        asset_criticality=body.asset_criticality,
        is_external_facing=body.is_external_facing,
        is_multi_stage=body.is_multi_stage,
    )
    return {
        "severity": severity.value,
        "triage_reason": reason,
        "risk_score": body.risk_score,
        "factors": {
            "has_critical_ti": body.has_critical_ti,
            "asset_criticality": body.asset_criticality,
            "is_external_facing": body.is_external_facing,
            "is_multi_stage": body.is_multi_stage,
        },
    }


@router.post("/alerts/flood-control/check", summary="Check flood control allowance")
def flood_check(
    body: FloodCheckRequest,
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Check whether the alert flood controller permits the next alert from this source."""
    _require_role({"intelligence:write", "platform-admin"}, x_role)
    allowed, status_msg = _flood_controller.allow_alert()
    stats = _flood_controller.get_stats()
    return {
        "source_id": body.source_id,
        "allowed": allowed,
        "status": status_msg,
        "stats": stats,
    }


@router.get("/alerts/flood-control/stats", summary="Flood control statistics")
def flood_stats(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Return the current sliding-window alert flood control statistics."""
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)
    return _flood_controller.get_stats()


@router.get("/alerts/dedup/stats", summary="Alert deduplication statistics")
def dedup_stats(
    x_role: str | None = Header(None),
) -> dict[str, Any]:
    """Return alert deduplication group statistics."""
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)
    with _deduplicator._lock:  # noqa: SLF001
        group_count = len(_deduplicator._groups)  # noqa: SLF001
        alert_count = len(_deduplicator._primary_alerts)  # noqa: SLF001
    return {
        "dedup_group_count": group_count,
        "primary_alert_count": alert_count,
    }


# ---------------------------------------------------------------------------
# SOC Operational Overview
# ---------------------------------------------------------------------------


@router.get("/soc/overview", summary="Real-time SOC operational overview", response_model=SOCOverviewResponse)
def soc_overview(
    tenant_id: str | None = Query(None),
    x_role: str | None = Header(None),
) -> SOCOverviewResponse:
    """Provide a real-time SOC operational overview backed exclusively by live engine state.
    No fabricated, interpolated, or synthesized metrics are returned.
    """
    _require_role({"intelligence:read", "intelligence:write", "platform-admin"}, x_role)

    active_count = _ti_lifecycle.get_active_count()
    with _deduplicator._lock:  # noqa: SLF001
        group_count = len(_deduplicator._groups)  # noqa: SLF001
    flood_stats = _flood_controller.get_stats()

    return SOCOverviewResponse(
        active_indicators=active_count,
        alert_dedup_groups=group_count,
        flood_control_rate_1m=flood_stats["current_rate_1m"],
        flood_control_total_suppressed=flood_stats["total_suppressed"],
        last_updated=datetime.now(UTC).isoformat(),
        tenant_id=tenant_id,
    )
