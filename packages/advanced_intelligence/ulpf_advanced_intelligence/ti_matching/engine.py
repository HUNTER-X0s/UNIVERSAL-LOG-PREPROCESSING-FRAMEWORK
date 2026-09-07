"""Deterministic, Non-Blocking Offline Threat Intelligence Matching Engine for ULPF Phase 9."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from ulpf_advanced_intelligence.models.threat_intel import (
    ObservableType,
    ThreatIntelAssessment,
    ThreatIntelIndicator,
    ThreatIntelLifecycleState,
    ThreatIntelMatch,
    ThreatIntelStatus,
)
from ulpf_advanced_intelligence.threat_intel.lifecycle import ThreatIntelLifecycleManager

logger = logging.getLogger("ulpf.ti_matching")

_FIELD_TO_OBSERVABLE: dict[str, list[ObservableType]] = {
    "src_ip": [ObservableType.IPV4, ObservableType.IPV6],
    "dst_ip": [ObservableType.IPV4, ObservableType.IPV6],
    "source_ip": [ObservableType.IPV4, ObservableType.IPV6],
    "destination_ip": [ObservableType.IPV4, ObservableType.IPV6],
    "ip": [ObservableType.IPV4, ObservableType.IPV6],
    "domain": [ObservableType.DOMAIN],
    "hostname": [ObservableType.HOSTNAME, ObservableType.DOMAIN],
    "url": [ObservableType.URL, ObservableType.URI],
    "hash": [ObservableType.HASH],
    "file_hash": [ObservableType.HASH],
    "sha256": [ObservableType.HASH],
    "md5": [ObservableType.HASH],
    "email": [ObservableType.EMAIL],
}


class ThreatIntelMatchingEngine:
    """Performs deterministic offline matching of extracted observables against active local TI."""

    def __init__(self, lifecycle_manager: ThreatIntelLifecycleManager | None = None) -> None:
        self.lifecycle_manager = lifecycle_manager or ThreatIntelLifecycleManager()

    def match_event(
        self,
        event: dict[str, Any],
        tenant_id: str | None = None,
    ) -> ThreatIntelAssessment:
        """Scan event dictionary for candidate observables and match against active indicators.

        Guaranteed non-blocking: any parsing or matching anomaly logs a warning and returns an empty assessment.
        """
        matches: list[ThreatIntelMatch] = []
        try:
            event_id = str(event.get("event_id") or event.get("id") or "unknown-event")
            now_iso = datetime.now(UTC).isoformat()
            t_id = tenant_id or event.get("tenant_id")

            # Extract potential observables from top-level and nested attributes
            extracted: list[tuple[ObservableType, str]] = self._extract_observables(event)

            for obs_type, val in extracted:
                indicator = self._lookup_indicator(obs_type, val, t_id)
                if indicator and indicator.lifecycle_state == ThreatIntelLifecycleState.ACTIVE:
                    if indicator.is_valid_at(now_iso):
                        # Construct audit-linked match
                        match_type = "EXACT" if val == indicator.normalized_value else "NORMALIZED"
                        match_obj = ThreatIntelMatch(
                            event_id=event_id,
                            indicator_id=indicator.indicator_id,
                            match_type=match_type,
                            matched_value=val,
                            source=indicator.source,
                            confidence=indicator.confidence.indicator_confidence,
                            timestamp=now_iso,
                            tenant_id=t_id,
                            indicator_status=indicator.status,
                            risk_contribution=indicator.confidence.risk_contribution,
                        )
                        matches.append(match_obj)

            total_risk = min(100.0, sum(m.risk_contribution for m in matches))
            highest_sev = ThreatIntelStatus.UNKNOWN
            if matches:
                status_precedence = [
                    ThreatIntelStatus.MALICIOUS,
                    ThreatIntelStatus.BLOCKED,
                    ThreatIntelStatus.SUSPICIOUS,
                    ThreatIntelStatus.OBSERVED,
                    ThreatIntelStatus.ALLOWLISTED,
                    ThreatIntelStatus.UNKNOWN,
                ]
                for p in status_precedence:
                    if any(m.indicator_status == p for m in matches):
                        highest_sev = p
                        break

            return ThreatIntelAssessment(
                matches=tuple(matches),
                total_risk_contribution=total_risk,
                highest_severity_status=highest_sev,
            )
        except Exception as exc:
            logger.warning("Threat intelligence matching encountered non-blocking error: %s", exc)
            return ThreatIntelAssessment()

    def _extract_observables(self, event: dict[str, Any]) -> list[tuple[ObservableType, str]]:
        observables: list[tuple[ObservableType, str]] = []
        for key, types in _FIELD_TO_OBSERVABLE.items():
            val = event.get(key)
            if val is not None:
                str_val = str(val).strip()
                if str_val:
                    for t in types:
                        observables.append((t, str_val))

        # Check nested payload/event_body if present
        body = event.get("event_body") or event.get("payload")
        if isinstance(body, dict):
            for key, types in _FIELD_TO_OBSERVABLE.items():
                val = body.get(key)
                if val is not None:
                    str_val = str(val).strip()
                    if str_val:
                        for t in types:
                            observables.append((t, str_val))

        return observables

    def _lookup_indicator(
        self,
        obs_type: ObservableType,
        val: str,
        tenant_id: str | None,
    ) -> ThreatIntelIndicator | None:
        key = (obs_type.value, val.lower(), tenant_id)
        ind_id = self.lifecycle_manager._lookup.get(key)
        if not ind_id and tenant_id is not None:
            # Fallback to global tenant-agnostic feed
            key_global = (obs_type.value, val.lower(), None)
            ind_id = self.lifecycle_manager._lookup.get(key_global)

        if ind_id:
            return self.lifecycle_manager.get_indicator(ind_id)
        return None
