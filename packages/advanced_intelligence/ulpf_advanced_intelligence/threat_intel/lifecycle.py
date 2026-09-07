"""Threat Intelligence Lifecycle and Governance Manager for ULPF Phase 9."""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Sequence

from ulpf_advanced_intelligence.errors import IndicatorExpiredError, ThreatIntelValidationError
from ulpf_advanced_intelligence.models.threat_intel import (
    ThreatIntelIndicator,
    ThreatIntelLifecycleState,
)
from ulpf_advanced_intelligence.threat_intel.validator import ThreatIntelValidator


class ThreatIntelLifecycleManager:
    """Thread-safe governance lifecycle manager for indicators (DRAFT -> VALIDATED -> ACTIVE -> EXPIRED -> REVOKED)."""

    def __init__(self) -> None:
        self._indicators: dict[str, ThreatIntelIndicator] = {}
        # (type, normalized_val, tenant_id) -> list of indicator_ids
        self._lookup: dict[tuple[str, str, str | None], str] = {}
        self._history: dict[str, list[ThreatIntelIndicator]] = {}
        self._lock = threading.Lock()

    def register_indicator(self, indicator: ThreatIntelIndicator) -> ThreatIntelIndicator:
        """Register a new indicator in DRAFT or VALIDATED state."""
        ThreatIntelValidator.validate_indicator(indicator)
        with self._lock:
            self._indicators[indicator.indicator_id] = indicator
            self._history.setdefault(indicator.indicator_id, []).append(indicator)
            return indicator

    def activate_indicator(self, indicator_id: str) -> ThreatIntelIndicator:
        """Promote an indicator to ACTIVE lifecycle state if valid."""
        with self._lock:
            ind = self._indicators.get(indicator_id)
            if not ind:
                raise ThreatIntelValidationError(f"Indicator {indicator_id} not found")
            if not ind.is_valid_at():
                raise IndicatorExpiredError(f"Cannot activate expired indicator {indicator_id}")

            updated = dataclasses.replace(ind, lifecycle_state=ThreatIntelLifecycleState.ACTIVE)
            self._indicators[indicator_id] = updated
            self._history[indicator_id].append(updated)

            key = (updated.type.value, updated.normalized_value.lower(), updated.tenant_id)
            self._lookup[key] = indicator_id
            return updated

    def revoke_indicator(self, indicator_id: str, reason: str = "") -> ThreatIntelIndicator:
        """Revoke an indicator, removing it from active matching immediately."""
        with self._lock:
            ind = self._indicators.get(indicator_id)
            if not ind:
                raise ThreatIntelValidationError(f"Indicator {indicator_id} not found")

            updated = dataclasses.replace(
                ind,
                lifecycle_state=ThreatIntelLifecycleState.REVOKED,
                description=f"{ind.description} [REVOKED: {reason}]" if reason else ind.description,
            )
            self._indicators[indicator_id] = updated
            self._history[indicator_id].append(updated)

            key = (updated.type.value, updated.normalized_value.lower(), updated.tenant_id)
            if self._lookup.get(key) == indicator_id:
                del self._lookup[key]

            return updated

    def rollback_indicator(self, indicator_id: str) -> ThreatIntelIndicator:
        """Roll back an indicator to its immediate previous lifecycle revision."""
        with self._lock:
            history = self._history.get(indicator_id, [])
            if len(history) < 2:
                raise ThreatIntelValidationError(f"No prior state to rollback indicator {indicator_id}")

            history.pop()  # remove current
            previous = history[-1]
            self._indicators[indicator_id] = previous

            key = (previous.type.value, previous.normalized_value.lower(), previous.tenant_id)
            if previous.lifecycle_state == ThreatIntelLifecycleState.ACTIVE:
                self._lookup[key] = indicator_id
            elif self._lookup.get(key) == indicator_id:
                del self._lookup[key]

            return previous

    def bulk_register_and_activate(
        self,
        indicators: Sequence[ThreatIntelIndicator],
    ) -> list[ThreatIntelIndicator]:
        """Bulk register, deduplicate, and activate a batch of indicators."""
        deduped = ThreatIntelValidator.deduplicate_and_merge(indicators)
        activated: list[ThreatIntelIndicator] = []
        for ind in deduped:
            self.register_indicator(ind)
            act = self.activate_indicator(ind.indicator_id)
            activated.append(act)
        return activated

    def get_indicator(self, indicator_id: str) -> ThreatIntelIndicator | None:
        with self._lock:
            return self._indicators.get(indicator_id)

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._lookup)
