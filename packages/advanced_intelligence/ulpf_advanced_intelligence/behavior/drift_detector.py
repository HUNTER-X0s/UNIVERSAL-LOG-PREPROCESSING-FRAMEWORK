"""Baseline Drift Detection and Analyst Reset Controller for ULPF Phase 9."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from ulpf_advanced_intelligence.errors import BaselineDriftError
from ulpf_advanced_intelligence.models.behavior import (
    BaselineDriftState,
    EntityBehaviorProfile,
)


class BaselineDriftDetector:
    """Monitors entity behavior over sliding inspection windows to detect baseline drift."""

    @classmethod
    def evaluate_drift(
        cls,
        profile: EntityBehaviorProfile,
        recent_events: Sequence[dict[str, Any]],
        divergence_threshold: float = 0.45,
    ) -> EntityBehaviorProfile:
        """Measure divergence between baseline action frequencies and recent activity."""
        if not recent_events or not profile.baseline_frequencies:
            return profile

        recent_counts: dict[str, int] = {}
        for ev in recent_events:
            action = str(ev.get("action") or ev.get("category") or "EVENT").upper()
            recent_counts[action] = recent_counts.get(action, 0) + 1

        total = float(len(recent_events))
        recent_freqs = {k: v / total for k, v in recent_counts.items()}

        # Compute total variation distance / frequency divergence
        all_actions = set(profile.baseline_frequencies.keys()) | set(recent_freqs.keys())
        divergence = 0.5 * sum(abs(profile.baseline_frequencies.get(a, 0.0) - recent_freqs.get(a, 0.0)) for a in all_actions)

        new_state = BaselineDriftState.STABLE
        if divergence >= divergence_threshold * 1.5:
            new_state = BaselineDriftState.RESET_REQUIRED
        elif divergence >= divergence_threshold:
            new_state = BaselineDriftState.CHANGED
        elif divergence >= divergence_threshold * 0.5:
            new_state = BaselineDriftState.DRIFTING

        now_iso = datetime.now(UTC).isoformat()
        return dataclasses.replace(profile, drift_state=new_state, updated_at=now_iso)

    @classmethod
    def reset_baseline(
        cls,
        profile: EntityBehaviorProfile,
        approved_by: str,
        new_training_events: Sequence[dict[str, Any]],
    ) -> EntityBehaviorProfile:
        """Analyst-controlled baseline reset. Never replaces baseline automatically!"""
        if not approved_by:
            raise BaselineDriftError("Analyst approval signature required to reset baseline")

        from ulpf_advanced_intelligence.behavior.profiler import EntityBehaviorProfiler

        fresh_profile = EntityBehaviorProfiler.create_initial_profile(
            entity_id=profile.entity_id,
            entity_type=profile.entity_type,
            training_events=new_training_events,
            tenant_id=profile.tenant_id,
        )

        now_iso = datetime.now(UTC).isoformat()
        return dataclasses.replace(
            fresh_profile,
            version=profile.version + 1,
            drift_state=BaselineDriftState.STABLE,
            updated_at=now_iso,
        )
