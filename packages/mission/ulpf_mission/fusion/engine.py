"""Signal fusion engine for Phase 10 — multi-source evidence combiner."""

from __future__ import annotations

import time
from typing import Any

from ulpf_mission.models.fusion import (
    FusedSignal,
    FusionAssessment,
    SignalContribution,
    SignalSource,
)


class SignalFusionEngine:
    """Combines signals from multiple ULPF subsystems into fused entity risk scores.

    Design rules:
    - No signal is discarded; every contributor is preserved in the output.
    - Weights reflect source specificity (rule match > TI > correlation > anomaly).
    - Final score is a confidence-weighted average capped at 100.
    """

    # Default source weights (sum need not be 1.0; they are used as relative weights)
    _SOURCE_WEIGHTS: dict[SignalSource, float] = {
        SignalSource.DETECTION_RULE: 1.0,
        SignalSource.THREAT_INTELLIGENCE: 0.9,
        SignalSource.CAMPAIGN_CLUSTERING: 0.8,
        SignalSource.CORRELATION_ENGINE: 0.75,
        SignalSource.BEHAVIORAL_PROFILE: 0.65,
        SignalSource.RISK_SCORING: 0.6,
        SignalSource.ANOMALY_ENGINE: 0.55,
        SignalSource.EARLY_WARNING: 0.5,
    }

    def fuse(
        self,
        entity_id: str,
        entity_type: str,
        raw_signals: list[dict[str, Any]],
    ) -> FusedSignal:
        """Fuse a list of raw signal dicts into a single FusedSignal.

        Each raw_signal dict must contain:
            source (str | SignalSource): signal origin
            signal_id (str): unique identifier
            description (str): human-readable description
            confidence (float): 0.0–1.0
            risk_score (float): 0.0–100.0

        Optional keys: evidence_ids (list[str])
        """
        contributions: list[SignalContribution] = []
        evidence: set[str] = set()

        for raw in raw_signals:
            src_val = raw.get("source", "DETECTION_RULE")
            source = SignalSource(src_val) if isinstance(src_val, str) else SignalSource(str(src_val))
            confidence = float(raw.get("confidence", 0.5))
            raw_risk = float(raw.get("risk_score", 50.0))
            weight = self._SOURCE_WEIGHTS.get(source, 0.5)

            contributions.append(
                SignalContribution(
                    source=source,
                    signal_id=str(raw.get("signal_id", "unknown")),
                    description=str(raw.get("description", "")),
                    weight=weight,
                    confidence=confidence,
                    risk_contribution=round(raw_risk, 2),
                )
            )

            evidence_ids: list[Any] = raw.get("evidence_ids") or []
            for eid in evidence_ids:
                evidence.add(str(eid))

        if not contributions:
            return FusedSignal(
                entity_id=entity_id,
                entity_type=entity_type,
                contributions=[],
                fused_risk_score=0.0,
                fused_confidence=0.0,
                primary_source=SignalSource.DETECTION_RULE,
                timestamp=time.time(),
            )

        # Weighted average risk score
        total_weight = sum(c.weight * c.confidence for c in contributions)
        if total_weight == 0.0:
            fused_risk = 0.0
        else:
            fused_risk = sum(
                c.risk_contribution * c.weight * c.confidence for c in contributions
            ) / total_weight
        fused_risk = min(100.0, round(fused_risk, 2))

        # Fused confidence: diminishing returns as more sources agree
        avg_conf = sum(c.confidence for c in contributions) / len(contributions)
        multi_source_boost = min(0.2, (len(contributions) - 1) * 0.05)
        fused_conf = round(min(1.0, avg_conf + multi_source_boost), 4)

        # Primary source = highest-weight contribution
        primary = max(contributions, key=lambda c: c.weight * c.confidence).source

        return FusedSignal(
            entity_id=entity_id,
            entity_type=entity_type,
            contributions=contributions,
            fused_risk_score=fused_risk,
            fused_confidence=fused_conf,
            primary_source=primary,
            timestamp=time.time(),
            corroborating_evidence=sorted(evidence),
        )

    def fuse_batch(
        self,
        entity_signals: dict[str, tuple[str, list[dict[str, Any]]]],
    ) -> FusionAssessment:
        """Fuse signals for multiple entities in a single batch call.

        Args:
            entity_signals: mapping of entity_id → (entity_type, [raw_signals])

        Returns:
            FusionAssessment with one FusedSignal per entity.
        """
        fused: list[FusedSignal] = []
        total_inputs = 0

        for entity_id, (entity_type, raw_signals) in entity_signals.items():
            total_inputs += len(raw_signals)
            fused.append(self.fuse(entity_id, entity_type, raw_signals))

        notes: list[str] = []
        if not fused:
            notes.append("No entity signals provided; empty assessment produced.")

        return FusionAssessment(
            fused_signals=fused,
            total_input_signals=total_inputs,
            timestamp=time.time(),
            notes=notes,
        )
