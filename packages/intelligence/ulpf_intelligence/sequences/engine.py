"""Attack Sequence and Kill-Chain Progression Engine for ULPF Phase 8."""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime

from ulpf_intelligence.models.events import AttackSequence, DetectionEvent
from ulpf_intelligence.models.provenance import SequenceConfidence

# Standard Kill Chain Stage Ordering
STANDARD_ATTACK_STAGES = (
    "RECONNAISSANCE",
    "SCANNING",
    "INITIAL_ACCESS",
    "AUTH_ANOMALY",
    "EXECUTION",
    "PRIVILEGE_ESCALATION",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
)

# MITRE tactic codes → kill-chain stage mapping
_TACTIC_TO_STAGE: dict[str, str] = {
    "TA0043": "RECONNAISSANCE",
    "TA0042": "SCANNING",
    "TA0001": "INITIAL_ACCESS",
    "TA0006": "AUTH_ANOMALY",
    "TA0002": "EXECUTION",
    "TA0004": "PRIVILEGE_ESCALATION",
    "TA0008": "LATERAL_MOVEMENT",
    "TA0010": "EXFILTRATION",
}


def _classify_stage(detection: DetectionEvent) -> str:
    """Classify a detection into a kill-chain stage name."""
    if detection.mitre_tactics:
        for tactic in detection.mitre_tactics:
            tactic_upper = str(tactic).upper()
            for code, stage in _TACTIC_TO_STAGE.items():
                if code in tactic_upper:
                    return stage
            if "RECON" in tactic_upper:
                return "RECONNAISSANCE"
            if "CRED" in tactic_upper or "AUTH" in tactic_upper:
                return "AUTH_ANOMALY"
            if "LATERAL" in tactic_upper:
                return "LATERAL_MOVEMENT"

    title_lower = detection.title.lower()
    if "recon" in title_lower:
        return "RECONNAISSANCE"
    if "scan" in title_lower:
        return "SCANNING"
    if "auth" in title_lower or "brute" in title_lower or "credential" in title_lower:
        return "AUTH_ANOMALY"
    if "exploit" in title_lower or "initial" in title_lower:
        return "INITIAL_ACCESS"
    if "escalat" in title_lower or "privilege" in title_lower:
        return "PRIVILEGE_ESCALATION"
    if "lateral" in title_lower:
        return "LATERAL_MOVEMENT"
    if "exfil" in title_lower:
        return "EXFILTRATION"
    return "EXECUTION"


class AttackSequenceEngine:
    """Tracks ordered kill-chain progression across events for tracked entities."""

    def __init__(
        self,
        window_seconds: int = 1800,
        sequence_window_seconds: int | None = None,
    ) -> None:
        self.sequence_window_seconds = sequence_window_seconds or window_seconds
        # entity_key -> list of (timestamp_epoch, stage_name, raw_event_id, technique)
        self._entity_stages: dict[str, list[tuple[float, str, str, str | None]]] = {}
        self._lock = threading.Lock()

    def process_detection(self, detection: DetectionEvent) -> AttackSequence:
        """Extract entity and stage from detection event and record progression.

        Always returns an AttackSequence (never None), even for a single stage.
        Confidence level reflects how complete the sequence is.
        """
        # Determine entity key
        ids = detection.entity_ids or detection.entities
        entity_key = ids[0] if ids else "unknown"

        stage = _classify_stage(detection)
        tech: str | None = None
        if detection.mitre_techniques:
            tech = detection.mitre_techniques[0]
        elif detection.mitre_attack_technique:
            tech = detection.mitre_attack_technique

        ev = detection.evidence
        if hasattr(ev, "matched_event_ids") and ev.matched_event_ids:
            raw_id = ev.matched_event_ids[0]
        elif hasattr(ev, "raw_event_id") and ev.raw_event_id:
            raw_id = ev.raw_event_id
        else:
            raw_id = detection.detection_id

        return self.record_stage(
            entity_key=entity_key,
            stage_name=stage,
            raw_event_id=raw_id,
            mitre_technique=tech,
        )

    def record_stage(
        self,
        entity_key: str,
        stage_name: str,
        raw_event_id: str,
        mitre_technique: str | None = None,
    ) -> AttackSequence:
        """Record an observed stage for an entity and return updated sequence.

        Returns an AttackSequence for every call — single stage returns PARTIAL.
        """
        stage_upper = stage_name.upper().strip()
        now_epoch = time.time()
        now_iso = datetime.now(UTC).isoformat()

        with self._lock:
            cutoff = now_epoch - self.sequence_window_seconds
            stages = self._entity_stages.setdefault(entity_key, [])
            stages = [s for s in stages if s[0] > cutoff]
            stages.append((now_epoch, stage_upper, raw_event_id, mitre_technique))
            self._entity_stages[entity_key] = stages

            # Deduplicate stages in chronological order
            seen_stages: list[str] = []
            ordered_events: list[str] = []
            techniques: set[str] = set()

            for entry in sorted(stages, key=lambda x: x[0]):
                stg = entry[1]
                if stg not in seen_stages:
                    seen_stages.append(stg)
                ordered_events.append(entry[2])
                if entry[3]:
                    techniques.add(entry[3])

            stage_count = len(seen_stages)

            # Determine sequence confidence and risk
            if stage_count == 1:
                confidence = SequenceConfidence.PARTIAL_SEQUENCE
                base_risk = 35.0
            elif stage_count == 2:
                confidence = SequenceConfidence.POTENTIAL_SEQUENCE
                base_risk = 60.0
            elif stage_count == 3:
                confidence = SequenceConfidence.CORRELATED_SEQUENCE
                base_risk = 80.0
            else:
                confidence = SequenceConfidence.CONFIRMED_PATTERN
                base_risk = 95.0

            return AttackSequence(
                sequence_id=f"seq-{uuid.uuid4().hex[:12]}",
                stages_detected=tuple(seen_stages),
                ordered_event_ids=tuple(ordered_events),
                time_start=datetime.fromtimestamp(stages[0][0], UTC).isoformat(),
                time_end=now_iso,
                confidence=confidence,
                overall_risk=base_risk,
                mitre_attack_techniques=tuple(sorted(techniques)),
                metadata={"entity_key": entity_key, "stage_count": stage_count},
            )
