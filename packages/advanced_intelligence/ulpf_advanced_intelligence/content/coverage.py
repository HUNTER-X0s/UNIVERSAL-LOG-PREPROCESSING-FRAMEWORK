"""Detection Coverage Tracking and Gap Analysis for ULPF Phase 9."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ulpf_advanced_intelligence.content.lifecycle import AdvancedDetectionRule


@dataclass(frozen=True)
class CoverageReport:
    """Comprehensive breakdown of detection rule coverage across ATT&CK, entities, and sources."""

    total_rules: int
    active_rules: int
    covered_mitre_tactics: tuple[str, ...]
    covered_mitre_techniques: tuple[str, ...]
    covered_entities: tuple[str, ...]
    detected_gaps: tuple[str, ...]
    coverage_score: float  # 0.0 - 100.0


class CoverageTracker:
    """Computes transparent coverage metrics across all active detection content."""

    # Reference core MITRE Enterprise Tactics
    REFERENCE_TACTICS: tuple[str, ...] = (
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    )

    @classmethod
    def generate_report(cls, rules: Sequence[AdvancedDetectionRule]) -> CoverageReport:
        tactics: set[str] = set()
        techniques: set[str] = set()
        entities: set[str] = set()
        active_count = 0

        for r in rules:
            if r.state.value == "ACTIVE":
                active_count += 1
            for t in r.mitre_tactics:
                tactics.add(t)
            for tech in r.mitre_techniques:
                techniques.add(tech)
            for e in r.entity_scope:
                entities.add(e)

        # Detect gaps relative to core enterprise tactics
        gaps: list[str] = [t for t in cls.REFERENCE_TACTICS if t not in tactics]
        score = min(100.0, (len(tactics) / len(cls.REFERENCE_TACTICS)) * 100.0) if cls.REFERENCE_TACTICS else 0.0

        return CoverageReport(
            total_rules=len(rules),
            active_rules=active_count,
            covered_mitre_tactics=tuple(sorted(tactics)),
            covered_mitre_techniques=tuple(sorted(techniques)),
            covered_entities=tuple(sorted(entities)),
            detected_gaps=tuple(sorted(gaps)),
            coverage_score=round(score, 2),
        )
