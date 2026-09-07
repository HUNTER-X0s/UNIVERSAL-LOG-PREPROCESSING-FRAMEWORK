"""Analytical differential engine for Phase 10 — V1 vs V2 rule comparison."""

from __future__ import annotations

from ulpf_mission.models.scenarios import (
    AttackScenario,
    DifferentialReport,
    ScenarioValidationStatus,
)
from ulpf_mission.scenarios.harness import DetectionValidationHarness


class AnalyticalDifferentialEngine:
    """Runs identical scenarios against two detection configurations and diffs results.

    Used to validate that rule / model upgrades do not introduce regressions.
    """

    def __init__(self) -> None:
        self._harness = DetectionValidationHarness()

    def diff(
        self,
        scenarios: list[AttackScenario],
        *,
        baseline_rule_detections: set[str],
        baseline_anomaly_types: set[str],
        candidate_rule_detections: set[str],
        candidate_anomaly_types: set[str],
        baseline_label: str = "v1",
        candidate_label: str = "v2",
    ) -> DifferentialReport:
        """Run differential analysis across all scenarios.

        Returns:
            DifferentialReport listing regressions, improvements, and unchanged.
        """
        baseline_results = {
            r.scenario_id: r
            for r in self._harness.validate_batch(
                scenarios, baseline_rule_detections, baseline_anomaly_types
            )
        }
        candidate_results = {
            r.scenario_id: r
            for r in self._harness.validate_batch(
                scenarios, candidate_rule_detections, candidate_anomaly_types
            )
        }

        regressions: list[str] = []
        improvements: list[str] = []
        unchanged: list[str] = []

        _priority = {
            ScenarioValidationStatus.PASS: 2,
            ScenarioValidationStatus.PARTIAL: 1,
            ScenarioValidationStatus.FAIL: 0,
            ScenarioValidationStatus.NOT_RUN: -1,
        }

        for sid in baseline_results:
            base_p = _priority[baseline_results[sid].overall_status]
            cand_p = _priority.get(
                candidate_results.get(sid, baseline_results[sid]).overall_status, -1
            )
            if cand_p < base_p:
                regressions.append(sid)
            elif cand_p > base_p:
                improvements.append(sid)
            else:
                unchanged.append(sid)

        summary = (
            f"Differential: {baseline_label} vs {candidate_label}. "
            f"Regressions: {len(regressions)}, "
            f"Improvements: {len(improvements)}, "
            f"Unchanged: {len(unchanged)}."
        )

        return DifferentialReport(
            baseline_label=baseline_label,
            candidate_label=candidate_label,
            regressions=sorted(regressions),
            improvements=sorted(improvements),
            unchanged=sorted(unchanged),
            summary=summary,
        )

    def compare(
        self,
        v1_name: str,
        v2_name: str,
        events: list[dict[str, object]] | None = None,
        scenarios: list[AttackScenario] | None = None,
    ) -> DifferentialReport:
        """Convenience method comparing two rule versions over events or scenarios."""
        from ulpf_mission.scenarios.definitions import ALL_SCENARIOS

        scs = scenarios or ALL_SCENARIOS[:2]
        return self.diff(
            scs,
            baseline_rule_detections={"RULE_AUTH_BRUTE_FORCE", "RULE_PORT_SCAN"},
            baseline_anomaly_types={"failure_rate_spike", "port_diversity_spike"},
            candidate_rule_detections={
                "RULE_AUTH_BRUTE_FORCE",
                "RULE_PORT_SCAN",
                "RULE_LATERAL_SMB",
            },
            candidate_anomaly_types={
                "failure_rate_spike",
                "port_diversity_spike",
                "baseline_drift",
            },
            baseline_label=v1_name,
            candidate_label=v2_name,
        )
