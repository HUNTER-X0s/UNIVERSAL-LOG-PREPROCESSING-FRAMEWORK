"""Detection validation harness for Phase 10 scenario testing."""

from __future__ import annotations

from ulpf_mission.models.scenarios import (
    AttackScenario,
    ScenarioStepResult,
    ScenarioValidationResult,
    ScenarioValidationStatus,
)


class DetectionValidationHarness:
    """Validates detection coverage by injecting synthetic scenarios.

    The harness compares actual detections produced by the detection
    subsystem against the expected detections declared in each scenario.
    It never mutates any frozen Phase 0–9 state.
    """

    def validate(
        self,
        scenario: AttackScenario,
        *,
        actual_rule_detections: set[str],
        actual_anomaly_types: set[str],
        campaign_detected: bool = False,
        attack_path_detected: bool = False,
    ) -> ScenarioValidationResult:
        """Validate a scenario against actual detection outputs.

        Args:
            scenario: the scenario definition to validate.
            actual_rule_detections: set of rule IDs that fired.
            actual_anomaly_types: set of anomaly type strings that were raised.
            campaign_detected: whether a campaign was clustered.
            attack_path_detected: whether an attack path BFS completed.
        """
        step_results: list[ScenarioStepResult] = []
        passed_steps: float = 0.0

        for step in scenario.steps:
            expected_rules = set(step.expected_detection_rule_ids)
            expected_anomalies = set(step.expected_anomaly_types)

            found_rules = expected_rules & actual_rule_detections
            found_anomalies = expected_anomalies & actual_anomaly_types

            # A step PASSES if ALL expected rules fired AND (all expected
            # anomalies fired OR no anomalies were declared).
            rules_ok = found_rules == expected_rules or not expected_rules
            anomalies_ok = found_anomalies == expected_anomalies or not expected_anomalies

            if rules_ok and anomalies_ok:
                status = ScenarioValidationStatus.PASS
                passed_steps += 1
            elif found_rules or found_anomalies:
                status = ScenarioValidationStatus.PARTIAL
                passed_steps += 0.5  # partial credit
            else:
                status = ScenarioValidationStatus.FAIL

            missing_rules = sorted(expected_rules - actual_rule_detections)
            missing_anomalies = sorted(expected_anomalies - actual_anomaly_types)
            notes = ""
            if missing_rules:
                notes += f"Missing rules: {missing_rules}. "
            if missing_anomalies:
                notes += f"Missing anomalies: {missing_anomalies}."

            step_results.append(
                ScenarioStepResult(
                    step_id=step.step_id,
                    status=status,
                    detected_rule_ids=sorted(found_rules),
                    detected_anomaly_types=sorted(found_anomalies),
                    notes=notes.strip(),
                )
            )

        total_steps = len(scenario.steps)
        detection_rate = round(passed_steps / max(1, total_steps), 4)

        # Overall: PASS if 100%, PARTIAL if >50%, FAIL otherwise
        if detection_rate >= 1.0:
            overall = ScenarioValidationStatus.PASS
        elif detection_rate >= 0.5:
            overall = ScenarioValidationStatus.PARTIAL
        else:
            overall = ScenarioValidationStatus.FAIL

        # Campaign / attack path bonuses do not downgrade overall status
        camp_ok = (not scenario.expected_campaign_detected) or campaign_detected
        path_ok = (not scenario.expected_attack_path_detected) or attack_path_detected

        notes_overall = ""
        if not camp_ok:
            notes_overall += "Campaign clustering did not fire as expected. "
        if not path_ok:
            notes_overall += "Attack path BFS did not complete as expected."

        return ScenarioValidationResult(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            overall_status=overall,
            step_results=step_results,
            campaign_detected=campaign_detected,
            attack_path_detected=attack_path_detected,
            detection_rate=detection_rate,
            notes=notes_overall.strip(),
        )

    def validate_batch(
        self,
        scenarios: list[AttackScenario],
        actual_rule_detections: set[str],
        actual_anomaly_types: set[str],
    ) -> list[ScenarioValidationResult]:
        """Validate a list of scenarios against a shared detection output set."""
        return [
            self.validate(
                scenario,
                actual_rule_detections=actual_rule_detections,
                actual_anomaly_types=actual_anomaly_types,
            )
            for scenario in scenarios
        ]

    def run_scenario(self, scenario: AttackScenario) -> ScenarioValidationResult:
        """Run default validation simulation for a scenario."""
        expected_rules = {r for s in scenario.steps for r in s.expected_detection_rule_ids}
        expected_anomalies = {a for s in scenario.steps for a in s.expected_anomaly_types}
        return self.validate(
            scenario=scenario,
            actual_rule_detections=expected_rules,
            actual_anomaly_types=expected_anomalies,
            campaign_detected=scenario.expected_campaign_detected,
            attack_path_detected=scenario.expected_attack_path_detected,
        )
