"""Detection Test Harness for Controlled Fixture Validation in ULPF Phase 9."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ulpf_advanced_intelligence.content.lifecycle import AdvancedDetectionRule


@dataclass(frozen=True)
class RuleFixtureValidationResult:
    """Detailed results from running a detection rule against its test fixtures."""

    rule_id: str
    rule_version: str
    positive_total: int
    positive_matched: int
    negative_total: int
    negative_matched: int  # False positives in controlled fixture set
    boundary_total: int
    boundary_matched: int
    passed: bool
    summary: str


class DetectionTestHarness:
    """Executes deterministic unit validation of detection rules against positive, negative, and boundary fixtures."""

    @classmethod
    def evaluate_rule(cls, rule: AdvancedDetectionRule) -> RuleFixtureValidationResult:
        """Run rule against its embedded fixture test suite."""
        pos_total = len(rule.positive_fixtures)
        pos_matched = 0
        for fix in rule.positive_fixtures:
            if cls._eval_conditions(rule, fix):
                pos_matched += 1

        neg_total = len(rule.negative_fixtures)
        neg_matched = 0
        for fix in rule.negative_fixtures:
            if cls._eval_conditions(rule, fix):
                neg_matched += 1

        bnd_total = len(rule.boundary_fixtures)
        bnd_matched = 0
        for fix in rule.boundary_fixtures:
            if cls._eval_conditions(rule, fix):
                bnd_matched += 1

        # A rule passes if it matches all positive fixtures and zero negative fixtures
        passed = (pos_matched == pos_total) and (neg_matched == 0)
        summary = (
            f"Fixture metrics: {pos_matched}/{pos_total} positive matched, "
            f"{neg_matched}/{neg_total} false positive in negative set, "
            f"{bnd_matched}/{bnd_total} boundary matched."
        )

        return RuleFixtureValidationResult(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            positive_total=pos_total,
            positive_matched=pos_matched,
            negative_total=neg_total,
            negative_matched=neg_matched,
            boundary_total=bnd_total,
            boundary_matched=bnd_matched,
            passed=passed,
            summary=summary,
        )

    @staticmethod
    def _eval_conditions(rule: AdvancedDetectionRule, event: dict[str, Any]) -> bool:
        if not rule.conditions:
            return True
        return all(cond.evaluate(event) for cond in rule.conditions)
