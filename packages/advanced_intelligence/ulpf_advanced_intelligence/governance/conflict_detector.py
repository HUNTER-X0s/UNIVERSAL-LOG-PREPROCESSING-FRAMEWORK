"""Continuous Security Validation & Rule Conflict Detection Engine for ULPF Phase 9."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ulpf_advanced_intelligence.content.lifecycle import AdvancedDetectionRule
from ulpf_intelligence.rules.dsl import RuleOperator


@dataclass(frozen=True)
class GovernanceReviewFinding:
    """Security governance finding for invalid, conflicting, or duplicate detection content."""

    rule_id: str
    finding_type: str  # CONTRADICTION, DUPLICATE_CONDITIONS, MISSING_TESTS, INVALID_MITRE, MISSING_PROVENANCE
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str


@dataclass(frozen=True)
class ContentHealthScorecard:
    """Overall content quality and safety scorecard for security operations."""

    total_rules: int
    clean_rules: int
    findings: tuple[GovernanceReviewFinding, ...]
    health_score: float  # 0.0 - 100.0


class SecurityContentGovernanceEngine:
    """Performs static conflict detection, contradiction analysis, and quality auditing on rules."""

    @classmethod
    def audit_rules(cls, rules: Sequence[AdvancedDetectionRule]) -> ContentHealthScorecard:
        findings: list[GovernanceReviewFinding] = []
        rules_with_findings: set[str] = set()

        for r in rules:
            # 1. Contradiction check within same rule
            field_equal_values: dict[str, set[str]] = {}
            for cond in r.conditions:
                if cond.operator in (RuleOperator.EQUALS,):
                    f_name = cond.field
                    val_str = str(cond.value).lower()
                    field_equal_values.setdefault(f_name, set()).add(val_str)

            for f_name, vals in field_equal_values.items():
                if len(vals) > 1:
                    findings.append(
                        GovernanceReviewFinding(
                            rule_id=r.rule_id,
                            finding_type="CONTRADICTION",
                            severity="HIGH",
                            description=f"Rule contains contradictory EQUALS conditions on field '{f_name}': {vals}",
                        )
                    )
                    rules_with_findings.add(r.rule_id)

            # 2. Missing test fixtures
            if not r.positive_fixtures:
                findings.append(
                    GovernanceReviewFinding(
                        rule_id=r.rule_id,
                        finding_type="MISSING_TESTS",
                        severity="MEDIUM",
                        description="Rule has zero positive test fixtures",
                    )
                )
                rules_with_findings.add(r.rule_id)

            # 3. MITRE technique format check (e.g. T1110)
            for tech in r.mitre_techniques:
                if not (tech.startswith("T") and any(c.isdigit() for c in tech)):
                    findings.append(
                        GovernanceReviewFinding(
                            rule_id=r.rule_id,
                            finding_type="INVALID_MITRE",
                            severity="LOW",
                            description=f"Technique '{tech}' does not conform to MITRE ATT&CK identifier format",
                        )
                    )
                    rules_with_findings.add(r.rule_id)

        # 4. Duplicate conditions across rules
        for i in range(len(rules)):
            for j in range(i + 1, len(rules)):
                r1 = rules[i]
                r2 = rules[j]
                if r1.conditions and r2.conditions and r1.conditions == r2.conditions:
                    findings.append(
                        GovernanceReviewFinding(
                            rule_id=r2.rule_id,
                            finding_type="DUPLICATE_CONDITIONS",
                            severity="MEDIUM",
                            description=f"Rule {r2.rule_id} has identical conditions to {r1.rule_id}",
                        )
                    )
                    rules_with_findings.add(r2.rule_id)

        clean_count = max(0, len(rules) - len(rules_with_findings))
        score = (clean_count / len(rules) * 100.0) if rules else 100.0

        return ContentHealthScorecard(
            total_rules=len(rules),
            clean_rules=clean_count,
            findings=tuple(findings),
            health_score=round(score, 2),
        )
