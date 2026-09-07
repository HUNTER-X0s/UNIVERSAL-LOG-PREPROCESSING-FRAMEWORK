"""Detection gap analyzer for Phase 10 coverage plane."""

from __future__ import annotations

from dataclasses import dataclass

from ulpf_mission.coverage.matrix import CoverageMatrixReport, CoverageStatus


@dataclass
class CoverageGapAdvisory:
    """Actionable advisory for a single detection gap."""

    tactic_id: str
    gap_severity: str        # "CRITICAL" | "HIGH" | "MEDIUM"
    recommended_source: str
    business_impact: str
    recommended_rule_type: str = "detection_rule"

    @property
    def tactic(self) -> str:
        return self.tactic_id

    @property
    def source_type(self) -> str:
        return self.recommended_source

    @property
    def severity(self) -> str:
        return self.gap_severity

    @property
    def impact(self) -> str:
        return self.business_impact

    @property
    def remediation(self) -> str:
        return f"Deploy {self.recommended_source} with {self.recommended_rule_type} rules"


@dataclass
class GapAnalysisReport:
    """Full gap analysis report with prioritised advisories."""

    advisories: list[CoverageGapAdvisory]
    total_gaps: int
    critical_gaps: int
    coverage_score: float
    executive_summary: str = ""

    @property
    def gaps(self) -> list[CoverageGapAdvisory]:
        return self.advisories

    @property
    def high_gaps(self) -> int:
        return sum(1 for a in self.advisories if a.gap_severity == "HIGH")

    @property
    def medium_gaps(self) -> int:
        return sum(1 for a in self.advisories if a.gap_severity == "MEDIUM")

    @property
    def recommendations(self) -> list[str]:
        return [
            f"Remediate {a.tactic_id}: Deploy {a.recommended_source}"
            for a in self.advisories[:5]
        ]


# Priority map: which tactics are mission-critical
_CRITICAL_TACTICS: set[str] = {
    "TA0001_INITIAL_ACCESS",
    "TA0004_PRIVILEGE_ESCALATION",
    "TA0006_CREDENTIAL_ACCESS",
    "TA0008_LATERAL_MOVEMENT",
    "TA0010_EXFILTRATION",
}

_HIGH_TACTICS: set[str] = {
    "TA0002_EXECUTION",
    "TA0003_PERSISTENCE",
    "TA0005_DEFENSE_EVASION",
    "TA0011_COMMAND_AND_CONTROL",
}

_RECOMMENDED_SOURCES: dict[str, str] = {
    "TA0001_INITIAL_ACCESS": "firewall + auth_logs",
    "TA0002_EXECUTION": "endpoint_edr",
    "TA0003_PERSISTENCE": "endpoint_edr + syslog",
    "TA0004_PRIVILEGE_ESCALATION": "auth_logs + endpoint_edr",
    "TA0005_DEFENSE_EVASION": "endpoint_edr + syslog",
    "TA0006_CREDENTIAL_ACCESS": "auth_logs",
    "TA0007_DISCOVERY": "dns + syslog",
    "TA0008_LATERAL_MOVEMENT": "firewall + auth_logs",
    "TA0009_COLLECTION": "endpoint_edr + application_logs",
    "TA0010_EXFILTRATION": "firewall + application_logs",
    "TA0011_COMMAND_AND_CONTROL": "dns + firewall",
    "TA0040_IMPACT": "syslog + endpoint_edr",
}


class DetectionGapAnalyzer:
    """Produces actionable coverage advisory reports from coverage matrix data."""

    def analyze(self, matrix_report: CoverageMatrixReport) -> GapAnalysisReport:
        """Analyse coverage gaps and generate prioritised advisories."""
        advisories: list[CoverageGapAdvisory] = []

        for tc in matrix_report.tactic_coverage:
            if tc.status == CoverageStatus.COVERED:
                continue  # No advisory needed

            if tc.tactic_id in _CRITICAL_TACTICS:
                severity = "CRITICAL"
                impact = "Adversary can operate undetected in this critical kill-chain phase."
            elif tc.tactic_id in _HIGH_TACTICS:
                severity = "HIGH"
                impact = "High-risk blind spot enabling adversary dwell time."
            else:
                severity = "MEDIUM"
                impact = "Reduced visibility; may miss low-severity threats in this phase."

            if tc.status == CoverageStatus.PARTIALLY_COVERED:
                severity = min(severity, "HIGH") if severity == "CRITICAL" else "MEDIUM"
                impact = f"Partial coverage only. {tc.gap_description}"

            advisories.append(
                CoverageGapAdvisory(
                    tactic_id=tc.tactic_id,
                    gap_severity=severity,
                    recommended_source=_RECOMMENDED_SOURCES.get(tc.tactic_id, "general_siem"),
                    recommended_rule_type="threshold + behavioral",
                    business_impact=impact,
                )
            )

        # Sort: CRITICAL first, then HIGH, then MEDIUM
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        advisories.sort(key=lambda a: priority_order.get(a.gap_severity, 3))

        critical_count = sum(1 for a in advisories if a.gap_severity == "CRITICAL")
        total = len(advisories)

        summary = (
            f"Coverage score: {matrix_report.overall_coverage_pct}%. "
            f"{total} detection gaps found ({critical_count} CRITICAL). "
            f"Immediate action required for critical tactic blind spots."
            if critical_count
            else f"Coverage score: {matrix_report.overall_coverage_pct}%. "
            f"{total} detection gaps found. No critical blind spots."
        )

        return GapAnalysisReport(
            advisories=advisories,
            total_gaps=total,
            critical_gaps=critical_count,
            coverage_score=matrix_report.overall_coverage_pct,
            executive_summary=summary,
        )
