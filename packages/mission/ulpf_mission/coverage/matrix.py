"""Detection coverage matrix — maps telemetry sources to MITRE ATT&CK tactics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CoverageStatus(str, Enum):
    """ATT&CK technique coverage status."""

    COVERED = "COVERED"
    PARTIALLY_COVERED = "PARTIALLY_COVERED"
    UNCOVERED = "UNCOVERED"


# Canonical MITRE ATT&CK tactic set used by ULPF
MITRE_TACTICS: list[str] = [
    "TA0001_INITIAL_ACCESS",
    "TA0002_EXECUTION",
    "TA0003_PERSISTENCE",
    "TA0004_PRIVILEGE_ESCALATION",
    "TA0005_DEFENSE_EVASION",
    "TA0006_CREDENTIAL_ACCESS",
    "TA0007_DISCOVERY",
    "TA0008_LATERAL_MOVEMENT",
    "TA0009_COLLECTION",
    "TA0010_EXFILTRATION",
    "TA0011_COMMAND_AND_CONTROL",
    "TA0040_IMPACT",
]


@dataclass
class TacticCoverage:
    """Coverage record for a single ATT&CK tactic."""

    tactic_id: str
    status: CoverageStatus
    covering_sources: list[str] = field(default_factory=list)
    covering_rules: list[str] = field(default_factory=list)
    gap_description: str = ""


@dataclass
class CoverageMatrixReport:
    """Full detection coverage matrix report."""

    tactic_coverage: list[TacticCoverage]
    overall_coverage_pct: float
    covered_count: int
    partial_count: int
    uncovered_count: int
    recommendations: list[str] = field(default_factory=list)

    @property
    def sources(self) -> list[str]:
        return [
            "firewall", "endpoint_edr", "auth_logs", "dns",
            "application_logs", "syslog", "cloud_trail",
        ]

    @property
    def tactics(self) -> list[str]:
        return list(MITRE_TACTICS)

    @property
    def total_cells(self) -> int:
        return len(self.sources) * len(self.tactics)

    @property
    def covered_cells(self) -> int:
        return self.covered_count

    @property
    def partially_covered_cells(self) -> int:
        return self.partial_count

    @property
    def uncovered_cells(self) -> int:
        return self.uncovered_count

    @property
    def matrix(self) -> dict[str, dict[str, str]]:
        res: dict[str, dict[str, str]] = {}
        for s in self.sources:
            res[s] = {}
            for tc in self.tactic_coverage:
                if any(s in src.lower() for src in tc.covering_sources):
                    res[s][tc.tactic_id] = "COVERED"
                else:
                    res[s][tc.tactic_id] = "UNCOVERED"
        return res


class DetectionCoverageMatrix:
    """Maps registered telemetry sources and rules to MITRE ATT&CK tactics."""

    def generate_report(self, active_sources: list[str] | None = None) -> CoverageMatrixReport:
        sources = active_sources or [
            "firewall_prod",
            "auth_logs_dc01",
            "endpoint_edr_agent",
            "dns_primary",
            "application_logs_web",
            "syslog_linux",
            "cloud_trail_aws",
        ]
        return self.compute(sources)

    # Static mapping: which source types cover which tactics
    _SOURCE_TACTIC_MAP: dict[str, list[str]] = {
        "firewall": [
            "TA0001_INITIAL_ACCESS",
            "TA0008_LATERAL_MOVEMENT",
            "TA0010_EXFILTRATION",
            "TA0011_COMMAND_AND_CONTROL",
        ],
        "endpoint_edr": [
            "TA0002_EXECUTION",
            "TA0003_PERSISTENCE",
            "TA0004_PRIVILEGE_ESCALATION",
            "TA0005_DEFENSE_EVASION",
            "TA0009_COLLECTION",
        ],
        "auth_logs": [
            "TA0006_CREDENTIAL_ACCESS",
            "TA0004_PRIVILEGE_ESCALATION",
            "TA0001_INITIAL_ACCESS",
            "TA0008_LATERAL_MOVEMENT",
        ],
        "dns": [
            "TA0011_COMMAND_AND_CONTROL",
            "TA0007_DISCOVERY",
        ],
        "application_logs": [
            "TA0001_INITIAL_ACCESS",
            "TA0002_EXECUTION",
            "TA0009_COLLECTION",
            "TA0010_EXFILTRATION",
        ],
        "syslog": [
            "TA0003_PERSISTENCE",
            "TA0005_DEFENSE_EVASION",
            "TA0007_DISCOVERY",
            "TA0040_IMPACT",
        ],
        "cloud_trail": [
            "TA0001_INITIAL_ACCESS",
            "TA0003_PERSISTENCE",
            "TA0004_PRIVILEGE_ESCALATION",
            "TA0005_DEFENSE_EVASION",
            "TA0010_EXFILTRATION",
        ],
    }

    def compute(
        self,
        active_sources: list[str],
        active_rule_ids: list[str] | None = None,
    ) -> CoverageMatrixReport:
        """Compute coverage matrix given active telemetry sources."""
        rule_ids = active_rule_ids or []
        covered_tactics: dict[str, list[str]] = {}  # tactic → sources

        for source in active_sources:
            src_lower = source.lower()
            for src_key, tactics in self._SOURCE_TACTIC_MAP.items():
                if src_key in src_lower:
                    for tactic in tactics:
                        covered_tactics.setdefault(tactic, []).append(source)

        tactic_coverage: list[TacticCoverage] = []
        for tactic in MITRE_TACTICS:
            sources_covering = covered_tactics.get(tactic, [])
            if len(sources_covering) >= 2:
                status = CoverageStatus.COVERED
                gap = ""
            elif len(sources_covering) == 1:
                status = CoverageStatus.PARTIALLY_COVERED
                gap = f"Only 1 source covers {tactic}; add redundant source for full coverage."
            else:
                status = CoverageStatus.UNCOVERED
                gap = f"No telemetry source covers {tactic}. Add firewall, EDR, or auth logs."

            tactic_coverage.append(
                TacticCoverage(
                    tactic_id=tactic,
                    status=status,
                    covering_sources=sources_covering,
                    covering_rules=[r for r in rule_ids if tactic.split("_")[0] in r],
                    gap_description=gap,
                )
            )

        covered_count = sum(1 for t in tactic_coverage if t.status == CoverageStatus.COVERED)
        partial_count = sum(
            1 for t in tactic_coverage if t.status == CoverageStatus.PARTIALLY_COVERED
        )
        uncovered_count = sum(1 for t in tactic_coverage if t.status == CoverageStatus.UNCOVERED)
        total = len(MITRE_TACTICS)
        pct = round((covered_count + 0.5 * partial_count) / max(1, total) * 100.0, 1)

        recs: list[str] = []
        uncovered_names = [
            t.tactic_id for t in tactic_coverage
            if t.status == CoverageStatus.UNCOVERED
        ]
        if uncovered_names:
            recs.append(f"Deploy sources to cover uncovered tactics: {uncovered_names}.")
        if partial_count > 0:
            recs.append(
                f"Add redundant telemetry to promote {partial_count} "
                "partial coverages to full coverage."
            )

        return CoverageMatrixReport(
            tactic_coverage=tactic_coverage,
            overall_coverage_pct=pct,
            covered_count=covered_count,
            partial_count=partial_count,
            uncovered_count=uncovered_count,
            recommendations=recs,
        )
