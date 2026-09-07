"""Universal Log Pre-processing Framework (ULPF) — Phase 10 Mission Operations Plane.

Phase 10 provides the unified mission orchestration, security posture synthesis,
early-warning intelligence, signal fusion, cross-domain analytics, coverage matrix,
scenario validation, replay lab, simulation engine, AI analyst copilot, and safe
response playbook automation.
"""

from ulpf_mission.copilot.advisor import AIAnalystCopilot, CopilotCaseSummary
from ulpf_mission.coverage.gap_analyzer import DetectionGapAnalyzer, GapAnalysisReport
from ulpf_mission.coverage.matrix import DetectionCoverageMatrix
from ulpf_mission.coverage.reliability import (
    SourceReliabilityCalculator,
    SourceReliabilityScore,
)
from ulpf_mission.cross_domain.analytics import (
    CrossDomainAnalytics,
    CrossDomainReport,
    DomainCoverageStatus,
    TelemetryDomain,
)
from ulpf_mission.early_warning.engine import EarlyWarningEngine
from ulpf_mission.fusion.engine import SignalFusionEngine
from ulpf_mission.health.model import MissionHealthModel
from ulpf_mission.metrics.sla import OperationalMetricsTracker, SLAMetricsSnapshot
from ulpf_mission.models.early_warning import (
    EarlyWarningAssessment,
    EarlyWarningIndicatorType,
    EarlyWarningSignal,
)
from ulpf_mission.models.fusion import (
    FusedSignal,
    FusionAssessment,
    SignalContribution,
    SignalSource,
)
from ulpf_mission.models.health import (
    MISSION_SUBSYSTEMS,
    MissionHealthReport,
    MissionSubsystemHealth,
    SubsystemHealthState,
)
from ulpf_mission.models.playbooks import (
    DryRunResult,
    DryRunStepResult,
    PlaybookDefinition,
    PlaybookExecutionStatus,
    PlaybookStep,
    PlaybookStepType,
)
from ulpf_mission.models.posture import (
    RiskTrendRecord,
    SecurityPostureLevel,
    SecurityPostureState,
)
from ulpf_mission.models.scenarios import (
    AttackScenario,
    DifferentialReport,
    ScenarioStep,
    ScenarioStepResult,
    ScenarioValidationResult,
    ScenarioValidationStatus,
)
from ulpf_mission.models.state import (
    MissionOperationalState,
    MissionStateSnapshot,
    StateTransitionRecord,
)
from ulpf_mission.orchestration.pipeline import (
    MissionAnalysisPipeline,
    MissionPipelineResult,
)
from ulpf_mission.playbooks.engine import ResponsePlaybookEngine
from ulpf_mission.posture.engine import RiskTrendAnalytics, SecurityPostureEngine
from ulpf_mission.replay.lab import ReplayLab, ReplayLabResult, ReplaySession
from ulpf_mission.scenarios.definitions import ALL_SCENARIOS
from ulpf_mission.scenarios.differential import AnalyticalDifferentialEngine
from ulpf_mission.scenarios.harness import DetectionValidationHarness
from ulpf_mission.simulation.engine import MissionSimulationEngine, SimulatedEvent, SimulationRun

__all__ = [
    # Top-Level Orchestration
    "MissionAnalysisPipeline",
    "MissionPipelineResult",
    # Operational State & Health
    "MissionOperationalState",
    "MissionStateSnapshot",
    "StateTransitionRecord",
    "MissionHealthModel",
    "MissionHealthReport",
    "MissionSubsystemHealth",
    "SubsystemHealthState",
    "MISSION_SUBSYSTEMS",
    # Security Posture & Trends
    "SecurityPostureEngine",
    "RiskTrendAnalytics",
    "SecurityPostureLevel",
    "SecurityPostureState",
    "RiskTrendRecord",
    # Early Warning
    "EarlyWarningEngine",
    "EarlyWarningAssessment",
    "EarlyWarningSignal",
    "EarlyWarningIndicatorType",
    # Signal Fusion
    "SignalFusionEngine",
    "FusedSignal",
    "FusionAssessment",
    "SignalContribution",
    "SignalSource",
    # Cross-Domain Analytics
    "CrossDomainAnalytics",
    "CrossDomainReport",
    "TelemetryDomain",
    "DomainCoverageStatus",
    # Coverage & Gaps
    "DetectionCoverageMatrix",
    "DetectionGapAnalyzer",
    "GapAnalysisReport",
    "SourceReliabilityCalculator",
    "SourceReliabilityScore",
    # Scenarios & Purple Teaming
    "ALL_SCENARIOS",
    "AttackScenario",
    "ScenarioStep",
    "ScenarioValidationStatus",
    "ScenarioStepResult",
    "ScenarioValidationResult",
    "DifferentialReport",
    "DetectionValidationHarness",
    "AnalyticalDifferentialEngine",
    # Replay & Simulation
    "ReplayLab",
    "ReplayLabResult",
    "ReplaySession",
    "MissionSimulationEngine",
    "SimulatedEvent",
    "SimulationRun",
    # Copilot Advisory
    "AIAnalystCopilot",
    "CopilotCaseSummary",
    # Response Playbooks
    "ResponsePlaybookEngine",
    "PlaybookDefinition",
    "PlaybookStep",
    "PlaybookStepType",
    "PlaybookExecutionStatus",
    "DryRunResult",
    "DryRunStepResult",
    # SLA Metrics
    "OperationalMetricsTracker",
    "SLAMetricsSnapshot",
]
