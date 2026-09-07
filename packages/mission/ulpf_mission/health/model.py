"""Mission health model — unified 12-subsystem state machine for Phase 10."""

from __future__ import annotations

import time

from ulpf_mission.models.health import (
    MISSION_SUBSYSTEMS,
    MissionHealthReport,
    MissionSubsystemHealth,
    SubsystemHealthState,
)


class MissionHealthModel:
    """Manages and aggregates health state across all 12 ULPF subsystems.

    Health states are derived from telemetry; they are never hardcoded.
    Unknown state is returned when no telemetry is available.
    """

    def __init__(self) -> None:
        self._subsystem_states: dict[str, MissionSubsystemHealth] = {
            name: MissionSubsystemHealth(
                subsystem=name,
                state=SubsystemHealthState.UNKNOWN,
            )
            for name in MISSION_SUBSYSTEMS
        }

    def update(
        self,
        subsystem: str,
        *,
        state: SubsystemHealthState,
        latency_ms: float = 0.0,
        throughput_eps: float = 0.0,
        error_message: str = "",
    ) -> None:
        """Update health state for a specific subsystem."""
        if subsystem not in self._subsystem_states:
            # Accept unknown subsystems without crashing
            self._subsystem_states[subsystem] = MissionSubsystemHealth(
                subsystem=subsystem,
                state=state,
            )
        self._subsystem_states[subsystem] = MissionSubsystemHealth(
            subsystem=subsystem,
            state=state,
            last_checked=time.time(),
            error_message=error_message,
            latency_ms=latency_ms,
            throughput_eps=throughput_eps,
        )

    def report(self) -> MissionHealthReport:
        """Generate a full health report across all subsystems."""
        subsystems = list(self._subsystem_states.values())

        failed = [s.subsystem for s in subsystems if s.state == SubsystemHealthState.FAILED]
        degraded = [s.subsystem for s in subsystems if s.state == SubsystemHealthState.DEGRADED]

        if failed:
            overall = SubsystemHealthState.FAILED
        elif degraded:
            overall = SubsystemHealthState.DEGRADED
        elif any(s.state == SubsystemHealthState.UNKNOWN for s in subsystems):
            overall = SubsystemHealthState.UNKNOWN
        else:
            overall = SubsystemHealthState.HEALTHY

        return MissionHealthReport(
            subsystems=subsystems,
            overall_state=overall,
            timestamp=time.time(),
            failed_subsystems=failed,
            degraded_subsystems=degraded,
        )

    def mark_all_healthy(self) -> None:
        """Convenience: set all subsystems to HEALTHY (for testing/demo)."""
        for name in self._subsystem_states:
            self.update(name, state=SubsystemHealthState.HEALTHY)
