"""Operational health, readiness, and liveness checks for ULPF Phase 6.

Enforces:
- Rule 27: Distinct liveness (/health/live) and readiness (/health/ready)
- Rule 28: Dependency health: downstream failures do not mark entire service dead
- Rule 171/172: Status values: HEALTHY, DEGRADED, UNAVAILABLE
"""

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class DependencyCheckResult:
    name: str
    is_critical: bool
    state: HealthState
    message: str | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class HealthRegistry:
    """Monitors service and dependency health for Kubernetes/Docker health endpoints."""

    def __init__(self, service_name: str = "ulpf-runtime", version: str = "1.0.0") -> None:
        self.service_name = service_name
        self.version = version
        self._checks: dict[str, tuple[Callable[[], tuple[HealthState, str | None]], bool]] = {}
        self._lock = threading.Lock()

    def register_dependency(
        self,
        name: str,
        check_fn: Callable[[], tuple[HealthState, str | None]],
        is_critical: bool = True,
    ) -> None:
        """Register a health check function for a dependency."""
        with self._lock:
            self._checks[name] = (check_fn, is_critical)

    def check_liveness(self) -> dict[str, Any]:
        """Liveness check: returns 200 if the process is up and responding."""
        return {
            "service": self.service_name,
            "status": "UP",
            "version": self.version,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def check_readiness(self) -> dict[str, Any]:
        """Readiness check: evaluates registered dependencies.

        - If any critical dependency is UNAVAILABLE -> Overall UNAVAILABLE
        - If any non-critical dependency is UNAVAILABLE/DEGRADED -> Overall DEGRADED
        - Otherwise HEALTHY
        """
        results: list[DependencyCheckResult] = []
        has_critical_failure = False
        has_degraded = False

        with self._lock:
            checks_snapshot = list(self._checks.items())

        for name, (fn, is_crit) in checks_snapshot:
            try:
                state, msg = fn()
            except Exception as e:
                state, msg = HealthState.UNAVAILABLE, str(e)

            if state == HealthState.UNAVAILABLE:
                if is_crit:
                    has_critical_failure = True
                else:
                    has_degraded = True
            elif state == HealthState.DEGRADED:
                has_degraded = True

            results.append(
                DependencyCheckResult(
                    name=name,
                    is_critical=is_crit,
                    state=state,
                    message=msg,
                )
            )

        if has_critical_failure:
            overall = HealthState.UNAVAILABLE
        elif has_degraded:
            overall = HealthState.DEGRADED
        else:
            overall = HealthState.HEALTHY

        return {
            "service": self.service_name,
            "version": self.version,
            "overall_state": overall.value,
            "is_ready": overall in (HealthState.HEALTHY, HealthState.DEGRADED),
            "timestamp": datetime.now(UTC).isoformat(),
            "dependencies": [
                {
                    "name": r.name,
                    "critical": r.is_critical,
                    "state": r.state.value,
                    "message": r.message,
                }
                for r in results
            ],
        }
