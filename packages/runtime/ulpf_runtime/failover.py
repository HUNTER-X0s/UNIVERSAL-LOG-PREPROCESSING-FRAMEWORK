"""ULPF Phase 7 — Failover and Degraded Mode Controller.

Models graceful failover behavior in the face of:
- Search subsystem failure → canonical processing continues (degraded mode)
- Database subsystem failure → ingest REJECTED with fail-closed semantics
- Authentication subsystem failure → all requests rejected (fail-closed)
- Delivery sink failure → routed to DLQ (fail-open for delivery)

Enforces:
- Rule D7: Search failure does not stall canonical ingest/storage
- Rule D8: Database failure prevents false ACK (ingest fails closed)
- Rule D9: Auth failure fails closed (no anonymous privilege escalation)
- Rule D10: Delivery sink failure → DLQ (not silent drop)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, auto
from typing import Any

logger = logging.getLogger(__name__)


class SubsystemStatus(Enum):
    """Health status of a platform subsystem."""
    HEALTHY = auto()
    DEGRADED = auto()
    FAILED = auto()


class FailoverBehavior(Enum):
    """How to respond when a subsystem is unavailable."""
    FAIL_CLOSED = auto()   # Reject operation entirely
    FAIL_OPEN = auto()     # Continue with degraded service
    ROUTE_DLQ = auto()     # Accept but route to dead-letter queue


@dataclass
class SubsystemConfig:
    """Configuration for a subsystem's failover behavior."""
    name: str
    failure_behavior: FailoverBehavior
    description: str


# Platform subsystem failover configuration
SUBSYSTEM_CONFIGS: dict[str, SubsystemConfig] = {
    "database": SubsystemConfig(
        name="database",
        failure_behavior=FailoverBehavior.FAIL_CLOSED,
        description="Database failure: ingest rejected, no false ACK",
    ),
    "auth": SubsystemConfig(
        name="auth",
        failure_behavior=FailoverBehavior.FAIL_CLOSED,
        description="Auth failure: all requests rejected, no anonymous access",
    ),
    "search": SubsystemConfig(
        name="search",
        failure_behavior=FailoverBehavior.FAIL_OPEN,
        description="Search failure: canonical processing continues in degraded mode",
    ),
    "delivery": SubsystemConfig(
        name="delivery",
        failure_behavior=FailoverBehavior.ROUTE_DLQ,
        description="Delivery failure: route to DLQ, no silent drop",
    ),
    "stream": SubsystemConfig(
        name="stream",
        failure_behavior=FailoverBehavior.FAIL_CLOSED,
        description="Stream failure: ingest paused, backpressure active",
    ),
}


class FailoverDecision:
    """The result of a failover evaluation."""

    __slots__ = ("subsystem", "behavior", "allowed", "reason", "decided_at")

    def __init__(
        self,
        subsystem: str,
        behavior: FailoverBehavior,
        allowed: bool,
        reason: str,
    ) -> None:
        self.subsystem = subsystem
        self.behavior = behavior
        self.allowed = allowed
        self.reason = reason
        self.decided_at = datetime.now(UTC).isoformat()


class DegradedModeController:
    """Tracks subsystem health and evaluates failover decisions.

    The controller models fail-closed (database, auth, stream) and
    fail-open (search) behaviors according to the ULPF security policy.
    """

    def __init__(self) -> None:
        self._status: dict[str, SubsystemStatus] = {
            name: SubsystemStatus.HEALTHY for name in SUBSYSTEM_CONFIGS
        }
        self._incident_log: list[dict[str, Any]] = []

    def mark_failed(self, subsystem: str, reason: str = "") -> None:
        """Mark a subsystem as failed and log the incident."""
        if subsystem not in SUBSYSTEM_CONFIGS:
            raise ValueError(f"Unknown subsystem: {subsystem}")
        self._status[subsystem] = SubsystemStatus.FAILED
        self._incident_log.append({
            "subsystem": subsystem,
            "transition": "HEALTHY→FAILED",
            "reason": reason,
            "at": datetime.now(UTC).isoformat(),
        })
        logger.warning("Subsystem '%s' marked FAILED: %s", subsystem, reason)

    def mark_degraded(self, subsystem: str, reason: str = "") -> None:
        """Mark a subsystem as degraded (reduced performance)."""
        if subsystem not in SUBSYSTEM_CONFIGS:
            raise ValueError(f"Unknown subsystem: {subsystem}")
        self._status[subsystem] = SubsystemStatus.DEGRADED
        self._incident_log.append({
            "subsystem": subsystem,
            "transition": "→DEGRADED",
            "reason": reason,
            "at": datetime.now(UTC).isoformat(),
        })
        logger.warning("Subsystem '%s' marked DEGRADED: %s", subsystem, reason)

    def mark_recovered(self, subsystem: str) -> None:
        """Mark a subsystem as recovered."""
        if subsystem not in SUBSYSTEM_CONFIGS:
            raise ValueError(f"Unknown subsystem: {subsystem}")
        prev = self._status.get(subsystem, SubsystemStatus.HEALTHY)
        self._status[subsystem] = SubsystemStatus.HEALTHY
        self._incident_log.append({
            "subsystem": subsystem,
            "transition": f"{prev.name}→HEALTHY",
            "at": datetime.now(UTC).isoformat(),
        })
        logger.info("Subsystem '%s' recovered", subsystem)

    def evaluate(self, subsystem: str, operation: str = "") -> FailoverDecision:
        """Evaluate whether an operation should proceed given subsystem health."""
        config = SUBSYSTEM_CONFIGS.get(subsystem)
        if config is None:
            # Unknown subsystem: fail closed by default
            return FailoverDecision(
                subsystem=subsystem,
                behavior=FailoverBehavior.FAIL_CLOSED,
                allowed=False,
                reason=f"Unknown subsystem '{subsystem}': fail closed",
            )

        status = self._status.get(subsystem, SubsystemStatus.HEALTHY)

        if status == SubsystemStatus.HEALTHY:
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=True,
                reason="Subsystem healthy",
            )

        # Subsystem DEGRADED or FAILED
        if config.failure_behavior == FailoverBehavior.FAIL_CLOSED:
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=False,
                reason=f"{config.description} [status={status.name}]",
            )
        elif config.failure_behavior == FailoverBehavior.FAIL_OPEN:
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=True,
                reason=f"Degraded mode: {config.description} [status={status.name}]",
            )
        else:  # ROUTE_DLQ
            return FailoverDecision(
                subsystem=subsystem,
                behavior=config.failure_behavior,
                allowed=True,  # Allowed but will be routed to DLQ by caller
                reason=f"DLQ routing: {config.description} [status={status.name}]",
            )

    def get_status(self) -> dict[str, str]:
        return {name: status.name for name, status in self._status.items()}

    def incident_log(self) -> list[dict[str, Any]]:
        return list(self._incident_log)

    def is_healthy(self) -> bool:
        return all(s == SubsystemStatus.HEALTHY for s in self._status.values())
