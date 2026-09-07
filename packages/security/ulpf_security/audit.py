"""Security audit logging module for ULPF Phase 7.

Enforces:
- Rule 14: Audit admin actions
- Rule 81: Audit immutability
- Rule 91: Security event logging without credential leakage
"""

import json
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SecurityAuditEvent:
    """Immutable security audit record for governance and compliance."""

    event_id: str
    timestamp: str
    actor: str
    auth_method: str
    permission: str
    target: str
    action: str
    result: str  # GRANTED, DENIED, ERROR
    reason: str
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None
    correlation_id: str | None = None
    client_ip: str | None = None


class SecurityAuditLogger:
    """Thread-safe append-only audit logger for tracking privileged security events."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        self._lock = threading.Lock()
        self._events: list[SecurityAuditEvent] = []
        self._log_path = Path(log_path).resolve() if log_path else None
        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event_id: str,
        actor: str,
        auth_method: str,
        permission: str,
        target: str,
        action: str,
        result: str,
        reason: str = "",
        previous_state: dict[str, Any] | None = None,
        new_state: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        client_ip: str | None = None,
    ) -> SecurityAuditEvent:
        ev = SecurityAuditEvent(
            event_id=event_id,
            timestamp=datetime.now(UTC).isoformat(),
            actor=actor,
            auth_method=auth_method,
            permission=permission,
            target=target,
            action=action,
            result=result,
            reason=reason,
            previous_state=previous_state,
            new_state=new_state,
            correlation_id=correlation_id,
            client_ip=client_ip,
        )

        with self._lock:
            self._events.append(ev)
            if self._log_path:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(ev)) + "\n")

        return ev

    def get_events(self, limit: int = 100) -> list[SecurityAuditEvent]:
        with self._lock:
            return list(self._events[-limit:])

    def count(self) -> int:
        with self._lock:
            return len(self._events)
