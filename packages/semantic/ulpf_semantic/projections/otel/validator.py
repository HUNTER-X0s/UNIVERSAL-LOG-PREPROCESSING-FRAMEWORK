"""OpenTelemetry Logs Projection Validator for ULPF Phase 4.

Validates compliance with the OpenTelemetry Logs Data Model (OTLP Logs).
"""

from typing import Any

from ulpf_semantic.projections.base import ProjectionStatus


class OTelValidator:
    """Validates structural compliance of projected OpenTelemetry LogRecord payloads."""

    @staticmethod
    def validate(otel_dict: dict[str, Any]) -> tuple[ProjectionStatus, list[str]]:
        """Validate an OTLP ResourceLogs structure."""
        errors: list[str] = []

        if not otel_dict:
            return ProjectionStatus.INVALID, ["Empty OTel payload"]

        if "resource_logs" not in otel_dict:
            errors.append("Missing 'resource_logs' root container")
            return ProjectionStatus.INVALID, errors

        res_logs = otel_dict.get("resource_logs", [])
        if not isinstance(res_logs, list) or not res_logs:
            errors.append("'resource_logs' must be a non-empty list")
            return ProjectionStatus.INVALID, errors

        first_scope = res_logs[0].get("scope_logs", [])
        if not isinstance(first_scope, list) or not first_scope:
            errors.append("'scope_logs' must be a non-empty list")
            return ProjectionStatus.INVALID, errors

        log_records = first_scope[0].get("log_records", [])
        if not isinstance(log_records, list) or not log_records:
            errors.append("'log_records' must be a non-empty list")
            return ProjectionStatus.INVALID, errors

        record = log_records[0]
        for field_name in ("time_unix_nano", "severity_number", "severity_text", "body"):
            if field_name not in record:
                errors.append(f"Missing mandatory LogRecord field '{field_name}'")

        if errors:
            return ProjectionStatus.PARTIAL, errors

        return ProjectionStatus.VALID, []
