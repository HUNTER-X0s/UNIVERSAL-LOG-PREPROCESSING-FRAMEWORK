"""OpenTelemetry Logs Projection Mapper for ULPF Phase 4.

Projects SemanticEvent and UCE records into OTLP-compliant LogRecord structures.
"""

from datetime import UTC, datetime
from typing import Any

from ulpf_semantic.models import SemanticEvent
from ulpf_semantic.projections.base import BaseProjection, ProjectionResult
from ulpf_semantic.projections.otel.validator import OTelValidator


def _iso_to_unix_nano(iso_str: str) -> int:
    """Convert ISO-8601 timestamp string to Unix epoch nanoseconds."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1_000_000_000)
    except (ValueError, TypeError):
        return int(datetime.now(UTC).timestamp() * 1_000_000_000)


def _map_severity_to_otel(severity: int) -> tuple[int, str]:
    """Map UCE severity (0-10) to OTel severity_number (1-24) and severity_text."""
    if severity <= 2:
        return 9, "INFO"
    if severity <= 4:
        return 10, "INFO"
    if severity <= 6:
        return 13, "WARN"
    if severity <= 8:
        return 17, "ERROR"
    return 21, "FATAL"


class OTelProjection(BaseProjection):
    """Outbound projection mapping UCE and SemanticEvent into OpenTelemetry Logs."""

    projection_id = "otel.logs.v1"
    version = "1.0.0"

    def project(
        self,
        semantic_event: SemanticEvent,
        uce_event: dict[str, Any],
    ) -> ProjectionResult:
        """Construct an OTLP-compliant ResourceLogs dictionary."""
        time_nano = _iso_to_unix_nano(semantic_event.timestamp)
        now_nano = int(datetime.now(UTC).timestamp() * 1_000_000_000)
        sev_num, sev_text = _map_severity_to_otel(semantic_event.severity)

        event_body = uce_event.get("event", {})
        meta = event_body.get("metadata", {})
        vendor = str(meta.get("vendor", "generic"))
        product = str(meta.get("product", "telemetry"))

        # Resource attributes
        res_attrs = [
            {"key": "service.name", "value": {"string_value": f"ulpf.{vendor}.{product}".lower()}},
            {"key": "telemetry.sdk.name", "value": {"string_value": "ulpf-semantic-pipeline"}},
            {"key": "telemetry.sdk.version", "value": {"string_value": self.version}},
        ]
        host = (
            semantic_event.correlation_context.host if semantic_event.correlation_context else None
        )
        if host:
            res_attrs.append({"key": "host.name", "value": {"string_value": host}})

        # LogRecord attributes
        triple = semantic_event.semantic_triple
        log_attrs = [
            {"key": "event.category", "value": {"string_value": triple.category}},
            {"key": "event.class", "value": {"string_value": triple.class_name}},
            {"key": "event.type", "value": {"string_value": triple.type_name}},
            {"key": "event.action", "value": {"string_value": semantic_event.action.semantic}},
            {"key": "event.result", "value": {"string_value": semantic_event.result.status}},
            {"key": "ulpf.event_id", "value": {"string_value": semantic_event.semantic_event_id}},
            {"key": "ulpf.uce_id", "value": {"string_value": semantic_event.uce_event_id}},
        ]

        if semantic_event.correlation_context:
            cc = semantic_event.correlation_context
            if cc.source_ip:
                log_attrs.append({"key": "source.ip", "value": {"string_value": cc.source_ip}})
            if cc.destination_ip:
                log_attrs.append(
                    {"key": "destination.ip", "value": {"string_value": cc.destination_ip}}
                )
            if cc.user:
                log_attrs.append({"key": "user.name", "value": {"string_value": cc.user}})
            if cc.equivalence_key:
                log_attrs.append(
                    {"key": "correlation.key", "value": {"string_value": cc.equivalence_key}}
                )

        # Unmapped attributes as baggage
        for k, v in semantic_event.unmapped_semantic_fields.items():
            if isinstance(v, str | int | float | bool):
                log_attrs.append({"key": f"unmapped.{k}", "value": {"string_value": str(v)}})

        # LogRecord body
        body_text = (
            f"[{triple.category}:{triple.class_name}] {triple.type_name} - "
            f"action={semantic_event.action.semantic} result={semantic_event.result.status}"
        )

        trace_id = (
            semantic_event.correlation_context.trace_id
            if semantic_event.correlation_context
            else None
        )
        span_id = (
            semantic_event.correlation_context.span_id
            if semantic_event.correlation_context
            else None
        )

        log_record: dict[str, Any] = {
            "time_unix_nano": time_nano,
            "observed_time_unix_nano": now_nano,
            "severity_number": sev_num,
            "severity_text": sev_text,
            "body": {"string_value": body_text},
            "attributes": log_attrs,
        }
        if trace_id:
            log_record["trace_id"] = trace_id
        if span_id:
            log_record["span_id"] = span_id

        otlp_doc: dict[str, Any] = {
            "resource_logs": [
                {
                    "resource": {"attributes": res_attrs},
                    "scope_logs": [
                        {
                            "scope": {
                                "name": "ulpf.semantic.projection",
                                "version": self.version,
                            },
                            "log_records": [log_record],
                        }
                    ],
                }
            ]
        }

        status, errors = OTelValidator.validate(otlp_doc)

        return ProjectionResult(
            projection_id=self.projection_id,
            version=self.version,
            status=status,
            output=otlp_doc,
            errors=tuple(errors),
            metadata={"severity_number": sev_num, "severity_text": sev_text},
        )
