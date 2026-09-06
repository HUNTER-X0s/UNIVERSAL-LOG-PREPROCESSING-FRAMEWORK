"""OCSF v1.1.0 Projection Mapper for ULPF Phase 4.

Transforms SemanticEvent and UCE structures into standard OCSF v1.1.0 records.
"""

from datetime import UTC, datetime
from typing import Any

from ulpf_semantic.models import EntityType, SemanticEvent
from ulpf_semantic.projections.base import BaseProjection, ProjectionResult
from ulpf_semantic.projections.ocsf.validator import OCSFValidator


def _iso_to_epoch_ms(iso_str: str) -> int:
    """Convert ISO-8601 timestamp string to epoch milliseconds."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return int(datetime.now(UTC).timestamp() * 1000)


def _map_severity_to_ocsf(severity: int) -> int:
    """Map UCE severity (0-10) to OCSF severity_id (0-6)."""
    if severity <= 0:
        return 0  # Unknown
    if severity <= 2:
        return 1  # Informational
    if severity <= 4:
        return 2  # Low
    if severity <= 6:
        return 3  # Medium
    if severity <= 8:
        return 4  # High
    return 5  # Critical


class OCSFProjection(BaseProjection):
    """Outbound projection mapping UCE and SemanticEvent into OCSF v1.1.0."""

    projection_id = "ocsf.v1"
    version = "1.1.0"

    def project(
        self,
        semantic_event: SemanticEvent,
        uce_event: dict[str, Any],
    ) -> ProjectionResult:
        """Project a SemanticEvent and raw UCE into an OCSF v1.1.0 compliant object."""
        triple = semantic_event.semantic_triple
        category = triple.category
        class_name = triple.class_name
        time_ms = _iso_to_epoch_ms(semantic_event.timestamp)
        event_body = uce_event.get("event", {})
        meta = event_body.get("metadata", {})
        vendor = meta.get("vendor", "Generic")
        product = meta.get("product", "Telemetry")

        # 1. Resolve Class UID and Category UID
        class_uid = 4001  # Default: Network Activity
        category_uid = 4  # Default: Network Activity
        activity_id = 99  # Other

        if class_name in ("Firewall", "Network Activity"):
            class_uid = 4001
            category_uid = 4
            activity_id = 1 if semantic_event.action.semantic in ("allow", "accept") else 2
        elif class_name in ("Detection Finding", "Security Finding", "IDS/IPS"):
            class_uid = 2004  # Detection Finding per OCSF v1.1.0 (2002=Vulnerability Finding)
            category_uid = 2  # Findings
            activity_id = 1  # Create
        elif class_name in ("Authentication", "Identity"):
            class_uid = 3002  # Authentication
            category_uid = 3  # Identity & Access
            activity_id = 1 if semantic_event.action.semantic in ("login", "logon", "auth") else 2
        elif class_name == "HTTP Activity":
            class_uid = 4002  # HTTP Activity
            category_uid = 4
            activity_id = 1
        elif class_name == "DNS Activity":
            class_uid = 4003  # DNS Activity
            category_uid = 4
            activity_id = 1
        elif class_name == "Cloud API":
            class_uid = 6003  # API Activity
            category_uid = 6  # Application Activity
            activity_id = 1
        elif class_name == "Process Activity":
            class_uid = 1007  # Process Activity
            category_uid = 1  # System Activity
            activity_id = 1

        type_uid = class_uid * 100 + activity_id
        severity_id = _map_severity_to_ocsf(semantic_event.severity)

        # 2. Extract endpoints from entities
        src_endpoint: dict[str, Any] = {}
        dst_endpoint: dict[str, Any] = {}
        user_obj: dict[str, Any] = {}

        for ent in semantic_event.entities:
            if ent.entity_type == EntityType.IP.value:
                if ent.role == "source" and not src_endpoint:
                    src_endpoint["ip"] = ent.normalized_value or ent.value
                    if "port" in ent.attributes:
                        src_endpoint["port"] = ent.attributes["port"]
                elif ent.role == "destination" and not dst_endpoint:
                    dst_endpoint["ip"] = ent.normalized_value or ent.value
                    if "port" in ent.attributes:
                        dst_endpoint["port"] = ent.attributes["port"]
            elif ent.entity_type == EntityType.USER.value and not user_obj:
                user_obj["name"] = ent.value

        # OCSF v1.1.0 status_id: 1=Unknown, 2=Success/Allowed, 3=Failure/Denied
        _success_statuses = {"SUCCESS", "ALLOWED"}
        _failure_statuses = {"FAILURE", "DENIED", "BLOCKED", "ERROR"}
        result_status = semantic_event.result.status
        if result_status in _success_statuses:
            status_id = 2
        elif result_status in _failure_statuses:
            status_id = 3
        else:
            status_id = 1  # Unknown

        ocsf_obj: dict[str, Any] = {
            "activity_id": activity_id,
            "category_uid": category_uid,
            "class_uid": class_uid,
            "type_uid": type_uid,
            "severity_id": severity_id,
            "time": time_ms,
            "status_id": status_id,
            "status": semantic_event.result.status,
            "metadata": {
                "version": self.version,
                "product": {
                    "vendor_name": vendor,
                    "name": product,
                },
                "profiles": ["ulpf_canonical"],
                "original_time": semantic_event.timestamp,
                "correlation_uid": (
                    semantic_event.correlation_context.equivalence_key
                    if semantic_event.correlation_context
                    else None
                ),
            },
            "unmapped": semantic_event.unmapped_semantic_fields,
        }

        if src_endpoint:
            ocsf_obj["src_endpoint"] = src_endpoint
        if dst_endpoint:
            ocsf_obj["dst_endpoint"] = dst_endpoint
        if user_obj:
            ocsf_obj["user"] = user_obj

        # Attach Security Context Finding if finding class
        if category_uid == 2:
            finding_title = (
                semantic_event.security_context.threat
                or semantic_event.security_context.rule
                or "Security Finding"
            )
            ocsf_obj["finding_info"] = {
                "title": finding_title,
                "desc": f"Rule {semantic_event.security_context.rule or 'alert'} triggered",
            }

        # 4. Validate output
        status, errors = OCSFValidator.validate(ocsf_obj)

        return ProjectionResult(
            projection_id=self.projection_id,
            version=self.version,
            status=status,
            output=ocsf_obj,
            errors=tuple(errors),
            metadata={"class_name": class_name, "category": category},
        )
