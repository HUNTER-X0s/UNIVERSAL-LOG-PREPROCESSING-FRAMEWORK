"""OCSF v1.1.0 Validation Engine for ULPF Phase 4.

Ensures projected OCSF records conform to standard OCSF base event requirements.
"""

from typing import Any

from ulpf_semantic.projections.base import ProjectionStatus

# Mandatory base event attributes per OCSF Specification v1.1.0
MANDATORY_OCSF_BASE_FIELDS = (
    "activity_id",
    "category_uid",
    "class_uid",
    "metadata",
    "severity_id",
    "time",
    "type_uid",
)


class OCSFValidator:
    """Validates projected dictionaries against OCSF structural specifications."""

    @staticmethod
    def validate(ocsf_dict: dict[str, Any]) -> tuple[ProjectionStatus, list[str]]:
        """Validate OCSF dictionary completeness and return status and error list."""
        errors: list[str] = []

        if not ocsf_dict:
            return ProjectionStatus.INVALID, ["Empty OCSF payload"]

        for req_f in MANDATORY_OCSF_BASE_FIELDS:
            if req_f not in ocsf_dict or ocsf_dict[req_f] is None:
                errors.append(f"Missing mandatory OCSF field: '{req_f}'")

        if errors:
            return ProjectionStatus.INVALID, errors

        # Validate types of fundamental attributes
        if not isinstance(ocsf_dict["activity_id"], int):
            errors.append("OCSF 'activity_id' must be an integer")
        if not isinstance(ocsf_dict["category_uid"], int):
            errors.append("OCSF 'category_uid' must be an integer")
        if not isinstance(ocsf_dict["class_uid"], int):
            errors.append("OCSF 'class_uid' must be an integer")
        if not isinstance(ocsf_dict["severity_id"], int):
            errors.append("OCSF 'severity_id' must be an integer")
        if not isinstance(ocsf_dict["time"], int | float):
            errors.append("OCSF 'time' must be epoch millisecond numeric")

        if errors:
            return ProjectionStatus.PARTIAL, errors

        return ProjectionStatus.VALID, []
