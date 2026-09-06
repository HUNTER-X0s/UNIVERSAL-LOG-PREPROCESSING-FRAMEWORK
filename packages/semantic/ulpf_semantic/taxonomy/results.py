"""Controlled Semantic Result Taxonomy for ULPF Phase 4.

Cleanly separates ACTION from RESULT (e.g. action="authenticate", result="FAILURE").
"""

from enum import Enum

from ulpf_semantic.models import SemanticAction, SemanticResult


class ResultStatus(str, Enum):
    """Controlled status codes for semantic outcomes."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    ALLOWED = "ALLOWED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    TIMEOUT = "TIMEOUT"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


def derive_result(
    action: SemanticAction,
    status_code: int | None = None,
    raw_status: str | None = None,
    is_error: bool = False,
) -> SemanticResult:
    """Derive deterministic SemanticResult from action, HTTP status codes, and status hints."""
    if is_error:
        return SemanticResult(status=ResultStatus.ERROR.value, detail="Error flag raised")

    # If raw status token is provided (e.g., from auth logs: 'failure', 'success')
    if raw_status:
        st_clean = raw_status.strip().upper()
        if st_clean in ("SUCCESS", "OK", "PASS"):
            return SemanticResult(status=ResultStatus.SUCCESS.value, detail=raw_status)
        if st_clean in ("FAIL", "FAILURE", "FAILED"):
            return SemanticResult(status=ResultStatus.FAILURE.value, detail=raw_status)
        if st_clean in ("DENY", "DENIED"):
            return SemanticResult(status=ResultStatus.DENIED.value, detail=raw_status)
        if st_clean in ("BLOCK", "BLOCKED"):
            return SemanticResult(status=ResultStatus.BLOCKED.value, detail=raw_status)
        if st_clean in ("TIMEOUT", "TIMED_OUT"):
            return SemanticResult(status=ResultStatus.TIMEOUT.value, detail=raw_status)

    # HTTP Status code semantics
    if status_code is not None:
        if 200 <= status_code < 400:
            return SemanticResult(
                status=ResultStatus.SUCCESS.value, detail=f"HTTP status {status_code}"
            )
        if status_code == 401:
            return SemanticResult(status=ResultStatus.DENIED.value, detail="HTTP 401 Unauthorized")
        if status_code == 403:
            return SemanticResult(status=ResultStatus.DENIED.value, detail="HTTP 403 Forbidden")
        if status_code == 408 or status_code == 504:
            return SemanticResult(
                status=ResultStatus.TIMEOUT.value, detail=f"HTTP {status_code} Timeout"
            )
        if status_code >= 400:
            return SemanticResult(
                status=ResultStatus.FAILURE.value, detail=f"HTTP error {status_code}"
            )

    # Action-driven default result
    act = action.semantic.lower()
    if act in ("allow", "accept"):
        return SemanticResult(status=ResultStatus.ALLOWED.value, detail=f"Action '{act}' permitted")
    if act in ("deny", "reject"):
        return SemanticResult(status=ResultStatus.DENIED.value, detail=f"Action '{act}' denied")
    if act in ("drop", "block", "quarantine"):
        return SemanticResult(status=ResultStatus.BLOCKED.value, detail=f"Action '{act}' blocked")
    if act in ("fail",):
        return SemanticResult(status=ResultStatus.FAILURE.value, detail="Action failure")
    crud_acts = {
        "create",
        "delete",
        "modify",
        "execute",
        "start",
        "stop",
        "connect",
        "read",
        "write",
    }
    if act in crud_acts:
        return SemanticResult(status=ResultStatus.SUCCESS.value, detail=f"Action '{act}' completed")

    return SemanticResult(status=ResultStatus.UNKNOWN.value, detail="Undetermined result status")
