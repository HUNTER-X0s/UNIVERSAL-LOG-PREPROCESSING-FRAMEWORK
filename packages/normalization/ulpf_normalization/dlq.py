"""Dead-Letter Queue (DLQ) envelope builder for ULPF Phase 3.

Adheres to:
- contracts/jsonschema/dlq-event.v1.schema.json
- contracts/jsonschema/ulpf-common.v1.schema.json#/$defs/error
- Spec §37: Error Handling & DLQ Management
"""

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_parser_runtime.errors import ParseError


class DLQEventBuilder:
    """Constructs DLQEvent v1 instances for quarantined or unprocessable records."""

    contract_version: str = "1.0.0"

    def build_dlq_event(
        self,
        error: ParseError,
        raw_payload_bytes: bytes,
        raw_event_id: str | None = None,
        source_id: str | None = None,
        parser_id: str | None = None,
        parser_version: str | None = None,
        processing_run_id: str | None = None,
        status: str = "quarantined",
        replay_eligible: bool = True,
    ) -> dict[str, Any]:
        """Produce a complete DLQ event conforming to dlq-event.v1.schema.json."""
        dlq_id = f"dlq_{uuid.uuid4().hex[:16]}"
        raw_id = raw_event_id or f"raw_{uuid.uuid4().hex[:16]}"
        src_id = source_id or f"src_{uuid.uuid4().hex[:16]}"
        manifest_id = f"evm_{uuid.uuid4().hex[:16]}"
        now_iso = datetime.now(UTC).isoformat()
        payload_hash = hashlib.sha256(raw_payload_bytes).hexdigest()

        parser_ref = {"id": parser_id, "version": parser_version or "1.0.0"} if parser_id else None

        dlq_event: dict[str, Any] = {
            "contract_version": self.contract_version,
            "dlq_event_id": dlq_id,
            "raw_event_id": raw_id,
            "source_id": src_id,
            "evidence": {
                "payload_sha256": payload_hash,
                "evidence_manifest_id": manifest_id,
            },
            "artifact_context": {
                "parser_selection_status": "selected" if parser_id else "not_selected",
                "source_profile": None,
                "parser": parser_ref,
                "mapping": None,
                "schema": None,
            },
            "failure": {
                "code": error.code.value,
                "stage": error.stage,
                "message": error.message[:4096],
                "recoverable": error.recoverable,
                "occurred_at": error.occurred_at.isoformat(),
            },
            "status": status,
            "attempt_count": 1,
            "failed_at": now_iso,
            "replay_eligible": replay_eligible,
            "created_at": now_iso,
        }

        if processing_run_id:
            dlq_event["artifact_context"]["processing_run_id"] = processing_run_id

        return dlq_event
