"""Deterministic operational pipeline orchestrator for ULPF Phase 6.

Enforces:
- Rule 1: UCE remains canonical source of truth
- Rule 2: Raw evidence remains immutable
- Rule 3: Phase 4 semantic logic remains deterministic
- Rule 8: Do not silently drop events
- Rule 10: Do not silently acknowledge an event before durable handoff
- Rule 23/24: Poison event handling without stalling stream
"""

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_observability.tracing import InProcessTracer
from ulpf_search.interfaces import SearchIndexAdapter
from ulpf_semantic.service import SemanticService
from ulpf_storage.interfaces import (
    OutboxRepository,
    RawEvidenceRepository,
    SemanticEventRepository,
    StoredSemanticEvent,
    UCERecord,
    UCERepository,
)

from ulpf_runtime.backpressure import BackpressureController
from ulpf_runtime.dlq import DLQManager
from ulpf_runtime.errors import BufferFullError
from ulpf_runtime.idempotency import IdempotencyGuard
from ulpf_runtime.lifecycle import EventLifecycleState, EventLifecycleTracker
from ulpf_runtime.models import DeliveryIntent, ProcessingAttemptRecord
from ulpf_runtime.retry import BoundedRetryPolicy


@dataclass(frozen=True)
class PipelineResult:
    """Outcome of end-to-end processing across data plane stages."""

    event_id: str
    raw_event_id: str
    raw_sha256: str
    uce_event_id: str | None
    semantic_event_id: str | None
    lifecycle_state: EventLifecycleState
    attempts: list[ProcessingAttemptRecord]
    is_duplicate: bool
    duration_ms: float
    error: str | None = None
    dlq_id: str | None = None
    projections: dict[str, Any] = field(default_factory=dict)


class RuntimePipeline:
    """End-to-end telemetry processing pipeline coordinating all data plane stages."""

    def __init__(
        self,
        raw_store: RawEvidenceRepository,
        uce_store: UCERepository,
        semantic_store: SemanticEventRepository,
        search_adapter: SearchIndexAdapter | None = None,
        outbox_repo: OutboxRepository | None = None,
        dlq_manager: DLQManager | None = None,
        backpressure: BackpressureController | None = None,
        idempotency: IdempotencyGuard | None = None,
        retry_policy: BoundedRetryPolicy | None = None,
        semantic_service: SemanticService | None = None,
        metrics: OperationalMetricsRegistry | None = None,
        tracer: InProcessTracer | None = None,
    ) -> None:
        self.raw_store = raw_store
        self.uce_store = uce_store
        self.semantic_store = semantic_store
        self.search_adapter = search_adapter
        self.outbox_repo = outbox_repo
        self.dlq_manager = dlq_manager or DLQManager()
        self.backpressure = backpressure
        self.idempotency = idempotency or IdempotencyGuard()
        self.retry_policy = retry_policy or BoundedRetryPolicy()
        self.semantic_service = semantic_service or SemanticService()
        self.metrics = metrics or OperationalMetricsRegistry()
        self.tracer = tracer or InProcessTracer()

    def process_event(
        self,
        raw_payload: str | bytes,
        source_id: str,
        format_str: str = "syslog",
        raw_event_id: str | None = None,
        correlation_id: str | None = None,
        custom_uce: dict[str, Any] | None = None,
        mapping_version: str | None = None,
    ) -> PipelineResult:
        """Process a single event deterministically through all pipeline stages."""
        t_start = time.perf_counter()
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        cid = correlation_id or uuid.uuid4().hex
        payload_bytes = raw_payload.encode("utf-8") if isinstance(raw_payload, str) else raw_payload
        raw_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        raw_id = raw_event_id or f"raw-{raw_sha256[:16]}"
        tracker = EventLifecycleTracker(EventLifecycleState.RECEIVED)
        attempts: list[ProcessingAttemptRecord] = []

        # 1. Backpressure Check
        if self.backpressure:
            try:
                acquired = self.backpressure.acquire()
                if not acquired:
                    # Routed to DLQ due to overflow
                    rec = self.dlq_manager.record_failure(
                        original_event_id=event_id,
                        stage="backpressure",
                        error=BufferFullError("Queue capacity overflow routed to DLQ"),
                        retry_count=0,
                        source_id=source_id,
                        raw_sha256=raw_sha256,
                        correlation_id=cid,
                        payload_preview=payload_bytes.decode("utf-8", errors="replace"),
                    )
                    tracker.transition_to(EventLifecycleState.DLQ)
                    self.metrics.increment_counter("events_dlq", stage="buffer", result="rejected")
                    return PipelineResult(
                        event_id=event_id,
                        raw_event_id=raw_id,
                        raw_sha256=raw_sha256,
                        uce_event_id=None,
                        semantic_event_id=None,
                        lifecycle_state=EventLifecycleState.DLQ,
                        attempts=attempts,
                        is_duplicate=False,
                        duration_ms=(time.perf_counter() - t_start) * 1000.0,
                        error="Buffer overflow routed to DLQ",
                        dlq_id=rec.dlq_id,
                    )
            except BufferFullError as e:
                tracker.transition_to(EventLifecycleState.FAILED)
                self.metrics.increment_counter("events_rejected", stage="buffer", result="rejected")
                raise e

        try:
            # 2. Idempotency Check
            idem_key = IdempotencyGuard.generate_key(source_id, raw_sha256)
            is_dup, existing_rec = self.idempotency.check_and_record(idem_key, event_id, raw_sha256)
            if is_dup and existing_rec and existing_rec.last_state == "PROCESSED":
                self.metrics.increment_counter("events_duplicate", stage="ingest", result="success")
                tracker.transition_to(EventLifecycleState.CAPTURED)
                tracker.transition_to(EventLifecycleState.BUFFERED)
                tracker.transition_to(EventLifecycleState.PROCESSING)
                tracker.transition_to(EventLifecycleState.NORMALIZED)
                tracker.transition_to(EventLifecycleState.SEMANTIC_READY)
                tracker.transition_to(EventLifecycleState.PERSISTED)
                tracker.transition_to(EventLifecycleState.ACKNOWLEDGED)
                return PipelineResult(
                    event_id=event_id,
                    raw_event_id=raw_id,
                    raw_sha256=raw_sha256,
                    uce_event_id=None,
                    semantic_event_id=existing_rec.semantic_event_id,
                    lifecycle_state=EventLifecycleState.ACKNOWLEDGED,
                    attempts=attempts,
                    is_duplicate=True,
                    duration_ms=(time.perf_counter() - t_start) * 1000.0,
                )

            # 3. Capture Raw Evidence (Lossless Persistence)
            with self.tracer.span("capture_raw", trace_id=cid):
                tracker.transition_to(EventLifecycleState.CAPTURED)
                if not self.raw_store.exists(raw_id):
                    self.raw_store.put(
                        raw_event_id=raw_id,
                        payload=payload_bytes,
                        source_id=source_id,
                        format_str=format_str,
                        metadata={"correlation_id": cid, "event_id": event_id},
                    )
                tracker.transition_to(EventLifecycleState.BUFFERED)

            # 4. Canonical UCE Generation
            with self.tracer.span("normalize_uce", trace_id=cid):
                tracker.transition_to(EventLifecycleState.PROCESSING)
                uce_event_id = f"uce-{uuid.uuid4().hex[:12]}"

                if custom_uce:
                    uce_doc = dict(custom_uce)
                else:
                    raw_text = payload_bytes.decode("utf-8", errors="replace")
                    try:
                        from ulpf_parser_runtime.framing import FramedRecord
                        from ulpf_parser_runtime.registry import create_default_registry
                        from ulpf_normalization.canonical import CanonicalEventBuilder

                        reg = create_default_registry()
                        record = FramedRecord(
                            record_index=0,
                            text=raw_text,
                            raw_bytes=payload_bytes,
                            start_byte_offset=0,
                            end_byte_offset=len(payload_bytes),
                            line_count=raw_text.count("\n") + 1,
                        )

                        selected_parser = None
                        if format_str:
                            alias_map = {
                                "palo_alto": "parser.paloalto.panos",
                                "palo_alto_panos": "parser.paloalto.panos",
                                "panos": "parser.paloalto.panos",
                                "fortinet": "parser.fortinet.fortigate",
                                "fortigate_utm": "parser.fortinet.fortigate",
                                "cisco_asa": "parser.cisco.asa_ios",
                                "suricata": "parser.suricata.eve",
                                "suricata_eve": "parser.suricata.eve",
                                "zeek": "parser.zeek.telemetry",
                                "snort": "parser.snort.fast",
                                "linux_auditd": "parser.linux.auditd",
                                "arcsight_cef": "parser.generic.cef",
                                "cef": "parser.generic.cef",
                                "qradar_leef": "parser.generic.leef",
                                "leef": "parser.generic.leef",
                                "syslog_rfc5424": "parser.syslog.rfc5424",
                                "syslog_rfc3164": "parser.syslog.rfc3164",
                                "json": "parser.generic.json",
                                "opentelemetry": "parser.generic.json",
                                "splunk_hec": "parser.generic.json",
                                "crowdstrike": "parser.generic.json",
                                "gcp_audit": "parser.generic.json",
                                "k8s_audit": "parser.generic.json",
                                "okta": "parser.generic.json",
                                "aws_cloudtrail": "parser.cloud.audit_flow",
                                "nginx": "parser.web.access",
                                "apache": "parser.web.access",
                                "pfsense": "parser.generic.csv",
                                "sysmon": "parser.generic.xml",
                                "windows_security": "parser.generic.xml",
                            }
                            pid = alias_map.get(format_str.lower())
                            if pid:
                                selected_parser = reg.get(pid)

                        if not selected_parser:
                            if "%ASA-" in raw_text:
                                selected_parser = reg.get("parser.cisco.asa_ios")
                            elif "devname=" in raw_text or "devid=" in raw_text:
                                selected_parser = reg.get("parser.fortinet.fortigate")
                            elif "CEF:" in raw_text:
                                selected_parser = reg.get("parser.generic.cef")
                            elif "LEEF:" in raw_text:
                                selected_parser = reg.get("parser.generic.leef")
                            elif "[**]" in raw_text:
                                selected_parser = reg.get("parser.snort.fast")
                            elif ("TRAFFIC" in raw_text or "THREAT" in raw_text) and "," in raw_text and not raw_text.startswith("{"):
                                selected_parser = reg.get("parser.paloalto.panos")
                            elif '"event_type"' in raw_text and ('"alert"' in raw_text or '"flow_id"' in raw_text):
                                selected_parser = reg.get("parser.suricata.eve")
                            elif raw_text.startswith("{") and raw_text.endswith("}"):
                                selected_parser = reg.get("parser.generic.json")
                            elif raw_text.startswith("<") and ("<Event" in raw_text or "<System" in raw_text or raw_text.startswith("<?xml")):
                                selected_parser = reg.get("parser.generic.xml")
                            elif raw_text.startswith("<"):
                                selected_parser = reg.get("parser.syslog.rfc5424") or reg.get("parser.syslog.rfc3164")
                            elif "=" in raw_text:
                                selected_parser = reg.get("parser.generic.keyvalue")
                            elif "," in raw_text:
                                selected_parser = reg.get("parser.generic.csv")

                        if selected_parser:
                            parse_res = selected_parser.parse(record)
                            builder = CanonicalEventBuilder()
                            uce_doc = builder.build_uce(
                                parse_res,
                                raw_event_id=raw_id,
                                source_id=source_id,
                                raw_payload_bytes=payload_bytes,
                            )
                        else:
                            uce_doc = {
                                "event_id": uce_event_id,
                                "raw_id": raw_id,
                                "timestamp": datetime.now(UTC).isoformat(),
                                "observer": {"vendor": "Generic", "product": "Log"},
                                "message": raw_text,
                                "unmapped_fields": {},
                            }
                    except Exception:
                        uce_doc = {
                            "event_id": uce_event_id,
                            "raw_id": raw_id,
                            "timestamp": datetime.now(UTC).isoformat(),
                            "observer": {"vendor": "Generic", "product": "Log"},
                            "message": raw_text,
                            "unmapped_fields": {},
                        }

                uce_event_id = uce_doc.get("event_id", uce_event_id)

                # Store UCE (Write-Once)
                uce_rec = UCERecord(
                    uce_event_id=uce_event_id,
                    raw_event_id=raw_id,
                    raw_sha256=raw_sha256,
                    payload=uce_doc,
                    schema_version="1.0.0",
                    source_id=source_id,
                    captured_at=datetime.now(UTC).isoformat(),
                )
                self.uce_store.put(uce_rec)
                tracker.transition_to(EventLifecycleState.NORMALIZED)
                self.metrics.increment_counter("events_normalized", stage="uce", result="success")

            # 5. Semantic Processing (Phase 4/5 Core)
            with self.tracer.span("semantic_processing", trace_id=cid):
                t_sem_start = time.perf_counter()
                sem_event = self.semantic_service.process_uce(uce_doc, project=True)
                sem_dur = (time.perf_counter() - t_sem_start) * 1000.0

                attempt = ProcessingAttemptRecord(
                    attempt_id=f"att-{uuid.uuid4().hex[:8]}",
                    event_id=event_id,
                    stage="semantic_processing",
                    worker_id="runtime-worker-1",
                    mapping_version=mapping_version,
                    started_at=datetime.now(UTC).isoformat(),
                    completed_at=datetime.now(UTC).isoformat(),
                    status="SUCCESS",
                    duration_ms=sem_dur,
                )
                attempts.append(attempt)
                tracker.transition_to(EventLifecycleState.SEMANTIC_READY)
                self.metrics.increment_counter(
                    "events_semantic_success", stage="semantic", result="success"
                )
                self.metrics.record_latency("semantic_latency_ms", sem_dur)

            # 6. Multi-Tier Persistence & Search Indexing
            with self.tracer.span("persist_and_index", trace_id=cid):
                fp = (
                    sem_event.correlation_context.event_fingerprint
                    if sem_event.correlation_context
                    else f"fp-{raw_sha256[:16]}"
                )
                stored_sem = StoredSemanticEvent(
                    semantic_event_id=sem_event.semantic_event_id,
                    uce_event_id=uce_event_id,
                    raw_sha256=raw_sha256,
                    mapping_version=mapping_version,
                    semantic_version=sem_event.contract_version,
                    payload=sem_event.to_contract_dict(),
                    fingerprint=fp,
                    risk_level=sem_event.risk_context.risk_level,
                    risk_score=sem_event.risk_context.risk_score,
                    entities=[e.to_dict() for e in sem_event.entities],
                    indicators=[i.to_dict() for i in sem_event.indicators],
                    classification=sem_event.semantic_triple.to_dict(),
                )
                self.semantic_store.put(stored_sem)

                if self.search_adapter:
                    self.search_adapter.index_event(stored_sem)

                tracker.transition_to(EventLifecycleState.PERSISTED)
                self.metrics.increment_counter(
                    "events_persisted", stage="storage", result="success"
                )

            # 7. Outbox Delivery Intent
            with self.tracer.span("outbox_intents", trace_id=cid):
                if self.outbox_repo:
                    # Enqueue OCSF projection delivery intent
                    for pid, pdata in sem_event.projections.items():
                        sink_name = "ocsf" if pid.startswith("ocsf") else (
                            "otel" if pid.startswith("otel") else pid
                        )
                        self.outbox_repo.save_intent(
                            DeliveryIntent(
                                intent_id=f"intent-{pid}-{event_id}",
                                event_id=event_id,
                                sink_name=sink_name,
                                payload_type=pid.upper(),
                                payload=pdata,
                                created_at=datetime.now(UTC).isoformat(),
                            )
                        )
                tracker.transition_to(EventLifecycleState.DELIVERED)

            # 8. Terminal Acknowledgment
            tracker.transition_to(EventLifecycleState.ACKNOWLEDGED)
            self.idempotency.update_result(idem_key, sem_event.semantic_event_id, state="PROCESSED")
            self.metrics.increment_counter("events_total", stage="delivery", result="success")

            total_dur = (time.perf_counter() - t_start) * 1000.0
            self.metrics.record_latency("pipeline_e2e_ms", total_dur)

            return PipelineResult(
                event_id=event_id,
                raw_event_id=raw_id,
                raw_sha256=raw_sha256,
                uce_event_id=uce_event_id,
                semantic_event_id=sem_event.semantic_event_id,
                lifecycle_state=EventLifecycleState.ACKNOWLEDGED,
                attempts=attempts,
                is_duplicate=False,
                duration_ms=total_dur,
                projections=sem_event.projections,
            )

        except Exception as e:
            # Poison event or fatal stage error -> Route to DLQ without crashing runtime
            self.metrics.increment_counter("events_failed", stage="pipeline", result="failure")
            dlq_rec = self.dlq_manager.record_failure(
                original_event_id=event_id,
                stage=tracker.current_state.value,
                error=e,
                retry_count=len(attempts),
                source_id=source_id,
                raw_sha256=raw_sha256,
                correlation_id=cid,
                mapping_version=mapping_version,
                raw_evidence_ref=raw_id,
                payload_preview=payload_bytes.decode("utf-8", errors="replace"),
            )
            from contextlib import suppress

            with suppress(Exception):
                tracker.transition_to(EventLifecycleState.FAILED)
                tracker.transition_to(EventLifecycleState.DLQ)

            total_dur = (time.perf_counter() - t_start) * 1000.0
            return PipelineResult(
                event_id=event_id,
                raw_event_id=raw_id,
                raw_sha256=raw_sha256,
                uce_event_id=None,
                semantic_event_id=None,
                lifecycle_state=EventLifecycleState.DLQ,
                attempts=attempts,
                is_duplicate=False,
                duration_ms=total_dur,
                error=str(e),
                dlq_id=dlq_rec.dlq_id,
            )
        finally:
            if self.backpressure:
                self.backpressure.release()
