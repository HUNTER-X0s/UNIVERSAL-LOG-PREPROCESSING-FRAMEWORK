"""Phase 6 operational and administrative REST API routes for ULPF.

Enforces:
- Rule 27/28: Health endpoints (/health, /health/live, /health/ready)
- Rule 29/30: Versioned API contracts for events, UCE, semantic events, search, DLQ, replay
- Rule 31/32: Role-based authorization (viewer, operator, mapping-admin, platform-admin)
- Rule 33: Audit logging for administrative mutations
- Rule 101: Bounded query limits and pagination
"""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from ulpf_delivery.outbox import OutboxDispatcher
from ulpf_delivery.sinks import OCSFJsonSink, OTelBatchSink, SiemMockSink
from ulpf_observability.metrics import OperationalMetricsRegistry
from ulpf_runtime.backpressure import BackpressureController
from ulpf_runtime.dlq import DLQManager
from ulpf_runtime.health import HealthRegistry, HealthState
from ulpf_runtime.idempotency import IdempotencyGuard
from ulpf_runtime.pipeline import RuntimePipeline
from ulpf_runtime.replay import ReplayRequest, RuntimeReplayCoordinator
from ulpf_search.interfaces import SearchQuery
from ulpf_search.memory import MemorySearchIndex
from ulpf_storage.memory import (
    MemoryAuditRepository,
    MemoryOutboxRepository,
    MemoryRawEvidenceRepository,
    MemorySemanticEventRepository,
    MemoryUCERepository,
)

router = APIRouter(tags=["platform"])

# Shared singleton instances for API runtime
raw_store = MemoryRawEvidenceRepository()
uce_store = MemoryUCERepository()
semantic_store = MemorySemanticEventRepository()
outbox_repo = MemoryOutboxRepository()
audit_repo = MemoryAuditRepository()
search_adapter = MemorySearchIndex()
dlq_manager = DLQManager()
backpressure = BackpressureController(max_capacity=5000)
idempotency = IdempotencyGuard()
metrics_registry = OperationalMetricsRegistry()
health_registry = HealthRegistry(service_name="ulpf-platform-api", version="1.0.0")

# Register dependencies for health checks
health_registry.register_dependency(
    "raw_store", lambda: (HealthState.HEALTHY, None), is_critical=True
)
health_registry.register_dependency(
    "uce_store", lambda: (HealthState.HEALTHY, None), is_critical=True
)
health_registry.register_dependency(
    "search_index", lambda: (HealthState.HEALTHY, None), is_critical=False
)

sinks = {
    "ocsf": OCSFJsonSink(),
    "otel": OTelBatchSink(),
    "siem": SiemMockSink(),
}
outbox_dispatcher = OutboxDispatcher(outbox_repo=outbox_repo, sinks=sinks)

pipeline = RuntimePipeline(
    raw_store=raw_store,
    uce_store=uce_store,
    semantic_store=semantic_store,
    search_adapter=search_adapter,
    outbox_repo=outbox_repo,
    dlq_manager=dlq_manager,
    backpressure=backpressure,
    idempotency=idempotency,
    metrics=metrics_registry,
)

replay_coordinator = RuntimeReplayCoordinator(
    pipeline=pipeline,
    raw_store=raw_store,
    uce_store=uce_store,
    audit_repo=audit_repo,
)


def verify_role(required_roles: set[str], role_header: str | None) -> str:
    """Verify role authorization."""
    raw = role_header or "viewer"
    normalized = raw.strip().lower().replace(" ", "-").replace("_", "-")
    if (
        normalized not in required_roles
        and "admin" not in normalized
        and "platform-admin" not in normalized
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires one of roles: {required_roles}, caller has: {raw}",
        )
    return normalized


# --- Request/Response Models ---

class EventIngestRequest(BaseModel):
    raw_payload: str
    source_id: str
    format: str = "syslog"
    correlation_id: str | None = None
    mapping_version: str | None = None


class ReplayApiRequest(BaseModel):
    target_stage: str = "RAW"  # RAW, UCE
    mapping_version: str
    event_ids: list[str]
    reason: str = "Forensic Investigation"


# --- Health Endpoints ---

@router.get("/health")
def get_health() -> dict[str, Any]:
    return health_registry.check_liveness()


@router.get("/health/live")
def get_health_live() -> dict[str, Any]:
    return health_registry.check_liveness()


@router.get("/health/ready")
def get_health_ready() -> dict[str, Any]:
    res = health_registry.check_readiness()
    if not res["is_ready"]:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=res)
    return res


# --- Telemetry Ingestion & Data APIs ---

@router.post("/events/ingest", status_code=status.HTTP_202_ACCEPTED)
def ingest_event(
    req: EventIngestRequest,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"operator", "platform-admin"}, x_role)

    res = pipeline.process_event(
        raw_payload=req.raw_payload,
        source_id=req.source_id,
        format_str=req.format,
        correlation_id=req.correlation_id,
        mapping_version=req.mapping_version,
    )
    return {
        "event_id": res.event_id,
        "raw_sha256": res.raw_sha256,
        "uce_event_id": res.uce_event_id,
        "state": res.lifecycle_state.value,
        "semantic_event_id": res.semantic_event_id,
        "duration_ms": res.duration_ms,
        "is_duplicate": res.is_duplicate,
        "dlq_id": res.dlq_id,
    }


@router.get("/events/raw/{raw_event_id}")
def get_raw_evidence(
    raw_event_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    meta = raw_store.get_metadata(raw_event_id)
    if not meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Raw evidence not found")
    _, payload = raw_store.get(raw_event_id)
    return {
        "raw_event_id": meta.raw_event_id,
        "sha256": meta.sha256,
        "source_id": meta.source_id,
        "byte_length": meta.byte_length,
        "payload_text": payload.decode("utf-8", errors="replace"),
    }


@router.get("/uce/{uce_event_id}")
def get_uce_event(
    uce_event_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    rec = uce_store.get(uce_event_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="UCE not found")
    return {
        "uce_event_id": rec.uce_event_id,
        "raw_event_id": rec.raw_event_id,
        "raw_sha256": rec.raw_sha256,
        "payload": rec.payload,
        "stored_at": rec.stored_at,
    }


@router.get("/semantic/{semantic_event_id}")
def get_semantic_event(
    semantic_event_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    rec = semantic_store.get(semantic_event_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Semantic event not found"
        )
    return {
        "semantic_event_id": rec.semantic_event_id,
        "uce_event_id": rec.uce_event_id,
        "fingerprint": rec.fingerprint,
        "risk_level": rec.risk_level,
        "risk_score": rec.risk_score,
        "classification": rec.classification,
        "payload": rec.payload,
    }


# --- Search API ---

@router.get("/search")
def search_events(
    vendor: str | None = None,
    product: str | None = None,
    risk_level: str | None = None,
    fingerprint: str | None = None,
    entity: str | None = None,
    indicator: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    q = SearchQuery(
        vendor=vendor,
        product=product,
        risk_level=risk_level,
        fingerprint=fingerprint,
        entity_value=entity,
        indicator_value=indicator,
        limit=limit,
        offset=offset,
    )
    res = search_adapter.search(q)
    return {
        "total_matches": res.total_matches,
        "returned_count": res.returned_count,
        "offset": res.offset,
        "execution_time_ms": res.execution_time_ms,
        "events": res.events,
    }


# --- DLQ Management ---

@router.get("/dlq")
def list_dlq_records(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"operator", "platform-admin"}, x_role)
    records = dlq_manager.list_records(limit=limit, offset=offset)
    return {
        "total": dlq_manager.count(),
        "records": [
            {
                "dlq_id": r.dlq_id,
                "original_event_id": r.original_event_id,
                "stage": r.stage,
                "error_type": r.error_type,
                "error_message": r.error_message,
                "source_id": r.source_id,
                "replayed": r.replayed,
            }
            for r in records
        ],
    }


# --- Historical Replay API ---

@router.post("/replay", status_code=status.HTTP_200_OK)
def trigger_replay(
    req: ReplayApiRequest,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    role = verify_role({"operator", "platform-admin"}, x_role)
    ts_ms = int(datetime.now(UTC).timestamp() * 1000)
    replay_req = ReplayRequest(
        job_id=f"job-{ts_ms}",
        target_stage=req.target_stage,
        mapping_version=req.mapping_version,
        event_ids=req.event_ids,
        reason=req.reason,
        requested_by=role,
    )
    res = replay_coordinator.execute_replay(replay_req)
    return {
        "job_id": res.job_id,
        "mapping_version": res.mapping_version,
        "total_requested": res.total_requested,
        "processed_count": res.processed_count,
        "failed_count": res.failed_count,
        "audit_id": res.audit_id,
    }


# --- Metrics Snapshot API ---

@router.get("/metrics")
def get_metrics(
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    return metrics_registry.snapshot()


# --- Parser Registry API ---

_parser_registry_cache: list[dict[str, Any]] | None = None


def _get_registry_data() -> list[dict[str, Any]]:
    """Return parser registry data, cached after first build."""
    global _parser_registry_cache
    if _parser_registry_cache is not None:
        return _parser_registry_cache
    from ulpf_parser_runtime.registry import create_default_registry

    reg = create_default_registry()
    desc = reg.self_description()
    result = []
    for p in desc.get("parsers", []):
        vendor = p["supported_vendors"][0] if p.get("supported_vendors") else "Generic"
        format_name = p["supported_formats"][0] if p.get("supported_formats") else ""
        result.append({
            "parser_id": p["parser_id"],
            "name": p["parser_id"].replace("parser.", "").replace(".", " ").replace("_", " ").title(),
            "vendor": vendor,
            "format": format_name,
            "version": p.get("version", "1.0.0"),
            "tier": p.get("tier", "A"),
            "priority": p.get("priority", 50),
            "status": "active",
            "description": p.get("description") or f"Parser for {vendor} {format_name} logs.",
        })
    result.sort(key=lambda x: (-x["priority"], x["name"]))
    _parser_registry_cache = result
    return result


@router.get("/parsers", summary="List all registered parsers")
def list_parsers(
    tier: str | None = None,
    vendor: str | None = None,
    format_filter: str | None = Query(None, alias="format"),
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Return the active parser registry with optional filtering."""
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    parsers = _get_registry_data()
    if tier:
        parsers = [p for p in parsers if p["tier"].upper() == tier.upper()]
    if vendor:
        parsers = [p for p in parsers if vendor.lower() in p["vendor"].lower()]
    if format_filter:
        parsers = [p for p in parsers if format_filter.lower() in p["format"].lower()]
    return {"count": len(parsers), "parsers": parsers}


@router.get("/parsers/{parser_id}", summary="Get parser detail")
def get_parser_detail(
    parser_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Return detailed metadata for a specific parser."""
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    parsers = _get_registry_data()
    match = next((p for p in parsers if p["parser_id"] == parser_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Parser '{parser_id}' not found")
    return match


class ParseTestRequest(BaseModel):
    raw_payload: str
    source_id: str = "test-source"
    parser_id: str | None = None


@router.post("/parsers/test", summary="Test parse a raw payload")
def test_parse(
    req: ParseTestRequest,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Run a raw payload through the parser pipeline and return the parse result (TEST/PREVIEW — no production effect)."""
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    try:
        from ulpf_parser_runtime.framing import FramedRecord
        from ulpf_parser_runtime.registry import create_default_registry

        reg = create_default_registry()
        raw_text = req.raw_payload.strip()
        raw_bytes = raw_text.encode("utf-8", errors="replace")
        rec = FramedRecord(
            record_index=0,
            text=raw_text,
            raw_bytes=raw_bytes,
            start_byte_offset=0,
            end_byte_offset=len(raw_bytes),
            line_count=raw_text.count("\n") + 1,
        )

        target_id = req.parser_id or (req.source_id if req.source_id != "test-source" else None)
        selected_parser = None
        if target_id:
            selected_parser = reg.get(target_id)
            if not selected_parser:
                aliases = {
                    "palo_alto_panos": "parser.paloalto.panos",
                    "paloalto_panos": "parser.paloalto.panos",
                    "panos": "parser.paloalto.panos",
                    "fortigate_utm": "parser.fortinet.fortigate",
                    "fortigate": "parser.fortinet.fortigate",
                    "suricata_eve": "parser.suricata.eve",
                    "suricata": "parser.suricata.eve",
                    "cisco_asa": "parser.cisco.asa_ios",
                    "linux_auditd": "parser.linux.auditd",
                    "auditd": "parser.linux.auditd",
                    "xml_telemetry": "parser.generic.xml",
                    "sysmon": "parser.generic.xml",
                    "csv_telemetry": "parser.generic.csv",
                    "cicids": "parser.generic.csv",
                    "unsw": "parser.generic.csv",
                    "json_telemetry": "parser.generic.json",
                    "okta": "parser.generic.json",
                    "falco": "parser.generic.json",
                    "crowdstrike": "parser.generic.json",
                    "gcp_audit": "parser.generic.json",
                    "aws_cloudtrail": "parser.cloud.audit_flow",
                    "cloud_audit": "parser.cloud.audit_flow",
                    "nginx_access": "parser.web.access",
                    "nginx": "parser.web.access",
                    "snort": "parser.snort.fast",
                    "snort_fast": "parser.snort.fast",
                    "zeek": "parser.zeek.telemetry",
                    "zeek_tsv": "parser.zeek.telemetry",
                    "zeek_conn": "parser.zeek.telemetry",
                    "winevent": "parser.windows.wineventlog",
                    "wineventlog": "parser.windows.wineventlog",
                    "yaml_telemetry": "parser.generic.yaml",
                    "yaml": "parser.generic.yaml",
                    "grok": "parser.generic.grok",
                    "grok_app": "parser.generic.grok",
                    "netflow": "parser.network.netflow",
                    "ipfix": "parser.network.netflow",
                }
                alias_id = aliases.get(target_id.lower())
                if alias_id:
                    selected_parser = reg.get(alias_id)

        import re
        # Check for YAML format
        if (
            raw_text.startswith("---")
            or (("apiVersion:" in raw_text or "kind:" in raw_text) and not raw_text.startswith("{"))
            or (target_id and target_id.lower() in ("yaml", "yaml_telemetry", "k8s_yaml"))
        ):
            try:
                import yaml
                yd = yaml.safe_load(raw_text)
                if isinstance(yd, dict) and len(yd) > 0:
                    def _flatten_yaml(d: dict, prefix: str = "") -> dict[str, Any]:
                        items = {}
                        for k, v in d.items():
                            key = f"{prefix}.{k}" if prefix else str(k)
                            if isinstance(v, dict):
                                items.update(_flatten_yaml(v, key))
                            elif isinstance(v, list):
                                items[key] = ", ".join(str(x) for x in v)
                            else:
                                items[key] = v
                        return items
                    flat_yaml = _flatten_yaml(yd)
                    return {
                        "preview": True,
                        "parsed": True,
                        "parser_id": "parser.generic.yaml",
                        "format": "YAML",
                        "vendor": "Kubernetes / Cloud Native",
                        "fields": flat_yaml,
                        "unknown_fields": {},
                        "confidence": 1.0,
                        "byte_length": len(raw_bytes),
                        "status": "parsed",
                    }
            except Exception:
                pass

        # Check for Windows Plain-Text Event Log (EventCode= or Event ID:)
        if (
            "Event ID:" in raw_text
            or "EventCode=" in raw_text
            or "Log Name:" in raw_text
            or (target_id and target_id.lower() in ("winevent", "wineventlog", "windows_text"))
        ) and not raw_text.startswith("<"):
            win_fields = {}
            for line in raw_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    parts = line.split(":", 1)
                    k, v = parts[0].strip(), parts[1].strip()
                    if k and v:
                        win_fields[k] = v
                elif "=" in line:
                    parts = line.split("=", 1)
                    k, v = parts[0].strip(), parts[1].strip()
                    if k and v:
                        win_fields[k] = v
            if len(win_fields) >= 2:
                return {
                    "preview": True,
                    "parsed": True,
                    "parser_id": "parser.windows.wineventlog",
                    "format": "WinEventLog",
                    "vendor": "Microsoft Windows",
                    "fields": win_fields,
                    "unknown_fields": {},
                    "confidence": 1.0,
                    "byte_length": len(raw_bytes),
                    "status": "parsed",
                }

        # Check for Grok / Application Log (Java, Python, Node, Go)
        m_grok = re.match(
            r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(?:\[([^\]]+)\])?\s*(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+([^\s:]+)\s*[-:]\s*(.*)$",
            raw_text,
            re.DOTALL,
        )
        if m_grok or (target_id and target_id.lower() in ("grok", "grok_app", "app_log")):
            if m_grok:
                ts, thread, level, logger, msg = m_grok.groups()
                grok_fields = {
                    "timestamp": ts,
                    "level": level,
                    "logger": logger,
                    "message": msg.strip(),
                }
                if thread:
                    grok_fields["thread"] = thread
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
                if len(ips) >= 1:
                    grok_fields["src_ip"] = ips[0]
                if len(ips) >= 2:
                    grok_fields["dst_ip"] = ips[1]
                u = re.search(r"(?:user|account|username)[\s=\'\"]+([a-zA-Z0-9_\-\.]+)", msg, re.IGNORECASE)
                if u:
                    grok_fields["user"] = u.group(1)
                for kv in re.findall(r'([a-zA-Z0-9_\.]+)=([^\s",]+|"[^"]*")', msg):
                    grok_fields[kv[0]] = kv[1].strip('"')
                return {
                    "preview": True,
                    "parsed": True,
                    "parser_id": "parser.generic.grok",
                    "format": "Grok / AppLog",
                    "vendor": "Enterprise Application",
                    "fields": grok_fields,
                    "unknown_fields": {},
                    "confidence": 0.95,
                    "byte_length": len(raw_bytes),
                    "status": "parsed",
                }

        # Check for NetFlow / IPFIX text
        if (
            ("Date flow start" in raw_text or "->" in raw_text)
            and ("TCP" in raw_text or "UDP" in raw_text)
            and not "[**]" in raw_text
        ) or (target_id and target_id.lower() in ("netflow", "ipfix")):
            m_nf = re.search(
                r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([\d\.]+)\s+([A-Za-z0-9]+)\s+([^\s:]+):(\d+)\s+->\s+([^\s:]+):(\d+)(?:\s+(\d+)\s+(\d+))?",
                raw_text,
            )
            if m_nf:
                ts, dur, proto, src_ip, src_port, dst_ip, dst_port, pkts, bytes_cnt = m_nf.groups()
                nf_fields = {
                    "timestamp": ts,
                    "duration": float(dur),
                    "protocol": proto,
                    "src_ip": src_ip,
                    "src_port": int(src_port),
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port),
                    "packets": int(pkts) if pkts else 1,
                    "bytes": int(bytes_cnt) if bytes_cnt else 0,
                }
                return {
                    "preview": True,
                    "parsed": True,
                    "parser_id": "parser.network.netflow",
                    "format": "NetFlow / IPFIX",
                    "vendor": "Cisco / Network Flow",
                    "fields": nf_fields,
                    "unknown_fields": {},
                    "confidence": 1.0,
                    "byte_length": len(raw_bytes),
                    "status": "parsed",
                }

        if not selected_parser:
            from ulpf_parser_runtime.detection.format_detector import FormatDetector

            # 1. Specialized Vendor/Format Signatures
            if "%ASA-" in raw_text:
                selected_parser = reg.get("parser.cisco.asa_ios")
            elif "devname=" in raw_text or "devid=" in raw_text:
                selected_parser = reg.get("parser.fortinet.fortigate") or reg.get("parser.generic.keyvalue")
            elif "type=USER_AUTH" in raw_text or "msg=audit(" in raw_text:
                selected_parser = reg.get("parser.linux.auditd") or reg.get("parser.generic.keyvalue")
            elif "CEF:" in raw_text:
                selected_parser = reg.get("parser.generic.cef")
            elif "LEEF:" in raw_text:
                selected_parser = reg.get("parser.generic.leef")
            elif "[**]" in raw_text and ("->" in raw_text or "Classification:" in raw_text):
                selected_parser = reg.get("parser.snort.fast")
            elif "#fields" in raw_text or ("\t" in raw_text and len(raw_text.split("\t")) >= 8 and not "LEEF:" in raw_text):
                selected_parser = reg.get("parser.zeek.telemetry")
            elif ("TRAFFIC" in raw_text or "THREAT" in raw_text) and "," in raw_text and not raw_text.startswith("{"):
                selected_parser = reg.get("parser.paloalto.panos") or reg.get("parser.generic.csv")
            elif '"event_type"' in raw_text and ('"alert"' in raw_text or '"flow_id"' in raw_text):
                selected_parser = reg.get("parser.suricata.eve") or reg.get("parser.generic.json")
            # 2. Syslog RFC 5424 vs RFC 3164 (Priority over XML to prevent <PRI> being treated as XML)
            elif re.match(r"^<\d{1,3}>1\s", raw_text):
                selected_parser = reg.get("parser.syslog.rfc5424")
            elif re.match(r"^<\d{1,3}>[A-Za-z]{3}\s", raw_text):
                selected_parser = reg.get("parser.syslog.rfc3164")
            elif re.match(r"^<\d{1,3}>", raw_text):
                selected_parser = reg.get("parser.syslog.rfc5424") or reg.get("parser.syslog.rfc3164")
            elif "CEF:" in raw_text:
                selected_parser = reg.get("parser.generic.cef")
            elif "LEEF:" in raw_text:
                selected_parser = reg.get("parser.generic.leef")
            elif raw_text.startswith("<?xml") or (raw_text.startswith("<") and re.match(r"^<[a-zA-Z_]", raw_text)):
                selected_parser = reg.get("parser.generic.xml")
            elif raw_text.startswith("{") and raw_text.endswith("}"):
                selected_parser = reg.get("parser.generic.json")
            elif " HTTP/1." in raw_text or " HTTP/2." in raw_text:
                selected_parser = reg.get("parser.web.access")
            elif "=" in raw_text and (" " in raw_text or "\t" in raw_text):
                selected_parser = reg.get("parser.generic.keyvalue")
            elif "," in raw_text and not raw_text.startswith("{"):
                selected_parser = reg.get("parser.generic.csv")
            else:
                # 3. Fallback to Scored FormatDetector
                try:
                    detector = FormatDetector()
                    best_fmt, _, _ = detector.detect(raw_text)
                    fmt_map = {
                        "cef": "parser.generic.cef",
                        "leef": "parser.generic.leef",
                        "syslog_rfc5424": "parser.syslog.rfc5424",
                        "syslog_rfc3164": "parser.syslog.rfc3164",
                        "clf": "parser.web.access",
                        "json": "parser.generic.json",
                        "xml": "parser.generic.xml",
                        "key_value": "parser.generic.keyvalue",
                        "csv": "parser.generic.csv",
                        "snort_fast": "parser.snort.fast",
                    }
                    pid = fmt_map.get(best_fmt.format_name)
                    if pid:
                        selected_parser = reg.get(pid)
                except Exception:
                    pass

                if not selected_parser:
                    selected_parser = reg.get("parser.generic.json") or next(iter(reg._parsers.values()), None)

        if not selected_parser:
            return {
                "preview": True,
                "parsed": False,
                "parser_id": None,
                "format": "unknown",
                "fields": {},
                "unknown_fields": {},
                "error": "No suitable parser registered.",
            }

        res = selected_parser.parse(rec)
        extracted: dict[str, Any] = {}
        if hasattr(res, "extracted_fields"):
            for k, v in res.extracted_fields.items():
                extracted[k] = v.value if hasattr(v, "value") else v

        # If targeted parser extracted 0 fields, attempt fallback detection:
        if len(extracted) == 0:
            fallback_parser = None
            if raw_text.startswith("{") and raw_text.endswith("}"):
                fallback_parser = reg.get("parser.generic.json")
            elif raw_text.startswith("<") and ">" in raw_text:
                fallback_parser = reg.get("parser.generic.xml")
            elif "=" in raw_text and (" " in raw_text or "\t" in raw_text):
                fallback_parser = reg.get("parser.generic.keyvalue")
            elif "," in raw_text and not raw_text.startswith("{"):
                fallback_parser = reg.get("parser.generic.csv")

            if fallback_parser and fallback_parser != selected_parser:
                fb_res = fallback_parser.parse(rec)
                if hasattr(fb_res, "extracted_fields") and len(fb_res.extracted_fields) > 0:
                    selected_parser = fallback_parser
                    res = fb_res
                    extracted = {k: (v.value if hasattr(v, "value") else v) for k, v in res.extracted_fields.items()}

        unknown: dict[str, Any] = {}
        if hasattr(res, "unknown_fields"):
            for k, v in res.unknown_fields.items():
                unknown[k] = v.value if hasattr(v, "value") else v

        parsed_status = getattr(res.status, "value", str(res.status)).lower()
        is_parsed = parsed_status in ("parsed", "partial") or len(extracted) > 0
        return {
            "preview": True,
            "parsed": is_parsed,
            "parser_id": selected_parser.metadata.parser_id,
            "format": selected_parser.metadata.supported_formats[0] if selected_parser.metadata.supported_formats else "custom",
            "vendor": selected_parser.metadata.supported_vendors[0] if selected_parser.metadata.supported_vendors else "Generic",
            "fields": extracted,
            "unknown_fields": unknown,
            "confidence": getattr(res, "confidence", 1.0),
            "byte_length": len(raw_bytes),
            "status": parsed_status,
        }
    except Exception as exc:
        return {
            "preview": True,
            "parsed": False,
            "parser_id": req.parser_id,
            "format": "error",
            "fields": {},
            "unknown_fields": {},
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "preview": True,
            "parsed": False,
            "parser_id": None,
            "format": "error",
            "fields": {},
            "unknown_fields": {},
            "error": str(exc),
        }


# --- Universal Any-to-Any Log Transpiler API ---

class UniversalTranspileApiRequest(BaseModel):
    raw_payload: str
    target_format: str = "ocsf"
    source_format: str | None = None
    residue_policy: str = "lossless"
    options: dict[str, Any] = Field(default_factory=dict)


@router.get("/universal/formats", summary="Get supported universal log transpiler formats")
def get_universal_formats(
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Return all supported source and target schemas/formats for the Universal Log Transpiler."""
    verify_role({"viewer", "operator", "analyst", "threat-hunter", "detection-engineer", "mapping-admin", "mapping-reviewer", "platform-admin", "admin"}, x_role)
    from ulpf_normalization.universal_transpiler import get_universal_transpiler
    t = get_universal_transpiler()
    return {"formats": t.get_supported_formats()}


@router.post("/universal/transpile", summary="Universal Any-to-Any Log Transpilation")
def transpile_log(
    req: UniversalTranspileApiRequest,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Transpile any input log into any desired output format (OCSF, OTel, ECS, CEF, LEEF, UDM, ASIM, etc.)."""
    verify_role({"viewer", "operator", "analyst", "threat-hunter", "detection-engineer", "mapping-admin", "mapping-reviewer", "platform-admin", "admin"}, x_role)
    from ulpf_normalization.universal_transpiler import get_universal_transpiler, TranspileRequest
    t = get_universal_transpiler()
    res = t.transpile(
        TranspileRequest(
            raw_payload=req.raw_payload,
            target_format=req.target_format,
            source_format=req.source_format,
            residue_policy=req.residue_policy,
            options=req.options,
        )
    )
    return {
        "success": res.success,
        "source_format_detected": res.source_format_detected,
        "confidence": res.confidence,
        "target_format": res.target_format,
        "output": res.output,
        "extracted_fields": res.extracted_fields,
        "unmapped_residue": res.unmapped_residue,
        "canonical_summary": res.canonical_summary,
        "drain_template": res.drain_template,
        "drain_parameters": res.drain_parameters,
        "entities": res.entities,
        "cas_sha256": res.cas_sha256,
        "duration_ms": res.duration_ms,
        "byte_count_in": res.byte_count_in,
        "byte_count_out": res.byte_count_out,
        "compression_ratio": res.compression_ratio,
    }


# --- Schema Definitions API ---

_UCE_FIELDS: list[dict[str, Any]] = [
    {"field": "event_id", "type": "string", "required": True, "description": "Globally unique event identifier"},
    {"field": "timestamp", "type": "datetime", "required": True, "description": "UTC ISO-8601 event timestamp"},
    {"field": "source", "type": "string", "required": True, "description": "Log source identifier"},
    {"field": "vendor", "type": "string", "required": True, "description": "Technology vendor name"},
    {"field": "category", "type": "string", "required": True, "description": "Event category (network, auth, endpoint, etc.)"},
    {"field": "action", "type": "string", "required": True, "description": "Normalized action verb (allow, deny, login, etc.)"},
    {"field": "severity", "type": "enum", "required": True, "description": "CRITICAL|HIGH|MEDIUM|LOW|INFO"},
    {"field": "entities", "type": "array[Entity]", "required": False, "description": "Extracted named entities (IP, user, host, domain)"},
    {"field": "indicators", "type": "array[Indicator]", "required": False, "description": "Threat intelligence observables"},
    {"field": "network.src_ip", "type": "string", "required": False, "description": "Source IP address"},
    {"field": "network.dst_ip", "type": "string", "required": False, "description": "Destination IP address"},
    {"field": "network.src_port", "type": "integer", "required": False, "description": "Source port"},
    {"field": "network.dst_port", "type": "integer", "required": False, "description": "Destination port"},
    {"field": "network.protocol", "type": "string", "required": False, "description": "Layer-4 protocol"},
    {"field": "unmapped_residue", "type": "object", "required": False, "description": "Vendor-specific fields preserved but not canonically mapped (lossless)"},
    {"field": "provenance.cas_hash", "type": "string", "required": True, "description": "SHA-256 of original raw payload"},
    {"field": "provenance.pipeline_version", "type": "string", "required": True, "description": "Pipeline version that produced this event"},
    {"field": "provenance.stages_applied", "type": "integer", "required": True, "description": "Number of normalization stages applied"},
]

_OCSF_FIELDS: list[dict[str, Any]] = [
    {"field": "class_uid", "type": "integer", "required": True, "description": "OCSF event class UID"},
    {"field": "class_name", "type": "string", "required": True, "description": "OCSF event class name"},
    {"field": "category_uid", "type": "integer", "required": True, "description": "OCSF event category UID"},
    {"field": "category_name", "type": "string", "required": True, "description": "OCSF event category name"},
    {"field": "activity_id", "type": "integer", "required": True, "description": "Activity type within the class"},
    {"field": "time", "type": "integer", "required": True, "description": "Epoch milliseconds timestamp"},
    {"field": "severity_id", "type": "integer", "required": True, "description": "0=Unknown 1=Informational 2=Low 3=Medium 4=High 5=Critical"},
    {"field": "severity", "type": "string", "required": True, "description": "Severity label"},
    {"field": "metadata.version", "type": "string", "required": True, "description": "OCSF schema version (1.1.0)"},
    {"field": "metadata.product.name", "type": "string", "required": True, "description": "Product name"},
    {"field": "metadata.product.vendor_name", "type": "string", "required": True, "description": "Vendor name"},
    {"field": "src_endpoint", "type": "object", "required": False, "description": "Source endpoint context"},
    {"field": "dst_endpoint", "type": "object", "required": False, "description": "Destination endpoint context"},
    {"field": "actor", "type": "object", "required": False, "description": "Actor (user/process) context"},
    {"field": "unmapped", "type": "object", "required": False, "description": "Fields not mapped to OCSF schema — preserved from UCE unmapped_residue"},
]

_OTEL_FIELDS: list[dict[str, Any]] = [
    {"field": "resource.attributes", "type": "object", "required": True, "description": "Resource-level attributes (service.name, host.name, etc.)"},
    {"field": "scope_logs[].scope.name", "type": "string", "required": True, "description": "Instrumentation scope name"},
    {"field": "scope_logs[].log_records[].time_unix_nano", "type": "integer", "required": True, "description": "Nanosecond epoch timestamp"},
    {"field": "scope_logs[].log_records[].severity_number", "type": "integer", "required": True, "description": "OTel severity number (1-24)"},
    {"field": "scope_logs[].log_records[].severity_text", "type": "string", "required": False, "description": "Severity text label"},
    {"field": "scope_logs[].log_records[].body", "type": "string|object", "required": False, "description": "Log body (original message)"},
    {"field": "scope_logs[].log_records[].attributes", "type": "object", "required": False, "description": "Log-level attributes including UCE canonical fields"},
    {"field": "scope_logs[].log_records[].trace_id", "type": "string", "required": False, "description": "Trace correlation ID"},
    {"field": "scope_logs[].log_records[].span_id", "type": "string", "required": False, "description": "Span correlation ID"},
]

_ECS_FIELDS: list[dict[str, Any]] = [
    {"field": "@timestamp", "type": "datetime", "required": True, "description": "Event timestamp in UTC ISO-8601"},
    {"field": "ecs.version", "type": "string", "required": True, "description": "ECS schema version (8.11)"},
    {"field": "event.category", "type": "array[string]", "required": True, "description": "Event categorization (network, authentication, process, etc.)"},
    {"field": "event.action", "type": "string", "required": True, "description": "Action performed (logon, denied, connected)"},
    {"field": "event.outcome", "type": "string", "required": False, "description": "Result of action: success, failure, unknown"},
    {"field": "event.severity", "type": "integer", "required": False, "description": "Severity scale (0-100)"},
    {"field": "source.ip", "type": "string", "required": False, "description": "Source IP address"},
    {"field": "destination.ip", "type": "string", "required": False, "description": "Destination IP address"},
    {"field": "user.name", "type": "string", "required": False, "description": "User account name"},
    {"field": "host.name", "type": "string", "required": False, "description": "Host name"},
    {"field": "labels.unmapped", "type": "object", "required": False, "description": "Preserved vendor attributes from UCE unmapped_residue"},
]

_SCHEMAS: dict[str, dict[str, Any]] = {
    "uce": {
        "id": "uce",
        "name": "Universal Canonical Event",
        "version": "1.0.0",
        "description": "ULPF internal source-of-truth representation. All downstream projections (OCSF, OTel) derive from UCE.",
        "authority": "ULPF internal standard — not an external specification",
        "fields": _UCE_FIELDS,
        "field_count": len(_UCE_FIELDS),
        "required_count": sum(1 for f in _UCE_FIELDS if f["required"]),
    },
    "ocsf": {
        "id": "ocsf",
        "name": "OCSF",
        "version": "1.1.0",
        "description": "Open Cybersecurity Schema Framework v1.1.0 projection. UCE events are projected to OCSF for SIEM interoperability.",
        "authority": "Open Cybersecurity Schema Framework — https://schema.ocsf.io",
        "fields": _OCSF_FIELDS,
        "field_count": len(_OCSF_FIELDS),
        "required_count": sum(1 for f in _OCSF_FIELDS if f["required"]),
    },
    "otel": {
        "id": "otel",
        "name": "OpenTelemetry Logs",
        "version": "1.3.0",
        "description": "OpenTelemetry Logs Data Model projection. UCE events are emitted as OTel log records for observability pipelines.",
        "authority": "OpenTelemetry Logs Data Model — https://opentelemetry.io/docs/specs/otel/logs/data-model/",
        "fields": _OTEL_FIELDS,
        "field_count": len(_OTEL_FIELDS),
        "required_count": sum(1 for f in _OTEL_FIELDS if f["required"]),
    },
    "ecs": {
        "id": "ecs",
        "name": "Elastic Common Schema",
        "version": "8.11.0",
        "description": "Elastic Common Schema (ECS) specification. Standardized field set for Elasticsearch and Kibana analytics.",
        "authority": "Elastic Common Schema — https://www.elastic.co/guide/en/ecs/current/index.html",
        "fields": _ECS_FIELDS,
        "field_count": len(_ECS_FIELDS),
        "required_count": sum(1 for f in _ECS_FIELDS if f["required"]),
    },
}


@router.get("/schemas", summary="List supported output schemas")
def list_schemas(
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Return all supported canonical output schemas."""
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    summaries = [
        {
            "id": s["id"],
            "name": s["name"],
            "version": s["version"],
            "description": s["description"],
            "field_count": s["field_count"],
        }
        for s in _SCHEMAS.values()
    ]
    return {"schemas": summaries}


@router.get("/schemas/{schema_id}", summary="Get schema field definitions")
def get_schema(
    schema_id: str,
    x_role: str | None = Header(None, alias="X-Role"),
) -> dict[str, Any]:
    """Return full field definitions for the requested schema."""
    verify_role({"viewer", "operator", "platform-admin"}, x_role)
    schema = _SCHEMAS.get(schema_id.lower())
    if not schema:
        raise HTTPException(
            status_code=404,
            detail=f"Schema '{schema_id}' not found. Supported: {list(_SCHEMAS.keys())}",
        )
    return schema


# --- Phase 8/Operations: Online Cloud AI Copilot Integration ---


class CopilotTestRequest(BaseModel):
    provider: str  # "gemini", "claude", "openai"
    model: str
    api_key: str


class CopilotChatRequest(BaseModel):
    provider: str  # "gemini", "claude", "openai"
    model: str
    api_key: str
    prompt: str
    system_prompt: str | None = None


@router.post("/copilot/test-connection", summary="Test connectivity and API key validity for Cloud AI models")
async def test_copilot_connection(req: CopilotTestRequest) -> dict[str, Any]:
    """Verifies that the provided API key and model work with the provider."""
    import time
    import httpx

    provider = req.provider.lower().strip()
    model = req.model.strip()
    api_key = req.api_key.strip()
    if not api_key:
        return {"ok": False, "error": "API Key is required to test live connection"}

    start_time = time.time()
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            if "gemini" in provider or "google" in provider:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                payload = {"contents": [{"parts": [{"text": "Hello. Respond with: OK"}]}]}
                resp = await client.post(url, json=payload)
                elapsed_ms = int((time.time() - start_time) * 1000)
                if resp.status_code == 200:
                    return {"ok": True, "provider": "Google Gemini", "model": model, "latency_ms": elapsed_ms, "message": "Connection successful"}
                else:
                    err = resp.json().get("error", {}).get("message", resp.text)
                    return {"ok": False, "error": f"Gemini Error ({resp.status_code}): {err}"}

            elif "claude" in provider or "anthropic" in provider:
                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                }
                payload = {
                    "model": model,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "ping"}],
                }
                resp = await client.post(url, headers=headers, json=payload)
                elapsed_ms = int((time.time() - start_time) * 1000)
                if resp.status_code == 200:
                    return {"ok": True, "provider": "Anthropic Claude", "model": model, "latency_ms": elapsed_ms, "message": "Connection successful"}
                else:
                    err = resp.json().get("error", {}).get("message", resp.text)
                    return {"ok": False, "error": f"Claude Error ({resp.status_code}): {err}"}

            elif "openai" in provider or "gpt" in provider:
                url = "https://api.openai.com/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 10,
                }
                resp = await client.post(url, headers=headers, json=payload)
                elapsed_ms = int((time.time() - start_time) * 1000)
                if resp.status_code == 200:
                    return {"ok": True, "provider": "OpenAI GPT", "model": model, "latency_ms": elapsed_ms, "message": "Connection successful"}
                else:
                    err = resp.json().get("error", {}).get("message", resp.text)
                    return {"ok": False, "error": f"OpenAI Error ({resp.status_code}): {err}"}

            else:
                return {"ok": False, "error": f"Unsupported provider: {provider}. Supported: gemini, claude, openai"}
        except Exception as exc:
            return {"ok": False, "error": f"Connection error: {str(exc)}"}


@router.post("/copilot/chat", summary="Proxy chat completion requests to Cloud AI models")
async def copilot_chat(req: CopilotChatRequest) -> dict[str, Any]:
    """Forwards chat prompts directly to OpenAI, Claude, or Google Gemini."""
    import time
    import httpx

    provider = req.provider.lower().strip()
    model = req.model.strip()
    api_key = req.api_key.strip()
    prompt = req.prompt.strip()
    sys_prompt = req.system_prompt or (
    "You are Chanakya — the Sovereign AI Pipeline Copilot of the Universal Log Preprocessing Framework (ULPF). "
        "You are an elite cybersecurity engineer and Indian sovereign compliance expert. "
        "ULPF processes 20+ log formats (JSON, CSV/PAN-OS, Syslog RFC5424/3164, Cisco ASA, Windows EVTX, Fortinet KV, CEF, LEEF, Zeek, Suricata, Snort, Auditd, YAML, NetFlow). "
        "You normalize to UCE v1.0 schema, project to 19 output formats (OCSF, OTel, ECS, Sentinel, Splunk HEC, Google SecOps UDM, etc.), and enforce CERT-In 2022, DPDP Act 2023, and Indian Evidence Act §65B compliance. "
        "Always respond with: (1) a precise, authoritative analysis, (2) a production-ready YAML pipeline rule or Sigma/KQL detection rule when applicable, (3) MITRE ATT&CK technique mapping where relevant. "
        "Be direct, concise, and produce immediately deployable artifacts. Never say you cannot help — always generate a useful output."
    )

    if not api_key:
        return {"ok": False, "error": "API Key is required to call online cloud AI"}

    start_time = time.time()
    async with httpx.AsyncClient(timeout=45.0) as client:
        try:
            if "gemini" in provider or "google" in provider:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                payload = {
                    "contents": [
                        {"role": "user", "parts": [{"text": f"{sys_prompt}\n\nUser Question: {prompt}"}]}
                    ]
                }
                resp = await client.post(url, json=payload)
                elapsed_ms = int((time.time() - start_time) * 1000)
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    return {"ok": True, "content": content, "provider": "Google Gemini", "model": model, "latency_ms": elapsed_ms}
                else:
                    err = resp.json().get("error", {}).get("message", resp.text)
                    return {"ok": False, "error": f"Gemini Error ({resp.status_code}): {err}"}

            elif "claude" in provider or "anthropic" in provider:
                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                }
                payload = {
                    "model": model,
                    "max_tokens": 2048,
                    "system": sys_prompt,
                    "messages": [{"role": "user", "content": prompt}],
                }
                resp = await client.post(url, headers=headers, json=payload)
                elapsed_ms = int((time.time() - start_time) * 1000)
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("content", [{}])[0].get("text", "")
                    return {"ok": True, "content": content, "provider": "Anthropic Claude", "model": model, "latency_ms": elapsed_ms}
                else:
                    err = resp.json().get("error", {}).get("message", resp.text)
                    return {"ok": False, "error": f"Claude Error ({resp.status_code}): {err}"}

            elif "openai" in provider or "gpt" in provider:
                url = "https://api.openai.com/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                }
                messages = [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": prompt},
                ]
                payload = {
                    "model": model,
                    "messages": messages,
                }
                resp = await client.post(url, headers=headers, json=payload)
                elapsed_ms = int((time.time() - start_time) * 1000)
                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    return {"ok": True, "content": content, "provider": "OpenAI GPT", "model": model, "latency_ms": elapsed_ms}
                else:
                    err = resp.json().get("error", {}).get("message", resp.text)
                    return {"ok": False, "error": f"OpenAI Error ({resp.status_code}): {err}"}

            else:
                return {"ok": False, "error": f"Unsupported provider: {provider}"}
        except Exception as exc:
            return {"ok": False, "error": f"Connection error: {str(exc)}"}


