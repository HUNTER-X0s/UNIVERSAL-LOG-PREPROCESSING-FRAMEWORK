"""Universal Canonical Event (UCE) builder for ULPF Phase 3 Normalization.

Constructs normalized events strictly adhering to:
- contracts/jsonschema/normalized-event.v1.schema.json
- contracts/jsonschema/ulpf-common.v1.schema.json
- Spec §31: Field Provenance Tracking
- Spec §33: Universal Canonical Event (UCE) Schema
"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ulpf_parser_runtime.models import ParseResult

from ulpf_normalization.assertions import AssertionOrigin, FieldProvenanceRecord
from ulpf_normalization.normalizers.action import normalize_action
from ulpf_normalization.normalizers.classification import classify_event
from ulpf_normalization.normalizers.network import (
    normalize_direction,
    normalize_ip,
    normalize_metric,
    normalize_port,
    normalize_protocol,
)
from ulpf_normalization.normalizers.severity import normalize_severity
from ulpf_normalization.normalizers.timestamp import normalize_timestamp
from ulpf_normalization.unknown_fields import UnknownFieldPreserver


@dataclass
class CanonicalEventBuilder:
    """Builder for Universal Canonical Event (UCE) v1 contracts."""

    contract_version: str = "1.0.0"
    transformation_id: str = "ulpf.normalization.canonical:1.0.0"

    def build_uce(
        self,
        parse_result: ParseResult,
        raw_event_id: str | None = None,
        source_id: str | None = None,
        raw_payload_bytes: bytes | None = None,
        processing_run_id: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
    ) -> dict[str, Any]:
        """Transform a ParseResult into a valid NormalizedEvent contract dictionary."""
        ev_id = f"evt_{uuid.uuid4().hex[:16]}"
        raw_id = raw_event_id or f"raw_{uuid.uuid4().hex[:16]}"
        src_id = source_id or f"src_{uuid.uuid4().hex[:16]}"
        run_id = processing_run_id or f"run_{uuid.uuid4().hex[:16]}"
        now_iso = datetime.now(UTC).isoformat()

        # Compute payload hash and size
        if raw_payload_bytes is not None:
            p_bytes = raw_payload_bytes
        else:
            p_bytes = str(parse_result.unmapped_fields.get("raw_text", "")).encode("utf-8")
        payload_hash = hashlib.sha256(p_bytes).hexdigest()
        byte_len = len(p_bytes)

        # Flatten extracted field values for easy lookup
        fields: dict[str, Any] = {}
        for k, v in parse_result.extracted_fields.items():
            fields[k] = v.value if hasattr(v, "value") else v

        mapped_keys: set[str] = set()
        provenance_records: dict[str, dict[str, Any]] = {}

        def record_prov(
            path: str, origin: AssertionOrigin, src_key: str | None, explanation: str | None = None
        ) -> None:
            raw_p = tuple([f"{parse_result.format}:{src_key}"]) if src_key else ()
            inp_p = tuple([src_key]) if src_key else ()
            rec = FieldProvenanceRecord(
                origin=origin,
                transformation_id=self.transformation_id,
                rule_version="1.0.0",
                raw_paths=raw_p,
                input_field_paths=inp_p,
                confidence=1.0,
                explanation=explanation,
            )
            provenance_records[path] = rec.to_contract_dict()
            if src_key:
                mapped_keys.add(src_key)

        # 1. Normalize Timestamp
        raw_ts = (
            fields.get("timestamp")
            or fields.get("time")
            or fields.get("eventTime")
            or fields.get("ts")
            or fields.get("receive_time")
            or fields.get("date")
        )
        date_v = str(fields.get("date")) if "date" in fields else None
        time_v = str(fields.get("time")) if "time" in fields and "date" in fields else None
        norm_ts = normalize_timestamp(raw_ts, date_val=date_v, time_val=time_v)
        record_prov(
            "event.time",
            AssertionOrigin.DERIVED if raw_ts else AssertionOrigin.INFERRED,
            "timestamp" if "timestamp" in fields else None,
        )

        # 2. Normalize Severity
        raw_sev = (
            fields.get("severity")
            or fields.get("cisco_severity")
            or fields.get("priority")
            or fields.get("level")
            or fields.get("alert.severity")
        )
        is_syslog = parse_result.format.startswith("syslog") or "cisco" in parse_result.format
        norm_sev = normalize_severity(raw_sev, is_syslog=is_syslog)
        if raw_sev is not None:
            record_prov("event.severity", AssertionOrigin.DERIVED, "severity")

        # 3. Classify Event
        cat, ev_type, ev_class = classify_event(fields, parse_result.parser_id, vendor=vendor)
        record_prov("event.category", AssertionOrigin.INFERRED, None)
        record_prov("event.type", AssertionOrigin.INFERRED, None)

        # 4. Action
        raw_action = (
            fields.get("action")
            or fields.get("act")
            or fields.get("alert.action")
            or fields.get("log_action")
        )
        norm_act = normalize_action(raw_action) if raw_action else "unknown"
        if raw_action:
            record_prov("event.action", AssertionOrigin.DERIVED, "action")

        # 5. Network / Endpoints
        raw_sip = (
            fields.get("src_ip")
            or fields.get("srcip")
            or fields.get("src")
            or fields.get("client_ip")
            or fields.get("sourceIPAddress")
            or fields.get("id.orig_h")
            or fields.get("src_addr")
        )
        raw_dip = (
            fields.get("dst_ip")
            or fields.get("dstip")
            or fields.get("dst")
            or fields.get("dest_ip")
            or fields.get("id.resp_h")
            or fields.get("dst_addr")
        )
        raw_sport = (
            fields.get("src_port")
            or fields.get("srcport")
            or fields.get("spt")
            or fields.get("s_port")
            or fields.get("id.orig_p")
        )
        raw_dport = (
            fields.get("dst_port")
            or fields.get("dstport")
            or fields.get("dpt")
            or fields.get("service")
            or fields.get("id.resp_p")
        )
        raw_proto = fields.get("protocol") or fields.get("proto")

        src_obj: dict[str, Any] = {}
        sip = normalize_ip(raw_sip)
        if sip:
            src_obj["ip"] = sip
            record_prov("event.source.ip", AssertionOrigin.OBSERVED, "src_ip")
        sport = normalize_port(raw_sport)
        if sport:
            src_obj["port"] = sport
            record_prov("event.source.port", AssertionOrigin.OBSERVED, "src_port")

        dst_obj: dict[str, Any] = {}
        dip = normalize_ip(raw_dip)
        if dip:
            dst_obj["ip"] = dip
            record_prov("event.destination.ip", AssertionOrigin.OBSERVED, "dst_ip")
        dport = normalize_port(raw_dport)
        if dport:
            dst_obj["port"] = dport
            record_prov("event.destination.port", AssertionOrigin.OBSERVED, "dst_port")

        net_obj: dict[str, Any] = {
            "protocol": normalize_protocol(raw_proto),
        }
        if raw_proto:
            record_prov("event.network.protocol", AssertionOrigin.OBSERVED, "protocol")

        direction = normalize_direction(fields.get("direction") or fields.get("i/f_dir"))
        if direction != "unknown":
            net_obj["direction"] = direction
            record_prov("event.network.direction", AssertionOrigin.DERIVED, "direction")

        # Metrics (bytes, packets)
        raw_bytes = fields.get("bytes") or fields.get("sentbyte") or fields.get("response_bytes")
        if raw_bytes is not None:
            net_obj["bytes"] = normalize_metric(raw_bytes)
            record_prov("event.network.bytes", AssertionOrigin.OBSERVED, "bytes")

        # Identity
        id_obj: dict[str, Any] = {}
        raw_user = (
            fields.get("remote_user")
            or fields.get("src_user")
            or fields.get("user")
            or fields.get("usr")
            or fields.get("userIdentity.userName")
        )
        if raw_user:
            id_obj["user"] = {"name": str(raw_user)}
            record_prov("event.identity.user.name", AssertionOrigin.OBSERVED, "user")

        # Device / System
        dev_obj: dict[str, Any] = {}
        dev_host = fields.get("hostname") or fields.get("devname") or fields.get("device_vendor")
        if dev_host:
            dev_obj["hostname"] = str(dev_host)
            record_prov("event.device.hostname", AssertionOrigin.OBSERVED, "hostname")

        # Metadata
        meta_obj: dict[str, Any] = {
            "parser_id": parse_result.parser_id,
            "format": parse_result.format,
            "ingest_timestamp": now_iso,
        }
        if vendor:
            meta_obj["vendor"] = vendor
        if product:
            meta_obj["product"] = product

        # 6. Preserve all unmapped fields
        unmapped = UnknownFieldPreserver.preserve(
            extracted_fields=parse_result.extracted_fields,
            mapped_keys=mapped_keys,
            parser_unmapped=parse_result.unmapped_fields,
        )

        # Assemble Canonical Event (UCE)
        canonical: dict[str, Any] = {
            "contract_version": self.contract_version,
            "event_id": ev_id,
            "raw_event_id": raw_id,
            "source_id": src_id,
            "evidence": {
                "raw_event_id": raw_id,
                "payload": {
                    "uri": f"file://intake/raw/{raw_id}.dat",
                    "sha256": payload_hash,
                    "byte_length": byte_len,
                    "media_type": "text/plain",
                    "encoding": "utf-8",
                    "retention_class": "standard",
                },
                "payload_sha256": payload_hash,
                "evidence_manifest_id": f"evm_{uuid.uuid4().hex[:16]}",
            },
            "event": {
                "time": norm_ts,
                "category": cat,
                "type": ev_type,
                "class": ev_class,
                "action": norm_act,
                "severity": norm_sev,
                "source": src_obj,
                "destination": dst_obj,
                "network": net_obj,
                "device": dev_obj,
                "identity": id_obj,
                "metadata": meta_obj,
            },
            "unmapped_fields": unmapped,
            "field_provenance": provenance_records,
            "processing": {
                "processing_run_id": run_id,
                "source_profile": {
                    "id": f"srcprof.{vendor or 'generic'}.{product or 'telemetry'}".lower(),
                    "version": "1.0.0",
                },
                "parser": {
                    "id": parse_result.parser_id,
                    "version": parse_result.parser_version,
                },
                "mapping": {
                    "id": f"map.{parse_result.format}.uce_v1",
                    "version": "1.0.0",
                },
                "schema": {
                    "id": "https://ulpf.local/contracts/jsonschema/normalized-event.v1.schema.json",
                    "version": "1.0.0",
                },
                "processed_at": now_iso,
            },
            "lineage": {
                "uri": f"ulpf://lineage/{run_id}/{ev_id}",
                "sha256": payload_hash,
                "byte_length": byte_len,
                "media_type": "application/json",
            },
            "output_projections": ["ulpf", "json", "ndjson"],
        }

        return canonical
