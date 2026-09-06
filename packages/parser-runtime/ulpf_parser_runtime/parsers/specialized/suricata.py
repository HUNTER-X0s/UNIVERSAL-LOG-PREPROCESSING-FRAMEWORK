"""Suricata EVE JSON parser for ULPF Phase 3 (Tier B).

Parses Suricata Extensible Event format (EVE JSON):
- event_type: alert, flow, dns, http, tls, drop, fileinfo, anomaly

Extracts:
- timestamp, flow_id, in_iface, event_type, proto
- src_ip, src_port, dest_ip, dest_port
- alert: action, gid, signature_id, rev, signature, category, severity
- dns: type, id, rrname, rrtype, rdata
- http: hostname, url, http_user_agent, http_content_type, http_method, status
- tls: subject, issuerdn, fingerprint, sni, version
- flow: pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient

Adheres to:
- Spec §15: Vendor-Specific Specialized Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import json
import time
from typing import Any

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser


class SuricataEveParser(BaseParser):
    """Deterministic parser for Suricata EVE JSON telemetry."""

    metadata = ParserMetadata(
        parser_id="parser.suricata.eve",
        version="1.0.0",
        supported_formats=("suricata_eve_json", "json", "ndjson"),
        supported_vendors=("Suricata", "OISF"),
        supported_products=("EVE", "Suricata IDS/IPS"),
        tier="B",
        description="Suricata EVE JSON security, flow, and IDS alert parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            err = ParseError(
                code=ErrorCode.MALFORMED_JSON,
                stage="suricata_eve",
                message=f"Failed to parse Suricata JSON: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="suricata_eve_json",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        if not isinstance(data, dict):
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="suricata_eve_json",
                extracted_fields={},
                unmapped_fields={"raw_value": data},
                duration_ms=self.measure_duration(t0),
            )

        fields: dict[str, Any] = {}

        # Top-level common EVE fields
        for top_key in (
            "timestamp",
            "flow_id",
            "in_iface",
            "event_type",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
        ):
            if top_key in data:
                fields[top_key] = self.make_field(
                    top_key,
                    data[top_key],
                    Origin.OBSERVED,
                    raw_locator=f"eve:{top_key}",
                )

        # Alert sub-object
        if "alert" in data and isinstance(data["alert"], dict):
            al = data["alert"]
            for a_key in (
                "action",
                "gid",
                "signature_id",
                "rev",
                "signature",
                "category",
                "severity",
            ):
                if a_key in al:
                    fields[f"alert.{a_key}"] = self.make_field(
                        f"alert.{a_key}",
                        al[a_key],
                        Origin.OBSERVED,
                        raw_locator=f"eve:alert.{a_key}",
                    )

        # DNS sub-object
        if "dns" in data and isinstance(data["dns"], dict):
            dns = data["dns"]
            for d_key in ("type", "id", "rrname", "rrtype", "rdata", "tx_id"):
                if d_key in dns:
                    fields[f"dns.{d_key}"] = self.make_field(
                        f"dns.{d_key}",
                        dns[d_key],
                        Origin.OBSERVED,
                        raw_locator=f"eve:dns.{d_key}",
                    )

        # HTTP sub-object
        if "http" in data and isinstance(data["http"], dict):
            http = data["http"]
            for h_key in (
                "hostname",
                "url",
                "http_user_agent",
                "http_content_type",
                "http_method",
                "status",
            ):
                if h_key in http:
                    fields[f"http.{h_key}"] = self.make_field(
                        f"http.{h_key}",
                        http[h_key],
                        Origin.OBSERVED,
                        raw_locator=f"eve:http.{h_key}",
                    )

        # TLS sub-object
        if "tls" in data and isinstance(data["tls"], dict):
            tls = data["tls"]
            for t_key in ("subject", "issuerdn", "fingerprint", "sni", "version"):
                if t_key in tls:
                    fields[f"tls.{t_key}"] = self.make_field(
                        f"tls.{t_key}",
                        tls[t_key],
                        Origin.OBSERVED,
                        raw_locator=f"eve:tls.{t_key}",
                    )

        # Flow sub-object
        if "flow" in data and isinstance(data["flow"], dict):
            fl = data["flow"]
            for f_key in (
                "pkts_toserver",
                "pkts_toclient",
                "bytes_toserver",
                "bytes_toclient",
                "start",
                "end",
            ):
                if f_key in fl:
                    fields[f"flow.{f_key}"] = self.make_field(
                        f"flow.{f_key}",
                        fl[f_key],
                        Origin.OBSERVED,
                        raw_locator=f"eve:flow.{f_key}",
                    )

        # Retain everything else in unmapped
        extracted_roots = {
            "timestamp",
            "flow_id",
            "in_iface",
            "event_type",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
            "alert",
            "dns",
            "http",
            "tls",
            "flow",
        }
        unmapped = {k: v for k, v in data.items() if k not in extracted_roots}

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="suricata_eve_json",
            extracted_fields=fields,
            unmapped_fields=unmapped,
            duration_ms=self.measure_duration(t0),
        )
