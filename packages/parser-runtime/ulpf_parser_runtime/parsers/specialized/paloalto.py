"""Palo Alto Networks PAN-OS parser for ULPF Phase 3 (Tier B).

Parses PAN-OS CSV telemetry:
- Traffic logs (TRAFFIC)
- Threat logs (THREAT)
- System logs (SYSTEM)

Extracts:
- Serial number, receive_time, generate_time
- Source & destination IP, NAT IP, source & destination ports
- Source & destination zone, interfaces, virtual system (vsys)
- Action (allow, deny, drop, etc.)
- Protocol (tcp, udp, icmp), application, bytes, packets, session_id
- Threat name, category, severity, CVE, URI/URL (for THREAT logs)

Adheres to:
- Spec §15: Vendor-Specific Specialized Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import csv
import io
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

# PAN-OS 9.x/10.x Traffic Log field mappings (0-indexed)
TRAFFIC_FIELDS = {
    1: "receive_time",
    2: "serial_number",
    3: "type",
    4: "subtype",
    6: "generate_time",
    7: "src_ip",
    8: "dst_ip",
    9: "nat_src_ip",
    10: "nat_dst_ip",
    11: "rule_name",
    12: "src_user",
    13: "dst_user",
    14: "app",
    15: "vsys",
    16: "src_zone",
    17: "dst_zone",
    18: "inbound_iface",
    19: "outbound_iface",
    20: "log_action",
    22: "session_id",
    23: "repeat_count",
    24: "src_port",
    25: "dst_port",
    26: "nat_src_port",
    27: "nat_dst_port",
    28: "flags",
    29: "protocol",
    30: "action",
    31: "bytes",
    32: "bytes_sent",
    33: "bytes_received",
    34: "packets",
    35: "start_time",
    36: "elapsed_time",
    37: "category",
}

# PAN-OS Threat Log field mappings (0-indexed)
THREAT_FIELDS = {
    1: "receive_time",
    2: "serial_number",
    3: "type",
    4: "subtype",
    6: "generate_time",
    7: "src_ip",
    8: "dst_ip",
    9: "nat_src_ip",
    10: "nat_dst_ip",
    11: "rule_name",
    12: "src_user",
    13: "dst_user",
    14: "app",
    15: "vsys",
    16: "src_zone",
    17: "dst_zone",
    18: "inbound_iface",
    19: "outbound_iface",
    20: "log_action",
    22: "session_id",
    23: "repeat_count",
    24: "src_port",
    25: "dst_port",
    26: "nat_src_port",
    27: "nat_dst_port",
    28: "flags",
    29: "protocol",
    30: "action",
    31: "threat_name",
    32: "threat_id",
    33: "category",
    34: "severity",
    35: "direction",
}


class PaloAltoPanOSParser(BaseParser):
    """Deterministic parser for Palo Alto Networks PAN-OS CSV logs."""

    metadata = ParserMetadata(
        parser_id="parser.paloalto.panos",
        version="1.0.0",
        supported_formats=("panos_csv", "csv"),
        supported_vendors=("Palo Alto Networks", "PaloAlto", "PAN-OS"),
        supported_products=("PAN-OS", "PA-Series", "Firewall"),
        tier="B",
        description="Palo Alto Networks PAN-OS Traffic, Threat, and System CSV parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        # Check for optional syslog prefix before PAN-OS CSV
        # e.g., "1 2026-09-05T14:00:01Z myfirewall - - - 1,2026/09/05..."
        csv_start = 0
        if not text.startswith("1,") and not text.startswith("FUTURE_USE"):
            # Look for "1,20" (common PAN-OS start) or similar
            comma_idx = text.find(",20")
            if comma_idx != -1:
                # Look backwards for start of the numeric field before ',20'
                prev_space = text.rfind(" ", 0, comma_idx)
                if prev_space != -1:
                    csv_start = prev_space + 1

        csv_text = text[csv_start:].strip()

        try:
            reader = csv.reader(io.StringIO(csv_text))
            row = next(reader)
        except (csv.Error, StopIteration) as exc:
            err = ParseError(
                code=ErrorCode.INVALID_CSV,
                stage="paloalto_panos",
                message=f"Failed to parse PAN-OS CSV: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="panos_csv",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        if len(row) < 15:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="paloalto_panos",
                message=f"Row has only {len(row)} fields (minimum 15 required for PAN-OS)",
                severity=ErrorSeverity.ERROR,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="panos_csv",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        log_type = row[3].upper() if len(row) > 3 else "TRAFFIC"
        field_map = THREAT_FIELDS if log_type == "THREAT" else TRAFFIC_FIELDS

        fields: dict[str, Any] = {}
        for idx, fname in field_map.items():
            if idx < len(row):
                val = row[idx].strip()
                if val:
                    fields[fname] = self.make_field(
                        fname,
                        val,
                        Origin.OBSERVED,
                        raw_locator=f"panos:col_{idx}",
                    )

        # Unmapped columns for preservation
        mapped_indices = set(field_map.keys())
        unmapped: dict[str, Any] = {}
        for idx, val in enumerate(row):
            if idx not in mapped_indices and val.strip():
                unmapped[f"col_{idx}"] = val.strip()

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="panos_csv",
            extracted_fields=fields,
            unmapped_fields=unmapped,
            duration_ms=self.measure_duration(t0),
        )
