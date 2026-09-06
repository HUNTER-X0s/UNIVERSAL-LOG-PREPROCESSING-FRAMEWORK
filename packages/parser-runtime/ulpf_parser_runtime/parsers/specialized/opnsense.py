"""OPNsense and pfSense filterlog parser for ULPF Phase 3 (Tier B).

Parses FreeBSD packet filter (pf) filterlog CSV telemetry:
- IPv4 TCP/UDP/ICMP filterlog lines
- IPv6 filterlog lines
- Prefix handling for syslog headers (filterlog[pid]:)

Extracts:
- rule_number, sub_rule, tracker, interface, reason
- action (block, pass), direction (in, out)
- ip_version (4 or 6), tos, ttl, id, offset, ip_flags
- protocol_id, protocol (tcp, udp, icmp), length
- src_ip, dst_ip, src_port, dst_port, tcp_flags

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


class OPNsenseFilterlogParser(BaseParser):
    """Deterministic parser for OPNsense / pfSense filterlog packet filter telemetry."""

    metadata = ParserMetadata(
        parser_id="parser.opnsense.filterlog",
        version="1.0.0",
        supported_formats=("opnsense_filterlog", "csv"),
        supported_vendors=("OPNsense", "pfSense", "Netgate", "Deciso"),
        supported_products=("filterlog", "pf", "Firewall"),
        tier="B",
        description="OPNsense and pfSense filterlog packet filter CSV parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        # Check for filterlog tag prefix
        csv_start = 0
        tag_idx = text.find("filterlog")
        if tag_idx != -1:
            colon_idx = text.find(":", tag_idx)
            if colon_idx != -1:
                csv_start = colon_idx + 1

        csv_text = text[csv_start:].strip()

        try:
            reader = csv.reader(io.StringIO(csv_text))
            row = next(reader)
        except (csv.Error, StopIteration) as exc:
            err = ParseError(
                code=ErrorCode.INVALID_CSV,
                stage="opnsense_filterlog",
                message=f"Failed to parse filterlog CSV: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="opnsense_filterlog",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        if len(row) < 9:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="opnsense_filterlog",
                message=f"Row has only {len(row)} fields (minimum 9 required for filterlog)",
                severity=ErrorSeverity.ERROR,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="opnsense_filterlog",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        fields: dict[str, Any] = {}

        # Base filterlog fields (0-8)
        base_names = [
            "rule_number",
            "sub_rule",
            "anchor",
            "tracker",
            "interface",
            "reason",
            "action",
            "direction",
            "ip_version",
        ]
        for idx, fname in enumerate(base_names):
            if idx < len(row) and row[idx].strip():
                fields[fname] = self.make_field(
                    fname,
                    row[idx].strip(),
                    Origin.OBSERVED,
                    raw_locator=f"filterlog:{idx}",
                )

        ip_ver = row[8].strip() if len(row) > 8 else "4"

        # IPv4 field layout
        if ip_ver == "4" and len(row) >= 20:
            ipv4_map = {
                9: "tos",
                10: "ecn",
                11: "ttl",
                12: "id",
                13: "offset",
                14: "ip_flags",
                15: "protocol_id",
                16: "protocol",
                17: "length",
                18: "src_ip",
                19: "dst_ip",
            }
            for idx, fname in ipv4_map.items():
                if idx < len(row) and row[idx].strip():
                    fields[fname] = self.make_field(
                        fname,
                        row[idx].strip(),
                        Origin.OBSERVED,
                        raw_locator=f"filterlog:{idx}",
                    )

            # Ports if TCP or UDP
            if len(row) >= 22:
                fields["src_port"] = self.make_field(
                    "src_port", row[20].strip(), Origin.OBSERVED, raw_locator="filterlog:20"
                )
                fields["dst_port"] = self.make_field(
                    "dst_port", row[21].strip(), Origin.OBSERVED, raw_locator="filterlog:21"
                )
            if len(row) >= 25 and row[24].strip():
                fields["tcp_flags"] = self.make_field(
                    "tcp_flags", row[24].strip(), Origin.OBSERVED, raw_locator="filterlog:24"
                )

        # IPv6 field layout
        elif ip_ver == "6" and len(row) >= 17:
            ipv6_map = {
                9: "class",
                10: "flow_label",
                11: "hop_limit",
                12: "protocol",
                13: "protocol_id",
                14: "length",
                15: "src_ip",
                16: "dst_ip",
            }
            for idx, fname in ipv6_map.items():
                if idx < len(row) and row[idx].strip():
                    fields[fname] = self.make_field(
                        fname,
                        row[idx].strip(),
                        Origin.OBSERVED,
                        raw_locator=f"filterlog:{idx}",
                    )
            if len(row) >= 19:
                fields["src_port"] = self.make_field(
                    "src_port", row[17].strip(), Origin.OBSERVED, raw_locator="filterlog:17"
                )
                fields["dst_port"] = self.make_field(
                    "dst_port", row[18].strip(), Origin.OBSERVED, raw_locator="filterlog:18"
                )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="opnsense_filterlog",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
