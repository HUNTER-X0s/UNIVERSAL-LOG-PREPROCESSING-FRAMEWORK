"""Zeek / Bro network telemetry parser for ULPF Phase 3 (Tier B).

Parses Zeek TSV and JSON telemetry:
- conn.log (connection records)
- dns.log (DNS queries and answers)
- http.log (HTTP requests and responses)
- ssl.log (TLS/SSL handshakes)

Extracts:
- ts (epoch timestamp)
- uid (unique connection identifier)
- id.orig_h / id.orig_p (source IP and port)
- id.resp_h / id.resp_p (destination IP and port)
- proto, service, duration, orig_bytes, resp_bytes, conn_state

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

# Standard Zeek conn.log field order in TSV mode
DEFAULT_ZEEK_CONN_FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
)


class ZeekParser(BaseParser):
    """Deterministic parser for Zeek TSV and JSON network telemetry."""

    metadata = ParserMetadata(
        parser_id="parser.zeek.telemetry",
        version="1.0.0",
        supported_formats=("zeek_tsv", "zeek_json", "tsv"),
        supported_vendors=("Zeek", "Bro", "Corelight"),
        supported_products=("Zeek", "Bro Network Security Monitor"),
        tier="B",
        description="Zeek / Bro network telemetry (conn, dns, http, ssl) parser",
    )

    def __init__(self, default_tsv_fields: tuple[str, ...] | None = None) -> None:
        self._tsv_fields: list[str] = list(default_tsv_fields or DEFAULT_ZEEK_CONN_FIELDS)

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        # Handle Zeek JSON
        if text.startswith("{") and text.endswith("}"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    fields: dict[str, Any] = {}
                    for k, v in data.items():
                        fields[k] = self.make_field(
                            k,
                            v,
                            Origin.OBSERVED,
                            raw_locator=f"zeek:json:{k}",
                        )
                    return ParseResult(
                        status=ParseStatus.PARSED,
                        parser_id=self.metadata.parser_id,
                        parser_version=self.metadata.version,
                        format="zeek_json",
                        extracted_fields=fields,
                        duration_ms=self.measure_duration(t0),
                    )
            except (json.JSONDecodeError, ValueError):
                pass

        # Handle Zeek header comment directive: #fields field1 field2...
        if text.startswith("#fields"):
            tokens = text.split("\t")
            if len(tokens) > 1:
                self._tsv_fields = tokens[1:]
            else:
                self._tsv_fields = text.split()[1:]
            return ParseResult(
                status=ParseStatus.PARSED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="zeek_tsv",
                extracted_fields={
                    "directive": self.make_field("directive", "fields", Origin.OBSERVED),
                    "fields": self.make_field("fields", self._tsv_fields, Origin.OBSERVED),
                },
                duration_ms=self.measure_duration(t0),
            )

        if text.startswith("#"):
            return ParseResult(
                status=ParseStatus.PARSED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="zeek_tsv",
                extracted_fields={
                    "comment": self.make_field("comment", text, Origin.OBSERVED),
                },
                duration_ms=self.measure_duration(t0),
            )

        # Tab-separated data line
        parts = text.split("\t")
        if len(parts) < 4:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="zeek_parser",
                message="Zeek TSV record contains fewer than 4 columns",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="zeek_tsv",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        fields = {}
        for idx, val in enumerate(parts):
            if idx < len(self._tsv_fields):
                fname = self._tsv_fields[idx]
            else:
                fname = f"col_{idx}"

            # Zeek '-' is unset/null, '(empty)' is empty string
            if val != "-":
                actual_val = "" if val == "(empty)" else val
                fields[fname] = self.make_field(
                    fname,
                    actual_val,
                    Origin.OBSERVED,
                    raw_locator=f"zeek:tsv:{fname}",
                )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="zeek_tsv",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
