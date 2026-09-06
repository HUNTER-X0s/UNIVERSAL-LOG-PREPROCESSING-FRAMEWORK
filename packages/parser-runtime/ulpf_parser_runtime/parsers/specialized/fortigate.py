"""Fortinet FortiGate UTM and Traffic parser for ULPF Phase 3 (Tier B).

Parses FortiOS key=value telemetry:
- Traffic logs (type="traffic")
- UTM / Security logs (type="utm", subtype="virus", "ips", "webfilter")
- Event logs (type="event")

Extracts:
- date, time, eventtime, tz
- devname, devid, vd (virtual domain)
- logid, type, subtype, level
- srcip, srcport, srcintf, srcintfrole
- dstip, dstport, dstintf, dstintfrole
- proto, service, action, policyid, sessionid
- sentbyte, rcvdbyte, sentpkt, rcvdpkt, duration
- virus, signature, attack, url, msg (for UTM)

Adheres to:
- Spec §15: Vendor-Specific Specialized Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import re
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

# Regex for FortiGate key=value pairs with quoted and bare values
RE_FORTI_KV = re.compile(
    r"([a-zA-Z0-9_-]{1,64})="
    r'(?:"([^"]{0,4096})"'
    r"|'([^']{0,4096})'"
    r"|([^\s]{0,2048}))"
)


class FortiGateParser(BaseParser):
    """Deterministic parser for Fortinet FortiOS key=value logs."""

    metadata = ParserMetadata(
        parser_id="parser.fortinet.fortigate",
        version="1.0.0",
        supported_formats=("fortigate_kv", "key_value"),
        supported_vendors=("Fortinet", "FortiGate"),
        supported_products=("FortiOS", "FortiGate", "FortiWiFi"),
        tier="B",
        description="Fortinet FortiGate UTM, Traffic, and Event parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        fields: dict[str, Any] = {}
        pair_count = 0

        for match in RE_FORTI_KV.finditer(text):
            k = match.group(1).lower()
            v = (
                match.group(2)
                if match.group(2) is not None
                else (match.group(3) if match.group(3) is not None else match.group(4))
            )
            v = (v or "").strip()

            fields[k] = self.make_field(
                k,
                v,
                Origin.OBSERVED,
                raw_locator=f"fortigate:{k}",
            )
            pair_count += 1
            if pair_count >= 500:
                break

        if not fields:
            err = ParseError(
                code=ErrorCode.INVALID_KV,
                stage="fortigate",
                message="No valid FortiGate key=value pairs found",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="fortigate_kv",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        # Ensure minimum identity keys are present (e.g. devname, devid, logid, or srcip)
        has_id = any(k in fields for k in ("devname", "devid", "logid", "srcip", "type"))
        status = ParseStatus.PARSED if has_id else ParseStatus.PARTIAL

        return ParseResult(
            status=status,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="fortigate_kv",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
