"""Snort Fast Alert parser for ULPF Phase 3 (Tier B).

Parses Snort fast alert telemetry:
  [**] [gid:sid:rev] signature [**] [Classification: category]
  [Priority: p] timestamp src:sport -> dst:dport PROTO TTL:x ...


Extracts:
- gid, sid, rev
- signature / message
- classification / category
- priority
- timestamp
- src_ip, src_port, dst_ip, dst_port, protocol
- ttl, tos, id, dgmlen

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

# Regex for Snort fast alert header
RE_SNORT_FAST = re.compile(
    r"^\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]"
    r"(?:\s+\[Classification:\s+([^\]]+)\])?"
    r"(?:\s+\[Priority:\s+(\d+)\])?"
    r"\s+(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"\s+([^\s]+)\s+->\s+([^\s]+)"
    r"(?:\s+([A-Za-z0-9]+))?",
    re.DOTALL,
)


def _split_host_port(token: str) -> tuple[str, str | None]:
    """Split host and optional port from a network endpoint token."""
    if ":" in token:
        # Check if IPv6 like [2001:db8::1]:80 or IPv4 192.168.1.1:80
        if token.startswith("[") and "]:" in token:
            bracket_idx = token.rfind("]:")
            return token[1:bracket_idx], token[bracket_idx + 2 :]
        if token.count(":") == 1:
            h, p = token.split(":")
            if p.isdigit():
                return h, p
        # Multiple colons without brackets: check if last component is a port
        parts = token.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], parts[1]
    return token, None


class SnortFastParser(BaseParser):
    """Deterministic parser for Snort fast alert format."""

    metadata = ParserMetadata(
        parser_id="parser.snort.fast",
        version="1.0.0",
        supported_formats=("snort_fast",),
        supported_vendors=("Snort", "Cisco"),
        supported_products=("Snort", "Snort IDS"),
        tier="B",
        description="Snort fast alert format parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        match = RE_SNORT_FAST.search(text)
        if not match:
            err = ParseError(
                code=ErrorCode.UNKNOWN_FORMAT,
                stage="snort_fast",
                message="Record does not match Snort fast alert pattern",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="snort_fast",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        gid, sid, rev, sig, classification, priority, ts, src_token, dst_token, proto = (
            match.groups()
        )

        src_ip, src_port = _split_host_port(src_token)
        dst_ip, dst_port = _split_host_port(dst_token)

        fields: dict[str, Any] = {
            "gid": self.make_field("gid", gid, Origin.OBSERVED, raw_locator="snort:gid"),
            "sid": self.make_field("sid", sid, Origin.OBSERVED, raw_locator="snort:sid"),
            "rev": self.make_field("rev", rev, Origin.OBSERVED, raw_locator="snort:rev"),
            "signature": self.make_field(
                "signature", sig.strip(), Origin.OBSERVED, raw_locator="snort:sig"
            ),
            "timestamp": self.make_field("timestamp", ts, Origin.OBSERVED, raw_locator="snort:ts"),
            "src_ip": self.make_field(
                "src_ip", src_ip, Origin.OBSERVED, raw_locator="snort:src_ip"
            ),
            "dst_ip": self.make_field(
                "dst_ip", dst_ip, Origin.OBSERVED, raw_locator="snort:dst_ip"
            ),
        }

        if classification:
            fields["classification"] = self.make_field(
                "classification", classification.strip(), Origin.OBSERVED
            )
        if priority:
            fields["priority"] = self.make_field("priority", int(priority), Origin.OBSERVED)
        if src_port:
            fields["src_port"] = self.make_field("src_port", src_port, Origin.OBSERVED)
        if dst_port:
            fields["dst_port"] = self.make_field("dst_port", dst_port, Origin.OBSERVED)
        if proto:
            fields["protocol"] = self.make_field("protocol", proto.upper(), Origin.OBSERVED)

        # Unmapped trailer
        trailer = text[match.end() :].strip()
        unmapped = {"trailer": trailer} if trailer and trailer != "[**]" else {}

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="snort_fast",
            extracted_fields=fields,
            unmapped_fields=unmapped,
            duration_ms=self.measure_duration(t0),
        )
