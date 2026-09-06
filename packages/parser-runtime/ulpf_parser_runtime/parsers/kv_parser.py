"""Generic Key-Value parser for ULPF Phase 3.

Parses log lines containing key=value or key="quoted value" pairs.

Features:
- Supports both bare and double-quoted values
- Leading message text (before first key=) is extracted as `msg_prefix`
- Bounded pair count (prevent amplification)
- Deterministic, regex-based (linear time, no catastrophic backtracking)

Adheres to:
- Spec §18: Key-Value Strategy
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing

Examples handled:
  action=allow src=192.168.1.1 dst=8.8.8.8 dport=443
  vendor=Palo Alto type="traffic" bytes=1024
  msg="Login failed" user=admin src=10.0.0.1
"""

import re
import time

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

_MAX_PAIRS = 1000

# Matches: key=value, key="quoted value", key='quoted value'
# Key: alphanumeric, underscore, hyphen, dot (bounded to 128 chars)
# Value (quoted): up to 4096 chars
# Value (bare): up to 2048 non-space chars
_KV_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.\-]{0,127})"
    r"="
    r'(?:"([^"]{0,4096})"'
    r"|'([^']{0,4096})'"
    r"|([^\s\]\"']{0,2048}))"
)


class KeyValueParser(BaseParser):
    """Deterministic key=value log line parser with quoted value and prefix support."""

    metadata = ParserMetadata(
        parser_id="parser.generic.keyvalue",
        version="1.0.0",
        supported_formats=("key_value",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="Generic key=value log parser with quoted value support",
    )

    def __init__(self, max_pairs: int = _MAX_PAIRS) -> None:
        self.max_pairs = max_pairs

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        fields = {}
        errors: list[ParseError] = []

        first_match = _KV_RE.search(text)
        if first_match and first_match.start() > 0:
            prefix = text[: first_match.start()].strip()
            if prefix:
                fields["msg_prefix"] = self.make_field(
                    "msg_prefix",
                    prefix,
                    Origin.OBSERVED,
                    raw_locator="kv:msg_prefix",
                )

        pair_count = 0
        for match in _KV_RE.finditer(text):
            if pair_count >= self.max_pairs:
                errors.append(
                    ParseError(
                        code=ErrorCode.RESOURCE_LIMIT,
                        stage="kv_parser",
                        message=f"Key-value pair limit {self.max_pairs} exceeded; truncating",
                        severity=ErrorSeverity.WARNING,
                        recoverable=True,
                    )
                )
                break

            key = match.group(1)
            # Value: double-quoted group 2, single-quoted group 3, bare group 4
            value = match.group(2) or match.group(3) or match.group(4) or ""

            if key in fields:
                # Duplicate key: suffix with count
                count = sum(1 for k in fields if k == key or k.startswith(f"{key}__"))
                key = f"{key}__{count}"

            fields[key] = self.make_field(
                key,
                value,
                Origin.OBSERVED,
                raw_locator=f"kv:{key}",
            )
            pair_count += 1

        if not fields:
            err = ParseError(
                code=ErrorCode.INVALID_KV,
                stage="kv_parser",
                message="No key=value pairs found in record",
                severity=ErrorSeverity.WARNING,
                recoverable=True,
            )
            return ParseResult(
                status=ParseStatus.PARTIAL,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="key_value",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="key_value",
            extracted_fields=fields,
            errors=tuple(errors),
            duration_ms=self.measure_duration(t0),
        )
