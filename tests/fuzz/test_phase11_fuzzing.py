"""Phase 11 Fuzzing & Resource Exhaustion Adversarial Suite.

Subjecting all format and specialized parsers to malformed payloads,
deep recursion bombs, binary garbage, and ReDoS triggers to ensure bounded,
crash-free execution.
"""

from __future__ import annotations

import time

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseStatus
from ulpf_parser_runtime.parsers.csv_parser import GenericCsvParser
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser, NdJsonParser
from ulpf_parser_runtime.parsers.kv_parser import KeyValueParser
from ulpf_parser_runtime.parsers.specialized.cisco import CiscoSyslogParser
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.linux_auditd import LinuxAuditdParser
from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser
from ulpf_parser_runtime.parsers.syslog_rfc3164 import SyslogRFC3164Parser
from ulpf_parser_runtime.parsers.syslog_rfc5424 import SyslogRFC5424Parser


def _make_record(text: str) -> FramedRecord:
    raw = text.encode("utf-8", errors="replace")
    return FramedRecord(
        record_index=0,
        text=text,
        raw_bytes=raw,
        start_byte_offset=0,
        end_byte_offset=len(raw),
        line_count=text.count("\n") + 1,
    )


ALL_PARSERS = [
    GenericJsonParser(),
    NdJsonParser(),
    GenericCsvParser(),
    KeyValueParser(),
    SyslogRFC3164Parser(),
    SyslogRFC5424Parser(),
    PaloAltoPanOSParser(),
    CiscoSyslogParser(),
    SuricataEveParser(),
    FortiGateParser(),
    LinuxAuditdParser(),
]


# ===========================================================================
# 1. Broad Fuzzing Across All 11 Parsers
# ===========================================================================

MALFORMED_INPUTS = [
    "",
    "   ",
    "\x00" * 256,
    "\xff\xfe\xfa\xbc" * 64,
    "{" * 500,
    "}" * 500,
    "[" * 500,
    "]" * 500,
    "<134>" + "A" * 50000,  # Huge syslog
    "CEF:0|Vendor|Product|1.0|100|Event|" + "|".join(["k=v"] * 500),
    "key1='unclosed_quote key2=val2 key3=\"double_unclosed",
    "col1,col2,col3\n\"unclosed quote,123,456",
    "\r\n\r\n\r\n",
    "null\x00bytes\x00in\x00middle",
    "{\"a\": " * 30 + "1" + "}" * 30,  # Deep nesting
    "10.0.0.1 - - [invalid/timestamp/here] \"GET / HTTP/1.1\" invalid_status invalid_bytes",
]


def test_all_parsers_fuzz_resilience() -> None:
    """Verify all 11 parsers survive arbitrary malformed inputs without unhandled crashes."""
    for parser in ALL_PARSERS:
        for payload in MALFORMED_INPUTS:
            record = _make_record(payload)
            t0 = time.perf_counter()
            result = parser.parse(record)
            elapsed = time.perf_counter() - t0

            # Must finish within 500ms (no ReDoS / hang)
            assert elapsed < 0.5, f"Parser {parser} hung for {elapsed:.3f}s on input: {payload[:30]}"
            # Must return a valid parsed record with status
            assert result.status in (ParseStatus.PARSED, ParseStatus.PARTIAL, ParseStatus.FAILED)


# ===========================================================================
# 2. JSON Parser Specific Boundary & Depth Attacks
# ===========================================================================

def test_json_parser_deep_nesting_bomb() -> None:
    """Verify JSON parser rejects or bounds deeply nested structures safely."""
    parser = GenericJsonParser(max_depth=10)
    nested_bomb = "{\"k\":" * 100 + "42" + "}" * 100
    record = _make_record(nested_bomb)

    res = parser.parse(record)
    assert res.status == ParseStatus.FAILED or len(res.errors) > 0 or len(res.extracted_fields) == 0


def test_json_parser_oversized_key_count() -> None:
    """Verify JSON parser handles thousands of keys without memory explosion."""
    parser = GenericJsonParser()
    keys = {f"k_{i}": f"val_{i}" for i in range(1000)}
    import json
    large_payload = json.dumps(keys)
    record = _make_record(large_payload)

    t0 = time.perf_counter()
    res = parser.parse(record)
    elapsed = time.perf_counter() - t0

    assert elapsed < 0.2
    assert res.status in (ParseStatus.PARSED, ParseStatus.PARTIAL)
    assert len(res.extracted_fields) == 1000


# ===========================================================================
# 3. CSV / Key-Value Delimiter Chaos
# ===========================================================================

def test_csv_parser_mismatched_columns() -> None:
    """Verify CSV parser survives rows with inconsistent column counts."""
    parser = GenericCsvParser()
    csv_chaos = "header1,header2,header3\nval1\nval1,val2,val3,extra1,extra2\nvalA,valB"
    record = _make_record(csv_chaos)

    res = parser.parse(record)
    assert res.status in (ParseStatus.PARSED, ParseStatus.PARTIAL, ParseStatus.FAILED)


def test_kv_parser_pathological_quotes() -> None:
    """Verify key-value parser handles unbalanced, nested, and escaped quotes."""
    parser = KeyValueParser()
    payload = "src=10.0.0.1 msg=\"User \\\"admin\\\" attempted 'login' with pass=\\\"123\\\" dst=192.168.1.1"
    record = _make_record(payload)

    res = parser.parse(record)
    assert res.status in (ParseStatus.PARSED, ParseStatus.PARTIAL)
    assert "src" in res.extracted_fields
