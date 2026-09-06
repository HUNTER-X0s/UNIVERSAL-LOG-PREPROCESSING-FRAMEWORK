"""Throughput, latency, and memory performance micro-benchmarks for ULPF Phase 3.

Adheres to:
- Spec §43: Performance Requirements (>= 1,000 events/sec single-core)
- Spec §44: Latency Bounds (sub-millisecond parsing latency for common formats)
"""

import time
import unittest

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseStatus
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser
from ulpf_parser_runtime.parsers.specialized.fortigate import FortiGateParser
from ulpf_parser_runtime.parsers.specialized.paloalto import PaloAltoPanOSParser
from ulpf_parser_runtime.parsers.syslog_rfc3164 import SyslogRFC3164Parser


def _record(text: str) -> FramedRecord:
    raw = text.encode()
    return FramedRecord(
        record_index=0,
        text=text,
        raw_bytes=raw,
        start_byte_offset=0,
        end_byte_offset=len(raw),
        line_count=text.count("\n") + 1,
    )


class TestParserBenchmarks(unittest.TestCase):
    """Performance validation for deterministic parsing plane."""

    def test_json_parser_throughput(self) -> None:
        parser = GenericJsonParser()
        sample = '{"event_id": 100, "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "status": "allowed", "bytes": 1024}'
        rec = _record(sample)

        iterations = 500
        t0 = time.perf_counter()
        for _ in range(iterations):
            res = parser.parse(rec)
            self.assertEqual(res.status, ParseStatus.PARSED)
        elapsed = time.perf_counter() - t0

        events_per_sec = iterations / elapsed
        avg_latency_ms = (elapsed / iterations) * 1000.0

        # Assert throughput > 1,000 events/sec and average latency < 1.0 ms
        self.assertGreater(events_per_sec, 1000.0, f"JSON throughput was {events_per_sec:.1f} eps")
        self.assertLess(avg_latency_ms, 1.0, f"Average latency was {avg_latency_ms:.3f} ms")

    def test_paloalto_panos_throughput(self) -> None:
        parser = PaloAltoPanOSParser()
        sample = "1,2026/09/05 14:00:01,001801000001,TRAFFIC,drop,2304,2026/09/05 14:00:00,198.51.100.25,203.0.113.10,0.0.0.0,0.0.0.0,Block_External_Scan,,,not-applicable,vsys1,untrust,trust,ethernet1/1,,Syslog_Forwarder,2026/09/05 14:00:01,0,1,54321,23,0,0,0x0,tcp,deny,60,60,0,1,2026/09/05 14:00:00,0,any,0,12345678,0x0,United States,India,0,1,0,policy-deny,0,0,0,0,,PA-VM,from-policy"
        rec = _record(sample)

        iterations = 500
        t0 = time.perf_counter()
        for _ in range(iterations):
            res = parser.parse(rec)
            self.assertEqual(res.status, ParseStatus.PARSED)
        elapsed = time.perf_counter() - t0

        events_per_sec = iterations / elapsed
        self.assertGreater(
            events_per_sec, 1000.0, f"Palo Alto throughput was {events_per_sec:.1f} eps"
        )

    def test_fortigate_kv_throughput(self) -> None:
        parser = FortiGateParser()
        sample = 'date=2026-09-05 time=14:00:00 devname="FGT-CORP-01" devid="FGT60E4Q17012345" eventtime=1620000000 tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.10.10.25 srcport=51234 srcintf="port1" dstip=198.51.100.40 dstport=443 dstintf="port2" proto=6 action="accept" sentbyte=1250 rcvdbyte=8900'
        rec = _record(sample)

        iterations = 500
        t0 = time.perf_counter()
        for _ in range(iterations):
            res = parser.parse(rec)
            self.assertEqual(res.status, ParseStatus.PARSED)
        elapsed = time.perf_counter() - t0

        events_per_sec = iterations / elapsed
        self.assertGreater(
            events_per_sec, 1000.0, f"FortiGate throughput was {events_per_sec:.1f} eps"
        )

    def test_syslog_rfc3164_throughput(self) -> None:
        parser = SyslogRFC3164Parser()
        sample = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        rec = _record(sample)

        iterations = 500
        t0 = time.perf_counter()
        for _ in range(iterations):
            res = parser.parse(rec)
            self.assertEqual(res.status, ParseStatus.PARSED)
        elapsed = time.perf_counter() - t0

        events_per_sec = iterations / elapsed
        self.assertGreater(
            events_per_sec, 1000.0, f"Syslog 3164 throughput was {events_per_sec:.1f} eps"
        )


if __name__ == "__main__":
    unittest.main()
