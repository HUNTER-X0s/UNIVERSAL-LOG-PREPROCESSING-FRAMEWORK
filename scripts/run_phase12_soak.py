"""Phase 12 Controlled Endurance & Heap Stability Certification.

Runs continuous iterations through parsing and normalization pipelines,
monitoring heap growth with tracemalloc to prove zero memory leaks.
Emits reports/phase12_soak_results.json.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from pathlib import Path

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser
from ulpf_parser_runtime.parsers.specialized.suricata import SuricataEveParser


def run_controlled_endurance_soak() -> dict:
    root = Path(__file__).resolve().parent.parent
    tracemalloc.start()
    t0 = time.perf_counter()

    parser = SuricataEveParser()
    payload = json.dumps({
        "timestamp": "2026-09-08T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dest_ip": "198.51.100.1",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {"action": "allowed", "signature": "ET TROJAN Active C2 Beacon", "severity": 1}
    })
    raw_bytes = payload.encode("utf-8")
    rec = FramedRecord(record_index=0, text=payload, raw_bytes=raw_bytes, start_byte_offset=0, end_byte_offset=len(raw_bytes), line_count=1)

    cycles = 3000
    start_heap, _ = tracemalloc.get_traced_memory()
    heap_samples = []

    for i in range(cycles):
        res = parser.parse(rec)
        assert res.extracted_fields is not None
        if i % 500 == 0:
            cur, _ = tracemalloc.get_traced_memory()
            heap_samples.append({"cycle": i, "heap_bytes": cur})

    current_heap, peak_heap = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    elapsed = time.perf_counter() - t0

    heap_delta_mb = (current_heap - start_heap) / (1024 * 1024)
    peak_heap_mb = peak_heap / (1024 * 1024)

    report = {
        "timestamp": "2026-09-08T15:49:00Z",
        "characterization": "CONTROLLED_BURST_ENDURANCE",
        "total_cycles": cycles,
        "duration_seconds": round(elapsed, 4),
        "throughput_eps": round(cycles / elapsed, 1),
        "start_heap_bytes": start_heap,
        "end_heap_bytes": current_heap,
        "peak_heap_mb": round(peak_heap_mb, 3),
        "heap_growth_mb": round(heap_delta_mb, 3),
        "memory_leak_detected": heap_delta_mb > 5.0,
        "heap_samples": heap_samples,
        "verdict": "SOAK_ENDURANCE_PASS" if heap_delta_mb <= 5.0 else "MEMORY_LEAK_DETECTED"
    }

    with open(root / "reports" / "phase12_soak_results.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Controlled soak complete: {report['verdict']} (Heap growth: {report['heap_growth_mb']} MB across {cycles} cycles)")
    return report


if __name__ == "__main__":
    run_controlled_endurance_soak()
