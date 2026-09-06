#!/usr/bin/env python3
"""ULPF Phase 4 Semantic Pipeline Benchmark.

Measures per-component latency (p50/p95/p99) and aggregate throughput
for the end-to-end UCE -> SemanticEvent -> OCSF -> OTel pipeline.

Usage:
    python scripts/run_phase4_benchmarks.py

Output:
    reports/phase4_benchmarks.json
"""

import copy
import json
import sys
import time
from pathlib import Path

for pkg in ("packages/semantic", "packages/normalization", "packages/parser-runtime", "packages/foundation"):
    pkg_path = str(Path(pkg).resolve())
    if pkg_path not in sys.path:
        sys.path.insert(0, pkg_path)

from ulpf_semantic.analytics.fingerprint import EventFingerprinter
from ulpf_semantic.classification.classifier import SemanticClassifier
from ulpf_semantic.entities.extractor import EntityExtractor
from ulpf_semantic.indicators.extractor import IndicatorExtractor
from ulpf_semantic.mapping.engine import SemanticMapper
from ulpf_semantic.models import SemanticTriple
from ulpf_semantic.projections.ocsf.mapper import OCSFProjection
from ulpf_semantic.projections.otel.mapper import OTelProjection
from ulpf_semantic.risk.evaluator import RiskEvaluator
from ulpf_semantic.service import SemanticService
from ulpf_semantic.taxonomy.actions import map_action

FIREWALL_UCE = {
    "event_id": "bench-fw-001",
    "raw_event_id": "raw-fw-001",
    "event": {
        "time": "2026-09-06T10:00:00Z",
        "action": "deny",
        "severity": 7,
        "category": "firewall",
        "source": {"ip": "192.168.1.1", "port": 54321},
        "destination": {"ip": "10.0.0.1", "port": 80},
        "metadata": {"vendor": "Fortinet", "product": "FortiGate", "parser_id": "fortigate.kv"},
    },
    "unmapped_fields": {"policyname": "BLOCK-MALICIOUS"},
}

IDS_UCE = {
    "event_id": "bench-ids-001",
    "raw_event_id": "raw-ids-001",
    "event": {
        "time": "2026-09-06T10:00:00Z",
        "action": "alert",
        "severity": 9,
        "type": "alert",
        "metadata": {"vendor": "Suricata", "product": "EVE", "parser_id": "parser.suricata.eve"},
    },
    "unmapped_fields": {"signature": "GPL EXPLOIT Test", "sid": "2001219"},
}

HTTP_UCE = {
    "event_id": "bench-http-001",
    "raw_event_id": "raw-http-001",
    "event": {
        "time": "2026-09-06T10:00:00Z",
        "action": "allow",
        "severity": 1,
        "metadata": {"vendor": "NGINX", "product": "Web Server", "parser_id": "parser.web.access"},
    },
    "unmapped_fields": {"status_code": "200"},
}

N = 1000


def measure(fn, uce_factory, n=N):
    latencies = []
    for _ in range(n):
        uce = uce_factory()
        t0 = time.perf_counter()
        fn(uce)
        latencies.append((time.perf_counter() - t0) * 1000)
    latencies.sort()
    return latencies


def stats(latencies):
    n = len(latencies)
    return {
        "n": n,
        "p50_ms": round(latencies[n // 2], 4),
        "p95_ms": round(latencies[int(n * 0.95)], 4),
        "p99_ms": round(latencies[int(n * 0.99)], 4),
        "mean_ms": round(sum(latencies) / n, 4),
        "eps": round(1000 / (sum(latencies) / n), 1),
    }


def main():
    print("=" * 60)
    print("ULPF Phase 4 Semantic Pipeline Benchmarks")
    print(f"Samples: {N}")
    print("=" * 60)

    results = {}
    svc = SemanticService()
    mapper = SemanticMapper()
    classifier = SemanticClassifier()
    ocsf = OCSFProjection()
    otel = OTelProjection()

    lat = measure(lambda u: classifier.classify(u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["classification"] = stats(lat)
    print(f"[Classification]   p50={results['classification']['p50_ms']}ms  eps={results['classification']['eps']}")

    lat = measure(lambda u: EntityExtractor.extract_entities(u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["entity_extraction"] = stats(lat)
    print(f"[Entity Extraction] p50={results['entity_extraction']['p50_ms']}ms  eps={results['entity_extraction']['eps']}")

    lat = measure(lambda u: IndicatorExtractor.extract_indicators(u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["indicator_extraction"] = stats(lat)
    print(f"[Indicator Extraction] p50={results['indicator_extraction']['p50_ms']}ms  eps={results['indicator_extraction']['eps']}")

    lat = measure(lambda u: RiskEvaluator.evaluate(7, "deny", "DENIED", True, False, u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["risk_evaluation"] = stats(lat)
    print(f"[Risk Evaluation]  p50={results['risk_evaluation']['p50_ms']}ms  eps={results['risk_evaluation']['eps']}")

    sem_fw = mapper.map_uce_to_semantic(copy.deepcopy(FIREWALL_UCE))
    lat = measure(lambda u: ocsf.project(sem_fw, u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["ocsf_projection"] = stats(lat)
    print(f"[OCSF Projection]  p50={results['ocsf_projection']['p50_ms']}ms  eps={results['ocsf_projection']['eps']}")

    lat = measure(lambda u: otel.project(sem_fw, u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["otel_projection"] = stats(lat)
    print(f"[OTel Projection]  p50={results['otel_projection']['p50_ms']}ms  eps={results['otel_projection']['eps']}")

    lat = measure(lambda u: svc.process_uce(u), lambda: copy.deepcopy(FIREWALL_UCE))
    results["e2e_firewall"] = stats(lat)
    print(f"[E2E Firewall]     p50={results['e2e_firewall']['p50_ms']}ms  eps={results['e2e_firewall']['eps']}")

    lat = measure(lambda u: svc.process_uce(u), lambda: copy.deepcopy(IDS_UCE))
    results["e2e_ids"] = stats(lat)
    print(f"[E2E IDS Alert]    p50={results['e2e_ids']['p50_ms']}ms  eps={results['e2e_ids']['eps']}")

    lat = measure(lambda u: svc.process_uce(u), lambda: copy.deepcopy(HTTP_UCE))
    results["e2e_http"] = stats(lat)
    print(f"[E2E HTTP Access]  p50={results['e2e_http']['p50_ms']}ms  eps={results['e2e_http']['eps']}")

    print("=" * 60)
    min_eps = min(results[k]["eps"] for k in ["e2e_firewall", "e2e_ids", "e2e_http"])
    print(f"Minimum e2e eps: {min_eps:.0f}")
    assert min_eps >= 2000, f"PERFORMANCE REGRESSION: eps={min_eps:.0f} < 2000"
    print("PERFORMANCE GATE: PASS")
    print("=" * 60)

    report = {
        "benchmark_version": "1.0.0",
        "date": "2026-09-06",
        "samples_per_benchmark": N,
        "note": "Single-threaded microbenchmarks on development machine.",
        "results": results,
    }
    out = Path("reports/phase4_benchmarks.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report: {out}")


if __name__ == "__main__":
    main()
