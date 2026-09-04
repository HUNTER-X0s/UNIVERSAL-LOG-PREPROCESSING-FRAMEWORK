# Performance Strategy

## Principle

ULPF is architected for horizontal scale but has no Phase-0 measured throughput, latency, or capacity result. Performance claims are valid only when a reproducible workload, environment description, configuration, software revisions, raw results, and analysis are recorded together. A hackathon laptop demonstration proves workflow correctness; it does not prove a billions-of-events-per-day deployment.

## Benchmark questions

| Dimension | What to measure | Why it matters |
| --- | --- | --- |
| ingest throughput | acknowledged events/bytes per interval and rejection/spool behavior | collection capacity and safe backpressure |
| end-to-end latency | event receipt to durable normalized/search/lake state at P50/P95/P99 | investigator and downstream freshness |
| stage latency | evidence write, detection, parse, mapping, validation, lineage, each sink | bottleneck attribution |
| resource efficiency | CPU, memory, disk I/O, network I/O, broker/storage capacity, garbage/worker saturation | capacity planning and resource-limit safety |
| correctness under load | parse success, validation/normalization coverage, duplicate/out-of-order handling, hash/lineage success | speed must not compromise evidence or semantics |
| resilience | lag, retry age, DLQ rate, recovery/replay throughput during failures | operating behavior when dependencies degrade |
| onboarding quality | candidate mapping accuracy/approval rate and parser regression performance | reduces parser effort without overstating AI correctness |

## Reproducible benchmark protocol

Every result must include a benchmark manifest: corpus ID/version and provenance, generator settings, event count/byte distribution, source/format mix, malformed/unknown ratio, ordering/duplicate/late-event settings, software/image and parser/schema/mapping versions, hardware/OS/storage/network description, deployment topology, resource limits, warm-up duration, measurement window, repetitions, raw telemetry location, and known limitations.

```mermaid
flowchart LR
  C[Versioned corpus / generator] --> G[Workload manifest]
  G --> E[Isolated benchmark environment]
  E --> M[Raw metrics, traces, logs]
  M --> V[Validation of losslessness and correctness]
  V --> R[Versioned benchmark report]
  R --> D[Capacity / optimization decision]
```

Warm-up and steady-state periods are recorded separately. Runs use a fixed seed where synthetic generation is involved. A failed run is retained as a failed result; it is not quietly excluded. Comparisons change one declared factor at a time or explain all changed factors.

## Workload matrix

| Axis | Representative values to plan | Required reporting |
| --- | --- | --- |
| format/source | Syslog, JSON, CEF, LEEF, XML, CSV, key=value, semi-structured/unknown fixtures | composition and parser versions |
| payload shape | small/typical/large, Unicode, missing/extra fields, nested structures | byte-size distribution and limits |
| stream behavior | steady, burst, backpressure, duplicate, out-of-order, late, restart/replay | injection rate and resulting queue/retry states |
| parser behavior | known fast path, complex valid path, malformed, timeout/resource-boundary | result categories and timeouts |
| topology | developer, demo, single node, replicated/worker-scale test | component count, partitions, volumes, limits |
| downstream behavior | normal, slow search/lake, unavailable broker/store, recovery | data-loss/lag/DLQ/restore outcomes |

The corpus plan appears in [Dataset Strategy](DATASET_STRATEGY.md). It must not be replaced by unlicensed, sensitive, or undocumented logs just to create a high-looking number.

## Measurement semantics

- Throughput distinguishes submitted, durably accepted, parsed, normalized, indexed, lake-written, exported, retried, quarantined, and rejected events. “Events/sec” alone is insufficient.
- Latency has a stated start/end: e.g., collector submission to durable raw evidence, or durable evidence to normalized output. Event time is not a processing-latency start.
- Percentiles are computed from the full stated sample; discard rules and clock synchronization are documented.
- Resource metrics are tied to process/container and host context. Queue depth and consumer lag are reported beside latency so a low-latency subset does not hide an accumulating backlog.
- Correctness gates include exact raw byte/hash retention, lineage completion, version consistency, and deterministic reprocessing for the test’s pinned inputs.

## Capacity and scaling method

Start with a correct single-node baseline. Profile bottlenecks before increasing concurrency: evidence write latency, hot partitions, parser CPU/regex time, object-store I/O, OpenSearch indexing pressure, lake small-file behavior, and database/lineage writes. Scale stateless worker groups and partitions only after a capacity hypothesis is documented and verified. Storage, broker, and search replication are separate engineering workstreams with failure tests.

The scale ladder is developer correctness -> demo repeatability -> single-node sustained workload -> controlled multi-worker test -> clustered capacity test. Each step has a stop condition: if integrity, lineages, retries, or resource limits fail, fix that behavior before presenting a larger number.

## Optimization guardrails

Never optimize by truncating raw events, disabling integrity/lineage, skipping validation, dropping unknown fields, suppressing DLQ records, or converting errors to successes. Batching, compression, partitioning, compiled deterministic parsers, connection reuse, and columnar lake writes are reasonable candidates only after profiling. Any change that alters ordering, duplication, retention, schema semantics, or evidence handling needs contract/ADR review.

## Benchmark exit criteria

A benchmark report is publishable only when it states its scope, shows raw evidence/correctness checks, includes environment and corpus provenance, reports failures and limitations, and can be rerun from committed configuration plus authorized corpus access. “No result yet” is an honest Phase-0 status. Measured data will determine future performance targets and technology adjustments.
