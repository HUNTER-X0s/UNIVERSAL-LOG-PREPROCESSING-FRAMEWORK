# Phase 3 Handoff

Phase 3 begins from a frozen RawEvent reference produced by Phase 2. It must consume `raw-event.v1.schema.json` documents and retrieve authoritative payload bytes from the evidence reference; it must not revise Phase 2 receipt metadata, IDs, payload bytes, SHA-256, or byte length.

## Where events enter

- HTTP: `POST /api/v1/intake/raw`, one opaque request body per event.
- TCP: optional loopback-configured LF delimiter framing; the delimiter is part of the evidence bytes.
- UDP: optional configured listener; one datagram per event.
- fixture adapter: `whole-file` or `line` framing only.

The frozen contract contains `raw_event_id`, `source_id`, receipt times, payload reference/hash/length, transport context, and capture status. Phase 2’s internal `event_id` is projected as `raw_event_id`. `source_id` may be `unknown`; Phase 3 must not infer it silently.

## Invariants Phase 3 must preserve

1. Hash the bytes retrieved from the evidence reference before any semantic work and fail/quarantine explicitly on mismatch.
2. Never decode-and-replace or trim/re-encode the authoritative raw payload.
3. Treat TCP/UDP transport data as context, not source-log semantics.
4. Use a new ParsedEvent artifact/reference; do not add semantic fields to RawEvent.
5. Keep parser, mapping, and schema versions explicit; they are absent in Phase 2 by design.
6. Preserve duplicate receipts as separate inputs.

## Relevant fixtures and tests

`tests/test_raw_intake.py` covers raw HTTP capture, exact retrieval, hash, limits, tokens, and duplicates. `tests/test_intake_transports.py` covers TCP LF-byte retention, UDP datagrams, and file line-ending preservation. Future parser tests should reuse these opaque payloads without assuming their JSON-like or text-like contents are already understood.

## Known limitations

Phase 2 uses a bounded local-file evidence fallback, not the architecture’s durable S3-compatible evidence service, PostgreSQL catalog, signed manifest chain, or Kafka reference topic. TCP/UDP are disabled by default; HTTPS/TLS termination, mutual authentication, governed source registry, distributed rate limiting, durable handoff, and production retrieval authorization remain pending.

NO PHASE 3 SEMANTIC PARSING OR NORMALIZATION WAS IMPLEMENTED IN PHASE 2.
