# Intake Transports

**Status:** Phase 2 implementation. “Syslog” below means transport framing only, never Syslog semantic parsing.

| Transport | Enablement | Event boundary | Exact-byte behavior | Refusal behavior |
|---|---|---|---|---|
| HTTP | Always routed | one request body | stream is captured as received bytes; `Content-Type` is stored as metadata only | `413` for body limit, `431` for header limit, `429` for local rate limit, `401` for configured token failure |
| TCP | `ULPF_INTAKE_TCP_ENABLED=true` | LF-delimited frame, delimiter retained | each complete frame including LF or CRLF bytes is captured | oversized, incomplete-at-EOF, or timed-out frame is not accepted; connection closes |
| UDP | `ULPF_INTAKE_UDP_ENABLED=true` | one datagram | whole received datagram is captured | oversized/concurrency-refused datagram is not accepted; UDP supplies no acknowledgement |
| fixture file | direct adapter only | explicit `whole-file` or binary `line` mode | whole file or each `readline` byte sequence is captured; line endings are retained | oversized file/frame raises a local refusal |

## HTTP acknowledgement

`POST /api/v1/intake/raw` accepts any request body as opaque bytes and replies `202` only after local capture succeeds. A successful body states `accepted: true`, `status: captured`, event ID, receipt ID, receipt time, request ID, correlation ID, and trace ID. It never says parsed, normalized, processed, or delivered.

`GET /api/v1/intake/raw/{event_id}` returns exact bytes only when `ULPF_INTAKE_DEVELOPMENT_RETRIEVAL_ENABLED=true`; it is hidden from OpenAPI and otherwise returns a safe not-found response. The route is for local verification, not a governed evidence-retrieval API.

## Default limits

| Setting | Default | Meaning |
|---|---:|---|
| `ULPF_REQUEST_MAX_BYTES` | 1 MiB | declared HTTP request-body pre-check limit |
| `ULPF_INTAKE_MAX_EVENT_BYTES` | 1 MiB | maximum complete event, TCP frame, UDP datagram, or fixture frame |
| `ULPF_INTAKE_MAX_HTTP_HEADER_BYTES` | 16 KiB | aggregate HTTP header limit |
| `ULPF_INTAKE_HTTP_REQUESTS_PER_MINUTE` | 600 | per-process HTTP request window, not per-source distributed control |
| `ULPF_INTAKE_MAX_CONNECTIONS` | 64 | TCP connections and UDP capture tasks admitted locally |
| `ULPF_INTAKE_READ_TIMEOUT_SECONDS` | 5 | TCP frame-read timeout |
| `ULPF_INTAKE_EVIDENCE_MAX_EVENTS` | 10,000 | local fallback receipt capacity |
| `ULPF_INTAKE_EVIDENCE_MAX_BYTES` | 1 GiB | local fallback byte capacity |

`intake_max_event_bytes` cannot exceed the request bound, and local evidence capacity must hold at least one full event. Refusal is preferred to truncation.

## Delivery semantics

ULPF does not intentionally transform or truncate an accepted payload. This does not mean TCP delivers every source event, nor that UDP is lossless. UDP can lose, duplicate, or reorder datagrams before ULPF receives them; a locally refused datagram cannot receive a protocol acknowledgement. TCP provides ordered bytes for its connection but source retries or disconnects can still produce distinct receipts. Duplicate-looking bytes remain separate evidence receipts.
