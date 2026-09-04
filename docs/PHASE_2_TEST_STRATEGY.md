# Phase 2 Test Strategy

Phase 2 tests use synthetic opaque bytes and local loopback sockets only. They do not require Internet access, device hardware, a broker, an object store, or credentials outside the process.

| Test area | Evidence currently exercised |
|---|---|
| raw preservation | binary, CRLF, JSON-looking bytes round-trip exactly through HTTP and in-memory capture |
| integrity | SHA-256 and byte length match the authoritative captured bytes |
| duplicate receipts | equal payloads receive different event and receipt IDs |
| frozen contract | every accepted capture projects to `raw-event.v1.schema.json` |
| HTTP | `202 Captured`, disabled-by-default retrieval, event-size refusal, header refusal, static-token refusal, local rate-limit refusal |
| TCP | loopback LF framing retains delimiter bytes |
| UDP | loopback whole-datagram capture retains binary bytes |
| file fixture | whole-file/line framing is explicit and preserves line endings |
| configuration | invalid bounds and production-without-token fail safely |

The test suite intentionally does not claim real-device compatibility, TLS/mTLS, network-loss measurement, S3 durability, durable queues, Docker execution, load throughput, or production security certification. Those require their own infrastructure and human validation.
