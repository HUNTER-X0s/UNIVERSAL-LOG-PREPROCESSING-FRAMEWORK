# Phase 2 Completion Report

## 1. Objective and scope

Phase 2 implements the first ULPF data-plane boundary: bounded receipt, exact opaque capture, identity, SHA-256 integrity fingerprint, local development evidence write, and truthful acknowledgement. It is not a parser or normalization phase.

## 2. Architecture used

HTTP, TCP, UDP, and fixture adapters converge on `RawCaptureService`. The service uses `RawEventSink` for evidence and validates the frozen RawEvent JSON Schema after capture. `SourceResolver` is transport-context-only and defaults to an explicit unknown source. Future durable evidence and streaming implementations replace the port, not the adapters.

## 3. Transports implemented

HTTP is available at `/api/v1/intake/raw`. TCP and UDP listeners are disabled by default and can be enabled only through typed configuration. TCP uses documented LF framing and preserves the delimiter. UDP captures whole datagrams. The fixture adapter supports explicit whole-file or binary-line framing.

## 4. Raw event and preservation result

Every accepted receipt has unique event and receipt IDs, receipt UTC time, source context, transport context, exact byte length, SHA-256, request/correlation/trace IDs where available, and a frozen RawEvent projection. Focused tests demonstrated byte-for-byte preservation of binary, CRLF, and JSON-looking inputs; no payload semantic field was extracted.

## 5. Integrity and failure semantics

SHA-256 is calculated on the authoritative `bytes` before any semantic stage. A local retrieval verifies the stored hash and length. Oversized, malformed/incomplete TCP, timeout, header-limit, authentication, and local-rate refusal paths do not acknowledge a partial event. Accepted status is only `captured`; no processing completion is claimed.

## 6. Security and observability

Inputs are bounded, TCP/UDP default to loopback and disabled, payloads are not logged, and production settings require an injected token. The interim token mechanism is not a production identity solution. Capture counters have bounded outcome/transport dimensions; structured logs retain request/correlation/trace IDs without raw payloads. There is no metrics exporter, tracing SDK, or external telemetry call.

## 7. Tests and benchmarks

Phase 2 tests cover HTTP, TCP, UDP, fixture framing, exact bytes, hash, frozen-contract projection, duplicate receipts, capacity/auth/size/header/rate failures, and configuration guards. Tests use local loopback and synthetic bytes. No benchmark was run; no events-per-second, latency, CPU, or memory figure is claimed.

## 8. Docker and air-gap status

The existing API image includes the Phase 2 package and creates an owned evidence directory. The Compose development profile mounts a named local evidence volume while retaining a read-only service filesystem. Docker build/run was not performed in this environment, so no container-runtime claim is made. Runtime code uses only local dependencies and makes no Internet call; a network-denied air-gap drill remains manual.

## 9. Limitations, risks, and manual work

The local-file evidence sink is not the ADR-005 S3-compatible immutable evidence store and has no signed manifests, retention enforcement, PostgreSQL catalog, durable queue, replication, or disaster-recovery proof. No TLS/mTLS, OIDC/RBAC, device source registry, distributed rate limiting, real-device validation, or throughput validation exists. See [Phase 2 manual tasks](PHASE_2_MANUAL_TASKS.md).

## 10. Phase 3 prerequisite

Phase 3 must retrieve and verify the raw bytes by reference, preserve Phase 2 receipt identity and evidence invariants, and create a separate ParsedEvent artifact. See [Phase 3 handoff](PHASE_3_HANDOFF.md).

## Final acceptance result

**PASS WITH DOCUMENTED RISKS** after the final complete quality suite is recorded. The local Phase 2 capture boundary is demonstrated; durable production evidence and all semantic processing remain deferred.

NO PHASE 3 SEMANTIC PARSING OR NORMALIZATION WAS IMPLEMENTED.
