# Phase 2 Acceptance Checklist

This checklist records implemented evidence only.

## Architecture and raw capture

- [x] Frozen RawEvent schema used through `ContractRegistry`; no frozen contract modified.
- [x] Opaque byte capture, SHA-256, receipt IDs, transport metadata, and request/correlation/trace context implemented.
- [x] Equal payloads are retained as distinct receipts.
- [x] Configurable bounds reject rather than truncate.
- [x] No Phase 3 parsing, field extraction, source/vendor detection, or normalization implemented.

## Transport and security boundary

- [x] HTTP raw intake and truthful `202 Captured` acknowledgement implemented.
- [x] Bounded TCP LF framing implemented and tested on loopback.
- [x] Bounded UDP datagram capture implemented and tested on loopback; weaker delivery semantics documented.
- [x] Fixture-file adapter with explicit framing implemented and tested.
- [x] Header/body limits, static-token boundary, and local fixed-window rate limit implemented.
- [x] Payload content excluded from normal application logs and metric labels.

## Evidence, observability, and testing

- [x] Bounded local development evidence sink persists bytes plus receipt metadata and verifies SHA-256 on retrieval.
- [x] Capture counters use only bounded transport/outcome dimensions; no exporter is claimed.
- [x] Unit/integration tests cover byte preservation, hash, contract projection, duplicates, HTTP refusal paths, TCP, UDP, file framing, and configuration bounds.
- [ ] S3-compatible immutable evidence store, manifest signing, durable queue, and production retrieval authorization: deferred.
- [ ] Measured benchmark, Docker run, air-gap drill, real-device test, and production security review: human/manual evidence pending.
