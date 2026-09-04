# Architecture Self-critique: Hostile Review

This is a deliberate attempt to break the design. Each answer identifies the designed mitigation and what still must be proven in implementation.

| Attack question | Design response | Proof still required |
|---|---|---|
| What if a vendor changes its format tomorrow? | Drift signals compare profile expectations; create reviewed parser/mapping/schema candidate, test, publish, and optionally replay. | Drift sensitivity/false-positive tests on variant corpus. |
| What if AI maps a field incorrectly? | Proposal stays inferred and cannot publish/activate itself; reviewer and fixtures decide. | Offline/model/prompt-injection tests and review UX. |
| What if the same event arrives twice? | Preserve each RawEvent; relate fingerprints; idempotent consumers prevent duplicate projection effects. | Duplicate/at-least-once integration tests. |
| What if events arrive out of order or clocks are wrong? | Preserve event/receipt/process time, sequence, offset, precision, late/skew flags. | Timezone/clock-skew/out-of-order corpus tests. |
| What if a parser crashes or loops? | Isolated, bounded workers; retry/quarantine; raw evidence persists first. | Fuzz, limit, crash/restart, and resource-exhaustion tests. |
| What if raw evidence is tampered with? | SHA-256, signed manifests/Merkle roots, audited custody, explicit verification status. | Tamper and restore verification drills; key-custody implementation. |
| What if OpenSearch/Kafka/PostgreSQL fails? | Store responsibilities are separated; explicit degraded modes, retries/outbox/DLQ/recovery. | Chaos/recovery tests and runbooks. |
| What if AI/enrichment is unavailable? | Core deterministic processing continues; optional stage is marked unavailable. | Network-denied and service-unavailable tests. |
| What if a log contains malicious payload? | Treat it as data; safe rendering, no eval/shell, parser sandbox/limits, upload validation. | Security testing and code review. |
| What if one field is unknown or vendor sends 10,000 fields? | Preserve unknown namespaced fields/residue; limits prevent resource exhaustion; drift/onboarding follow-up. | Field-count/large-event/unknown-field tests. |
| What if traffic grows 100x? | Backpressure, partitioned transport, stateless workers, tiered stores, scale profiles; no laptop scale claim. | Load/capacity measurement on stated hardware. |
| What if a parser upgrade is wrong? | Immutable version pins, rollback, comparison replay, retained historical interpretation. | Upgrade/rollback/replay comparison tests. |
| What if an air-gapped site needs an update? | Signed OCI/config/schema/parser/model bundle, controlled transfer, offline verification/activation. | Real offline import/revocation drill. |
| What if two schemas describe the same field differently? | UCE remains internal semantic authority; projections use versioned adapters/rules with provenance. | Cross-schema conformance/semantic equivalence tests. |
| What if sensitive data appears in a log? | Classification, evidence permissions, masking in views, export audit/authorization; raw evidence remains protected. | Policy decisions, access-control/privacy tests. |
| What if a parser extension is malicious? | Trusted allowlisted adapters, signed declarative packs, least privilege, no arbitrary code. | Signature/revocation/isolation tests. |
| What if network disconnects for hours? | Bounded edge buffer/backpressure and source health; safe explicit reject policy once capacity ends. | Disconnection/reconnect/duplicate tests. |
| Why not just use Logstash/Fluent Bit/Vector/SIEM? | Those can transport/transform; ULPF focuses on governed universal onboarding, lossless evidence, field lineage, drift, replay, and air-gap assurance. | Demo must show this evidence lifecycle, not merely reformat logs. |

## Weaknesses that remain

- The architecture has no empirical performance evidence yet.
- A no-code promise has a boundary: complex novel grammars can require a trusted adapter implementation.
- Object-lock/retention, identity, and signing details depend on real deployment policy and infrastructure.
- Optional AI value is uncertain until it is evaluated on an authorized local corpus and available hardware.
- The six-member plan succeeds only with strict scope control and early integration.
