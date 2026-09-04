# Architecture Quality Review

**Review type:** Phase 0 design review, not an implementation certification.

| Review question | Phase 0 answer | Evidence / remaining condition |
|---|---|---|
| Does every NTRO requirement have an architectural home and future proof? | Yes | [Requirements Traceability](REQUIREMENTS_TRACEABILITY.md) maps REQ-001 through REQ-015 to components, phases, tests, and demo evidence. |
| Is raw data lossless and traceable? | Designed yes; not yet measured/implemented | Raw evidence, hash, manifest, UCE, and lineage contracts; requires future round-trip/restore tests. |
| Can a new source avoid core change? | Designed for compatible formats | Configuration-driven parser/source/mapping lifecycle; complex grammars may still need a trusted format adapter. |
| Can unknown formats be handled safely? | Yes, via review-gated path | Deterministic analysis first; optional offline AI; no auto-publish. |
| Can core operate without AI and Internet? | Yes by architecture | Local runtime/bundle model; needs network-denied proof in Phase 10/16. |
| Is there a scale path? | Yes, architecture only | Kafka partitions, stateless workers, purpose-specific stores; no throughput claim until Phase 15. |
| Are failures, drift, replay, and parser upgrades recoverable? | Designed yes | DLQ, immutable evidence, governed versions, replay comparison; requires integration tests. |
| Is malicious input considered? | Yes | threat model, sandbox/limits, supply-chain controls, fuzz test strategy. |
| Are SIEM/data lake/ML integrations scoped correctly? | Yes | OCSF primary plus adapters; ULPF is not positioned as a full SIEM. |
| Is the MVP feasible for six students? | Conditionally | A focused vertical slice is feasible; scope gate must exclude advanced analytics and distributed production claims. |
| Is differentiation defensible? | Yes, if demonstrated honestly | Evidence/field lineage + governed onboarding + drift/replay + air gap; must show tested flow, not just diagrams. |

## Review outcome

**Phase 0 architecture status: complete subject to the open implementation decisions below.** It is acceptable to enter Phase 1 only if the team first commits the architecture baseline, assigns owners, and preserves the Phase 0 guardrails.

## Open implementation decisions

1. Exact supported MVP formats and disclosed fixture corpus; this must be determined by available lawful data and team capacity.
2. Exact technology/library versions, license review, and offline package/image sourcing.
3. Hardware profile, storage retention periods, RBAC/identity integration details, and real organizational data classification policy.
4. Whether optional local AI is feasible on available hardware. This does not block the deterministic MVP.

These are implementation parameters, not reasons to re-open the core architectural decisions.
