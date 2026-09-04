# Project Risk Register

Scores are qualitative planning judgements, not measured probability. Owners are proposed workstreams and should be assigned to named team members before Phase 1.

| ID | Risk | Probability | Impact | Mitigation | Contingency | Owner |
|---|---|---|---|---|---|---|
| R-01 | Parser complexity exceeds MVP capacity | Medium | High | start with declared formats, reusable adapters, fixture-first packs, bounded scope | demo fewer formats with honest support matrix | Parser/ingestion |
| R-02 | Unknown logs produce misleading mappings | Medium | High | deterministic analysis, confidence, human review, no auto-publish | quarantine/reject candidate and retain sample/evidence | AI/onboarding |
| R-03 | AI is unreliable/offline hardware is inadequate | Medium | Medium | make AI optional and advisory; use heuristics first | demo deterministic onboarding without AI | AI/onboarding |
| R-04 | Dataset/license availability blocks realistic testing | Medium | High | synthetic corpus plus provenance workflow; acquire early | restrict claims to synthetic fixtures | Test/data |
| R-05 | Laptop/demo capacity is inadequate | Medium | High | small Compose profile, bounded corpus, early rehearsal | pre-record only a tested local workflow; reduce stack without falsifying scale | SRE/demo |
| R-06 | Evidence/store failures threaten losslessness | Low-Medium | Critical | persist evidence first, hash/manifest, backups/restore tests | stop acknowledgement/backpressure and recover before process | Data/SRE |
| R-07 | Air-gap bundle/import process fails | Medium | High | signed manifests, local registry, dry-run import, no cloud core dependency | use tested prior bundle and document limitation | Security/SRE |
| R-08 | Integration/output schemas diverge | Medium | Medium | versioned contracts, adapters, compatibility tests | pin compatible projection and defer optional target | Schema/platform |
| R-09 | Parser exploit/ReDoS/malicious logs | Medium | Critical | isolation, limits, safe grammar, fuzzing, no code execution | quarantine, revoke parser, replay with safe version | Security/parser |
| R-10 | Scope creep creates incomplete demo | High | High | feature gate in SCOPE_AND_MVP, weekly demo slice, owner approval | cut roadmap items; protect core evidence-to-trace path | Architect/team lead |
| R-11 | Frontend overengineering delays core proof | Medium | Medium | build dense operational flows around real contracts, no decorative features | use focused trace/onboarding/event screens | Frontend |
| R-12 | Insufficient integration/rehearsal time | Medium | High | contract-first work, weekly integration, demo rehearsal from early phase | simplify to a proven vertical slice | Team lead/demo |
| R-13 | Codex-generated technical debt | Medium | High | review rules, small modules, tests, ADRs, no unverified claims | refactor before merging; reject opaque generated code | All owners |
| R-14 | Dependency incompatibility or supply-chain issue | Medium | High | pin/scan/SBOM, air-gap bundle validation, license review | replace behind interface or revert signed release | SRE/security |
| R-15 | Raw data/privacy exposure | Low-Medium | Critical | classification, least privilege, redaction only in views, audited export | revoke access, incident response, preserve original evidence securely | Security/data owner |
| R-16 | Benchmark claims become unsupported | Medium | High | reproducible protocol and run artifacts, no numbers before measurement | remove claim and state planned test | Performance/team lead |
| R-17 | Schema drift breaks a source silently | Medium | High | structural/vocabulary drift signals, quality trends, regressions | quarantine route, rollback parser, replay after fix | Schema/parser |
| R-18 | Team merge conflicts block progress | Medium | Medium | ownership matrix, stable contracts, small PRs, integration cadence | freeze contract changes and designate integrator | Team lead |

## Escalation rules

Critical risks stop publication or production-like processing until an accountable owner documents mitigation or accepted exception. Any change that weakens evidence retention, origin labels, approval gates, air-gap runtime, or parser isolation needs an ADR and architecture review. The demo may omit an unproven capability; it must not conceal the omission.
