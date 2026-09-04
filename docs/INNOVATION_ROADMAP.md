# Innovation Roadmap and Differentiation

## Why ULPF is more than a transformation pipeline

Log collectors and transformation engines already move and reshape telemetry. ULPF differentiates by making the *interpretation lifecycle* governed and inspectable: immutable raw evidence, field-level lineage, reusable configuration-driven onboarding, schema drift controls, replayable versioned processing, offline-safe assistance, and interoperable outputs. It does not attempt to replace every downstream SIEM or data lake.

## Prioritization

| Priority | Innovation | Value / NTRO connection | Cost and risk | MVP decision |
|---|---|---|---|---|
| Must have | Raw evidence hash + trace view | Directly supports losslessness and traceability | Moderate storage/access-control design | Core architecture and future MVP proof |
| Must have | Versioned parser/mapping/schema lifecycle with fixtures | Reduces parser effort and supports extensibility | Requires disciplined registry workflow | Core architecture and future MVP proof |
| Must have | Replay and comparison | Makes corrections and parser upgrades trustworthy | Capacity/governance complexity | Scoped sample replay first |
| Should have | Unknown-format deterministic analysis + confidence-scored mapping proposal | Faster onboarding, vendor-neutrality | False positives, review burden | Advisory only; human approval |
| Should have | Schema-drift detection | Maintains reliability as vendors change | Baseline learning/noise | Simple structural drift signals first |
| Should have | Data-quality score and parser health | Makes coverage/uncertainty visible | Score misuse if not explained | Transparent component signals, no unsupported claim |
| Nice to have | Local semantic model / local LLM | Supports field inference in air gap | Hardware/model quality/prompt injection | Optional offline package, never per-event requirement |
| Nice to have | Local enrichment packs, MITRE/Sigma context, timelines | Improves investigations | Data quality/licensing and scope risk | Downstream overlay |
| Future | Advanced anomaly/correlation and multi-site federation | Demonstrable analytics and scale path | Large dataset/SRE complexity | Defer until core is tested |

## Guardrails

AI cannot mutate raw evidence, autonomously publish a parser, execute code from logs, or become a required online service. Any proposed mapping must expose samples, rules/reasoning, confidence, model/prompt/template version, test result, and reviewer approval. Blockchain is intentionally excluded: signed evidence manifests, hashes, append-only audit, access controls, and object-retention controls meet the requirement with less operational complexity.

## Demo differentiation proof

The future demo should show several formats reaching one UCE view, one raw-to-field trace with integrity verification, a recoverable parse/DLQ state, and an unknown-source proposal that is reviewed and published before deterministic processing. This shows trusted normalization rather than a superficial JSON conversion.
