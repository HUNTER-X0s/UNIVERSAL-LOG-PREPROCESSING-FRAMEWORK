# Two-minute Demo and Five-slide Presentation Strategy

## Demo objective

The future demonstration must prove NTRO requirements with a controlled, disclosed fixture corpus. It must never present synthetic results as live vendor support, inflate throughput, or imply an Internet dependency in the air-gapped runtime.

## Planned two-minute sequence

| Time | Story beat | Evidence shown | Requirement proof |
|---:|---|---|---|
| 0:00-0:12 | State the perimeter telemetry problem and show heterogeneous sample representations | disclosed Syslog/CEF/JSON/etc. fixtures | diversity and vendor neutrality |
| 0:12-0:28 | Ingest and identify formats/sources | receipt IDs, format decisions, source profiles | ingest/parse path |
| 0:28-0:45 | Show extracted fields and unified UCE event view | source-specific fields, common category/action/network fields | extraction and normalization |
| 0:45-1:02 | Open event trace | raw evidence reference, hash verification, parser/mapping/schema versions, field lineage | losslessness and traceability |
| 1:02-1:15 | Show quality/DLQ/replay boundary | explicit warning/failure and retained raw evidence | recoverable failures |
| 1:15-1:37 | Onboard an unknown/proprietary-style *synthetic* sample | detected structure, proposal/confidence, human review, fixture test | plug-and-play and AI assistance |
| 1:37-1:50 | Publish approved version and reprocess | deterministic output from pinned approved pack | controlled parser lifecycle |
| 1:50-2:00 | Show adapter/air-gap and measured-status framing | local bundle/status, OCSF/Parquet planned/export proof if built | interoperability/container/air gap |

If a feature is not implemented and tested, narrate it as architecture/roadmap rather than simulate it. The demo runner should rehearse from resettable local data and include a fallback screen capture only for a tested local workflow.

## Five-slide narrative

1. **Problem:** heterogeneous perimeter logs make analytics and investigation inconsistent; show evidence-loss and parser-maintenance consequences.
2. **Solution:** ULPF logical pipeline and separation of immutable evidence, governed control plane, and downstream adapters.
3. **Innovation:** configuration-driven onboarding, raw-to-field lineage, drift/replay, and optional local AI with human approval.
4. **Technical proof:** test corpus provenance, measured benchmark methodology/results only if actually run, quality/trace evidence, and failure recovery.
5. **Impact:** SIEM/data lake/ML interoperability, air-gapped deployment path, six-member MVP boundary, and future scale roadmap.

## Demo acceptance checklist

- Reset environment, fixture manifest, parser/schema/mapping versions, and expected outcomes are rehearsed.
- Every displayed metric has a timestamp, hardware/configuration, corpus, and command/run ID or is omitted.
- Raw evidence shown is non-sensitive/sanitized fixture data; its role as synthetic or public data is labeled.
- A failure/retry or unknown-source flow has a planned, safe branch.
- The presenter can explain why ULPF is not a full SIEM and why AI cannot bypass validation.
