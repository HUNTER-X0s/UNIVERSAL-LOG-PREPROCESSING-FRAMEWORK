# ULPF Phase 6 Security Threat Model

## Identified Threats & Mitigations

1. **Threat: Poison Message Flooding**
   - *Attack*: Attacker sends malformed, deeply nested, or oversized syslog records to stall workers.
   - *Mitigation*: Bounded frame sizes, strict parser timeouts, and automatic isolation into DLQ without stalling stream.

2. **Threat: Path Traversal on Raw Evidence**
   - *Attack*: Attacker crafts `event_id` or `source_id` with `../` to overwrite arbitrary host files.
   - *Mitigation*: Canonicalization and strict path segment character filtering in `FilesystemRawEvidenceRepository`.

3. **Threat: Secret Leakage in Logs**
   - *Attack*: Telemetry payloads contain plaintext passwords or tokens that leak into monitoring logs.
   - *Mitigation*: `StructuredJsonFormatter` automatically redacts sensitive tokens via regex patterns.

4. **Threat: Historical Replay Overwrite**
   - *Attack*: Historical replay mutates canonical timeline or overwrites existing UCE records.
   - *Mitigation*: Pinned version requirement, `REPLAYED` lineage tagging, and write-once UCE immutability.
