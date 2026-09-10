# ULPF — SIH Judge Q&A Defense Package

**Problem Statement:** SIH26156 (NTRO)  
**Coverage:** 30 Challenging Technical & Strategic Questions

---

### Q1: What exactly is "universal" about ULPF?
**Answer:** ULPF is universal in three distinct dimensions: (1) Ingestion universality across 20 distinct vendor formats; (2) Semantic universality via the Universal Canonical Event (UCE) schema that preserves unmapped fields; and (3) Interoperability universality projecting into both major industry open standards: OCSF v1.1.0 and OpenTelemetry Logs v1.0.0.

### Q2: How do you prove no information is lost during parsing?
**Answer:** ULPF preserves the original payload verbatim in content-addressed storage indexed by SHA-256. During UCE normalization, any key/value pair not part of the standard ontology is systematically preserved within the `unmapped_residue` dictionary. A round-trip reconstruction test confirms that raw content + residue yields 100% field recall.

### Q3: Why create UCE instead of adopting OCSF directly as your internal format?
**Answer:** OCSF is an excellent egress projection standard, but embedding OCSF as the primary internal storage format forces premature schema constraints and drops vendor-specific forensic residues. UCE acts as a superset canonical layer, decoupling raw telemetry preservation from external schema version migrations.

### Q4: Why not just use Logstash, Fluent Bit, or Vector?
**Answer:** Logstash and Vector are general-purpose stream multiplexers. They lack: (1) native cryptographic content-addressed evidence vaults; (2) automated schema drift detection; (3) unmapped residue retention guarantees; (4) built-in MITRE ATT&CK correlation; and (5) purple-team dry-run playbooks. ULPF is an end-to-end security telemetry intelligence platform.

### Q5: How does unknown-source onboarding work in practice?
**Answer:** `ulpf_onboarding/profiler.py` performs structural token discovery, evaluates delimiter patterns, checks entropy, and executes ReDoS-safe regex synthesis. It generates a declarative mapping definition in under 30 seconds that is compiled and activated dynamically without restarting worker nodes.

### Q6: What happens when a vendor firmware update introduces new fields (schema drift)?
**Answer:** The `DriftDetector` classifies drift into STABLE, MINOR, MAJOR, or BREAKING. New fields are seamlessly captured in `unmapped_residue` without dropping events or crashing pipelines, while alerting the operator to review the generated mapping delta.

### Q7: Can AI assistance corrupt forensic evidence?
**Answer:** No. In ULPF, AI assistance (`ulpf_ai`) is strictly advisory and read-only. It operates downstream from immutable evidence capture. The SHA-256 cryptographic hash is generated at byte receipt before any intelligence processing. AI cannot mutate raw storage.

### Q8: How do you prevent prompt injection against your AI advisor?
**Answer:** The AI advisor runs an offline deterministic rule-ensemble parser. Telemetry payloads are treated strictly as untrusted data literals, never interpolated as executable instructions. Prompts are validated against injection patterns via `PromptInjectionDefense`.

### Q9: Can ULPF operate in a classified, air-gapped facility with zero internet access?
**Answer:** Yes. ULPF requires zero cloud APIs, zero external model calls, and zero external package downloads at runtime. Our automated air-gap test suite intercepts all socket creation calls and proves zero outbound connections.

### Q10: What is your biggest limitation?
**Answer:** In the v1.0.0 release, distributed streaming relies on single-node partitioned memory-bounded channels rather than an external Kafka/Pulsar cluster. This was an intentional architectural trade-off to ensure 100% self-contained air-gap reproducibility without external infrastructure dependencies.
