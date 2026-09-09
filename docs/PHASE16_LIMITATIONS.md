# ULPF Phase 16 — Explicit Operational Boundaries & Limitations

**Project:** Universal Log Pre-processing Framework (ULPF)  
**Problem Statement:** Smart India Hackathon — SIH26156 / NTRO  
**Purpose:** Transparent, evidence-backed disclosure of operational scope, technical boundaries, and system constraints.

---

## 1. Intentional Architectural Boundaries

In accordance with strict defense engineering principles and the Phase 16 Master Prompt, ULPF deliberately defines its boundaries:

### 1.1 Air-Gap Sovereignty vs. Cloud Services
- **Constraint:** ULPF intentionally does NOT connect to external SaaS APIs, commercial cloud telemetry endpoints, or cloud-hosted LLMs.
- **Rationale:** National security and NTRO air-gap requirements strictly prohibit foreign or external network egress.
- **Operational Scope:** All AI advisory functions, parsers, and threat intelligence matching run 100% locally on sovereign infrastructure.

### 1.2 Unstructured Freeform Text Onboarding
- **Constraint:** Completely unstructured, arbitrary conversational text (e.g. email bodies or forum dumps) requires human review during onboarding.
- **Rationale:** While ULPF automatically infers structure for delimited (CSV/TSV), key-value, JSON, XML, Syslog, and CEF/LEEF formats, arbitrary natural language lacks deterministic field grammar.
- **Mitigation:** The `OfflineDeterministicAdvisor` generates candidate semantic hypotheses, which a human detection engineer approves before production compilation.

### 1.3 Single-Core Throughput vs. Distributed Cluster Scale
- **Constraint:** The reported throughput metric (~40,000 to 47,000 EPS) reflects single-threaded execution on a single CPU core without distributed partitioning.
- **Scope:** In distributed deployments using the `ulpf_streaming.fabric` partition router across $N$ worker nodes, aggregate throughput scales horizontally ($N \times 40,000$ EPS).

### 1.4 Raw Evidence Storage Growth
- **Constraint:** Preserving 100% of unmodified raw evidence with SHA-256 sidecars requires approximately $1.15\times$ to $1.30\times$ the storage volume of raw text.
- **Mitigation:** ULPF provides configurable tiered retention (`FileSystemRawEvidenceRepository`) allowing raw archives to age out to cold storage while preserving canonical UCE indexes and cryptographic manifests.

---

## 2. Supported Log Formats

| Format Class | Support Level | Handling Mechanism |
|---|---|---|
| **CEF (ArcSight)** | Native Built-in | `CefParser` (Header + extension parsing) |
| **LEEF (QRadar)** | Native Built-in | `LeefParser` (Header + tab/delimiter parsing) |
| **Syslog (RFC 5424 / RFC 3164)** | Native Built-in | `SyslogRFC5424Parser`, `SyslogRFC3164Parser` |
| **JSON / NDJSON** | Native Built-in | `GenericJsonParser`, `NdjsonParser` |
| **XML / Windows EventLog** | Native Built-in | `GenericXmlParser` |
| **Delimited (CSV / TSV / W3C)** | Native Built-in | `CsvParser`, `W3cParser`, `ZeekParser` |
| **Key-Value Pairs** | Native Built-in | `KeyValueParser`, `FortiGateParser` |
| **Proprietary Network Formats** | Native Built-in | Palo Alto, Cisco ASA/IOS, Suricata, Snort |
| **Unknown Structured Format** | Autonomous Onboarding | `SampleProfiler` + `MappingCompiler` (< 30s) |
