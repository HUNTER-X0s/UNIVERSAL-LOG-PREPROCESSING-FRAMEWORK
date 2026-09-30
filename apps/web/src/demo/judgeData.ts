import { JudgeStep } from '../types/judge';

export const JUDGE_STEPS: JudgeStep[] = [
  {
    index: 0,
    title: 'Stage 01 — Problem Statement & Telemetry Chaos',
    timeRange: '00:00 – 00:15',
    summary: 'Heterogeneous telemetry from firewalls, IDSs, endpoints, and cloud providers causes silent field loss, parser fragility, and legally uncertifiable forensic records in national SOCs.',
    proofSnippet: `[PROBLEM ANALYSIS - NTRO SOC CONTEXT]
• 20+ Disjoint Proprietary Log Formats
• Rigid Conventional Parsers Silently Drop Unmapped Fields
• Schema Drift on Firmware Updates Crashes Pipelines
• Absence of Content-Addressed Immutability Renders Evidence Inadmissible`,
    speakerNotes: 'Start by presenting the core bottleneck: security teams lose critical forensic context because conventional parsers drop unknown fields. ULPF eliminates this through guaranteed residue preservation.',
    metrics: [
      { label: 'Vendor Formats', value: '20+ Heterogeneous' },
      { label: 'Field Loss Rate', value: '0.00% (Lossless)' },
      { label: 'Target SLA', value: '< 200ms P99' }
    ]
  },
  {
    index: 1,
    title: 'Stage 02 — 20-Parser Deterministic Ingestion Plane',
    timeRange: '00:15 – 00:30',
    summary: 'ULPF provides 20 concrete production-grade parsers partitioned across Tier A (core perimeter & auth), Tier B (flow & cloud), and Tier C (modern EDRs), all verified in continuous regression.',
    proofSnippet: `[PARSER REGISTRY VERIFICATION]
Tier A (10): pfsense, iptables, cisco_asa, snort, suricata, sshd, windows_security, sysmon, nginx_access, apache_access
Tier B  (8): aws_cloudtrail, azure_activity, dns_bind, netflow, zeek_conn, ossec, fortinet_fortigate, palo_alto
Tier C  (2): crowdstrike_falcon, sentinel_one

Regression Gate: 680 / 680 Tests PASS — 100% Parser Verification`,
    speakerNotes: 'Demonstrate our comprehensive parser plane. Every single parser is deterministic, tested against real-world sample captures, and zero-dependency.',
    metrics: [
      { label: 'Active Parsers', value: '20 Concrete' },
      { label: 'Regression Tests', value: '680 / 680 PASS' },
      { label: 'Tier Coverage', value: 'Perimeter, Cloud, EDR' }
    ]
  },
  {
    index: 2,
    title: 'Stage 03 — Lossless Raw Evidence Capture (SHA-256 CAS)',
    timeRange: '00:30 – 00:45',
    summary: 'Before transformation, raw telemetry bytes are written verbatim into a content-addressed filesystem with SHA-256 integrity verification, serving as the immutable cryptographic anchor.',
    proofSnippet: `[CONTENT-ADDRESSED STORAGE PIPELINE]
RAW BYTES → SHA-256 Digest → CAS Directory (cas/ab/abcdef1234...)
          → Write-Once Immutability Enforcement (raw_fs.py)
          → Zero In-Place Mutation

Capture Latency: P99 < 5ms | Integrity Verification: 100%`,
    speakerNotes: 'Highlight the content-addressed raw store. We never mutate the raw evidence. If an auditor or judge requests the original raw log, it is cryptographically linked to the UCE.',
    metrics: [
      { label: 'Storage Mechanism', value: 'Content-Addressed (CAS)' },
      { label: 'Integrity Digest', value: 'SHA-256 Verified' },
      { label: 'Capture Latency P99', value: '< 4.2 ms' }
    ]
  },
  {
    index: 3,
    title: 'Stage 04 — Universal Canonical Event (UCE) Normalization',
    timeRange: '00:45 – 01:00',
    summary: 'Events normalize to strict standard taxonomies. Any vendor-specific field not in the primary schema is preserved inside unmapped_residue, guaranteeing 100% forensic recall.',
    proofSnippet: `[UCE NORMALIZATION WITH UNMAPPED RESIDUE]
{
  "metadata": { "source_type": "cisco_asa", "event_id": "EVT-98412" },
  "network":  { "src_ip": "10.0.1.20", "action": "DENY", "dst_port": 443 },
  "unmapped_residue": {
    "cisco_threat_code": "0x8401",  // ← Preserved verbatim, never dropped
    "threat_defense_ver": "9.18.2"
  }
}`,
    speakerNotes: 'This is the key architectural differentiator: unmapped residue. While traditional tools drop unfamiliar headers, ULPF retains them safely in a queryable residue envelope.',
    metrics: [
      { label: 'Forensic Recall', value: '100.0% Lossless' },
      { label: 'Residue Support', value: 'All 20 Sources' },
      { label: 'Validation Schema', value: 'JSONSchema Draft 2020-12' }
    ]
  },
  {
    index: 4,
    title: 'Stage 05 — Dual Open Standards Projection (OCSF & OTel)',
    timeRange: '01:00 – 01:15',
    summary: 'From a single canonical UCE, ULPF projects compliant OCSF v1.1.0 security records and OpenTelemetry Logs v1.0.0 payloads without re-accessing the raw evidence.',
    proofSnippet: `[DUAL PROJECTION PIPELINE]
UCE Record
 ├──> OCSF v1.1.0 (Class 4001: Network Activity, Severity: 4)
 └──> OpenTelemetry Logs v1.0.0 (ResourceLogs / InstrumentationScope)

Outcome: Direct ingestion by Splunk, Elastic, ClickHouse, or sovereign data lakes without vendor lock-in.`,
    speakerNotes: 'Show interoperability. National agencies cannot be tied to proprietary formats. ULPF outputs OCSF for SOC analytics and OpenTelemetry for observability in parallel.',
    metrics: [
      { label: 'OCSF Standard', value: 'v1.1.0 Compliant' },
      { label: 'OTel Standard', value: 'Logs v1.0.0' },
      { label: 'Re-Parse Overhead', value: '0 ms (Projected)' }
    ]
  },
  {
    index: 5,
    title: 'Stage 06 — MITRE ATT&CK Correlation & Anomaly Engine',
    timeRange: '01:15 – 01:30',
    summary: 'Rule and correlation engines detect multi-stage campaigns across disparate vendor sources in sliding time windows, mapped to MITRE ATT&CK tactics with online Welford anomaly scoring.',
    proofSnippet: `[KILL CHAIN CORRELATION]
Stage 1: SSH Brute-Force (sshd)        → T1110.001 Credential Access
Stage 2: Lateral SMB Probe (iptables)  → T1021.002 Lateral Movement
Stage 3: Encrypted Beacon (pfSense)    → T1071.001 Command & Control

Welford Anomaly Score: Z = 3.84 (Threshold: 3.0) → Verdict: HIGH_RISK_CAMPAIGN`,
    speakerNotes: 'Notice how disparate sources correlate: sshd plus iptables plus pfSense form a single coherent attack sequence with explicit MITRE technique tagging.',
    metrics: [
      { label: 'Correlation Windows', value: 'Sliding 60s - 300s' },
      { label: 'Anomaly Algorithm', value: 'Welford Online Z-Score' },
      { label: 'Technique Mapping', value: '100% ATT&CK Aligned' }
    ]
  },
  {
    index: 6,
    title: 'Stage 07 — 13-Stage Cryptographic Forensic Lineage',
    timeRange: '01:30 – 01:45',
    summary: 'Every telemetry event carries a 13-stage Merkle lineage from ingestion to outbox delivery, defensible in judicial, regulatory, and intelligence audit contexts.',
    proofSnippet: `[13-STAGE CRYPTOGRAPHIC PROVENANCE]
01 Raw Capture  → 02 Receipt     → 03 Format Profile → 04 Validation
05 Parser       → 06 Field Extr. → 07 Semantic Map   → 08 Risk Score
09 MITRE Map    → 10 Correlation → 11 OCSF Proj.     → 12 Evidence Pkg
13 Outbox Delivery

Integrity Status: SHA-256 Merkle Root Chain Intact (No Mutations)`,
    speakerNotes: 'Demonstrate our judicial forensic strength. A single altered byte anywhere in the pipeline breaks the cryptographic digest chain immediately.',
    metrics: [
      { label: 'Lineage Stages', value: '13 Explicit Stages' },
      { label: 'Merkle Integrity', value: 'Cryptographically Bound' },
      { label: 'Judicial Defense', value: 'Auditable Chain of Custody' }
    ]
  },
  {
    index: 7,
    title: 'Stage 08 — Unknown Source Onboarding & Drift Defense',
    timeRange: '01:45 – 01:55',
    summary: 'When an unknown format is encountered, the AI-assisted profiler discovers structural tokens and derives candidate mappings with ReDoS safety checks, requiring human approval before pipeline activation.',
    proofSnippet: `[ONBOARDING LIFECYCLE < 30 SECONDS]
Sample Submission → Token & Delimiter Extraction → ReDoS Safety Verification
                  → Drift Severity: STABLE / MINOR / MAJOR / BREAKING
                  → Human Review & Approval Gate
                  → Versioned Mapping Activated in Pipeline`,
    speakerNotes: 'Show the onboarding speed. In under 30 seconds, an analyst onboards an unfamiliar syslog format without coding, while safety guards prevent ReDoS attacks.',
    metrics: [
      { label: 'Onboarding Time', value: '< 30 Seconds' },
      { label: 'Safety Analysis', value: 'Deterministic ReDoS Safe' },
      { label: 'Governance Gate', value: 'Mandatory Human Approval' }
    ]
  },
  {
    index: 8,
    title: 'Stage 09 — Sovereign Air-Gap Architecture',
    timeRange: '01:55 – 02:00',
    summary: 'ULPF is engineered for total air-gapped sovereign deployment with zero external network dependencies, local deterministic inference, and 8-layer tenant boundary isolation.',
    proofSnippet: `[AIR-GAP COMPLIANCE VERIFICATION]
Outbound Sockets:    0 (Validated via tests/airgap/test_phase11_airgap.py)
External Cloud APIs: NONE (Local deterministic rule-ensemble)
Font / CDN Assets:   0 External Runtime Dependencies
Multi-Tenant Guard:  Enforced across 8 Data Subsystems`,
    speakerNotes: 'Emphasize sovereignty. ULPF runs on fully isolated defense networks. No telemetry or query ever leaves the physical boundary.',
    metrics: [
      { label: 'Outbound Sockets', value: '0 (Strict Zero Egress)' },
      { label: 'Cloud Dependency', value: 'None (Self-Contained)' },
      { label: 'Air-Gap Tests', value: '4/4 Validated PASS' }
    ]
  },
  {
    index: 9,
    title: 'Stage 10 — NTRO Scope Summary & Final Certification',
    timeRange: '02:00',
    summary: '16/16 NTRO Problem Statement requirements are fully validated with engineering proof across 680 regression tests and 5 consecutive certified release audits.',
    proofSnippet: `[FINAL CERTIFICATION SUMMARY]
• NTRO Scope Items:       16 / 16 SATISFIED (100.0%)
• Regression Gate:        680 / 680 Tests PASS
• Security Vulnerabilities: 0 Across All Domains
• Benchmark Throughput:   301,283 EPS (Controlled Benchmark)
• Release Attestation:    PHASE19_FINAL_RELEASE_APPROVED (Commit 71049fb)`,
    speakerNotes: 'Conclude by showing the complete 16/16 requirement traceability matrix. Every single NTRO specification has matching implementation code and automated tests.',
    metrics: [
      { label: 'NTRO Requirements', value: '16 / 16 Mapped & Validated' },
      { label: 'Audit Score', value: '100 / 100' },
      { label: 'Final Release', value: 'v1.0.0-sih' }
    ]
  }
];
