# ULPF — 2-Minute SIH Judge Demonstration Script

**Role:** Technical Presenter  
**Audience:** Smart India Hackathon Judges (NTRO Problem Statement SIH26156)  
**Total Target Duration:** 120 Seconds (2:00)

---

### [00:00 - 00:20] The Problem: Telemetry Chaos & Forensic Vulnerability
> *"Respected Judges, modern defense and enterprise operations ingest millions of logs every second across dozens of incompatible vendor formats—firewalls, IDSs, endpoints, and cloud logs. Traditional pipelines like Logstash or Vector either crash on unannounced schema updates or silently discard unmapped fields. When an incident goes to court or military inquest, the raw evidence is unproven and the forensic chain is broken. This is the exact challenge posed in NTRO Problem Statement SIH26156."*

### [00:20 - 00:40] The Solution: Lossless Raw Storage & Canonical UCE
> *"Our solution is ULPF: Universal Log Pre-processing Framework. When telemetry hits ULPF, before any parsing occurs, verbatim bytes are locked into SHA-256 Content-Addressed Storage. Next, our 20 concrete parsers normalize the event into the Universal Canonical Event schema. Any field not in the standard taxonomy is automatically captured inside `unmapped_residue`—guaranteeing 100% lossless forensic recall."*

### [00:40 - 01:00] Open Standards Interoperability: OCSF & OpenTelemetry
> *"ULPF does not create another proprietary silo. From a single canonical UCE, our projection engine simultaneously exports compliant OCSF v1.1.0 Security Events and OpenTelemetry Logs v1.0.0. This allows sovereign SIEMs and data lakes to query heterogeneous data with zero re-parsing overhead."*

### [01:00 - 01:25] Real-Time Threat Intelligence & Multi-Stage Correlation
> *"In the console, you see our deterministic correlation engine detect a coordinated multi-stage attack: an external brute-force on SSH, followed by an internal SMB sweep on port 445, and command-and-control beaconing. All signals map automatically to MITRE ATT&CK tactics, and our purple-team response playbooks execute safe, zero-mutation dry-run simulations."*

### [01:25 - 01:45] Zero-Code Onboarding & Schema Drift
> *"What happens when a new firewall firmware updates its syntax? Watch our Autonomous Source Profiler: in under 30 seconds, it discovers structural tokens, verifies ReDoS safety, and compiles a new mapping without touching the core codebase."*

### [01:45 - 02:00] Sovereignty & Final Proof
> *"Finally, ULPF is 100% sovereign and air-gapped: verified zero external network socket egress, 680 passed regression tests, and all 16 NTRO requirements fully verified. Thank you."*
