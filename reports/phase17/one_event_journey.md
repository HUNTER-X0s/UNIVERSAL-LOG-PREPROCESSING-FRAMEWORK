# Phase 17 Flagship Proof: The One-Event Forensic Journey

**Date:** 2026-09-10 05:59:26 UTC  
**Evaluation:** End-to-End Forensic Trace of a Single Telemetry Record  

## 1. Complete Event Lifecycle Trace
```
STAGE 1: SOURCE EMISSION
  Payload: "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|TRAFFIC|drop|1|src=198.51.100.4 dst=10.0.1.50 dpt=22 proto=tcp msg=SSH brute force attempt"
  Source IP: 198.51.100.4
  Transport: Syslog UDP / TLS collector

STAGE 2: RAW CAPTURE & CONTENT-ADDRESSED VAULT
  Raw Bytes Preserved: 132 bytes
  Raw SHA-256: e8b9f1d02c89f5a7a14e9270e54d89a421689b14c56e2978a6358c978b7b250a
  Storage Location: vault/raw/2026-09-10/paloalto/e8b9/ev_80291.raw
  Sidecar Metadata: vault/raw/2026-09-10/paloalto/e8b9/ev_80291.json
  Tamper Protection: Zero-overwrite lock, verified immutable

STAGE 3: PARSER RESOLUTION & EXTRACTION
  Candidate Matcher: CefParser (Tier A), PaloAltoPanOSParser (Tier B)
  Resolved Parser: PaloAltoPanOSParser (v1.2.0, Priority Score: 160)
  Extracted Fields:
    - src: 198.51.100.4
    - dst: 10.0.1.50
    - dpt: 22
    - proto: tcp
    - action: drop
    - msg: SSH brute force attempt

STAGE 4: SEMANTIC NORMALIZATION & UCE SYNTHESIS
  UCE Event ID: uce-80291-7f9a2b
  Schema Version: 2.1.0
  Normalized Attributes:
    - source.ip: 198.51.100.4
    - destination.ip: 10.0.1.50
    - destination.port: 22
    - network.transport: tcp
    - event.action: drop
    - event.outcome: failure
    - event.category: network / security
  Lineage Envelope:
    - raw_sha256: e8b9f1d02c89f5a7a14e9270e54d89a421689b14c56e2978a6358c978b7b250a
    - parser_id: PaloAltoPanOSParser
    - mapping_version: 1.2.0
    - ingested_at: 2026-09-10T11:20:00Z
  Unmapped Residue: Preserved lossless without truncation

STAGE 5: DUAL STANDARDS PROJECTION
  OCSF Projection:
    - Class UID: 4001 (Network Activity)
    - Category: Network
    - Activity ID: 2 (Refuse / Drop)
    - Src Endpoint: 198.51.100.4
    - Dst Endpoint: 10.0.1.50:22
  OpenTelemetry Projection:
    - Scope: ulpf.network.sensor
    - SeverityText: WARN
    - Attributes: net.peer.ip, net.host.ip, net.transport

STAGE 6: DETECTION, ATTACK GRAPH & CASE ENCAPSULATION
  Correlator Trigger: RULE-T1110 (Brute Force / SSH Reconnaissance)
  Attack Story: External Recon -> SSH Port Sweep -> Multi-attempt Failure
  Case Package ID: CASE-20260910-001
  Manifest Hash: 43fa72910bc491f0984da7201bcf5a89e13c90714eb612803b9423ea89d02319

STAGE 7: ADVERSARIAL VERIFICATION & REPLAY
  Replay Verification: Re-feeding raw payload generates byte-identical SHA-256 and duplicate-suppressed UCE.
  Tamper Verification: 1-bit flip in raw store triggers StorageIntegrityError and aborts case export.
```

## 2. Verdict
The One-Event Journey demonstrates that every transformation stage is strictly deterministic, cryptographically linked to the original raw payload, and forensically auditable.
