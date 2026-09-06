# PHASE 4 LIMITATIONS

This document records honest, independently-verified limitations of the
Phase 4 Semantic Intelligence & Interoperability Plane.

## 1. Classifier Coverage

The semantic classifier covers 7 event domains:
- Firewall (deny/allow)
- IDS/IPS alert
- DNS
- HTTP/Web access
- Network flow
- Cloud audit
- Authentication/Identity

Events from these domains produce correct semantic triples.

Events from ALL OTHER domains fall back to:
  category=OTHER, class=Unknown, type=generic.telemetry, confidence=0.50

Missing domains include:
- VPN session events
- Windows event log (Security, System, Application)
- Linux auditd syscall events
- Kubernetes admission/audit events
- Database query events
- Application exception/lifecycle events
- Process/file activity events
- Container lifecycle events

## 2. Entity Extraction

Only 5 of 17 EntityType values are extracted:
- IP (source, destination)
- USER (from event.identity.user.name)
- HOST (from event.device.hostname)
- CLOUD_RESOURCE (from unmapped AWS fields)

Not extracted: PROCESS, FILE, CERTIFICATE, URL, DOMAIN, DEVICE, SERVICE,
CONTAINER, POD, CLUSTER, CLOUD_ACCOUNT, DATABASE, APPLICATION.

## 3. Indicator Extraction

4 of 7 IndicatorType values are extracted:
- IP (public/global addresses only)
- DOMAIN (via RFC-compliant regex on specific unmapped fields)
- HASH_SHA256 (64-char hex in unmapped fields)
- HASH_MD5 (32-char hex in unmapped fields)

Not extracted: URL, EMAIL, CERT_FINGERPRINT.

## 4. OCSF Compliance Scope

The OCSF projection covers 7 of the official OCSF v1.1.0 event classes.
Validation checks 7 mandatory base fields plus type integrity.
It does NOT validate against the full OCSF v1.1.0 JSON schema.
Events not matching a known class default to Network Activity (4001).

## 5. OpenTelemetry Semantic Conventions

The OTel projection uses ULPF-specific attribute names (event.category,
event.class, event.type) in the LogRecord attributes array.
These are NOT official OpenTelemetry semantic convention names.
They are ULPF extensions and must be treated as such by consumers.

## 6. Mapping Rules Not Externalized

All semantic classification rules are hardcoded in Python.
Adding a new vendor/product classifier requires editing classifier.py.
No config-driven rule loading is implemented in Phase 4.

## 7. SemanticStatus Granularity

SemanticMapper always sets status=SemanticStatus.FULL regardless of classification
confidence. Fallback events (confidence=0.50) should ideally be PARTIAL or UNKNOWN.
This may cause consumers to over-trust fallback classifications.

## 8. Raw Payload SHA-256 Not Forwarded

SemanticEvent carries uce_event_id and raw_event_id for traceability.
The raw payload SHA-256 (available in Phase 3 UCE provenance) is not
forwarded into SemanticEvent. Full payload integrity verification requires
accessing the Phase 3 UCE directly.

## 9. Performance

Benchmarks are single-threaded microbenchmarks on a development machine.
Actual production throughput depends on deployment topology, Python GIL behavior,
batching strategy, and I/O overhead not included in these measurements.

## 10. No External Enrichment

Phase 4 performs NO external enrichment:
- No geo-IP resolution
- No ASN lookup
- No WHOIS
- No threat intelligence feeds
- No reputation databases
- No LLM inference

This is by design (air-gapped, deterministic). Enrichment is Phase 5+ scope.

## 11. Deduplication

Fingerprinting provides equivalence_key and event_fingerprint.
Phase 4 does NOT implement deduplication or cross-event correlation.
These keys are foundation for future deduplication logic only.
