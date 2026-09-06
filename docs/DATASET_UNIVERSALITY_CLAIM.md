# ULPF Universality Claim & Architectural Scope

**Document ID:** ULPF-DOC-UNIVERSALITY-CLAIM  
**Corpus Version:** v3.1.0  

---

### 1. What "Universal" Means in ULPF

ULPF defines **Universality** as **Architectural and Semantic Agnosticism**, NOT an impossible claim that the framework possesses pre-written hardcoded parsers for every proprietary format in existence.

Specifically, ULPF Universality means:

1. **Universal Transport & Intake (Phase 2):**
   - Capable of accepting arbitrary raw bytes over TCP, UDP, TLS, Syslog, HTTP/REST, and Kafka with byte-exact integrity preservation.
2. **Universal Format Recognition (Phase 3):**
   - Deterministic structural detection across 19 standard representations (Syslog, JSON, NDJSON, CSV, TSV, KV, CEF, LEEF, CRI, W3C, XML, Multiline, OTLP).
3. **Vendor-Agnostic Normalization (Phase 3):**
   - Normalizing heterogeneous vendor events into canonical semantic classes (Network, Flow, Firewall, Auth, Audit, Query, Error) mapped to standards like OCSF while preserving all raw vendor fields in unmapped/extension bags.
4. **Perimeter-First Priority:**
   - Designed to excel at NTRO's mission-critical domain (Perimeter Network & Security Telemetry) while extending seamlessly across modern cloud, container, and application ecosystems.

### 2. Support Status by Telemetry Domain

| Telemetry Domain | Current Support Level | Represented Datasets |
|---|---|---|
| **Perimeter Firewalls & VPN** | **SUPPORTED & DEMONSTRATED** | Palo Alto, Fortinet, Check Point, Cisco ASA, Juniper SRX, OPNsense, WireGuard |
| **Network Sensors & IDS/IPS** | **SUPPORTED & DEMONSTRATED** | Zeek (conn, dns, http), Suricata EVE, Snort Fast, SecRepo |
| **Routing & Switching** | **SUPPORTED & DEMONSTRATED** | Cisco IOS-XE (BGP, OSPF, ACL), Huawei alarm knowledge |
| **Enterprise SIEM Standards** | **SUPPORTED & DEMONSTRATED** | CEF, LEEF, RFC 5424 Syslog, Windows XML 4624/4625 |
| **Cloud Audit & Flow** | **SUPPORTED & DEMONSTRATED** | AWS CloudTrail, AWS VPC Flow, Azure Activity, Azure NSG v2, GCP Audit |
| **Container & Kubernetes** | **SUPPORTED & DEMONSTRATED** | Containerd CRI (`stdout F/P`), Docker daemon, Kubernetes Audit |
| **Databases & Messaging** | **SUPPORTED & DEMONSTRATED** | MySQL general query, PostgreSQL, MongoDB JSON, Redis, Kafka |
| **Web & Service Mesh** | **SUPPORTED & DEMONSTRATED** | Envoy JSON, IIS W3C Extended, NGINX, HAProxy |
| **Application Runtimes** | **SUPPORTED & DEMONSTRATED** | Java Log4j multiline stack traces, Python structlog, Go Zap |
| **Observability Telemetry** | **SUPPORTED & DEMONSTRATED** | OpenTelemetry OTLP JSON Log Data Model v1 |
| **Raw PCAP Ingestion** | **ARCHITECTURALLY EXCLUDED** | ULPF is a telemetry/log preprocessor, not a packet analyzer |
