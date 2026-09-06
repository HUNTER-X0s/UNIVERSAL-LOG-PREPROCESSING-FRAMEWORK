# ULPF Format Forensic Audit & Structural Grammar Verification

**Document ID:** ULPF-DOC-FORMAT-FORENSIC-AUDIT  
**Corpus Version:** v3.1.0  

---

### Verified Log Formats (19 Formats)

1. **RFC 3164 Syslog:** Legacy BSD format (`<PRI>Mmm dd hh:mm:ss HOST TAG: MSG`).
2. **RFC 5424 Syslog:** Modern structured syslog with structured data elements (`[id@vendor key="val"]`).
3. **CEF (Common Event Format):** ArcSight pipe-delimited format.
4. **LEEF (Log Event Extended Format):** IBM QRadar tab/pipe/custom delimited format.
5. **Key-Value Pairs:** Space-separated `key=value` records (FortiOS, iptables).
6. **Flat JSON:** Single-level dictionary objects.
7. **Nested JSON:** Deeply structured objects with arrays (AWS CloudTrail, GCP Audit).
8. **NDJSON:** Stream of independent JSON records (Suricata EVE, Zeek JSON).
9. **CSV:** Comma-delimited records with optional quoting (Palo Alto, pfSense/OPNsense filterlog).
10. **TSV:** Tab-delimited records (Zeek default TSV).
11. **W3C Extended:** Header-declared space-delimited records (Microsoft IIS).
12. **Combined/Common Web Log:** Apache and NGINX HTTP access logs.
13. **CRI Container Framing:** Kubernetes CRI framing (`stdout F` / `stdout P` partial lines).
14. **Glog:** Google logging convention used across Kubernetes daemon components.
15. **Multiline Stack Traces:** Java Log4j2 chained exception stack traces.
16. **Structured Application JSON:** Typed event objects (Python structlog, Go Zap).
17. **OTLP JSON:** OpenTelemetry v1 LogRecord specification.
18. **Windows Event XML:** Windows Security Event Log schema 2.0 (Events 4624/4625).
19. **Zed ZSON / Super-Structured:** Type-rich structured record formats (`.sup`, `.bsup`).

*(PCAP is explicitly classified as a binary packet capture artifact, not a log format).*
