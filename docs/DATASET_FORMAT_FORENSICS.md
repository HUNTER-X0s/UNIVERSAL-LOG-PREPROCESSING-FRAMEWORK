# ULPF Format Forensics & Structural Parsing Rules

**Document ID:** ULPF-DOC-FORMAT-FORENSICS-FINAL  
**Corpus Version:** v3.1.0  

---

### 1. Verified Structural Formats (19 Formats)

1. **RFC 3164 Syslog:** BSD format (`<PRI>Mmm dd hh:mm:ss HOST TAG: MSG`).
2. **RFC 5424 Syslog:** Modern structured syslog with version, ISO 8601 timestamp, structured data blocks `[id@vendor key="val"]`.
3. **CEF (Common Event Format):** Pipe-delimited headers (`CEF:0|Vendor|Product|Version|ID|Name|Sev|Extension`).
4. **LEEF (Log Event Extended Format):** IBM QRadar format (`LEEF:2.0|Vendor|Product|Version|EventID|delimiter|Key=Value`).
5. **Key-Value Pairs:** Delimited by spaces, quotes, or colons (FortiOS, iptables).
6. **Flat JSON:** Single-level dictionary objects.
7. **Nested JSON:** Deeply structured objects with arrays (AWS CloudTrail, GCP Audit).
8. **NDJSON (Newline-Delimited JSON):** Stream of independent JSON objects (Suricata EVE, Zeek JSON).
9. **CSV (Comma-Separated Values):** Delimited fields with optional quoting (Palo Alto, OPNsense filterlog).
10. **TSV (Tab-Separated Values):** Tab-delimited fields with comment headers (Zeek default).
11. **W3C Extended Log:** `#Fields:` header declaration followed by space-delimited fields (Microsoft IIS).
12. **Combined / Common Log Format:** Apache/NGINX web server access logs.
13. **CRI Container Framing:** ISO timestamp + stream identifier + partial/full line flag (`F` or `P`) + message payload.
14. **Glog-Style Logs:** Google logging convention used across Kubernetes components (`Lmmdd hh:mm:ss.uuuuuu threadid file:line] msg`).
15. **Multiline Exception Stack Traces:** Heading exception followed by indented `at ...` lines and chained `Caused by:` blocks.
16. **Structured Application JSON:** Typed event logging (Python structlog, Go Zap).
17. **OTLP JSON:** OpenTelemetry v1 LogRecord specification format.
18. **Windows Event XML:** Windows EventLog schema 2.0 (`<Event><System>...</System><EventData>...</EventData></Event>`).
19. **Zed ZSON / Super-Structured:** Type-rich structured record formats (`.sup`, `.bsup`).

*(Note: PCAP is explicitly excluded as it is a packet capture file, not a log format).*
