# ULPF Telemetry Semantic Coverage Matrix

**Document ID:** ULPF-DOC-SEMANTIC-COVERAGE-FINAL  
**Corpus Version:** v3.1.0  

---

### 1. Semantic Class Coverage Table

| Semantic Class | Coverage Status | Representative Fixture / Dataset |
|---|---|---|
| `network_connection` | **PRESENT** | Zeek conn.log, SecRepo conn.log, WireGuard VPN |
| `network_flow` | **PRESENT** | AWS VPC Flow, Azure NSG Flow v2, Juniper SRX RT_FLOW |
| `firewall_event` | **PRESENT** | Palo Alto PAN-OS, Fortinet FortiOS, Check Point FW-1, Cisco ASA, OPNsense |
| `ids_alert` | **PRESENT** | Suricata EVE JSON, Snort Fast Alert |
| `dns_query` | **PRESENT** | Zeek dns.log, Palo Alto DNS threat events |
| `http_transaction` | **PRESENT** | Zeek http.log, SecRepo http.log, Envoy, IIS W3C, NGINX |
| `vpn_session` | **PRESENT** | Cisco ASA AnyConnect, WireGuard kernel logs |
| `authentication` | **PRESENT** | Windows Security Event 4624/4625, Linux OpenSSH (LogHub), Linux auditd |
| `cloud_audit` | **PRESENT** | AWS CloudTrail, GCP Cloud Audit LogEntry, Azure Activity Log |
| `container_lifecycle` | **PRESENT** | Docker daemon, Containerd CRI, Kubernetes Audit |
| `database_query` | **PRESENT** | MySQL general query, PostgreSQL server, MongoDB JSON, Redis |
| `distributed_queue` | **PRESENT** | Apache Kafka broker coordination logs |
| `observability_telemetry` | **PRESENT** | OpenTelemetry OTLP LogRecords |
| `routing_protocol` | **PRESENT** | Cisco IOS-XE BGP/OSPF events |
| `telecom_alarm` | **PRESENT** | LUK Cisco and Huawei network alarm types |
