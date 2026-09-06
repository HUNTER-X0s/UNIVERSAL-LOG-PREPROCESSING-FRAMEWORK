# ULPF Domain Coverage Matrix

**Document ID:** ULPF-DOC-DATA-DOMAIN-001  
**Status:** COMPLETE / MULTI-DOMAIN  

---

## 1. Domain Distribution

| Domain | Core / Extended | Active Dataset Families | File Count | Aggregate Size | Primary Vendors |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Network Security** | **CORE_NTRO** | 10 | 175 | 6,076.38 MB | Palo Alto, Fortinet, Cisco, Check Point, Suricata, Snort, Zeek, Juniper, OPNsense, WireGuard |
| **Cloud Telemetry** | EXTENDED | 5 | 10 | 4.8 KB | AWS CloudTrail, AWS VPC Flow, Azure Activity, Azure NSG, GCP Audit |
| **Containers & Cloud-Native** | EXTENDED | 3 | 6 | 3.5 KB | Kubernetes Audit, Docker Daemon, Containerd CRI |
| **Database Telemetry** | EXTENDED | 4 | 8 | 5.2 KB | PostgreSQL, MongoDB, MySQL, Redis |
| **Identity & Host Audit** | EXTENDED | 3 | 6 | 6.5 KB | Windows Security XML, Linux Auditd |
| **Web & Application Runtime** | EXTENDED | 6 | 13 | 42.5 KB | NGINX, HAProxy, Envoy, IIS, Java Log4j, Python Structlog, Go Zap |
| **Operating Systems** | EXTENDED | 4 | 8 | 1.70 MB | Linux 2k, Mac 2k, Windows 2k, Android 2k |
| **Distributed Systems** | EXTENDED | 8 | 16 | 2.30 MB | BGL, Hadoop, HDFS, HPC, OpenStack, Spark, Zookeeper, Kafka |
| **Multi-Format Standards** | **CORE_NTRO** | 2 | 8 | 6.5 KB | ArcSight CEF, IBM LEEF, IETF RFC 5424, OpenTelemetry OTLP |
| **Adversarial & Robustness** | FORMAT_STRESS | 1 | 9 | 18.5 KB | Syntax fuzzing, Unicode, BOM, Regex stress, Nested JSON |
