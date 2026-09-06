# ULPF Real vs. Specification-Derived vs. Synthetic Telemetry Audit

**Document ID:** ULPF-DOC-REAL-VS-SYNTHETIC-FINAL  
**Standard:** Strict Forensics (Never label synthetic or spec-derived data as authentic public data)  
**Corpus Version:** v3.1.0  

---

### 1. Classification Methodology

Every dataset and fixture is categorized into one of five mutually exclusive forensic classes:
1. **`REAL_PUBLIC_DATASET` / `ACADEMIC_RESEARCH`:** Genuine telemetry collected from real physical systems, academic clusters, supercomputers, or security capture environments.
2. **`SPECIFICATION_DERIVED`:** Synthesized records engineered strictly to match official vendor documentation, RFC specifications, or product message guides with 100% syntactic precision.
3. **`ULPF_ADVERSARIAL`:** Handcrafted malformed, fuzzing, or boundary-stress records designed to test parser robustness.
4. **`REFERENCE_KNOWLEDGE`:** Reference ground truth, parsing templates, and alarm type catalogs.
5. **`METADATA`:** Manifests, READMEs, and licensing documentation.

---

### 2. Forensic Audit Table

| Dataset Family | Storage Path | Provenance Class | Real-World Status | Upstream Source / Spec Authority |
|---|---|---|---|---|
| **SecRepo CCDC** | `data/benchmarks/secrepo/` | `REAL_PUBLIC_DATASET` | Authentic Public Capture | SecRepo / Mid-Atlantic CCDC 2012 captures |
| **BrimData Zed** | `data/fixtures/real_world/multi_format/zed/` | `REAL_PUBLIC_DATASET` | Authentic Public Capture | Brim Data / Zeek WRCCDC 2018 capture |
| **LogHub (16 Systems)** | `data/reference/loghub/` | `REAL_PUBLIC_DATASET` | Authentic Research Logs | LogPAI / CUHK / Zenodo Research Dataset |
| **LUK Alarm Knowledge** | `data/reference/alarm_knowledge/` | `REAL_PUBLIC_DATASET` | Authentic Operational Data | LUK Benchmark / Huawei & Cisco real alarms |
| **Palo Alto PAN-OS** | `data/fixtures/real_world/network_security/paloalto/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Palo Alto PAN-OS 10.x/11.x Syslog Guide |
| **Fortinet FortiOS** | `data/fixtures/real_world/network_security/fortinet/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | FortiOS 7.x Log Message Reference |
| **Check Point FW-1** | `data/fixtures/real_world/network_security/checkpoint/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Check Point Log Exporter CEF/Syslog Spec |
| **Cisco ASA** | `data/fixtures/real_world/network_security/cisco_asa/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Cisco ASA Series Syslog Guide |
| **Cisco IOS-XE** | `data/fixtures/real_world/network_security/cisco_ios/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Cisco IOS-XE System Message Guide |
| **Juniper SRX** | `data/fixtures/real_world/network_security/juniper_srx/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Juniper Junos OS RT_FLOW Reference |
| **OPNsense / pfSense**| `data/fixtures/real_world/network_security/opnsense/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | pfSense / OPNsense Filterlog CSV Spec |
| **WireGuard VPN** | `data/fixtures/real_world/network_security/wireguard/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Linux WireGuard Kernel Debug Logging |
| **AWS CloudTrail** | `data/fixtures/real_world/cloud/aws_cloudtrail/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | AWS CloudTrail Event Reference |
| **AWS VPC Flow** | `data/fixtures/real_world/cloud/aws_vpcflow/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | AWS VPC Flow Logs v2 Specification |
| **Azure Activity** | `data/fixtures/real_world/cloud/azure_activity/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Microsoft Azure Monitor Activity Log Schema |
| **Azure NSG Flow v2**| `data/fixtures/real_world/cloud/azure_nsg/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Azure Network Watcher NSG Flow Log Schema v2 |
| **GCP Cloud Audit** | `data/fixtures/real_world/cloud/gcp_audit/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Google Cloud Audit Logs LogEntry Spec |
| **Containerd CRI** | `data/fixtures/real_world/container/containerd_cri/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Kubernetes CRI Log Framing (`stdout F/P`) |
| **Kubernetes Audit** | `data/fixtures/real_world/container/kubernetes_audit/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Kubernetes Advanced Audit Policy Schema |
| **Docker Daemon** | `data/fixtures/real_world/container/docker_events/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Docker Engine Daemon Log Format |
| **MySQL Server** | `data/fixtures/real_world/database/mysql/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | MySQL 8.0 General Query Log Spec |
| **PostgreSQL Server**| `data/fixtures/real_world/database/postgresql/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | PostgreSQL Server Log Format |
| **MongoDB Server** | `data/fixtures/real_world/database/mongodb/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | MongoDB 4.4+ Structured JSON Log Spec |
| **Redis Server** | `data/fixtures/real_world/database/redis/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Redis Server Operational Log Spec |
| **Apache Kafka** | `data/fixtures/real_world/distributed_system/kafka/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Apache Kafka Broker Log4j Output |
| **Envoy Proxy** | `data/fixtures/real_world/application/envoy/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Envoy JSON Access Log Spec |
| **Microsoft IIS** | `data/fixtures/real_world/application/iis/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Microsoft IIS W3C Extended Log File Format |
| **NGINX Web** | `data/fixtures/real_world/application/nginx/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | NGINX Combined and Error Log Spec |
| **HAProxy Edge** | `data/fixtures/real_world/application/haproxy/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | HAProxy HTTP Log Format |
| **Java Log4j2** | `data/fixtures/real_world/application/java_stacktrace/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Java Multiline Exception Chaining Pattern |
| **Python structlog** | `data/fixtures/real_world/application/python_app/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Python structlog Key-Value JSON Pattern |
| **Go Uber Zap** | `data/fixtures/real_world/application/go_app/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Uber Zap Typed JSON Logging Spec |
| **OpenTelemetry** | `data/fixtures/real_world/multi_format/opentelemetry/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | OpenTelemetry OTLP Log Data Model v1 |
| **Windows Security** | `data/fixtures/real_world/identity/windows_security/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Microsoft Windows Event XML Schema (4624/4625) |
| **Linux Auditd** | `data/fixtures/real_world/identity/linux_auditd/` | `SPECIFICATION_DERIVED` | Synthetic (Spec-Derived) | Linux Kernel Audit Daemon Specification |
| **Adversarial Edge** | `data/fixtures/adversarial/` | `ULPF_ADVERSARIAL` | Synthetic Adversarial | ULPF Parser Boundary & Fuzzing Scenarios |

---

### 3. Key Forensic Clarification

> [!NOTE]
> Even though many specification-derived test fixtures reside inside the directory path `data/fixtures/real_world/...` (due to architectural directory structure inheritance from earlier sprints), their official provenance classification is **`SPECIFICATION_DERIVED`**. They are never claimed to be raw production packet dumps or field captures.
