# ULPF Universal Dataset Coverage Matrix

**Document ID:** ULPF-DOC-DATA-MATRIX-002  
**Status:** COMPLETE / MULTI-DIMENSIONAL  

---

## 1. Domain vs Format Coverage Matrix

| Domain | Syslog | JSON / NDJSON | Key=Value | CSV | XML | Delimited / Text | Binary / Super |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Network Security (Core NTRO)** | **YES** (Cisco ASA) | **YES** (Suricata, Zed) | **YES** (Fortinet, CheckPoint) | **YES** (Palo Alto) | - | **YES** (Snort, SecRepo TSV)| **YES** (Zed BSUP) |
| **Cloud Telemetry** | - | **YES** (CloudTrail) | - | - | - | **YES** (VPC Flow space-sep)| - |
| **Containers & Cloud-Native** | - | **YES** (K8s Audit) | **YES** (Docker logrus)| - | - | - | - |
| **Database Systems** | - | **YES** (MongoDB) | - | - | - | **YES** (PostgreSQL prefixed)| - |
| **Identity & Host Audit** | - | - | **YES** (Linux Auditd)| - | **YES** (Win Event)| - | - |
| **Web & Edge Applications** | **YES** (HAProxy) | - | - | **YES** (Apache Loghub)| - | **YES** (NGINX CLF) | - |
| **Distributed Systems** | **YES** (Linux Loghub) | **YES** (Spark Loghub) | - | **YES** (HDFS Loghub) | - | **YES** (BGL Loghub) | - |
| **Enterprise SIEM Standards** | **YES** (RFC 5424) | - | **YES** (CEF, LEEF) | - | - | - | - |
| **Adversarial / Stress Vectors**| **YES** (Corrupted) | **YES** (Broken JSON) | **YES** (Null Injection) | **YES** (Bad Quoting) | - | **YES** (Regex Stress) | - |

---

## 2. Vendor Coverage Table

| Vendor / Project | Product Line | Telemetry Family | Formats Available | Tier | Priority Class |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **Palo Alto Networks** | PA-VM, PA-5000 | Firewall Traffic & Threat | CSV-over-syslog | Tier 1 | CORE_NTRO |
| **Fortinet** | FortiGate (FortiOS 7.x) | Firewall & UTM | Key=Value Syslog | Tier 1 | CORE_NTRO |
| **Cisco Systems** | Cisco ASA / FTD / IOS | Firewall & Infrastructure| RFC 3164 Syslog, JSON KB | Tier 1 | CORE_NTRO |
| **Check Point** | Gaia FireWall-1 | Security Gateway | Pipe-delimited KV | Tier 1 | CORE_NTRO |
| **OISF** | Suricata IDS/IPS | Network Intrusion Alert | NDJSON (EVE-JSON) | Tier 1 | CORE_NTRO |
| **Cisco Talos** | Snort 2.9 / 3.x | Network Intrusion Alert | Bracketed Fast Alert | Tier 1 | CORE_NTRO |
| **Zeek Project** | Zeek Network Monitor | Protocol & Flow Telemetry| TSV, JSON, SUP, BSUP | Tier 1 | CORE_NTRO |
| **F5 / NGINX** | NGINX Core | Reverse Proxy & Web | Combined Log Format | Tier 3 | EXTENDED |
| **HAProxy Tech** | HAProxy | Edge Load Balancer | HTTP Timer Tuple | Tier 3 | EXTENDED |
| **Amazon Web Services** | AWS CloudTrail, VPC | Cloud Audit & Flow | Nested JSON, Space-delim | Tier 5 | EXTENDED |
| **CNCF / Kubernetes** | kube-apiserver | Cluster Control Plane | NDJSON | Tier 6 | EXTENDED |
| **Docker Inc.** | dockerd / containerd | Container Runtime | Logrus KV | Tier 6 | EXTENDED |
| **PostgreSQL GDG** | PostgreSQL Server | Relational Database | Prefixed Log Text | Tier 7 | EXTENDED |
| **MongoDB Inc.** | mongod 5.0+ | Document Database | Structured JSON | Tier 7 | EXTENDED |
| **Microsoft** | Windows Server / Active Dir| Security & Logon Audit | XML (Event 4624/4625) | Tier 8 | EXTENDED |
| **Linux Kernel** | Audit Subsystem (auditd)| Kernel Exec & Syscall | Netlink Key=Value | Tier 8 | EXTENDED |
| **ArcSight / IBM** | CEF & LEEF Standards | Enterprise SIEM Wire | Pipe/Tab Delimited | Tier 10 | CORE_NTRO |

---

## 3. Telemetry Semantics & Parser Complexity

| Dataset | Telemetry Semantics | Structural Richness | Primary Parser Exercise |
| :--- | :--- | :--- | :--- |
| **Palo Alto** | Session state, NAT IP, threat rule | Positional 30+ column CSV | Exact column indexing and threat classification |
| **FortiGate** | UTM virus, forward traffic, policy UUID | Dynamic Key=Value pairs | Quoted value extraction and dynamic schema parsing |
| **Cisco ASA** | Connection teardown, ACL drop, IP spoof | Syslog header + %ASA-ID body | Message code regex and interface tuple parsing |
| **Check Point** | Firewall rule drop, blade event | Pipe-delimited key=value | Pipe delimiter splitting and rule resolution |
| **Suricata** | Alert signature, flow counters, DNS query | Deeply nested JSON stream | JSON field unwrapping and alert severity mapping |
| **AWS CloudTrail** | IAM user identity, API call parameters | Multi-layer nested JSON | Schema flattening and principal ARN extraction |
| **Kubernetes Audit**| RBAC user groups, URI, HTTP response | Standardized Cloud-Native JSON | Stage timestamp correlation and authorization audit |
| **Linux Auditd** | Syscall ID, executable path, process args | Hex-encoded & quoted KV | Multiline audit message correlation via timestamp ID |
| **Windows Event** | LogonType, SID, status hex code | Hierarchical XML elements | XPath querying and hexadecimal error code decoding |
