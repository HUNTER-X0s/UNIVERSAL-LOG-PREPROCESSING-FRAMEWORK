# ULPF Final Forensic Dataset Audit Report

**Document ID:** ULPF-DOC-FORENSIC-AUDIT-FINAL  
**Scope:** Complete physical and logical inspection of `data/`  
**Corpus Version:** v3.1.0  
**Verification Date:** 2026-09-06  

---

### 1. Physical Inventory & Filesystem Architecture

The corpus contains exactly:
- **Total Physical Files:** 344 files
- **Total Physical Bytes:** 6,409,481,418 bytes (~6,112.56 MB)
- **Telemetry Payload Files:** 286 files (6,409,385,655 bytes)
- **Metadata & Manifest Files:** 58 files (95,763 bytes)
- **Symlinks:** 0 (Zero symlinks or broken references)
- **Orphan Files:** 0 (All data files map to registered datasets or benchmark structures)
- **Duplicate Content Groups:** 0 unintended duplicate groups

### 2. Physical Layout Breakdown

```
data/
├── fixtures/
│   ├── real_world/
│   │   ├── network_security/      (Palo Alto, Fortinet, Check Point, Cisco, Juniper, OPNsense, WireGuard, Snort, Suricata)
│   │   ├── cloud/                 (AWS CloudTrail, AWS VPC Flow, Azure Activity, Azure NSG v2, GCP Audit)
│   │   ├── container/             (Containerd CRI, Docker daemon, Kubernetes audit)
│   │   ├── database/              (MySQL general, PostgreSQL, MongoDB, Redis server)
│   │   ├── application/           (Envoy access, IIS W3C, NGINX, HAProxy, Java multiline, Python structlog, Go Zap)
│   │   ├── distributed_system/    (Kafka broker)
│   │   ├── identity/              (Windows Security 4624/4625 XML, Linux auditd)
│   │   └── multi_format/          (CEF, LEEF, RFC 5424, OpenTelemetry OTLP JSON, Zed Zeek multi-format)
│   └── adversarial/               (Deeply nested JSON, UTF-8 BOM, impossible timestamps, delimiter injection)
├── reference/
│   ├── loghub/                    (16 benchmark systems: raw, structured CSV, templates CSV)
│   └── alarm_knowledge/          (Cisco and Huawei alarm reference catalogs)
├── benchmarks/
│   └── secrepo/                   (Large-scale 4.17 GB network/HTTP/conn captures)
└── DATASET_MANIFEST.json          (Forensic Manifest v3.1.0)
```
