# ULPF Final Privacy, PII & Secrets Audit

**Document ID:** ULPF-DOC-PRIVACY-FINAL  
**Corpus Version:** v3.1.0  
**Scan Scope:** 100% of corpus files (<10MB) via high-entropy and regex secret scanning  

---

### 1. Scan Findings & Forensic Resolution

Total flagged patterns during automated scan: **94 items** across two specific categories:

1. **`AKIAEXAMPLE123456789` (1 occurrence):**
   - *File:* `data/fixtures/real_world/cloud/aws_cloudtrail/cloudtrail_events.json`
   - *Forensic Assessment:* **FALSE POSITIVE / DOCUMENTATION PLACEHOLDER**. This is the standard AWS documentation example access key ID specified by Amazon Web Services. It carries zero credential entropy and has no access capabilities.

2. **`password: "nessus@nessus.org"` (93 occurrences):**
   - *File:* `data/fixtures/real_world/multi_format/zed/sup/ftp.sup`
   - *Forensic Assessment:* **BENIGN VULNERABILITY SCANNER ARTIFACT**. In academic cyber defense competitions (WRCCDC), Nessus scanners issue anonymous FTP requests using the standard email identifier `nessus@nessus.org` as the password. This is a public research artifact, not a real user password.

### 2. Network & IP Addressing Audit
- All synthetic and specification-derived fixtures use reserved RFC 5737 documentation ranges:
  - `192.0.2.0/24` (TEST-NET-1)
  - `198.51.100.0/24` (TEST-NET-2)
  - `203.0.113.0/24` (TEST-NET-3)
  - RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Zero real employee names, corporate email addresses, live passwords, or operational private keys exist in the repository.
