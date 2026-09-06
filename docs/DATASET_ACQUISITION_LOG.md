# ULPF Dataset Acquisition & Curation Log

**Document ID:** ULPF-DOC-DATA-ACQ-001  
**Timestamp:** 2026-09-05T14:15:00Z  

---

## Curation Execution Log

| Target File | Source Organization | Derivation & Provenance | Byte Count | SHA-256 Checksum |
| :--- | :--- | :--- | :---: | :--- |
| `panos_traffic.log` | Palo Alto Networks | Official PAN-OS 10.x Syslog Reference Specification | 722 | `b5420d4f39b6b7ba97034dfbfda7a2cb69165b4c107bf26649171b3e85e985b8` |
| `panos_threat.log` | Palo Alto Networks | Official PAN-OS 10.x Threat Event Specification | 874 | `ea0937a7b97397b91c8413b5bf08d24b69986348ef11b7dfb196888258525b68` |
| `fortigate_utm.log` | Fortinet Inc. | FortiOS 7.4 Log Message Reference Specification | 1,162 | `a90c95029307c08b4ef22c1b2b35dbf4d22cb85cb796b4bf2da32306bfd69a23` |
| `cisco_asa.log` | Cisco Systems | Cisco ASA Series Syslog Message Guide | 572 | `f3ea534cf5e2bb25f822a9f4c3cb4529bcba64eb98f8b89895c898c62c2f2c8d` |
| `checkpoint_fw1.log` | Check Point | Check Point R81 Logging & Monitoring Guide | 525 | `5d3ca24d35e7cb8a336fbf1552a4220379ea7f0f6795f7cbb1a980eb79b0a1d4` |
| `suricata_eve.json` | OISF | Suricata 7.x Extensible Event Format (EVE-JSON) Spec | 682 | `9c82c23f114c0a5b98dfae07ff017f8b965ba3ee299f0e15998a44b7410065fa` |
| `snort_fast.log` | Cisco Talos | Snort 3.x Fast-Alert Emitter Specification | 445 | `2f9eb2a36bcfd30a84aa3351981152a46618e001ba90b9b3e945c22881b22e1b` |
| `cloudtrail_events.json`| AWS | AWS CloudTrail User Guide Management Event Schema | 1,073 | `ce220f86241b312788e04b4c715bc9631742eb55be62ba4a778c187be08a1c97` |
| `vpc_flow.log` | AWS | Amazon VPC User Guide: VPC Flow Logs Version 2 | 344 | `f73a3c2005a76e053d2d0b57e7eb16a5ee8da16a827ba76c4ea52e79e605d8f6` |
| `k8s_audit.json` | CNCF / Kubernetes | `audit.k8s.io/v1` API Server Event Specification | 1,029 | `95d63f2760a927a7c5b6b80d0d57e841f3d8caae7e187bf59fa4ee920199e8d4` |
| `docker_daemon.log` | Docker / Moby | Moby 24.x dockerd Logrus Structured Emitter Spec | 345 | `a807384a3262db801b7a2d4b971a814fe04481ca6e828d15448332bfb58832a8` |
| `postgresql.log` | PostgreSQL GDG | PostgreSQL 16 Server Logging Specification | 496 | `3d4639e443831b0a88bf0a0f6701bb1727ff06a8166d11f67fa4b1b3699bfae6` |
| `mongodb_server.json` | MongoDB Inc. | MongoDB 5.0+ Structured Server JSON Log Reference | 805 | `ce03c58f00d2da2c8b8f2191ae79c4b7ec83fb8251e605f63901ca968cfeb547` |
| `win_security.xml` | Microsoft | Windows Security Auditing Event Reference (4624/4625) | 1,847 | `cf7903f8f1c841cb5dfc1e54a4925dfce3d6a457a4e61ea7728f322ea36f7881` |
| `auditd.log` | Linux Kernel Org | Linux Kernel Audit Subsystem (auditd 3.x) Spec | 525 | `f6a453f669db7bc9910d68f237efb233a1e285f8fdfab2f80c6fb0e0bc87b92f` |
| `nginx_access.log` | F5 / NGINX | NGINX Combined Log Format Specification | 328 | `99e82c5f11183c5a6ba29ca2b0bb8db7ef7454848d79d71c6eb33f990977d4c9` |
| `nginx_error.log` | F5 / NGINX | NGINX Core Module Error Log Specification | 425 | `60293cb84a95a86d26732cfd16f39fae7c9cb6dcf3819e625a666e13b8606c4b` |
| `haproxy_traffic.log` | HAProxy Tech | HAProxy 2.8 HTTP Log Format Specification | 398 | `42d0b5fb31f47c3e1e2d42df7cf84b43491ea9ff88d22797e887f48bfa9df0e3` |
| `cef_events.log` | Micro Focus | ArcSight Common Event Format (CEF 0.1) Standard | 432 | `a90ffb57e7ec97e682245bcae9fa1e2b696f8c40fae4e5aa06b12a8684d0b1ea` |
| `leef_events.log` | IBM Security | IBM QRadar Log Event Extended Format (LEEF 2.0) | 435 | `95d665f97973d098867a544f8841a1f3aeec2244a1b0255562762f928e12df13` |
| `rfc5424_syslog.log` | IETF | IETF RFC 5424 Structured Syslog Protocol Standard | 465 | `6903bf2b542ec7f7bfec4412995ab3524b07fb880b912282ad5b9b1d0a514210` |
| `malformed_json.log` | ULPF Research | Adversarial Fuzzing: Unclosed syntax & bad quoting | 398 | `fcf69b03657754b2a8d5f3089d53f5ab500989f64bfeb895780f2d93e15729fb` |
| `null_byte_inj.log` | ULPF Research | Adversarial Fuzzing: Injected \x00 null characters | 358 | `bc78bfb0d35e7df24a549646b9a9101f349c4d32f505db172f3ce4802c011e13` |
| `regex_stress.log` | ULPF Research | Adversarial Fuzzing: Backtracking DoS strings | 5,528 | `ee2e276b5c3ff898950835f8e5c54e0b04bcf843818e87498c4fc1ca20935574` |
| `corrupted_frame.log`| ULPF Research | Adversarial Fuzzing: Invalid framing & stack traces | 448 | `ad1964177d6118d0521e8e2aa6e0fae5cbff962b92d6e3c0ee0aa713ee07ff50` |
