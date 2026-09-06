# ULPF Canonical Event Normalization Targets

**Document ID:** ULPF-DOC-DATA-NORM-001  
**Governing Event Model:** `docs/EVENT_MODEL.md` & `docs/DATA_MODEL.md`  

---

## 1. Canonical Field Mappings Across Key Datasets

| Canonical Field | Palo Alto PAN-OS | Fortinet FortiGate | Cisco ASA | Suricata EVE | AWS CloudTrail | Kubernetes Audit |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `event_time` | `ReceiveTime` (pos 2) | `date` + `time` | Syslog Timestamp | `timestamp` (ISO8601)| `eventTime` | `requestReceivedTimestamp` |
| `source_ip` | `SourceIP` (pos 8) | `srcip` | Inside/Outside IP | `src_ip` | `sourceIPAddress` | `sourceIPs[0]` |
| `source_port` | `SourcePort` (pos 25)| `srcport` | Port tuple | `src_port` | N/A | N/A |
| `destination_ip`| `DestinationIP` (pos 9)| `dstip` | Inside/Outside IP | `dest_ip` | N/A | N/A |
| `destination_port`|`DestinationPort` (pos 26)|`dstport` | Port tuple | `dest_port` | N/A | N/A |
| `protocol` | `Protocol` (pos 30) | `proto` (IANA code)| Protocol name | `proto` (TCP/UDP) | N/A | N/A |
| `action` | `Action` (pos 31) | `action` | Built/Teardown/Deny| `alert.action` | N/A | N/A |
| `user` | `SourceUser` (pos 13)| `user` | User in %ASA | N/A | `userIdentity.userName`| `user.username` |
| `rule_id` | `RuleName` (pos 12) | `policyid` | Access-group name | `alert.signature_id`| N/A | N/A |
| `severity` | Threat severity | `level` | Syslog Priority (0-7)| `alert.severity` (1-4)| `eventCategory` | `level` |
