# ULPF Adversarial and Robustness Coverage Matrix

**Document ID:** ULPF-DOC-DATA-ADV-001  
**Status:** COMPLETE / ROBUST  

---

## 1. Adversarial Test Vectors Catalog

| Vector ID | Test File | Fault Injection Description | Parser Failure Prevented | Expected Pipeline Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **ADV-01** | `malformed_json.log` | Unclosed quotes, trailing commas, missing braces | JSON parser fatal crash | Route to DLQ with `ERROR_JSON_SYNTAX` |
| **ADV-02** | `null_byte_injection.log` | Embedded `\x00` in syslog & CSV | String truncation / C-string exploits | Retain as raw binary; escape safely |
| **ADV-03** | `regex_backtracking_stress.log`| Catastrophic backtracking string (5,000 'a's) | ReDoS CPU exhaustion | Bound regex execution; timeout fallback |
| **ADV-04** | `corrupted_framing.log` | Inconsistent length header, split stacktrace | Buffer desynchronization | Isolate malformed chunk; emit framing alert |
| **ADV-05** | `deeply_nested_json.log` | 35 levels of recursive JSON nesting | Call stack overflow | Max recursion depth guard (cap at 20) |
| **ADV-06** | `utf8_bom_and_escapes.log` | UTF-8 Byte Order Mark (`\ufeff`) + escaped null | Header corruption | Strip BOM cleanly; decode valid UTF-8 |
| **ADV-07** | `impossible_timestamps.log` | Feb 30th, Month 13, Timezone +25:00 | Timestamp parser exception | Fallback to ingestion receipt time; tag drift |
| **ADV-08** | `mixed_delimiter_injection.log`| Comma, pipe, tab inside quoted strings | Delimiter confusion | Strict grammar adherence to quote boundaries |
