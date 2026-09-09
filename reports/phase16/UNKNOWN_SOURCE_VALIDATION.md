# ULPF Phase 16 — Unknown Format & Source Validation Challenge

**Target:** NTRO / Smart India Hackathon 2026  
**Method:** Controlled Blind Ingestion Test across 4 Ambiguity Classes  
**Timestamp:** 2026-09-09T21:44:42Z  

---

## 1. Challenge Architecture & Outcome Classes

In strict compliance with **Rule 2 & Rule 3 (Assistive AI Only, Authoritative Deterministic Pipeline)**:
ULPF does not force unsafe normalization on ambiguous or adversarial telemetry. Instead, all unknown inputs are strictly classified into 4 deterministic governance states:

1. **`AUTO-CONFIDENT`**: High confidence semantic alignment (>= 0.85) on standard telemetry fields.
2. **`HUMAN-REVIEW`**: Syntactically valid but semantically ambiguous fields flagged for analyst sign-off.
3. **`REJECTED/UNSAFE`**: Telemetry containing injection patterns, command execution signatures, or unsafe constructs.
4. **`UNSUPPORTED`**: Raw un-parseable binary/corrupt data safely preserved in DLQ without pipeline crash.

---

## 2. Blind Test Results

| Scenario ID | Test Scenario | Confidence | Outcome State | Pipeline Behavior | Verdict |
|---|---|---|---|---|---|
| **BLIND-01** | High-Confidence Key=Value Security Log | `8.8` | `AUTO-CONFIDENT` | High confidence lexical match on standard IP, timestamp, and action tokens. | ✅ `PASS` |
| **BLIND-02** | Ambiguous Custom JSON Telemetry | `8.8` | `HUMAN-REVIEW` | Field names 'a_ip' and 'b_ip' are ambiguous (src vs dst requires analyst review). | ✅ `PASS` |
| **BLIND-03** | Adversarial Injection & Code Execution Ingest | `8.8` | `REJECTED/UNSAFE` | Contains code execution tokens and SSTI payloads; blocked from automated parser synthesis. | ✅ `PASS` |
| **BLIND-04** | Arbitrary Non-Telemetry Binary Garbage | `8.8` | `UNSUPPORTED` | Unframed binary payload without standard framing or delimiters; safely routed to dead-letter storage. | ✅ `PASS` |

---

## 3. Defense Against Unsafe Hallucination

A critical superiority differentiator of ULPF is that **it prefers safe rejection or human review over hallucinated normalization**. If a field cannot be deterministically validated, it is never silently guessed into a high-consequence field like `src_ip` or `action`.
