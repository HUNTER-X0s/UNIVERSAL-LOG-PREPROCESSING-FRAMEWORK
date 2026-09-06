# ULPF Phase 5 Exit Findings

**Date:** 2026-09-06 | **Commit:** eadbf1f

## Summary

| Severity | Count | Status |
|---|---|---|
| CRITICAL | 0 | - |
| HIGH | 2 | Both remediated |
| MEDIUM | 2 | 1 remediated, 1 non-blocking |
| LOW | 2 | Non-blocking, documented |

Blocking defects at freeze: 0

---

## F-P5-01: GIT-UNCOMMIT [HIGH - REMEDIATED]

At audit start, all Phase 5 code was uncommitted.
A freeze without committing would leave no reproducible baseline.

Evidence: git status showed 20 modified + 20 untracked at commit 8cfe492.
Action: All Phase 5 committed as eadbf1f during this audit.
Status: REMEDIATED

---

## F-P5-02: DSL-BRACKET [MEDIUM - REMEDIATED]

get_nested_field(doc, "items[0]") returned None instead of the correct value.
Bracket notation key[n] was not parsed. Only dot notation key.n worked.

Evidence: get_nested_field({"items":[10,20,30]}, "items[0]") returned None.
Impact: Any mapping rule using field[n] syntax would silently fail.
Fix: Added _BRACKET_RE bracket notation parser to operators.py.
Negative indices and OOB indices return None (safe).
Status: REMEDIATED

---

## F-P5-03: AI-OUTPUTVAL-RANGE [MEDIUM - NON-BLOCKING]

AIOutputValidator does not reject confidence > 1.0 or invalid taxonomy enums.

Impact: AI output with out-of-range confidence passes the first validation layer.
Mitigation: registry.validate() schema validation provides a second layer.
Status: NON-BLOCKING (documented limitation L-01)

---

## F-P5-04: FLAKY-BENCHMARK [LOW - KNOWN]

test_parser_benchmarks.py::test_paloalto_panos_throughput failed once during
full suite run but passed in isolation. Pre-existing timing sensitivity.
Status: NON-BLOCKING

---

## F-P5-05: SEMANTIC-ATTR-NAMING [LOW - NON-BLOCKING]

SemanticEvent stores triple in 'semantic_triple' and ID in 'semantic_event_id'.
Docs referencing 'triple' or 'fingerprint' would produce AttributeError.
Status: NON-BLOCKING (documentation gap only)

---

## False Positives Resolved

| Scan ID | Finding | Resolution |
|---|---|---|
| SEC-COMPILE | compile( found | False positive: re.compile() in operators.py - safe |
| SEC-EVAL | eval( found | False positive: string literal in safety.py detection list |
| SEC-EXEC | exec( found | False positive: string literal in safety.py detection list |
| SEC-SUBPROCESS | subprocess found | False positive: string literal in safety.py |
| SEC-OS.SYSTEM | os.system found | False positive: string literal in safety.py |
