# RUNBOOK-02: Parser Failure / Parsing Exception Spike

## 1. Trigger & Condition
**Condition:** Parser failure rate exceeds 2% threshold (SLO-PARSE burn).  
**Trigger:** SLO-PARSE alert triggered; DLQ recording `PARSER_FAILURE` events.  

---

## 2. Diagnosis & Root Cause Identification
1. Identify source vendor emitting malformed telemetry.
2. Query parser error log for exception name (e.g., `RegexTimeoutError`, `UnicodeDecodeError`).
3. Extract sample payload from DLQ raw payload repository.

---

## 3. Mitigation & Resolution Steps
1. If unknown vendor format, trigger source onboarding flow: `ulpf-onboard --analyze-sample`.
2. If corrupted format, engage source administrator to remediate agent output.
3. If candidate parser fix available, deploy to canary shadow mode first (`ParserCanaryEngine`).

---

## 4. Verification & Health Restoration
Run canary semantic differential test to verify zero regressions before promoting parser.

---

## 5. Rollback & Post-Incident Safeguards
Revert active parser registration to fallback generic parser or previous version.

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
