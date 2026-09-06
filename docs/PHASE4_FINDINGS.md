# PHASE 4 FORENSIC FINDINGS

## CORRECTED DEFECTS (Resolved During Audit)

### F-01 [HIGH] OCSF Detection Finding class_uid Incorrect
- **Root Cause:** class_uid=2002 maps to Vulnerability Finding per OCSF v1.1.0. Detection Finding is 2004.
- **File:** packages/semantic/ulpf_semantic/projections/ocsf/mapper.py
- **Correction:** Changed class_uid from 2002 to 2004 in the Detection Finding branch.
- **Test Updated:** 	ests/test_semantic_ocsf.py line 70 updated to assert 2004.

### F-02 [HIGH] OCSF status_id Mapping Incorrect
- **Root Cause:** Implementation used status_id=1 for SUCCESS. OCSF v1.1.0 defines 1=Unknown, 2=Success, 3=Failure.
- **File:** packages/semantic/ulpf_semantic/projections/ocsf/mapper.py
- **Correction:** Replaced flat 1/2 mapping with correct OCSF-defined Unknown/Success/Failure triplet.

## OPEN FINDINGS (Non-Blocking)

### F-03 [MEDIUM] SemanticStatus Always FULL
SemanticMapper sets status=SemanticStatus.FULL unconditionally, even when classification fell back to generic OTHER/Unknown.
Should use PARTIAL for partial classification, UNKNOWN for complete classification failure.

### F-04 [MEDIUM] raw_sha256 Not Forwarded in SemanticEvent
Phase 3 UCE carries aw_sha256 in provenance fields. SemanticEvent does not forward this digest.
Future Phase 5 auditors cannot verify raw payload integrity from SemanticEvent alone.

### F-05 [MEDIUM] Phase 4 Documentation Absent
15 of 16 expected Phase 4 documentation files are absent from docs/.
Minimum required: PHASE4_LIMITATIONS.md, PHASE4_SEMANTIC_ARCHITECTURE.md, PHASE4_COMPLETION_REPORT.md.

### F-06 [MEDIUM] Mapping Rules Not Externalized
Classification rules are hardcoded in classifier.py. Adding a new vendor requires modifying Python source.
Phase 5 AI-assisted onboarding will need config-driven rule files.

### F-07 [MEDIUM] Entity Types PROCESS, FILE, CERTIFICATE, URL, DOMAIN Not Extracted
These entity types are defined in EntityType enum but EntityExtractor does not extract them.
They are taxonomy placeholders for Phase 5+ implementation.

### F-08 [MEDIUM] Risk and Fingerprint Decisions Not Traced
Only classification decisions produce a DecisionTrace. Risk evaluation and fingerprinting produce no trace.
Full audit traceability requires traces from all decision points.

### F-09 [MEDIUM] Benchmark Script Absent
scripts/run_phase4_benchmarks.py referenced in the Phase 4 mission was not created.
Performance data comes only from inline audit measurements.

### F-10 [LOW] 35 Taxonomy Categories Unused
EventCategory defines 42 categories; the classifier maps only 7.
No documentation of intentional scope limitation.

### F-11 [LOW] accept Mapped to allow
ccept and llow collapse to the same semantic action ActionTaxonomy.ALLOW.
Technically TCP ACCEPT may differ from policy-level ALLOW. Documented approximation.

### F-12 [LOW] OCSF Validator Not Full-Schema Backed
OCSFValidator checks 7 mandatory base fields and their types.
It does not validate against the official OCSF JSON schema (not bundled).
Validation scope should be documented.

### F-13 [LOW] Email Indicator Not Extracted
IndicatorType.EMAIL defined but not implemented in IndicatorExtractor.

### F-14 [LOW] Benchmark Test Threshold Too Low
	est_semantic_pipeline_throughput asserts > 500 eps.
Actual throughput is ~5,000 eps. Threshold should be >= 2000 to be meaningful.
