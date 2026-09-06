# PHASE 4 ADVERSARIAL EXIT LIMITATIONS
**Project:** Universal Log Preprocessing Framework (ULPF)  
**Date:** 2026-09-06  

---

## 1. Scope & Functional Boundaries

1. **Classification Scope:**
   - Classification rules currently cover 7 core telemetry classes: Firewall, IDS/IPS alert, DNS query/response, HTTP access, Network flow, Cloud audit, and Authentication.
   - Events outside these classes fall back to `category=OTHER`, `action=unknown`, `status=UNKNOWN`, `confidence=0.50`.

2. **Hardcoded Rules vs. Configuration:**
   - All classification rules reside statically in `packages/semantic/ulpf_semantic/classification/classifier.py`.
   - Onboarding a new log format requires a Python code change. Externalized YAML/JSON configuration is explicitly deferred to Phase 5.

3. **Entity Taxonomy Coverage:**
   - The taxonomy defines 17 entity types; runtime extraction implements 4 primary types: `IP` (source/dest), `HOST`, `USER`, and `CLOUD_RESOURCE`.
   - Extended entity extraction (`PROCESS`, `FILE`, `CONTAINER`, `DATABASE`) is planned for Phase 5.

4. **Raw Payload Digest Forwarding:**
   - `SemanticEvent` forwards `uce_event_id` and `raw_event_id`, but does not duplicate the raw payload SHA-256 digest at the root. Full payload cryptographic verification must reference the Phase 3 UCE record.

5. **OCSF Schema Validation Depth:**
   - The OCSF projector validates mandatory base fields and primitive types. It does not validate nested attributes against the full official 50MB OCSF v1.1.0 JSON schema.

6. **Air-Gap Constraint:**
   - The engine performs no dynamic external lookups (no DNS resolution, no GeoIP lookups, no threat intelligence API calls, no LLM queries). All enrichments are strictly derived from local event evidence.
