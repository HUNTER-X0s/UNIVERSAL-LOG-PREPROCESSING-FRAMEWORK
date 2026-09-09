# ULPF Phase 13 AI Safety and Grounding Specification

**Status:** ACTIVE SPECIFICATION  
**Scope:** Offline Advisory, Prompt Injection Defense, Hallucination Prevention, Evidence Citations  

---

## 1. AI Safety Guarantees

1. **Zero External Dependence (Rule 5):**
   No cloud APIs (OpenAI, Anthropic, Gemini) or remote inference endpoints are permitted. The system operates 100% offline with zero external network connectivity.
2. **Deterministic Primacy (Rule 4):**
   The deterministic pipeline is authoritative. AI outputs are advisory and never overwrite raw bytes, normalized UCE records, or cryptographic lineage.
3. **Prompt Injection Sanitization:**
   Incoming strings are checked against `_INJECTION_PATTERNS` in `advisor.py`. Malicious control instructions (`ignore previous`, `system:`, `<script>`, `bypass security`) are redacted.
4. **Strict Grounding & Citation Mandate:**
   Every AI statement must be classified into `[VERIFIED FACT]`, `[SYSTEM INFERENCE]`, or `[ANALYST SUGGESTION]`, citing exact contributing `event_ids` and cryptographic `raw_sha256` digests.
5. **Human Authorization for State Changes:**
   State modifications require a `ProposedStateAction` token and valid human operator credentials.
