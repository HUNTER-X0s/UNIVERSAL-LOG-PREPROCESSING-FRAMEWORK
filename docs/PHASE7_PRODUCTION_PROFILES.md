# Phase 7 Production Configuration & Profiles

## ProductionConfigValidator
- Rejects `debug=True`, default/weak secrets, in-memory databases, and disabled auth.
- Enforces minimum secret length (>= 32 chars) and secure database URLs.
