# Configuration Foundation

Phase 1 keeps configuration declarative and separate from code, runtime state, user data, generated artifacts, and secrets.

| Concern | Phase 1 location or mechanism | Source-control rule |
| --- | --- | --- |
| Application defaults | application/defaults.json | tracked; non-secret only |
| Configuration contract | application/schema.json and ulpf_platform.config | tracked; code validates environment input |
| Environment values | ULPF_ environment variables | inject at runtime; .env is ignored |
| Secrets | protected runtime secret store or protected environment injection | never tracked or logged |
| Runtime state | data/runtime outside committed source | ignored |
| User data and evidence | future protected services | never tracked as fixtures without approval |
| Generated artifacts | artifacts and build output | ignored |

The process shells accept only the variables documented in .env.example. Unknown variables are not interpreted as configuration. Phase 1 has no database, identity-provider, signing-key, or cloud credential requirement; future components must declare their required secrets through a reviewed configuration change.

Configuration validation is fail-closed for malformed values. Production secret injection is intentionally a deployment responsibility rather than a development fallback.
