# Phase 7 Security Architecture

## Threat Model & Principles
- **Fail-Closed Gateways**: Missing or invalid credentials return 401/403.
- **Zero Header Trust**: Unauthenticated `X-Role` headers are strictly rejected.
- **Cryptographic Verification**: HMAC-SHA256 tokens and X.509 certificates verified at boundaries.
- **Tenant Isolation**: Queries strictly scoped by authenticated tenant ID.
- **Path Containment**: Object store rejects directory traversal attempts.
