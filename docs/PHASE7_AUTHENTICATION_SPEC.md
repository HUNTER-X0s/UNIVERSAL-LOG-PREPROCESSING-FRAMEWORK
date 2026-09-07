# Phase 7 Authentication Specification

## Authentication Providers
1. **JWTAuthenticationProvider**: Validates header, claims (`iss`, `aud`, `exp`, `nbf`), and HMAC-SHA256 signatures with KeyRotationManager.
2. **MTLSAuthenticationProvider**: Validates Common Name, trusted issuer CA list, and validity dates.
3. **ProxyAuthenticationProvider**: Cryptographically verifies signed gateway proxy headers.
