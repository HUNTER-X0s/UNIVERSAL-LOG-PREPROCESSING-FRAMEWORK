# ADR-013: Parser Isolation and Content Safety

**Status:** Accepted for Phase 0

## Context

Logs and uploaded samples are hostile inputs. Parser defects, regex backtracking, decompression bombs, path traversal, or plugin code could compromise availability or integrity.

## Decision

Treat log content as data, run parsing under least privilege with bounded resources, use trusted format adapters and declarative packs, deny arbitrary code/network/filesystem/process access, and test with fuzz/adversarial corpora.

## Alternatives considered

- Parse in the main API process.
- Allow general-purpose plugin scripts.
- Rely only on input validation without resource isolation.

## Pros

Reduces blast radius, enables clear failure behavior, and aligns with air-gap and supply-chain controls.

## Cons

Isolation introduces runtime overhead and packaging/testing complexity.

## Security implications

Limits mitigate RCE, ReDoS, DoS, secret access, data exfiltration, and parser-pack tampering.

## Operational implications

Workers need quotas, health monitoring, kill/retry/quarantine behavior, and incident response for revoked packs.

## Consequences

Parser extensibility is intentionally constrained; unsafe convenience is rejected in favor of predictable governed behavior.
