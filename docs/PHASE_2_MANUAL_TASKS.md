# Phase 2 Manual Tasks

| Task | Why a human team is required | Completion evidence |
|---|---|---|
| Select and provision immutable S3-compatible evidence storage | ADR-005 requires infrastructure lifecycle, access controls, retention, backup, and key custody beyond this local fallback | approved MinIO/S3 deployment, retention policy, restore/hash test |
| Select source authentication | The interim static bearer token is not device identity, OIDC, mTLS, or authorization policy | approved source/identity design, secret injection, certificate/rotation runbook |
| Allocate TCP/UDP ports and firewall rules | Network policy and source reachability are organization-controlled | approved listener ports, firewall rules, scoped source test |
| Obtain approved representative device samples | Real telemetry may be sensitive and licensing/provenance constrained | sanitized, authorized fixtures with provenance record |
| Run container proof | Docker configuration and volume ownership are environment-specific | build/run record proving evidence volume behavior |
| Run air-gap drill | Local dependencies must be transferred and verified under the organization process | network-denied run record and approved bundle/checksum evidence |
| Run measured performance test | Hardware, load generator, and isolation determine meaningful results | benchmark manifest with hardware, configuration, corpus, commands, and raw results |

No manual task blocks local Phase 2 unit/integration testing. All block production-like claims.
