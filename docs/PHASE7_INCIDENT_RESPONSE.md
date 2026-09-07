# Phase 7 Incident Response Runbook

## Incident Handling Procedures
- Authentication breaches: immediate key rotation and session revocation.
- Storage bit-rot: trigger restore from latest verified backup.
- Sink outage: monitor outbox queue; increase retry backoff.
