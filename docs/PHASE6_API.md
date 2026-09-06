# ULPF Phase 6 REST API Specification

## Endpoints Summary

| Method | Path | Required Role | Description |
|---|---|---|---|
| GET | `/health` | Any | Operational liveness |
| GET | `/health/live` | Any | Process liveness |
| GET | `/health/ready` | Any | Dependency readiness check |
| POST | `/api/v1/events/ingest` | operator, platform-admin | Telemetry ingestion |
| GET | `/api/v1/events/raw/{id}` | viewer, operator, platform-admin | Retrieve raw evidence & verify SHA-256 |
| GET | `/api/v1/uce/{id}` | viewer, operator, platform-admin | Retrieve canonical UCE |
| GET | `/api/v1/semantic/{id}` | viewer, operator, platform-admin | Retrieve semantic event |
| GET | `/api/v1/search` | viewer, operator, platform-admin | Bounded structured search |
| GET | `/api/v1/dlq` | operator, platform-admin | Inspect dead letter records |
| POST | `/api/v1/replay` | operator, platform-admin | Trigger historical replay with pinned version |
| GET | `/api/v1/metrics` | viewer, operator, platform-admin | Point-in-time metrics snapshot |
