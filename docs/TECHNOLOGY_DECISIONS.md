# Technology Decisions

## Decision method

Selections are evaluated against NTRO coverage, development speed, horizontal scalability, security, air-gapped operation, maintainability, and six-member-team feasibility. They are replaceable behind contracts; they are not claims that the chosen products are already installed or configured.

| Concern | Candidates considered | Selected architecture | Why | Trade-offs and fallback |
| --- | --- | --- | --- | --- |
| Backend | Python/FastAPI; Go; Java/Spring | Python 3.12 + FastAPI planned for MVP | Typed request models, mature parsing/data tooling, fast student delivery, OpenAPI generation | CPU-heavy parse paths may need worker isolation; a service boundary permits a Go/Rust worker later |
| Frontend | React/TypeScript; Vue; Angular | React + TypeScript | Strong ecosystem for dense operational screens and component testing | Requires state discipline; Vue is an acceptable replacement behind HTTP contracts |
| Parser runtime | hard-coded adapters; config-only regex; plugin packs | Deterministic format adapters plus signed, versioned configuration-driven parser packs | Covers common formats while reducing per-vendor code and supporting review/rollback | Complex grammars may need a sandboxed parser implementation; no arbitrary code upload |
| Streaming | Apache Kafka; Redpanda; NATS JetStream; direct HTTP | Apache Kafka-compatible transport, KRaft mode | Partitions, replay, consumer groups, retained transport, established large-scale path | Resource-heavy for a laptop; MVP may use a small single-node profile through the same transport interface |
| Metadata database | PostgreSQL; SQLite; document DB | PostgreSQL | Reliable transactions for governance, approvals, audit indexes, and configuration | SQLite may support isolated developer tests only; raw evidence is not stored here |
| Search | OpenSearch; Elasticsearch; PostgreSQL FTS | OpenSearch | Event search, aggregations, dashboards, and mature security-oriented queries | Operational dependency; degraded mode retains evidence and queues index work |
| Raw evidence store | filesystem; PostgreSQL blobs; MinIO/S3 | MinIO with S3-compatible object model | Content-addressable immutable evidence, portability, lifecycle controls, air-gap suitability | Demo can use local MinIO; enterprise can supply compatible object storage |
| Data lake | JSON files; Parquet; Iceberg tables | Partitioned Parquet with Iceberg-compatible table strategy | Efficient analytics while retaining a path to schema/partition evolution | Iceberg catalog is not required in MVP; Parquet export is the MVP baseline |
| Canonical security schema | direct OCSF; ECS; OpenTelemetry Logs; bespoke | ULPF Universal Canonical Event (UCE), projected primarily to OCSF; OTel Logs and ECS adapters | UCE protects losslessness and lineage, OCSF gives security semantics, adapters prevent lock-in | Maintaining projections has cost; see ADR-002 |
| AI assistance | cloud LLM; local LLM; no AI | Optional offline local inference behind deterministic heuristics and human approval | Supports unknown-source onboarding without making online AI a production dependency | Model quality/hardware are uncertain; core processing works without AI |
| Observability | vendor SaaS; OpenTelemetry; custom metrics | OpenTelemetry instrumentation plus Prometheus/Grafana-compatible local stack | Vendor-neutral signals and air-gap-friendly operation | Initial MVP may expose fewer dashboards, never fewer critical metrics |
| Identity | custom sessions; Keycloak/OIDC; cloud IAM | Offline-capable OIDC provider such as Keycloak with application RBAC | Local identity, role management, standards-based service integration | Adds an operational component; development can use a bounded local test identity profile |
| Packaging | host installs; Docker Compose; Kubernetes | OCI containers; Docker Compose for demo/single-node; Kubernetes as a later deployment target | Repeatable offline bundle and practical hackathon operation | Kubernetes is intentionally not an MVP prerequisite |

## Cross-cutting selection rules

- The core runtime must have no required internet dependency.
- All third-party artifacts must be pinned, inventoried, and bundled before entering an air-gapped environment.
- Technology boundaries are contracts, not permission to duplicate business logic.
- A fallback must retain raw evidence, auditability, and explicit failure routing.
- Future implementation must measure performance before claiming it.
