# Deployment Foundation

Phase 1 provides only an API shell container definition and a local Compose profile. It deliberately does not orchestrate Kafka, PostgreSQL, MinIO, OpenSearch, identity, or any product data plane. All deployment configuration is non-secret and local-runtime capable.
