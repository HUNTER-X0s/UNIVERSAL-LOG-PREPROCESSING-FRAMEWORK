# ULPF Phase 6 Deployment & Operations

## Deployment Modes
1. **Mode 1 (Single-Node Development)**: In-memory stream, local filesystem raw store, local search index.
2. **Mode 2 (Production-Like Single-Node)**: Filesystem raw store, background worker threads, FastAPI REST daemon.
3. **Mode 3 (Containerized Production)**: Docker container running unprivileged (`10001:10001`) with read-only root and durable data volumes.
4. **Mode 4 (Air-Gapped Perimeter)**: Self-contained deployment from air-gap bundle manifest.
