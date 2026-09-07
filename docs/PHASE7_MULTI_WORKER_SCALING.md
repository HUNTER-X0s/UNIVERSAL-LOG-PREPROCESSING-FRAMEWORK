# Phase 7 Multi-Worker Scaling Specification

## MultiWorkerCoordinator
- Coordinates multiple isolated worker threads/processes.
- Exclusive partition leases prevent concurrent duplicate execution.
- Signal-driven graceful drain finishes inflight batches before shutdown.
