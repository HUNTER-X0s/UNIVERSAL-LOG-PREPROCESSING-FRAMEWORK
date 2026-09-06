# ULPF Phase 6 Scalability Model

## 1. Single-Node to Horizontally Scaled
- Stateless processing workers (`WorkerHost`) scale horizontally across stream partitions.
- Stream partitioning guarantees per-device/per-source order without cross-worker locking.
- Persistence repositories support filesystem, database, and object-storage backends.
