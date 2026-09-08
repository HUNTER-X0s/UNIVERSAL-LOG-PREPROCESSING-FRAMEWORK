# ULPF Phase 12 Non-Blocking Operational Limitations

**Document Purpose:** Formally document real-world operational constraints and non-blocking boundaries.

---

1. **Hardware Ingestion Scale:** Measured throughput (>94k EPS) reflects single-node local benchmarking; multi-node clustered ingestion requires external network orchestrators.
2. **Third-Party Government Accreditation:** The framework has been rigorously tested against defined internal engineering criteria; formal government accreditation (e.g., MeitY, DRDO) is an external organizational process.
3. **Local Bloom Filter Capacity:** In-memory Bloom filters for threat intelligence are bounded to 1,000,000 indicators; larger indicator sets require partitioned disk-backed stores.
