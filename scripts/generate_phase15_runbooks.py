"""Generate the 15 Phase 15 Operational SRE Runbooks."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNBOOKS_DIR = ROOT / "docs" / "runbooks"
RUNBOOKS_DIR.mkdir(parents=True, exist_ok=True)

RUNBOOKS = [
    (
        "runbook_01_service_failure.md",
        "RUNBOOK-01: Service / Process Crash or Unavailability",
        "Ingestion listener or core pipeline worker process terminates unexpectedly.",
        "Systemd watchdog alert, Prometheus probe failure, or container exit code > 0.",
        "1. Identify terminated PID and reason from system journal (`journalctl -u ulpf-*`).\n2. Inspect crash stack trace in `/var/log/ulpf/crash.log` or Windows Event Viewer.\n3. Verify file descriptor and memory limits (`ulimit -a`).\n4. If out-of-memory (OOM-killer), verify heap allocation in configuration.",
        "1. Restart daemon process: `systemctl restart ulpf-worker`.\n2. In high-availability mode, verify FailoverCoordinator transferred leases to surviving node.\n3. Validate zero dropped partitions using `ulpf-diagnostics --check-leases`.",
        "1. Run platform health check: `python scripts/run_phase14_sih_demo.py --quick`.\n2. Confirm listener port 514/TCP and 8080/TCP active and accepting records.",
        "If process fails repeatedly upon restart, rollback to previous release binary or container image.",
    ),
    (
        "runbook_02_parser_failure.md",
        "RUNBOOK-02: Parser Failure / Parsing Exception Spike",
        "Parser failure rate exceeds 2% threshold (SLO-PARSE burn).",
        "SLO-PARSE alert triggered; DLQ recording `PARSER_FAILURE` events.",
        "1. Identify source vendor emitting malformed telemetry.\n2. Query parser error log for exception name (e.g., `RegexTimeoutError`, `UnicodeDecodeError`).\n3. Extract sample payload from DLQ raw payload repository.",
        "1. If unknown vendor format, trigger source onboarding flow: `ulpf-onboard --analyze-sample`.\n2. If corrupted format, engage source administrator to remediate agent output.\n3. If candidate parser fix available, deploy to canary shadow mode first (`ParserCanaryEngine`).",
        "Run canary semantic differential test to verify zero regressions before promoting parser.",
        "Revert active parser registration to fallback generic parser or previous version.",
    ),
    (
        "runbook_03_storage_failure.md",
        "RUNBOOK-03: Storage / Evidence Volume Unavailability",
        "Underlying disk, NAS volume, or storage engine becomes read-only or unresponsive.",
        "I/O error during raw payload write; SLO-EVID failure alert.",
        "1. Check mount status and dmesg for SCSI/disk errors.\n2. Check available disk space (`df -h`).\n3. Check inode exhaustion (`df -i`).",
        "1. Immediately engage in-memory burst buffer and spool pending writes to temporary spool path.\n2. Remount or attach spare storage volume.\n3. Execute storage flush and re-verify SHA-256 digests against memory ledger.",
        "Run `ulpf_platform.diagnostics.PlatformSelfDiagnostics` to verify storage read/write integrity.",
        "If primary volume corrupted, initiate cryptographic disaster recovery from latest verified backup archive.",
    ),
    (
        "runbook_04_stream_failure.md",
        "RUNBOOK-04: Stream / Partition Rebalance Disruption",
        "Partition consumer loses lease or stream buffer drops out of sync.",
        "Lag accumulation across one or more stream partitions.",
        "1. Inspect `DistributedIngestionFabric` partition queue depth.\n2. Identify stuck partition index.\n3. Check worker lease heartbeat timestamps.",
        "1. Trigger forced lease eviction for unresponsive worker: `ulpf-stream --evict-worker`.\n2. Trigger partition rebalance across healthy active workers.\n3. Verify committed offset resumption without rewind or message skip.",
        "Monitor partition consumption rate until lag returns to 0.",
        "Restart fabric in single-partition fallback mode if network partition prevents consensus.",
    ),
    (
        "runbook_05_database_failure.md",
        "RUNBOOK-05: Metadata / State Database Unavailability",
        "State store (PostgreSQL or SQLite metadata store) becomes unavailable.",
        "Connection refused on state store socket; metadata sync failure.",
        "1. Verify database service status (`systemctl status postgresql`).\n2. Check connection pool exhaustion.\n3. Check database disk space and lock contention.",
        "1. Fail over to read-only replica or standby database instance.\n2. Route in-flight state mutations to local write-ahead log (WAL) buffer.\n3. Replay buffered WAL mutations once primary database recovers.",
        "Verify state table row counts and integrity hashes match WAL transaction ledger.",
        "Restore database state from latest continuous WAL archive or snapshot.",
    ),
    (
        "runbook_06_search_failure.md",
        "RUNBOOK-06: Search Indexer / Index Cluster Degraded",
        "Downstream search cluster (Elasticsearch/OpenSearch/ClickHouse) slows or drops indexing.",
        "Indexer backpressure signal activated; buffer queue rising.",
        "1. Check downstream cluster cluster health (`GET /_cluster/health`).\n2. Check bulk thread pool rejections.\n3. Check indexing disk watermarks (flood stage watermark).",
        "1. Enable ULPF downstream backpressure rate limiter.\n2. Spool excess normalized events to local disk buffer (`BoundedLatenessBuffer`).\n3. Expand downstream search nodes or resolve shard allocation blocks.",
        "Validate zero event drops; drain spool queue at controlled throttle rate.",
        "Divert search index output to cold archive object storage until index cluster recovers.",
    ),
    (
        "runbook_07_dlq_surge.md",
        "RUNBOOK-07: Dead-Letter Queue (DLQ) Surge",
        "DLQ volume suddenly increases beyond standard baseline (> 100 eps).",
        "SLO-DLQ warning alert; DLQ disk growth rate monitor.",
        "1. Group DLQ records by `failure_reason` and `source_id`.\n2. Identify whether surge is caused by schema validation, parser crash, or intentional security payload.\n3. Verify SHA-256 manifests on DLQ batches.",
        "1. If unmapped source, isolate source to quarantine partition.\n2. If transient mapping bug, apply patch via canary pipeline.\n3. Execute DLQ replay once patch is certified: `ulpf-dlq --replay --batch-id <ID>`.",
        "Verify replayed events successfully normalize into UCE without re-entering DLQ.",
        "Quarantined records remain sealed in DLQ storage; no records are deleted without audit sign-off.",
    ),
    (
        "runbook_08_evidence_integrity_failure.md",
        "RUNBOOK-08: Cryptographic Evidence Integrity Breach",
        "SHA-256 manifest mismatch detected during forensic verification or backup drill.",
        "CRITICAL ALERT: `CasePackageVerificationResult.is_valid == False` or manifest hash divergence.",
        "1. Quarantine affected case package or archive volume immediately.\n2. Compare computed SHA-256 vs manifest SHA-256 for each event record.\n3. Identify specific byte offsets containing alterations.\n4. Check system access logs for unauthorized file modification.",
        "1. Mark affected case package as `COMPROMISED_EVIDENCE` in audit trail.\n2. Restore authentic copy from write-once read-many (WORM) secondary archive.\n3. Notify security incident response team and generate forensic tampering report.",
        "Re-run `CasePackageManager.verify_package` on restored bundle to confirm `is_valid == True`.",
        "Retain corrupted byte image in forensic quarantine folder for hostile tampering investigation.",
    ),
    (
        "runbook_09_certificate_failure.md",
        "RUNBOOK-09: mTLS Certificate or Token Expiry",
        "Internal service-to-service communication fails due to expired certificate or bad signature.",
        "SSL handshake failure; HTTP 401/403 unauthorized on internal API routes.",
        "1. Inspect certificate expiration date (`openssl x509 -enddate -noout -in <cert>`).\n2. Inspect signing CA trust chain.\n3. Verify system clock synchronization (`chronyc tracking`).",
        "1. Rotate expired certificate with offline CA-signed bundle.\n2. Distribute updated certificate to worker nodes.\n3. Gracefully reload service daemons (`systemctl reload ulpf-*`).",
        "Test mTLS mutual handshake with `curl --cert <cert> --key <key> https://localhost:8443/health`.",
        "Fallback to pre-staged emergency certificate if CA infrastructure is temporarily unreachable.",
    ),
    (
        "runbook_10_disk_pressure.md",
        "RUNBOOK-10: Disk Pressure / High Watermark Condition",
        "Disk capacity utilization exceeds 85% warning or 95% critical watermark.",
        "Disk capacity alert; PlatformSelfDiagnostics reporting `DISK_PRESSURE`.",
        "1. Run `df -h` and `du -sh /var/log/ulpf/*` to locate high-growth directories.\n2. Check DLQ volume, debug traces, and temporary spillover queues.\n3. Verify age of retention tiers.",
        "1. Compress and archive verified cold storage bundles to secondary tape/network storage.\n2. Purge non-critical debug logs and ephemeral traces older than 7 days.\n3. Ensure raw evidence and DLQ archives remain preserved and unmodified.",
        "Confirm available disk space returns above 25% safety margin.",
        "If local disk remains full, enable storage quota throttling on non-priority sources.",
    ),
    (
        "runbook_11_configuration_corruption.md",
        "RUNBOOK-11: Configuration Corruption / Schema Incompatibility",
        "Platform fails to start due to malformed YAML/JSON configuration or incompatible schema version.",
        "Fatal error during `PlatformSelfDiagnostics.run_diagnostics` or startup configuration parse.",
        "1. Identify offending configuration file from startup traceback.\n2. Run JSON/YAML schema validation against specification schema.\n3. Run `git diff` against known-good configuration revision.",
        "1. Revert corrupted configuration to last known-good revision from git or backup: `git checkout HEAD~1 config/`.\n2. Validate configuration syntax with schema validator.\n3. Restart service with validated configuration.",
        "Run `PlatformSelfDiagnostics` to confirm all configuration assertions pass.",
        "Keep invalid configuration copy in `/var/log/ulpf/invalid_config_<ts>` for defect triage.",
    ),
    (
        "runbook_12_rollback.md",
        "RUNBOOK-12: Production Component Rollback Procedure",
        "Newly deployed release or parser causes unpredicted operational degradation.",
        "SRE / Release manager decision following failed smoke test or SLO breach.",
        "1. Determine affected component scope (whole release, single package, or single parser).\n2. Verify state store schema backwards-compatibility.\n3. Ensure queue drain or pause active ingestion to prevent state divergence.",
        "1. For parser regression: disable candidate parser in registry; promote fallback parser.\n2. For release binary: switch systemd symlink to previous verified release: `ln -sfn /opt/ulpf-prev /opt/ulpf-active`.\n3. Restart pipeline daemons and resume ingestion.",
        "Run 657-test regression suite to confirm restored baseline stability.",
        "Capture pre-rollback forensic core dump and memory snapshot before termination.",
    ),
    (
        "runbook_13_backup_restore.md",
        "RUNBOOK-13: Backup & Restore Verification Drill",
        "Routine or emergency restoration of configuration, schemas, and evidence repositories.",
        "Scheduled monthly recovery drill or disaster restoration requirement.",
        "1. Identify latest verified backup archive in backup repository.\n2. Verify SHA-256 archive manifest before unpacking.\n3. Prepare isolated clean-room staging directory for restoration test.",
        "1. Execute restore runner: `python -m ulpf_platform.backup_restore --restore <archive> --target <dir>`.\n2. Verify database records, schema registry files, and raw evidence checksums match manifest exactly.\n3. Confirm zero byte data loss.",
        "Validate restored system by executing end-to-end ingestion and normalization test.",
        "If archive manifest fails verification, reject archive and fail over to previous signed backup.",
    ),
    (
        "runbook_14_disaster_recovery.md",
        "RUNBOOK-14: Full Site Disaster Recovery (Cold Standby / Air-Gap)",
        "Primary datacenter or operations site completely unavailable.",
        "Catastrophic site outage declaration by incident commander.",
        "1. Declare disaster recovery state and activate cold-standby hardware site.\n2. Ensure network isolation and air-gap integrity at standby site.\n3. Retrieve encrypted backup media from offsite vault.",
        "1. Bootstrap base OS and Python 3.12 environment from signed offline media.\n2. Restore ULPF packages, configuration, and state store from verified backup archive.\n3. Redirect collector telemetry forwarding to standby site ingestion VIP.",
        "Execute 10-scenario SIH Judge Mode demo to verify full operational readiness.",
        "Calculate and record actual RTO (Recovery Time Objective) and RPO (Recovery Point Objective) in DR log.",
    ),
    (
        "runbook_15_airgapped_update.md",
        "RUNBOOK-15: Air-Gapped Release Update & Patch Procedure",
        "Deploying software updates or parser extensions into a strictly air-gapped sovereign environment.",
        "Scheduled security patch or version update cycle.",
        "1. Build signed offline release bundle and dependency wheels on clean packaging workstation.\n2. Generate cryptographic SHA-256 release manifest (`PHASE15_RELEASE_MANIFEST.json`).\n3. Transfer bundle to read-only optical or cryptographically approved removable media.\n4. Perform security virus/malware scan at air-gap transfer kiosk.",
        "1. Mount media on target air-gapped host.\n2. Verify release manifest SHA-256 signature against offline public key.\n3. Install wheel packages: `pip install --no-index --find-links=/media/wheels <package>`.\n4. Run `PlatformSelfDiagnostics` and `scripts/run_phase15_continuous_assurance.py`.",
        "Confirm zero network socket connections attempted during post-update execution.",
        "If verification fails, unmount media and restore previous verified wheel installation.",
    ),
]

for filename, title, cond, trig, diag, mit, ver, rb in RUNBOOKS:
    content = f"""# {title}

## 1. Trigger & Condition
**Condition:** {cond}  
**Trigger:** {trig}  

---

## 2. Diagnosis & Root Cause Identification
{diag}

---

## 3. Mitigation & Resolution Steps
{mit}

---

## 4. Verification & Health Restoration
{ver}

---

## 5. Rollback & Post-Incident Safeguards
{rb}

---
*ULPF SRE Runbook — Standard Operating Procedure (Phase 15)*
"""
    (RUNBOOKS_DIR / filename).write_text(content, encoding="utf-8")
    print(f"Generated {filename}")

print(f"\nAll {len(RUNBOOKS)} operational runbooks generated in docs/runbooks/")
