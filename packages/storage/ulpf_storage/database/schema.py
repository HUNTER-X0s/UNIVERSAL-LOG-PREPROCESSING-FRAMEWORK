"""ULPF Phase 7 — Database Schema Definition and Migration Engine.

Enforces:
- Rule B1: Strict versioned schema migrations with rollback capability
- Rule B2: Write-once immutability constraints on canonical UCE records
- Rule B3: Normalized relational tables for events, UCE, semantic, mappings,
           outbox, audit, replay jobs
- Air-gap compliance: pure SQLite stdlib — no external ORM or migration tool
"""

from __future__ import annotations

from dataclasses import dataclass

CURRENT_SCHEMA_VERSION = 8


@dataclass(frozen=True)
class Migration:
    """A single schema migration step with forward and optional rollback SQL."""

    version: int
    description: str
    up_sql: list[str]
    down_sql: list[str]


# ---------------------------------------------------------------------------
# Schema DDL — all migrations ordered and numbered
# ---------------------------------------------------------------------------

SCHEMA_MIGRATIONS: list[Migration] = [
    Migration(
        version=1,
        description="Create schema_migrations tracking table",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                version        INTEGER PRIMARY KEY,
                description    TEXT    NOT NULL,
                applied_at     TEXT    NOT NULL
            )"""
        ],
        down_sql=[],  # Never roll back the migration table itself
    ),
    Migration(
        version=2,
        description="Create raw_references table",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS raw_references (
                raw_event_id   TEXT    PRIMARY KEY,
                sha256         TEXT    NOT NULL,
                captured_at    TEXT    NOT NULL,
                source_id      TEXT    NOT NULL,
                format         TEXT    NOT NULL,
                byte_length    INTEGER NOT NULL,
                storage_path   TEXT    NOT NULL,
                metadata_json  TEXT    NOT NULL DEFAULT '{}'
            )"""
        ],
        down_sql=["DROP TABLE IF EXISTS raw_references"],
    ),
    Migration(
        version=3,
        description="Create uce_records table with write-once enforcement trigger",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS uce_records (
                uce_event_id   TEXT    PRIMARY KEY,
                raw_event_id   TEXT    NOT NULL,
                raw_sha256     TEXT    NOT NULL,
                payload_json   TEXT    NOT NULL,
                schema_version TEXT    NOT NULL,
                source_id      TEXT    NOT NULL,
                captured_at    TEXT    NOT NULL,
                stored_at      TEXT    NOT NULL,
                metadata_json  TEXT    NOT NULL DEFAULT '{}'
            )""",
            # Write-once trigger: reject any UPDATE attempt
            """CREATE TRIGGER IF NOT EXISTS trg_uce_no_update
               BEFORE UPDATE ON uce_records
               BEGIN
                   SELECT RAISE(ABORT, 'UCE records are immutable: updates forbidden');
               END""",
        ],
        down_sql=[
            "DROP TRIGGER IF EXISTS trg_uce_no_update",
            "DROP TABLE IF EXISTS uce_records",
        ],
    ),
    Migration(
        version=4,
        description="Create semantic_events table",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS semantic_events (
                semantic_event_id TEXT    PRIMARY KEY,
                uce_event_id      TEXT    NOT NULL,
                raw_sha256        TEXT    NOT NULL,
                mapping_version   TEXT,
                semantic_version  TEXT    NOT NULL,
                payload_json      TEXT    NOT NULL,
                fingerprint       TEXT    NOT NULL,
                risk_level        TEXT    NOT NULL,
                risk_score        REAL    NOT NULL,
                entities_json     TEXT    NOT NULL DEFAULT '[]',
                indicators_json   TEXT    NOT NULL DEFAULT '[]',
                classification_json TEXT  NOT NULL DEFAULT '{}',
                stored_at         TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_semantic_uce ON semantic_events(uce_event_id)",
            "CREATE INDEX IF NOT EXISTS idx_semantic_risk ON semantic_events(risk_level)",
            "CREATE INDEX IF NOT EXISTS idx_semantic_fp ON semantic_events(fingerprint)",
        ],
        down_sql=[
            "DROP INDEX IF EXISTS idx_semantic_fp",
            "DROP INDEX IF EXISTS idx_semantic_risk",
            "DROP INDEX IF EXISTS idx_semantic_uce",
            "DROP TABLE IF EXISTS semantic_events",
        ],
    ),
    Migration(
        version=5,
        description="Create outbox_records table",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS outbox_records (
                intent_id       TEXT    PRIMARY KEY,
                event_id        TEXT    NOT NULL,
                sink_name       TEXT    NOT NULL,
                payload_type    TEXT    NOT NULL,
                payload_json    TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                attempt_count   INTEGER NOT NULL DEFAULT 0,
                max_attempts    INTEGER NOT NULL DEFAULT 3,
                status          TEXT    NOT NULL DEFAULT 'PENDING',
                last_attempt_at TEXT,
                last_error      TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox_records(status)",
        ],
        down_sql=[
            "DROP INDEX IF EXISTS idx_outbox_status",
            "DROP TABLE IF EXISTS outbox_records",
        ],
    ),
    Migration(
        version=6,
        description="Create audit_events table",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS audit_events (
                event_id        TEXT    PRIMARY KEY,
                actor           TEXT    NOT NULL,
                auth_method     TEXT    NOT NULL,
                permission      TEXT    NOT NULL,
                target          TEXT,
                action          TEXT    NOT NULL,
                result          TEXT    NOT NULL,
                reason          TEXT,
                correlation_id  TEXT,
                occurred_at     TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor)",
        ],
        down_sql=[
            "DROP INDEX IF EXISTS idx_audit_actor",
            "DROP TABLE IF EXISTS audit_events",
        ],
    ),
    Migration(
        version=7,
        description="Create replay_jobs and idempotency_keys tables",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS replay_jobs (
                job_id          TEXT    PRIMARY KEY,
                source_filter   TEXT,
                from_ts         TEXT,
                to_ts           TEXT,
                requested_by    TEXT    NOT NULL,
                requested_at    TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'QUEUED',
                completed_at    TEXT,
                events_replayed INTEGER NOT NULL DEFAULT 0,
                error           TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS idempotency_keys (
                fingerprint     TEXT    PRIMARY KEY,
                event_id        TEXT    NOT NULL,
                first_seen_at   TEXT    NOT NULL
            )""",
        ],
        down_sql=[
            "DROP TABLE IF EXISTS idempotency_keys",
            "DROP TABLE IF EXISTS replay_jobs",
        ],
    ),
    Migration(
        version=8,
        description="Create intelligence tables: detections, correlations, anomalies, cases, rules",
        up_sql=[
            """CREATE TABLE IF NOT EXISTS intelligence_detections (
                detection_id    TEXT    PRIMARY KEY,
                tenant_id       TEXT    NOT NULL,
                rule_id         TEXT    NOT NULL,
                rule_version    TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                title           TEXT    NOT NULL,
                description     TEXT    NOT NULL,
                status          TEXT    NOT NULL,
                entity_ids      TEXT    NOT NULL,
                evidence        TEXT    NOT NULL,
                provenance      TEXT    NOT NULL,
                mitre_tactics   TEXT    NOT NULL,
                mitre_techniques TEXT   NOT NULL,
                detected_at     TEXT    NOT NULL,
                indexed_at      TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_intel_det_tenant ON intelligence_detections(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_intel_det_rule ON intelligence_detections(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_intel_det_severity ON intelligence_detections(severity)",
            "CREATE INDEX IF NOT EXISTS idx_intel_det_time ON intelligence_detections(detected_at)",
            """CREATE TABLE IF NOT EXISTS intelligence_correlations (
                group_id        TEXT    PRIMARY KEY,
                tenant_id       TEXT    NOT NULL,
                title           TEXT    NOT NULL,
                correlation_type TEXT   NOT NULL,
                detection_ids   TEXT    NOT NULL,
                primary_entity_id TEXT,
                aggregated_risk REAL    NOT NULL,
                status          TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_intel_corr_tenant ON intelligence_correlations(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_intel_corr_entity ON intelligence_correlations(primary_entity_id)",
            """CREATE TABLE IF NOT EXISTS intelligence_anomalies (
                anomaly_id      TEXT    PRIMARY KEY,
                tenant_id       TEXT    NOT NULL,
                entity_id       TEXT    NOT NULL,
                metric_name     TEXT    NOT NULL,
                observed_value  REAL    NOT NULL,
                baseline_mean   REAL    NOT NULL,
                baseline_std    REAL    NOT NULL,
                z_score         REAL    NOT NULL,
                severity        TEXT    NOT NULL,
                detected_at     TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_intel_anom_tenant ON intelligence_anomalies(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_intel_anom_entity ON intelligence_anomalies(entity_id)",
            """CREATE TABLE IF NOT EXISTS intelligence_cases (
                case_id         TEXT    PRIMARY KEY,
                tenant_id       TEXT    NOT NULL,
                title           TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                status          TEXT    NOT NULL,
                assignee        TEXT,
                detection_ids   TEXT    NOT NULL,
                entity_ids      TEXT    NOT NULL,
                timeline        TEXT    NOT NULL,
                notes           TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_intel_case_tenant ON intelligence_cases(tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_intel_case_status ON intelligence_cases(status)",
            """CREATE TABLE IF NOT EXISTS intelligence_rules (
                rule_id         TEXT    PRIMARY KEY,
                rule_version    TEXT    NOT NULL,
                name            TEXT    NOT NULL,
                description     TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                state           TEXT    NOT NULL,
                rule_json       TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_intel_rules_state ON intelligence_rules(state)",
        ],
        down_sql=[
            "DROP TABLE IF EXISTS intelligence_rules",
            "DROP TABLE IF EXISTS intelligence_cases",
            "DROP TABLE IF EXISTS intelligence_anomalies",
            "DROP TABLE IF EXISTS intelligence_correlations",
            "DROP TABLE IF EXISTS intelligence_detections",
        ],
    ),
]
