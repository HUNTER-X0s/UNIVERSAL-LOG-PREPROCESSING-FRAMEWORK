"""SQLite Relational Schemas and Migrations for ULPF Phase 9."""

from __future__ import annotations

from ulpf_storage.database.relational import SQLiteDatabase

PHASE9_DDL: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS advanced_ti_indicators (
        indicator_id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        normalized_value TEXT NOT NULL,
        source TEXT NOT NULL,
        source_version TEXT NOT NULL,
        confidence_json TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        valid_from TEXT,
        valid_until TEXT,
        status TEXT NOT NULL,
        lifecycle_state TEXT NOT NULL,
        provenance TEXT NOT NULL,
        integrity_hash TEXT NOT NULL,
        tenant_id TEXT,
        created_at TEXT NOT NULL,
        tags_json TEXT,
        description TEXT
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_adv_ti_lookup 
    ON advanced_ti_indicators (type, normalized_value, tenant_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS advanced_alerts (
        alert_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        tenant_id TEXT,
        primary_entity_id TEXT,
        entity_ids_json TEXT,
        detection_ids_json TEXT,
        anomaly_ids_json TEXT,
        ti_match_ids_json TEXT,
        risk_score REAL NOT NULL,
        fingerprint TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        assignee TEXT,
        triage_reason TEXT,
        contributing_factors_json TEXT
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_adv_alerts_fingerprint
    ON advanced_alerts (fingerprint, tenant_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS advanced_campaigns (
        campaign_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        name TEXT NOT NULL,
        stage TEXT NOT NULL,
        confidence REAL NOT NULL,
        entity_ids_json TEXT,
        indicator_ids_json TEXT,
        detection_ids_json TEXT,
        alert_ids_json TEXT,
        attack_sequences_json TEXT,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        summary TEXT,
        supporting_evidence_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS advanced_incidents (
        incident_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        priority TEXT NOT NULL,
        tenant_id TEXT,
        case_id TEXT NOT NULL,
        status TEXT NOT NULL,
        assignee TEXT,
        team TEXT,
        alert_ids_json TEXT,
        tasks_json TEXT,
        actions_json TEXT,
        sla_deadline TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS advanced_evidence_packages (
        package_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        tenant_id TEXT,
        manifest_json TEXT NOT NULL,
        version_pins_json TEXT NOT NULL,
        exported_at TEXT NOT NULL
    );
    """,
]


def apply_phase9_migrations(db: SQLiteDatabase) -> None:
    """Execute Phase 9 table and index migrations safely."""
    for stmt in PHASE9_DDL:
        db.execute(stmt)
