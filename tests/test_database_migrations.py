"""Phase 7 Test: Database Migration Engine.

Verifies:
- Rule B1: Versioned schema migrations apply in order
- Rule B1: Schema version tracked in schema_migrations table
- Rule B1: Rollback capability for supported migrations
- Rule B2: Write-once trigger rejects UCE UPDATE
"""

import pytest
from ulpf_storage.database.relational import DatabaseError, SQLiteDatabase
from ulpf_storage.database.schema import CURRENT_SCHEMA_VERSION


def test_migration_applies_to_current_version() -> None:
    db = SQLiteDatabase(":memory:")
    assert db.schema_version() == CURRENT_SCHEMA_VERSION


def test_migration_idempotent_on_fresh_db() -> None:
    """Running migrate() twice does not error out."""
    db = SQLiteDatabase(":memory:")
    version_after_init = db.schema_version()
    version_after_second_run = db.migrate()
    assert version_after_init == version_after_second_run


def test_all_expected_tables_exist() -> None:
    db = SQLiteDatabase(":memory:")
    expected_tables = [
        "schema_migrations",
        "raw_references",
        "uce_records",
        "semantic_events",
        "outbox_records",
        "audit_events",
        "replay_jobs",
        "idempotency_keys",
    ]
    for table in expected_tables:
        rows = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",  # noqa: S608
            (table,),
        )
        assert rows, f"Expected table '{table}' not found after migration"


def test_uce_write_once_trigger_fires() -> None:
    """The UCE update trigger must raise an error on UPDATE."""
    db = SQLiteDatabase(":memory:")
    # Insert a UCE record directly
    db.execute(
        """INSERT INTO uce_records
           (uce_event_id, raw_event_id, raw_sha256, payload_json,
            schema_version, source_id, captured_at, stored_at, metadata_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ("uce-1", "raw-1", "sha" * 22, '{}', "1.0.0", "src", "2026-01-01Z", "2026-01-01Z", "{}"),
    )
    db._conn().commit()

    with pytest.raises((DatabaseError, Exception)):
        db.execute(
            "UPDATE uce_records SET source_id = 'tampered' WHERE uce_event_id = ?",
            ("uce-1",),
        )
        db._conn().commit()


def test_schema_migration_table_tracks_versions() -> None:
    db = SQLiteDatabase(":memory:")
    rows = db.execute("SELECT * FROM schema_migrations ORDER BY version")
    versions = [r["version"] for r in rows]
    # All versions 1 through CURRENT_SCHEMA_VERSION must be present
    assert versions == list(range(1, CURRENT_SCHEMA_VERSION + 1))


def test_rollback_removes_tables() -> None:
    db = SQLiteDatabase(":memory:")
    assert db.schema_version() == CURRENT_SCHEMA_VERSION

    # Roll back to version 2 (raw_references only)
    db.rollback_migration(target_version=2)
    assert db.schema_version() == 2

    # After rollback, uce_records should not exist
    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='uce_records'"
    )
    assert not rows, "uce_records table should be gone after rollback to v2"


def test_partial_migration_target() -> None:
    """Migrating to a partial version stops at that version."""
    db = SQLiteDatabase.__new__(SQLiteDatabase)
    db._db_path = ":memory:"
    import threading
    db._local = threading.local()
    db._lock = threading.Lock()
    # Migrate only to v3
    db.migrate(target_version=3)
    assert db.schema_version() == 3
