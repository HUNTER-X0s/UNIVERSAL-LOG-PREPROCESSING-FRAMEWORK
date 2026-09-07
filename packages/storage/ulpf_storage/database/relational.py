"""ULPF Phase 7 — Relational Database Adapter.

Provides a production relational database adapter supporting SQLite (local
air-gap) with parameterized queries, connection pooling, and transaction
rollback semantics.

Enforces:
- Rule B1: Versioned schema migration with rollback
- Rule B3: Parameterized queries only (no string interpolation)
- Rule B4: Connection pool with thread-local access
- Rule B5: Transaction context manager with automatic rollback on error
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from ulpf_storage.database.schema import CURRENT_SCHEMA_VERSION, SCHEMA_MIGRATIONS


class DatabaseError(Exception):
    """Base error for database layer failures."""


class MigrationError(DatabaseError):
    """Schema migration failure."""


class RelationalDatabase:
    """Abstract relational database interface."""

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        raise NotImplementedError

    def execute_many(self, sql: str, param_list: list[tuple[Any, ...]]) -> None:
        raise NotImplementedError

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        raise NotImplementedError
        yield  # pragma: no cover

    def migrate(self, target_version: int | None = None) -> int:
        raise NotImplementedError

    def schema_version(self) -> int:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SQLiteDatabase(RelationalDatabase):
    """Thread-safe SQLite production adapter.

    Uses thread-local connections so each thread gets its own SQLite
    connection without cross-thread sharing. Applies schema migrations
    on initialization.
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        # Shared path for thread-local connections
        self._local = threading.local()
        self._lock = threading.Lock()
        # Run migrations from the primary thread's connection
        self.migrate()

    def _conn(self) -> sqlite3.Connection:
        """Return (or create) a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return cast(sqlite3.Connection, self._local.conn)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """Execute a parameterized SQL statement and return all rows as dicts."""
        conn = self._conn()
        try:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQL execution failed: {exc}") from exc

    def execute_many(self, sql: str, param_list: list[tuple[Any, ...]]) -> None:
        """Execute a parameterized SQL statement against multiple parameter sets."""
        conn = self._conn()
        try:
            conn.executemany(sql, param_list)
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise DatabaseError(f"Batch execution failed: {exc}") from exc

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Context manager providing atomic transaction with rollback on exception."""
        conn = self._conn()
        try:
            yield
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def schema_version(self) -> int:
        """Return the currently applied schema version."""
        try:
            rows = self.execute(
                "SELECT MAX(version) AS v FROM schema_migrations"
            )
            if rows and rows[0]["v"] is not None:
                return int(rows[0]["v"])
            return 0
        except DatabaseError:
            return 0

    def migrate(self, target_version: int | None = None) -> int:
        """Apply all pending migrations up to target_version (default: latest).

        Returns the new schema version.
        Raises MigrationError if a migration fails.
        """
        target = target_version if target_version is not None else CURRENT_SCHEMA_VERSION

        # Ensure the migration tracking table exists first (migration version=1)
        first = SCHEMA_MIGRATIONS[0]
        conn = self._conn()
        try:
            for stmt in first.up_sql:
                conn.execute(stmt)
            conn.commit()
        except sqlite3.Error as exc:
            raise MigrationError(f"Bootstrap migration failed: {exc}") from exc

        current = self.schema_version()
        pending = [m for m in SCHEMA_MIGRATIONS if current < m.version <= target]

        for migration in pending:
            try:
                with self.transaction():
                    for stmt in migration.up_sql:
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT OR REPLACE INTO schema_migrations "
                        "(version, description, applied_at) VALUES (?, ?, ?)",
                        (
                            migration.version,
                            migration.description,
                            datetime.now(UTC).isoformat(),
                        ),
                    )
            except Exception as exc:
                raise MigrationError(
                    f"Migration v{migration.version} '{migration.description}' failed: {exc}"
                ) from exc

        return self.schema_version()

    def rollback_migration(self, target_version: int) -> int:
        """Roll back migrations down to target_version.

        Returns the new schema version after rollback.
        """
        current = self.schema_version()
        if target_version >= current:
            return current

        # Identify migrations to roll back in reverse order
        to_rollback = [
            m
            for m in reversed(SCHEMA_MIGRATIONS)
            if target_version < m.version <= current
        ]

        conn = self._conn()
        for migration in to_rollback:
            if not migration.down_sql:
                raise MigrationError(
                    f"Migration v{migration.version} has no rollback SQL."
                )
            try:
                with self.transaction():
                    for stmt in migration.down_sql:
                        conn.execute(stmt)
                    conn.execute(
                        "DELETE FROM schema_migrations WHERE version = ?",
                        (migration.version,),
                    )
            except Exception as exc:
                raise MigrationError(
                    f"Rollback of v{migration.version} failed: {exc}"
                ) from exc

        return self.schema_version()

    def close(self) -> None:
        """Close the thread-local connection, if open."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _json_loads(s: str) -> Any:
    return json.loads(s)
