"""ULPF Phase 7 — Relational Database Layer.

Provides schema management, migration engine, and production
relational adapter supporting SQLite (air-gap) and PostgreSQL-compatible
syntax with parameterized queries.
"""

from ulpf_storage.database.relational import RelationalDatabase, SQLiteDatabase
from ulpf_storage.database.schema import CURRENT_SCHEMA_VERSION, SCHEMA_MIGRATIONS

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "SCHEMA_MIGRATIONS",
    "RelationalDatabase",
    "SQLiteDatabase",
]
