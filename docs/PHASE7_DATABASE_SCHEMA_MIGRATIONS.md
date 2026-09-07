# Phase 7 Database Schema & Migration Specification

## Versioned Migrations
- Migration runner tracks applied versions in `schema_migrations` table.
- Supports deterministic upgrade and transactional rollback.
- All SQL statements parameterized against injection.
