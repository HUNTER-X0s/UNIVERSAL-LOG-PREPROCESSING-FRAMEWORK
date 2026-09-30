"""
SQLite-backed persistent ledger for the ULPF permissioned blockchain.

The ledger provides:
- Append-only block storage (blocks are never updated or deleted)
- Atomic writes (no partial block states can be persisted)
- Integrity checks on load (hash recomputed and verified)
- Air-gap compatible (zero external dependencies — pure stdlib SQLite)
- Thread-safe reads and writes

This is the durable backbone of the ULPF blockchain. In a production
deployment, this would be backed by a distributed append-only store
(IPFS, Hyperledger Fabric state DB, or object storage with S3 Object Lock).
For NTRO hackathon demo, SQLite provides a fully functional equivalent.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from ulpf_blockchain.block import Block, create_genesis_block


class LedgerError(RuntimeError):
    """Base exception for ledger persistence failures."""


class LedgerIntegrityError(LedgerError):
    """Raised when a loaded block fails hash verification."""


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS blocks (
    block_index   INTEGER PRIMARY KEY,
    block_hash    TEXT    NOT NULL UNIQUE,
    previous_hash TEXT    NOT NULL,
    timestamp     REAL    NOT NULL,
    merkle_root   TEXT    NOT NULL,
    nonce         INTEGER NOT NULL DEFAULT 0,
    tx_count      INTEGER NOT NULL,
    block_json    TEXT    NOT NULL,   -- full serialized block
    created_at    REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(block_hash);
CREATE INDEX IF NOT EXISTS idx_blocks_ts   ON blocks(timestamp);
"""


class BlockchainLedger:
    """
    Append-only SQLite ledger for ULPF blockchain blocks.

    Thread-safe via a single connection + lock strategy.
    Initializes with the genesis block if the database is new.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        """
        Initialize the ledger.

        Args:
            db_path: Path to the SQLite file. None → in-memory (tests/demo).
        """
        self._db_path = str(db_path) if db_path else ":memory:"
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._ensure_initialized()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_block(self, block: Block) -> None:
        """
        Append a block to the ledger.

        Args:
            block: The finalized, signed Block to persist

        Raises:
            LedgerError: If the block index already exists (immutability)
        """
        block_json = json.dumps(block.to_dict(), separators=(",", ":"))
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    INSERT INTO blocks
                        (block_index, block_hash, previous_hash, timestamp,
                         merkle_root, nonce, tx_count, block_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        block.index,
                        block.hash,
                        block.previous_hash,
                        block.timestamp,
                        block.merkle_root,
                        block.nonce,
                        len(block.transactions),
                        block_json,
                        time.time(),
                    ),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                raise LedgerError(
                    f"Block at index {block.index} already exists in the ledger. "
                    "The blockchain is append-only."
                ) from exc

    def load_chain(self) -> list[Block]:
        """
        Load the full blockchain from the ledger.

        Returns:
            Ordered list of Block objects (index 0 = genesis)

        Raises:
            LedgerIntegrityError: If any block's stored hash doesn't match recomputed hash
        """
        with self._lock:
            conn = self._get_connection()
            rows = conn.execute(
                "SELECT block_json FROM blocks ORDER BY block_index ASC"
            ).fetchall()

        blocks: list[Block] = []
        for (block_json,) in rows:
            data = json.loads(block_json)
            block = Block.from_dict(data)
            # Recompute and verify hash on load
            recomputed = block.compute_hash()
            if recomputed != block.hash:
                raise LedgerIntegrityError(
                    f"Block {block.index} hash mismatch: "
                    f"stored={block.hash[:16]}... computed={recomputed[:16]}..."
                )
            blocks.append(block)

        return blocks

    def get_block_by_index(self, index: int) -> Block | None:
        """Retrieve a single block by its index."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT block_json FROM blocks WHERE block_index = ?", (index,)
            ).fetchone()
        if row is None:
            return None
        return Block.from_dict(json.loads(row[0]))

    def get_latest_block(self) -> Block | None:
        """Retrieve the most recent block."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT block_json FROM blocks ORDER BY block_index DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return Block.from_dict(json.loads(row[0]))

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics from the ledger."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT COUNT(*), SUM(tx_count), MIN(timestamp), MAX(timestamp) FROM blocks"
            ).fetchone()
        count, total_tx, min_ts, max_ts = row
        return {
            "block_count": count or 0,
            "total_transactions": total_tx or 0,
            "oldest_block_ts": min_ts,
            "newest_block_ts": max_ts,
        }

    def chain_height(self) -> int:
        """Return the current chain height (number of blocks)."""
        with self._lock:
            conn = self._get_connection()
            row = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()
        return row[0] if row else 0

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise LedgerError("Ledger connection is not initialized.")
        return self._conn

    def _ensure_initialized(self) -> None:
        """Create schema and seed genesis block if database is new."""
        with self._lock:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")  # Write-ahead log for concurrency
            conn.execute("PRAGMA synchronous=FULL")  # Durable writes
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
            self._conn = conn

        # Seed genesis block if chain is empty
        if self.chain_height() == 0:
            genesis = create_genesis_block()
            self.save_block(genesis)
