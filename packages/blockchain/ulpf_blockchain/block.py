"""Block data structure for the ULPF permissioned blockchain."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any


@dataclass
class Block:
    """
    A single block in the ULPF blockchain.

    Each block contains:
    - A batch of log event SHA-256 hashes (transactions)
    - The Merkle root of those transactions
    - A SHA-256 link to the previous block (chain integrity)
    - An authority signature (Proof of Authority consensus)
    - A nonce for lightweight proof-of-work (demo-grade difficulty)
    """

    index: int
    timestamp: float
    transactions: list[dict[str, str]]  # [{event_id, sha256, source, anchored_at}]
    merkle_root: str
    previous_hash: str
    nonce: int = 0
    hash: str = field(default="", init=False)
    authority_signature: str = field(default="", init=False)

    # Block metadata
    block_version: str = "ULPF-BC-v1"
    framework: str = "Universal Log Pre-processing Framework"

    def __post_init__(self) -> None:
        """Compute block hash immediately after construction."""
        if not self.hash:
            self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this block's canonical representation."""
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "block_version": self.block_version,
            "transaction_count": len(self.transactions),
        }
        canonical = json.dumps(block_data, sort_keys=True, separators=(",", ":"))
        return sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize block to a JSON-compatible dictionary."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "timestamp_iso": _ts_to_iso(self.timestamp),
            "transactions": self.transactions,
            "transaction_count": len(self.transactions),
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
            "authority_signature": self.authority_signature,
            "block_version": self.block_version,
            "framework": self.framework,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Block":
        """Reconstruct a Block from a persisted dictionary (ledger restore)."""
        b = cls(
            index=data["index"],
            timestamp=data["timestamp"],
            transactions=data["transactions"],
            merkle_root=data["merkle_root"],
            previous_hash=data["previous_hash"],
            nonce=data.get("nonce", 0),
            block_version=data.get("block_version", "ULPF-BC-v1"),
            framework=data.get("framework", "Universal Log Pre-processing Framework"),
        )
        b.hash = data.get("hash", b.compute_hash())
        b.authority_signature = data.get("authority_signature", "")
        return b

    @property
    def is_genesis(self) -> bool:
        """Return True if this is the genesis block (index == 0)."""
        return self.index == 0


def _ts_to_iso(ts: float) -> str:
    """Convert a UNIX timestamp to an ISO-8601 UTC string."""
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()


def create_genesis_block() -> Block:
    """
    Create the immutable ULPF genesis block.

    The genesis block is hardcoded and deterministic — it anchors the entire
    chain to a known, auditable starting state. This is the chain of custody
    origin for all NTRO log evidence.
    """
    genesis_transactions = [
        {
            "event_id": "00000000-0000-0000-0000-000000000001",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "source": "ULPF_GENESIS",
            "anchored_at": "2026-01-01T00:00:00+00:00",
            "description": "ULPF Permissioned Blockchain Genesis — NTRO SIH 2026",
        }
    ]
    merkle_root = sha256(b"ULPF-GENESIS-BLOCK-NTRO-SIH-2026").hexdigest()

    genesis = Block(
        index=0,
        timestamp=1751328000.0,  # 2026-01-01 00:00:00 UTC (fixed for determinism)
        transactions=genesis_transactions,
        merkle_root=merkle_root,
        previous_hash="0" * 64,  # No predecessor — genesis
        nonce=0,
    )
    genesis.authority_signature = sha256(
        f"GENESIS-AUTHORITY-{genesis.hash}".encode()
    ).hexdigest()
    return genesis
