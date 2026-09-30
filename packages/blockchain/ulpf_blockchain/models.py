"""Pydantic models for the ULPF blockchain API and service layer."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TransactionRecord(BaseModel):
    """A single log event transaction anchored in a block."""

    event_id: str = Field(description="UUID of the original log event")
    sha256: str = Field(description="SHA-256 hash of the raw log payload")
    source: str = Field(description="Log source type (e.g., FIREWALL, IDS)")
    anchored_at: str = Field(description="ISO-8601 timestamp when anchored")
    description: str = Field(default="", description="Optional human-readable description")


class BlockSummary(BaseModel):
    """Lightweight block header for the Block Explorer list view."""

    index: int = Field(description="Block height / position in chain")
    timestamp: float = Field(description="UNIX timestamp of block creation")
    timestamp_iso: str = Field(description="ISO-8601 UTC timestamp")
    transaction_count: int = Field(description="Number of log events in this block")
    merkle_root: str = Field(description="Merkle root of all event hashes in block")
    previous_hash: str = Field(description="SHA-256 hash of the previous block")
    hash: str = Field(description="SHA-256 hash of this block")
    authority_signature: str = Field(description="HMAC-SHA256 PoA signature")
    block_version: str = Field(default="ULPF-BC-v1")
    is_genesis: bool = Field(default=False)


class BlockDetail(BlockSummary):
    """Full block data including all transactions."""

    transactions: list[TransactionRecord] = Field(default_factory=list)
    framework: str = Field(default="Universal Log Pre-processing Framework")


class ChainStats(BaseModel):
    """Blockchain statistics for the dashboard."""

    chain_height: int = Field(description="Total number of blocks in chain")
    total_events_anchored: int = Field(description="Total log events anchored")
    chain_integrity: str = Field(description="VALID | TAMPERED | UNKNOWN")
    genesis_hash: str = Field(description="Hash of the genesis block")
    latest_block_hash: str = Field(description="Hash of the most recent block")
    latest_block_time: str = Field(description="ISO-8601 time of latest block")
    authority_node_id: str = Field(description="ID of the signing authority node")
    pending_transactions: int = Field(description="Events queued but not yet in a block")
    consensus_algorithm: str = Field(default="Proof of Authority (PoA)")
    hash_algorithm: str = Field(default="SHA-256")
    merkle_algorithm: str = Field(default="Binary Merkle Tree (SHA-256)")


class AnchorReceipt(BaseModel):
    """Receipt returned when a log event is successfully anchored."""

    event_id: str = Field(description="The anchored event's UUID")
    sha256: str = Field(description="SHA-256 hash that was anchored")
    status: str = Field(description="QUEUED | ANCHORED | REJECTED")
    block_index: int | None = Field(default=None, description="Block index if already anchored")
    merkle_root: str | None = Field(default=None, description="Merkle root of the block")
    rejection_reason: str | None = Field(default=None, description="Reason if rejected by contract")
    anchored_at: str = Field(description="ISO-8601 timestamp of anchoring")


class VerificationResult(BaseModel):
    """Result of verifying a log event's inclusion in the blockchain."""

    event_id: str = Field(description="The event being verified")
    verified: bool = Field(description="True if the event is proven in the chain")
    block_index: int | None = Field(default=None, description="Block containing this event")
    block_hash: str | None = Field(default=None, description="Hash of the block")
    merkle_root: str | None = Field(default=None, description="Merkle root of the block")
    merkle_proof: list[dict[str, str]] = Field(
        default_factory=list, description="Merkle inclusion proof steps"
    )
    sha256_match: bool | None = Field(default=None, description="Hash matches stored value")
    signature_valid: bool | None = Field(default=None, description="PoA signature valid")
    verification_timestamp: str = Field(description="When this verification was performed")
    error: str | None = Field(default=None, description="Error message if verification failed")


class AnchorRequest(BaseModel):
    """Request body for manually anchoring a log event."""

    event_id: str = Field(description="UUID of the log event to anchor")
    sha256: str = Field(description="SHA-256 hash of the raw log payload")
    source: str = Field(description="Source type (e.g., FIREWALL, IDS, WINDOWS_EVENT)")
    description: str = Field(default="", description="Optional description")
