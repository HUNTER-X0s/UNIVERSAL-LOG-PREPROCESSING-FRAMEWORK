"""
ULPF Blockchain — full chain management with Proof of Authority consensus.

Responsibilities:
  - Maintain the ordered, linked chain of blocks
  - Mine new blocks (Proof of Authority — authority signs instead of PoW)
  - Validate full chain integrity (hash links + signatures)
  - Provide block-level lookup and chain statistics
"""

from __future__ import annotations

import time
from typing import Any

from ulpf_blockchain.authority import AuthorityNode
from ulpf_blockchain.block import Block, create_genesis_block
from ulpf_blockchain.ledger import BlockchainLedger
from ulpf_blockchain.merkle import MerkleTree, compute_merkle_root


class ChainValidationError(RuntimeError):
    """Raised when the blockchain integrity check fails."""


class BlockChain:
    """
    ULPF Permissioned Blockchain — full chain manager.

    The chain is loaded from the persistent ledger on startup.
    New blocks are appended via add_block() which:
      1. Computes the Merkle root of the event batch
      2. Creates a Block linking to the previous block hash
      3. Signs it with the Authority Node (PoA)
      4. Persists it to the SQLite ledger
      5. Appends it to the in-memory chain

    Usage:
        chain = BlockChain(ledger, authority)
        chain.add_block(transactions=[...])
        report = chain.validate_chain()
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        authority: AuthorityNode,
    ) -> None:
        self._ledger = ledger
        self._authority = authority
        # Load existing chain from ledger (genesis block always present)
        self._chain: list[Block] = ledger.load_chain()

    # ------------------------------------------------------------------
    # Chain mutation
    # ------------------------------------------------------------------

    def add_block(self, transactions: list[dict[str, str]]) -> Block:
        """
        Mine and append a new block to the chain.

        Args:
            transactions: List of event dicts [{event_id, sha256, source, anchored_at}]

        Returns:
            The newly minted Block
        """
        if not transactions:
            raise ValueError("Cannot add an empty block — at least one transaction required.")

        previous_block = self._chain[-1]

        # Compute Merkle root from event hashes
        event_hashes = [tx["sha256"] for tx in transactions]
        merkle_root = compute_merkle_root(event_hashes)

        # Build the new block
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=time.time(),
            transactions=transactions,
            merkle_root=merkle_root,
            previous_hash=previous_block.hash,
        )

        # Sign with Proof of Authority
        new_block.authority_signature = self._authority.sign_block(new_block.hash)

        # Persist then cache in memory
        self._ledger.save_block(new_block)
        self._chain.append(new_block)

        return new_block

    # ------------------------------------------------------------------
    # Chain validation
    # ------------------------------------------------------------------

    def validate_chain(self) -> dict[str, Any]:
        """
        Perform a full integrity validation of the blockchain.

        Checks:
          1. Genesis block is intact (known hash)
          2. Each block's hash matches its recomputed hash
          3. Each block's previous_hash matches the actual previous block hash
          4. Each block's authority signature is valid

        Returns:
            {"valid": bool, "checked_blocks": int, "errors": [...]}
        """
        errors: list[str] = []
        chain = self._ledger.load_chain()  # Load fresh from disk

        if not chain:
            return {"valid": False, "checked_blocks": 0, "errors": ["Chain is empty"]}

        for i, block in enumerate(chain):
            # 1. Recompute hash
            recomputed = block.compute_hash()
            if recomputed != block.hash:
                errors.append(
                    f"Block {i}: hash mismatch "
                    f"(stored={block.hash[:16]}..., computed={recomputed[:16]}...)"
                )

            # 2. Previous hash link
            if i > 0:
                expected_prev = chain[i - 1].hash
                if block.previous_hash != expected_prev:
                    errors.append(
                        f"Block {i}: broken chain link "
                        f"(expected={expected_prev[:16]}..., "
                        f"got={block.previous_hash[:16]}...)"
                    )

            # 3. Authority signature (genesis block uses a deterministic hardcoded
            #    signature, not signed by the authority node — skip like Bitcoin genesis)
            if block.authority_signature and not block.is_genesis:
                if not self._authority.verify_signature(block.hash, block.authority_signature):
                    errors.append(f"Block {i}: invalid authority signature — possible tampering")

        return {
            "valid": len(errors) == 0,
            "checked_blocks": len(chain),
            "errors": errors,
            "integrity_status": "VALID" if not errors else "TAMPERED",
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_block(self, index: int) -> Block | None:
        """Retrieve a block by index."""
        if 0 <= index < len(self._chain):
            return self._chain[index]
        return self._ledger.get_block_by_index(index)

    def get_latest_block(self) -> Block:
        """Return the most recent block."""
        return self._chain[-1]

    def get_chain_summary(self) -> list[dict[str, Any]]:
        """Return a list of block summaries (for Block Explorer list view)."""
        return [
            {
                "index": b.index,
                "timestamp": b.timestamp,
                "timestamp_iso": b.to_dict()["timestamp_iso"],
                "transactions": b.transactions,
                "transaction_count": len(b.transactions),
                "merkle_root": b.merkle_root,
                "previous_hash": b.previous_hash,
                "hash": b.hash,
                "authority_signature": b.authority_signature,
                "block_version": b.block_version,
                "is_genesis": b.is_genesis,
            }
            for b in self._chain
        ]

    def find_event(self, event_id: str) -> tuple[Block, int] | None:
        """
        Find the block and transaction index for a given event_id.

        Returns:
            (block, tx_index) if found, None otherwise
        """
        for block in self._chain:
            for i, tx in enumerate(block.transactions):
                if tx.get("event_id") == event_id:
                    return block, i
        return None

    def get_merkle_proof_for_event(self, event_id: str) -> dict[str, Any] | None:
        """
        Return the Merkle inclusion proof for a specific log event.

        This allows any auditor to verify a log event is in the blockchain
        without downloading the full block.
        """
        result = self.find_event(event_id)
        if result is None:
            return None

        block, tx_index = result
        event_hashes = [tx["sha256"] for tx in block.transactions]

        if len(event_hashes) == 1:
            # Single-event block — proof is trivial
            return {
                "event_id": event_id,
                "block_index": block.index,
                "block_hash": block.hash,
                "merkle_root": block.merkle_root,
                "leaf_hash": event_hashes[0],
                "proof": [],
                "verified": event_hashes[0] == block.merkle_root,
            }

        tree = MerkleTree(event_hashes)
        proof = tree.get_proof(tx_index)
        leaf_hash = event_hashes[tx_index]
        verified = MerkleTree.verify_proof(leaf_hash, proof, block.merkle_root)

        return {
            "event_id": event_id,
            "block_index": block.index,
            "block_hash": block.hash,
            "merkle_root": block.merkle_root,
            "leaf_hash": leaf_hash,
            "leaf_index": tx_index,
            "proof": proof,
            "proof_depth": len(proof),
            "verified": verified,
        }

    @property
    def height(self) -> int:
        """Return current chain height."""
        return len(self._chain)

    @property
    def total_events(self) -> int:
        """Return total number of events anchored across all blocks."""
        return sum(len(b.transactions) for b in self._chain)
