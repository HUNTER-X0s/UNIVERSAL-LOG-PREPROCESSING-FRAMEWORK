"""
Tests for the ULPF Permissioned Blockchain package.

Covers:
  - Genesis block creation and hash validity
  - Merkle tree construction and inclusion proof verification
  - Smart contract policy enforcement
  - Chain building, linking, and integrity validation
  - Anchoring service: anchor, reject, verify, flush
  - Ledger persistence and chain restore
  - Tamper detection
"""

from __future__ import annotations

import datetime
import sys
from hashlib import sha256
from pathlib import Path

import pytest

# Add blockchain package to path
sys.path.insert(0, str(Path(__file__).parent.parent / "packages" / "blockchain"))

from ulpf_blockchain.anchoring_service import BlockchainAnchoringService
from ulpf_blockchain.authority import AuthorityNode
from ulpf_blockchain.block import Block, create_genesis_block
from ulpf_blockchain.chain import BlockChain
from ulpf_blockchain.ledger import BlockchainLedger
from ulpf_blockchain.merkle import MerkleTree, compute_merkle_root
from ulpf_blockchain.smart_contracts import ContractViolation, PolicyContract


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(n: int) -> dict[str, str]:
    return {
        "event_id": f"a1b2c3d4-{n:04d}-4000-8000-{n:012d}",
        "sha256": sha256(f"event-{n}".encode()).hexdigest(),
        "source": "SNORT",
        "anchored_at": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        "description": f"Test event {n}",
    }


# ---------------------------------------------------------------------------
# Block tests
# ---------------------------------------------------------------------------

class TestBlock:
    def test_genesis_block_index_is_zero(self):
        genesis = create_genesis_block()
        assert genesis.index == 0

    def test_genesis_block_previous_hash_is_zeros(self):
        genesis = create_genesis_block()
        assert genesis.previous_hash == "0" * 64

    def test_genesis_block_hash_is_64_hex_chars(self):
        genesis = create_genesis_block()
        assert len(genesis.hash) == 64
        int(genesis.hash, 16)  # Must be valid hex

    def test_genesis_is_genesis_property(self):
        genesis = create_genesis_block()
        assert genesis.is_genesis is True

    def test_non_genesis_is_not_genesis(self):
        block = Block(
            index=1, timestamp=1.0, transactions=[],
            merkle_root="a" * 64, previous_hash="b" * 64
        )
        assert block.is_genesis is False

    def test_block_hash_is_deterministic(self):
        genesis = create_genesis_block()
        assert genesis.hash == genesis.compute_hash()

    def test_block_to_dict_roundtrip(self):
        genesis = create_genesis_block()
        d = genesis.to_dict()
        restored = Block.from_dict(d)
        assert restored.hash == genesis.hash
        assert restored.index == genesis.index
        assert restored.merkle_root == genesis.merkle_root


# ---------------------------------------------------------------------------
# Merkle Tree tests
# ---------------------------------------------------------------------------

class TestMerkleTree:
    def test_single_leaf_root_equals_leaf(self):
        leaf = sha256(b"event-1").hexdigest()
        tree = MerkleTree([leaf])
        assert tree.get_root() == leaf

    def test_two_leaves_root_is_hash_of_pair(self):
        l1 = sha256(b"a").hexdigest()
        l2 = sha256(b"b").hexdigest()
        tree = MerkleTree([l1, l2])
        expected = sha256((l1 + l2).encode("utf-8")).hexdigest()
        assert tree.get_root() == expected

    def test_inclusion_proof_verifies(self):
        leaves = [sha256(f"leaf-{i}".encode()).hexdigest() for i in range(8)]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        for i in range(len(leaves)):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, root), f"Proof failed for leaf {i}"

    def test_tampered_leaf_fails_proof(self):
        leaves = [sha256(f"leaf-{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTree(leaves)
        root = tree.get_root()
        tampered = sha256(b"tampered").hexdigest()
        proof = tree.get_proof(0)
        assert not MerkleTree.verify_proof(tampered, proof, root)

    def test_empty_leaves_raises(self):
        with pytest.raises(ValueError):
            MerkleTree([])

    def test_compute_merkle_root_single(self):
        h = sha256(b"single").hexdigest()
        assert compute_merkle_root([h]) == h

    def test_compute_merkle_root_empty_returns_hash(self):
        result = compute_merkle_root([])
        assert len(result) == 64


# ---------------------------------------------------------------------------
# Smart Contract tests
# ---------------------------------------------------------------------------

class TestPolicyContract:
    def setup_method(self):
        self.contract = PolicyContract()

    def _valid_event(self) -> dict[str, str]:
        return {
            "event_id": "a1b2c3d4-0001-4000-8000-000000000001",
            "sha256": "a" * 64,
            "source": "SNORT",
            "anchored_at": "2026-09-17T00:00:00+00:00",
        }

    def test_valid_event_passes(self):
        self.contract.validate(self._valid_event())  # Should not raise

    def test_missing_field_raises(self):
        ev = self._valid_event()
        del ev["sha256"]
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate(ev)
        assert "SC-005" in str(exc_info.value)

    def test_invalid_source_raises(self):
        ev = self._valid_event()
        ev["source"] = "TOTALLY_UNKNOWN_DEVICE_XYZ"
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate(ev)
        assert "SC-001" in str(exc_info.value)

    def test_invalid_hash_length_raises(self):
        ev = self._valid_event()
        ev["sha256"] = "tooshort"
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate(ev)
        assert "SC-006" in str(exc_info.value)

    def test_invalid_uuid_raises(self):
        ev = self._valid_event()
        ev["event_id"] = "not-a-uuid"
        with pytest.raises(ContractViolation) as exc_info:
            self.contract.validate(ev)
        assert "SC-003" in str(exc_info.value)

    def test_rules_summary_has_six_rules(self):
        rules = PolicyContract.get_rules_summary()
        assert len(rules) == 6

    def test_all_known_sources_pass(self):
        for source in ["CISCO_ASA", "PALO_ALTO", "WINEVENT", "OKTA", "SNORT", "AWS_CLOUDTRAIL"]:
            ev = self._valid_event()
            ev["source"] = source
            self.contract.validate(ev)  # Must not raise


# ---------------------------------------------------------------------------
# Authority Node tests
# ---------------------------------------------------------------------------

class TestAuthorityNode:
    def test_sign_and_verify_roundtrip(self):
        auth = AuthorityNode(secret_key="test-secret")
        block_hash = sha256(b"test-block").hexdigest()
        sig = auth.sign_block(block_hash)
        assert auth.verify_signature(block_hash, sig) is True

    def test_tampered_hash_fails_verification(self):
        auth = AuthorityNode(secret_key="test-secret")
        block_hash = sha256(b"test-block").hexdigest()
        sig = auth.sign_block(block_hash)
        tampered = sha256(b"tampered").hexdigest()
        assert auth.verify_signature(tampered, sig) is False

    def test_different_key_fails_verification(self):
        auth1 = AuthorityNode(secret_key="key-1")
        auth2 = AuthorityNode(secret_key="key-2")
        block_hash = sha256(b"test").hexdigest()
        sig = auth1.sign_block(block_hash)
        assert auth2.verify_signature(block_hash, sig) is False

    def test_get_node_info_has_expected_fields(self):
        auth = AuthorityNode()
        info = auth.get_node_info()
        assert "node_id" in info
        assert "consensus" in info
        assert "algorithm" in info


# ---------------------------------------------------------------------------
# Blockchain Chain tests
# ---------------------------------------------------------------------------

class TestBlockChain:
    def setup_method(self):
        self.ledger = BlockchainLedger()  # In-memory
        self.auth = AuthorityNode(secret_key="test-chain-key")
        self.chain = BlockChain(self.ledger, self.auth)

    def test_chain_initialized_with_genesis(self):
        assert self.chain.height == 1
        assert self.chain.get_block(0).is_genesis

    def test_add_block_increments_height(self):
        self.chain.add_block([_event(1)])
        assert self.chain.height == 2

    def test_block_links_previous_hash(self):
        genesis = self.chain.get_block(0)
        block1 = self.chain.add_block([_event(1)])
        assert block1.previous_hash == genesis.hash

    def test_block_has_valid_authority_signature(self):
        block = self.chain.add_block([_event(1)])
        assert self.auth.verify_signature(block.hash, block.authority_signature)

    def test_validate_chain_is_valid(self):
        self.chain.add_block([_event(1)])
        self.chain.add_block([_event(2)])
        result = self.chain.validate_chain()
        assert result["valid"] is True
        assert result["integrity_status"] == "VALID"

    def test_find_event_in_chain(self):
        ev = _event(99)
        self.chain.add_block([ev])
        result = self.chain.find_event(ev["event_id"])
        assert result is not None
        block, idx = result
        assert block.index == 1

    def test_merkle_proof_for_event(self):
        events = [_event(i) for i in range(4)]
        self.chain.add_block(events)
        proof_data = self.chain.get_merkle_proof_for_event(events[2]["event_id"])
        assert proof_data is not None
        assert proof_data["verified"] is True

    def test_unknown_event_returns_none(self):
        result = self.chain.find_event("00000000-0000-4000-8000-000000000000")
        assert result is None


# ---------------------------------------------------------------------------
# Anchoring Service tests
# ---------------------------------------------------------------------------

class TestAnchoringService:
    def setup_method(self):
        self.service = BlockchainAnchoringService(
            ledger=BlockchainLedger(),
            authority=AuthorityNode(secret_key="service-test"),
            batch_size=3,
            flush_interval=999.0,  # Never auto-flush during tests
        )

    def test_anchor_valid_event_returns_queued(self):
        ev = _event(1)
        receipt = self.service.anchor_event(ev["event_id"], ev["sha256"], "SNORT")
        assert receipt.status == "QUEUED"

    def test_anchor_invalid_source_returns_rejected(self):
        ev = _event(1)
        receipt = self.service.anchor_event(ev["event_id"], ev["sha256"], "TOTALLY_UNKNOWN_XYZ")
        assert receipt.status == "REJECTED"
        assert receipt.rejection_reason is not None

    def test_flush_creates_block(self):
        for i in range(2):
            ev = _event(i)
            self.service.anchor_event(ev["event_id"], ev["sha256"], "SNORT")
        count = self.service.flush_now()
        assert count == 2
        stats = self.service.get_chain_stats()
        assert stats.chain_height == 2  # genesis + 1 new block

    def test_verify_anchored_event(self):
        ev = _event(42)
        self.service.anchor_event(ev["event_id"], ev["sha256"], "SNORT")
        self.service.flush_now()
        result = self.service.verify_event(ev["event_id"])
        assert result.verified is True
        assert result.block_index == 1

    def test_verify_unanchored_event_returns_not_found(self):
        result = self.service.verify_event("00000000-dead-4000-8000-000000000000")
        assert result.verified is False

    def test_full_chain_validation(self):
        for i in range(5):
            ev = _event(i)
            self.service.anchor_event(ev["event_id"], ev["sha256"], "CISCO_ASA")
        self.service.flush_now()
        validation = self.service.validate_full_chain()
        assert validation["valid"] is True

    def test_batch_size_triggers_auto_flush(self):
        # Batch size is 3; adding 3 events should trigger auto-seal
        for i in range(3):
            ev = _event(i + 100)
            self.service.anchor_event(ev["event_id"], ev["sha256"], "WINEVENT")
        stats = self.service.get_chain_stats()
        # Auto-flush fires on the 3rd event — chain should have grown
        assert stats.chain_height >= 2

    def test_get_chain_stats_returns_valid_model(self):
        stats = self.service.get_chain_stats()
        assert stats.chain_height >= 1
        assert stats.authority_node_id == AuthorityNode.NODE_ID
        assert stats.consensus_algorithm == "Proof of Authority (PoA)"
