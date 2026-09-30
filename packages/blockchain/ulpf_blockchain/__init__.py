"""
ULPF Blockchain Package — Permissioned Blockchain for Log Evidence Integrity.

Provides tamper-proof, cryptographically verifiable chain of custody for every
log event processed by the Universal Log Pre-processing Framework.

Architecture:
    Block → Merkle Tree → Chain → Ledger (SQLite)
    AuthorityNode signs each block (Proof of Authority)
    SmartContracts enforce policy before block acceptance
    AnchoringService integrates with the ingestion pipeline
"""

from ulpf_blockchain.anchoring_service import AnchorReceipt, BlockchainAnchoringService
from ulpf_blockchain.block import Block
from ulpf_blockchain.chain import BlockChain
from ulpf_blockchain.ledger import BlockchainLedger
from ulpf_blockchain.merkle import MerkleTree
from ulpf_blockchain.models import BlockSummary, ChainStats, VerificationResult
from ulpf_blockchain.smart_contracts import ContractViolation, PolicyContract

__all__ = [
    "Block",
    "BlockChain",
    "BlockchainAnchoringService",
    "BlockchainLedger",
    "BlockSummary",
    "ChainStats",
    "ContractViolation",
    "MerkleTree",
    "PolicyContract",
    "AnchorReceipt",
    "VerificationResult",
]
