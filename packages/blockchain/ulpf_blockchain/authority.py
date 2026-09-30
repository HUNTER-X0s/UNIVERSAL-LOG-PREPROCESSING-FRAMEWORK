"""
Proof of Authority node for the ULPF permissioned blockchain.

In a public blockchain (Bitcoin/Ethereum), consensus is achieved through
Proof of Work (energy-intensive) or Proof of Stake. For a government/enterprise
permissioned blockchain like ULPF, we use Proof of Authority (PoA):

  - Only authorized nodes (Authority Nodes) may sign and finalize blocks
  - Block finality is instant — no mining competition
  - Authority is cryptographically provable via HMAC-SHA256 signatures
  - Suitable for air-gapped, NTRO-controlled deployments

This is the same consensus model used by enterprise blockchain platforms
such as Hyperledger Besu (PoA IBFT) and Quorum.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time


class AuthorityNode:
    """
    ULPF Proof of Authority consensus node.

    Signs blocks with HMAC-SHA256 using a node-specific secret key.
    The signature proves the block was finalized by an authorized ULPF
    node and has not been tampered with since signing.

    In production, the authority key would be stored in an HSM (Hardware
    Security Module). For hackathon demo, it is derived from an env var
    or a deterministic seed.
    """

    NODE_ID: str = "ULPF-AUTHORITY-NODE-NTRO-001"
    ALGORITHM: str = "HMAC-SHA256-PoA"

    def __init__(self, secret_key: str | None = None) -> None:
        """
        Initialize the authority node.

        Args:
            secret_key: HMAC secret. If None, reads from ULPF_BC_AUTHORITY_KEY
                       env var, or generates a deterministic demo key.
        """
        if secret_key:
            self._key = secret_key.encode("utf-8")
        elif env_key := os.environ.get("ULPF_BC_AUTHORITY_KEY"):
            self._key = env_key.encode("utf-8")
        else:
            # Deterministic demo key — reproducible across restarts
            self._key = hashlib.sha256(
                b"ULPF-DEMO-AUTHORITY-KEY-NTRO-SIH-2026-PERMISSIONED-BC"
            ).digest()

    def sign_block(self, block_hash: str) -> str:
        """
        Sign a block hash with HMAC-SHA256 (Proof of Authority signature).

        Args:
            block_hash: The SHA-256 hash of the block to sign

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        signature = hmac.new(
            self._key,
            msg=f"ULPF-BLOCK-SIGN:{block_hash}:{self.NODE_ID}".encode("utf-8"),
            digestmod=hashlib.sha256,
        )
        return signature.hexdigest()

    def verify_signature(self, block_hash: str, signature: str) -> bool:
        """
        Verify a block's authority signature.

        Args:
            block_hash: The block's SHA-256 hash
            signature: The stored authority signature

        Returns:
            True if the signature is valid (block was signed by this authority)
        """
        expected = self.sign_block(block_hash)
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected, signature)

    def get_node_info(self) -> dict[str, str]:
        """Return node metadata for the Block Explorer UI."""
        return {
            "node_id": self.NODE_ID,
            "algorithm": self.ALGORITHM,
            "consensus": "Proof of Authority (PoA)",
            "key_fingerprint": hashlib.sha256(self._key).hexdigest()[:16] + "...",
            "status": "ACTIVE",
            "framework": "Universal Log Pre-processing Framework",
            "organization": "NTRO — National Technical Research Organisation",
        }
