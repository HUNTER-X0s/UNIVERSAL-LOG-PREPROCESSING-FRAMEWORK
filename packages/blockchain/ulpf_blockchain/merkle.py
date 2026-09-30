"""
Merkle Tree implementation for ULPF blockchain batch verification.

Each block contains a Merkle root computed from the SHA-256 hashes of all
log events in that block. This enables O(log n) inclusion proofs — any
auditor can verify a single log event belongs to a block without downloading
the full transaction list.

Used by NTRO forensic analysts and SIEM teams to verify log evidence integrity.
"""

from __future__ import annotations

from hashlib import sha256


class MerkleTree:
    """
    Binary Merkle Tree for log event batch hashing.

    Construction:
        leaves = [sha256(event) for event in batch]
        tree = MerkleTree(leaves)
        root = tree.get_root()

    Inclusion proof (for judicial/forensic verification):
        proof = tree.get_proof(leaf_index)
        valid = MerkleTree.verify_proof(leaf_hash, proof, root)
    """

    def __init__(self, leaves: list[str]) -> None:
        """
        Build the Merkle tree from a list of leaf hashes.

        Args:
            leaves: List of hex SHA-256 strings (one per log event)
        """
        if not leaves:
            raise ValueError("Cannot build a Merkle tree with no leaves.")
        self._leaves: list[str] = list(leaves)
        self._tree: list[list[str]] = self._build_tree(self._leaves)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_root(self) -> str:
        """Return the Merkle root hash (single source of truth for the batch)."""
        return self._tree[-1][0]

    def get_proof(self, leaf_index: int) -> list[dict[str, str]]:
        """
        Return the Merkle inclusion proof for the leaf at *leaf_index*.

        The proof is an ordered list of sibling hashes with their position
        (left/right). An auditor uses this proof to recompute the Merkle root
        and confirm the leaf's membership without any other data.

        Returns:
            [{"hash": "...", "position": "left"|"right"}, ...]
        """
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range (0..{len(self._leaves)-1})")

        proof: list[dict[str, str]] = []
        index = leaf_index

        for level in self._tree[:-1]:  # Exclude root level
            # Determine sibling index
            if index % 2 == 0:
                # Current node is left child → sibling is right
                sibling_index = index + 1
                if sibling_index < len(level):
                    proof.append({"hash": level[sibling_index], "position": "right"})
                else:
                    # Odd number of nodes — duplicate the last node
                    proof.append({"hash": level[index], "position": "right"})
            else:
                # Current node is right child → sibling is left
                sibling_index = index - 1
                proof.append({"hash": level[sibling_index], "position": "left"})

            index //= 2  # Move to parent level

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[dict[str, str]], root: str) -> bool:
        """
        Verify a Merkle inclusion proof.

        Args:
            leaf_hash: The SHA-256 hash of the event being verified
            proof: The proof list from get_proof()
            root: The expected Merkle root (from the blockchain block)

        Returns:
            True if the proof is valid and the leaf is in the tree
        """
        computed = leaf_hash
        for step in proof:
            sibling = step["hash"]
            if step["position"] == "right":
                combined = computed + sibling
            else:
                combined = sibling + computed
            computed = sha256(combined.encode("utf-8")).hexdigest()
        return computed == root

    @property
    def leaves(self) -> list[str]:
        """Return the original leaf hashes."""
        return list(self._leaves)

    @property
    def depth(self) -> int:
        """Return tree depth (number of levels including root)."""
        return len(self._tree)

    @property
    def leaf_count(self) -> int:
        """Return number of leaf nodes."""
        return len(self._leaves)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """SHA-256 of the concatenation of two hex strings."""
        return sha256((left + right).encode("utf-8")).hexdigest()

    @classmethod
    def _build_tree(cls, leaves: list[str]) -> list[list[str]]:
        """Build all tree levels bottom-up, returning list-of-levels."""
        tree: list[list[str]] = [list(leaves)]
        current_level = list(leaves)

        while len(current_level) > 1:
            next_level: list[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                # If odd number of nodes, duplicate the last one (standard Bitcoin approach)
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(cls._hash_pair(left, right))
            tree.append(next_level)
            current_level = next_level

        return tree


def compute_merkle_root(hashes: list[str]) -> str:
    """
    Convenience function: compute the Merkle root of a list of hashes.

    For a single-event batch, the root IS the event hash.
    """
    if not hashes:
        return sha256(b"EMPTY_BLOCK").hexdigest()
    if len(hashes) == 1:
        return hashes[0]
    return MerkleTree(hashes).get_root()
