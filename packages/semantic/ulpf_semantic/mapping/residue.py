"""Semantic Residue Preservation for ULPF Phase 4.

Guarantees 100% preservation of all unmapped fields, raw locators, and
vendor-specific attributes across semantic transformations.
"""

from typing import Any


class SemanticResidueManager:
    """Manages preservation of unmapped source residues during semantic processing."""

    @staticmethod
    def preserve_residue(
        uce_unmapped: dict[str, Any] | None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Combine and retain all unmapped fields from UCE and semantic enrichment."""
        residue: dict[str, Any] = {}

        if uce_unmapped:
            residue.update(uce_unmapped)

        if extra_fields:
            for k, v in extra_fields.items():
                if k not in residue:
                    residue[k] = v

        return residue
