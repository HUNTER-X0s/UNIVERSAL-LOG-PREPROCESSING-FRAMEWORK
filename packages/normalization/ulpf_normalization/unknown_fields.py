"""Unknown and unmapped field preservation for ULPF Phase 3.

Adheres to:
- Spec §27: Unknown Field Preservation (strict zero data loss guarantee)
- Spec §33: Universal Canonical Event (UCE) Schema (unmapped_fields object)
"""

from typing import Any


class UnknownFieldPreserver:
    """Collects and organizes unmapped telemetry attributes preserving source fidelity."""

    @staticmethod
    def preserve(
        extracted_fields: dict[str, Any],
        mapped_keys: set[str],
        parser_unmapped: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Aggregate all unmapped source keys into a clean dictionary."""
        out: dict[str, Any] = {}

        # 1. Any parser unmapped residue
        if parser_unmapped:
            for k, v in parser_unmapped.items():
                out[k] = v

        # 2. Any extracted field not explicitly normalized into canonical model
        for k, v in extracted_fields.items():
            if k not in mapped_keys:
                # If v is an ExtractedField object or dict with 'value'
                if hasattr(v, "value"):
                    out[k] = v.value
                elif isinstance(v, dict) and "value" in v:
                    out[k] = v["value"]
                else:
                    out[k] = v

        return out
