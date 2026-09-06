"""Action normalizer for ULPF Phase 3.

Maps vendor-specific firewall and security actions to canonical action taxonomy:
- allow
- deny
- drop
- reject
- alert
- quarantine
- unknown

Adheres to:
- Spec §30: Action Normalization Taxonomy
- Spec §33: Universal Canonical Event (UCE) Schema
"""

from typing import Any

_ACTION_MAP: dict[str, str] = {
    "allow": "allow",
    "permit": "allow",
    "accept": "allow",
    "pass": "allow",
    "built": "allow",
    "allowed": "allow",
    "success": "allow",
    "deny": "deny",
    "block": "deny",
    "blocked": "deny",
    "policy-deny": "deny",
    "drop": "drop",
    "dropped": "drop",
    "reject": "reject",
    "rejected": "reject",
    "reset": "reject",
    "reset-both": "reject",
    "reset-client": "reject",
    "reset-server": "reject",
    "alert": "alert",
    "warn": "alert",
    "warning": "alert",
    "quarantine": "quarantine",
    "isolate": "quarantine",
}


def normalize_action(raw_val: Any) -> str:
    """Normalize a raw action string into canonical taxonomy."""
    if not raw_val:
        return "unknown"
    val_str = str(raw_val).strip().lower()
    if val_str in _ACTION_MAP:
        return _ACTION_MAP[val_str]
    for k, v in _ACTION_MAP.items():
        if k in val_str:
            return v
    return "unknown"
