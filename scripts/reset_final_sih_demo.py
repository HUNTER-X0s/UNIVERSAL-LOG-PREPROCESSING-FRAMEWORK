"""ULPF Phase 16 — Reset Final SIH Judge Demo.

Cleans up demo artifacts, resets temporary SQLite databases,
and ensures deterministic idempotency for live judge evaluation.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "data" / "demo"
DEMO_VAULT = ROOT / "data" / "vault" / "demo"
REPORTS_P16 = ROOT / "reports" / "phase16"


def reset_demo() -> bool:
    """Reset all state for the SIH Judge Mode demo."""
    print("[*] Resetting ULPF SIH Judge Mode state...")

    # Clean demo data directory
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR, ignore_errors=True)
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    # Clean demo vault
    if DEMO_VAULT.exists():
        shutil.rmtree(DEMO_VAULT, ignore_errors=True)
    DEMO_VAULT.mkdir(parents=True, exist_ok=True)

    # Ensure reports directory exists
    REPORTS_P16.mkdir(parents=True, exist_ok=True)

    print("[+] Demo environment successfully reset to baseline.")
    return True


if __name__ == "__main__":
    reset_demo()
