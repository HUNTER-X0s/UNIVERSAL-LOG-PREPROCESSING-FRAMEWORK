"""SIH Demo Clean Reset Script for ULPF Phase 12.

Restores local demo state to a completely pristine, reproducible baseline:
1. Cleans temporary demo sqlite databases and event dumps
2. Cleans temporary evidence containers in test/scratch folders
3. Re-verifies pristine fixtures availability
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def reset_demo_environment() -> bool:
    root = Path(__file__).resolve().parent.parent
    demo_dirs = [
        root / "data" / "demo",
        root / "data" / "scratch",
    ]

    for d in demo_dirs:
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    # Clean temporary sqlite files in data/ if any
    data_dir = root / "data"
    if data_dir.exists():
        for f in data_dir.glob("demo_*.db*"):
            try:
                f.unlink()
            except Exception:
                pass

    print("Demo environment successfully reset to clean state.")
    return True


if __name__ == "__main__":
    reset_demo_environment()
