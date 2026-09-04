"""Test-only import setup for an editable-monorepo checkout."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative_path in (
    "apps/api",
    "apps/worker",
    "packages/contracts",
    "packages/domain",
    "packages/ingestion",
    "packages/platform",
):
    location = str(ROOT / relative_path)
    if location not in sys.path:
        sys.path.insert(0, location)
