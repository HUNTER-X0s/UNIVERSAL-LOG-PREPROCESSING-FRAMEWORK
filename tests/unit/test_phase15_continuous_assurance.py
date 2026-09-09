"""Phase 15 Unit Tests for Milestone B: Continuous Assurance / Anti-Regression."""

import json
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_phase15_continuous_assurance import scan_anti_tampering, execute_levels


def test_anti_tampering_scanner_on_clean_codebase():
    result = scan_anti_tampering()
    assert result["clean_scan"] is True
    assert result["tampering_detected"] is False
    assert len(result["tampering_findings"]) == 0


def test_continuous_assurance_fast_profile_execution():
    report = execute_levels("phase15-fast")
    assert report["verdict"] == "CONTINUOUS_ASSURANCE_PASSED"
    assert "LEVEL_1_FAST_UNIT" in report["levels"]
    assert "LEVEL_4_CONTRACT_SCHEMA" in report["levels"]
    assert "LEVEL_6_AIRGAP" in report["levels"]
    assert report["levels"]["LEVEL_1_FAST_UNIT"]["passed"] is True
    assert report["levels"]["LEVEL_6_AIRGAP"]["passed"] is True
    assert report["anti_tampering"]["clean_scan"] is True


def test_continuous_assurance_report_file_persisted():
    report_file = ROOT / "reports" / "phase15" / "continuous_assurance_phase15_fast.json"
    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["profile"] == "phase15-fast"
    assert "environment" in data
    assert "git_commit" in data["environment"]
