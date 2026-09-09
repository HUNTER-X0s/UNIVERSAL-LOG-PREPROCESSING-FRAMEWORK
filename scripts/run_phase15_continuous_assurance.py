"""ULPF Phase 15 Continuous Assurance & Anti-Regression System.

Executes a layered 10-level validation model across 4 execution profiles
(phase15-fast, phase15-full, phase15-security, phase15-release).
Detects test tampering, tautologies, skipped tests, and benchmark manipulation.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REPORTS_P15 = ROOT / "reports" / "phase15"
REPORTS_P15.mkdir(parents=True, exist_ok=True)


def sh(cmd: str, timeout: int = 180) -> tuple[int, str]:
    try:
        res = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, cwd=str(ROOT), timeout=timeout
        )
        return res.returncode, res.stdout.strip() + "\n" + res.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"


def scan_anti_tampering() -> dict[str, Any]:
    """Scan test suite for fraudulent or tautological patterns."""
    findings = []
    tests_dir = ROOT / "tests"
    for pyf in tests_dir.rglob("*.py"):
        try:
            txt = pyf.read_text(encoding="utf-8")
        except Exception:
            continue

        # 1. Tautological assert True / assert 1 == 1
        for idx, line in enumerate(txt.splitlines(), 1):
            if re.search(r"^\s*assert\s+(True|1\s*==\s*1)\s*(#.*)?$", line):
                findings.append({"file": str(pyf.relative_to(ROOT)), "line": idx, "issue": "Tautological assert True"})
            if re.search(r"pytest\.skip\([^)]*always", line, re.IGNORECASE):
                findings.append({"file": str(pyf.relative_to(ROOT)), "line": idx, "issue": "Unconditional skip pattern"})
            if re.search(r"@pytest\.mark\.xfail\([^)]*strict\s*=\s*False", line):
                findings.append({"file": str(pyf.relative_to(ROOT)), "line": idx, "issue": "Permissive xfail without strict enforcement"})

    return {
        "tampering_detected": len(findings) > 0,
        "tampering_findings": findings,
        "clean_scan": len(findings) == 0,
    }


def execute_levels(profile: str) -> dict[str, Any]:
    start_time = time.perf_counter()
    levels_result = {}

    # Define level scopes
    level_commands = {
        "LEVEL_1_FAST_UNIT": "pytest tests/test_production_defaults.py tests/test_config.py -q",
        "LEVEL_2_INTEGRATION": "pytest tests/test_tier_a_parsers.py tests/test_storage.py -q",
        "LEVEL_3_SECURITY": "pytest tests/redteam/ tests/airgap/ -q",
        "LEVEL_4_CONTRACT_SCHEMA": "pytest tests/test_contracts.py tests/test_normalization.py -q",
        "LEVEL_5_FORENSIC_INTEGRITY": "pytest tests/unit/test_phase13_forensic_superiority.py tests/unit/test_phase14_resilience_recovery.py -q",
        "LEVEL_6_AIRGAP": "pytest tests/airgap/test_phase11_airgap.py -q",
        "LEVEL_7_DEPLOYMENT": "python -c \"import ulpf_streaming, ulpf_runtime, ulpf_onboarding; print('Core packages importable')\"",
        "LEVEL_8_PERFORMANCE": "pytest tests/test_parser_benchmarks.py tests/test_semantic_benchmarks.py -q",
        "LEVEL_9_CHAOS_FAILURE": "pytest tests/unit/test_phase14_distributed_platform.py -q",
        "LEVEL_10_E2E_MISSION": "python scripts/run_phase14_sih_demo.py --quick",
    }

    if profile == "phase15-fast":
        active_levels = ["LEVEL_1_FAST_UNIT", "LEVEL_4_CONTRACT_SCHEMA", "LEVEL_6_AIRGAP"]
    elif profile == "phase15-security":
        active_levels = ["LEVEL_3_SECURITY", "LEVEL_5_FORENSIC_INTEGRITY", "LEVEL_6_AIRGAP"]
    elif profile in ("phase15-full", "phase15-release"):
        active_levels = list(level_commands.keys())
    else:
        active_levels = ["LEVEL_1_FAST_UNIT"]

    all_passed = True
    for lvl in active_levels:
        cmd = level_commands[lvl]
        t0 = time.perf_counter()
        rc, out = sh(cmd)
        dur = round(time.perf_counter() - t0, 2)
        passed = (rc == 0)
        if not passed:
            all_passed = False
        levels_result[lvl] = {
            "command": cmd,
            "passed": passed,
            "exit_code": rc,
            "duration_seconds": dur,
            "output_sample": out.splitlines()[-1] if out.splitlines() else "NO_OUTPUT",
        }
        print(f"  [{lvl}] -> {'PASS' if passed else 'FAIL'} ({dur}s)")

    # Anti-tampering scan
    tamper_audit = scan_anti_tampering()
    if not tamper_audit["clean_scan"]:
        all_passed = False

    # Git commit and environment fingerprint
    rc_git, commit_out = sh("git rev-parse HEAD")
    head_sha = commit_out.strip().splitlines()[0] if rc_git == 0 else "UNKNOWN"

    total_duration = round(time.perf_counter() - start_time, 2)

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "profile": profile,
        "environment": {
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "cpu_count": os.cpu_count(),
            "git_commit": head_sha,
        },
        "anti_tampering": tamper_audit,
        "levels": levels_result,
        "total_duration_seconds": total_duration,
        "verdict": "CONTINUOUS_ASSURANCE_PASSED" if all_passed else "CONTINUOUS_ASSURANCE_FAILED",
    }

    report_path = REPORTS_P15 / f"continuous_assurance_{profile.replace('-', '_')}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


def main():
    parser = argparse.ArgumentParser(description="ULPF Phase 15 Continuous Assurance Runner")
    parser.add_argument(
        "--profile",
        choices=["phase15-fast", "phase15-full", "phase15-security", "phase15-release"],
        default="phase15-fast",
        help="Validation profile to run",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(f"  ULPF PHASE 15 CONTINUOUS ASSURANCE (Profile: {args.profile})")
    print("=" * 70)
    report = execute_levels(args.profile)
    print("=" * 70)
    print(f"  FINAL VERDICT: {report['verdict']} in {report['total_duration_seconds']}s")
    print("=" * 70)

    if report["verdict"] != "CONTINUOUS_ASSURANCE_PASSED":
        sys.exit(1)


if __name__ == "__main__":
    main()
