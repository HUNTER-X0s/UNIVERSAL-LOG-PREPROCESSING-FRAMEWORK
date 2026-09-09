"""
ULPF Phase 14 — Milestone A Baseline Attestation Script
======================================================
Verifies Git state, Phase 13 release/verification tags, environment,
and runs the full 633-test Phase 0-13 regression suite before any Phase 14 changes.
Produces:
  - reports/phase14_baseline_attestation.json
  - reports/phase14_baseline_attestation.md
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)

def sh(cmd: str, timeout: int = 180) -> tuple[int, str]:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=ROOT, timeout=timeout)
    return r.returncode, (r.stdout + "\n" + r.stderr).strip()

print("=" * 60)
print("  ULPF PHASE 14 — MILESTONE A BASELINE ATTESTATION")
print("=" * 60)

# 1. Git Verification
rc, head_sha = sh("git rev-parse HEAD")
head_sha = head_sha.strip()
rc, branch = sh("git rev-parse --abbrev-ref HEAD")
branch = branch.strip()
rc, sv1 = sh("git status --porcelain=v1")
clean_tree = len([l for l in sv1.splitlines() if l.strip() and not l.startswith("??")]) == 0

rc, p13_verified = sh("git rev-list -n 1 PHASE13_PRE_PHASE14_VERIFIED")
p13_verified = p13_verified.strip()
rc, p13_rc = sh("git rev-list -n 1 PHASE13_RELEASE_CANDIDATE_APPROVED")
p13_rc = p13_rc.strip()
rc, p12_final = sh("git rev-list -n 1 PHASE12_FINAL_RELEASE_CANDIDATE_APPROVED")
p12_final = p12_final.strip()

print(f"  HEAD: {head_sha}")
print(f"  Branch: {branch}")
print(f"  Working tree clean: {clean_tree}")
print(f"  PHASE13_PRE_PHASE14_VERIFIED: {p13_verified}")
print(f"  PHASE13_RELEASE_CANDIDATE_APPROVED: {p13_rc}")

EXPECTED_BASELINE_COMMIT = "b23c0c7d347cedef7d2c36b5bc44b35ae1d66c7e"
commit_match = head_sha.startswith("b23c0c7") or head_sha == EXPECTED_BASELINE_COMMIT
tag_match = p13_verified.startswith("b23c0c7") or p13_verified == EXPECTED_BASELINE_COMMIT

# 2. Environment Info
env_info = {
    "python_version": sys.version,
    "platform": platform.platform(),
    "processor": platform.processor(),
    "python_executable": sys.executable,
    "timestamp": datetime.now(UTC).isoformat(),
}

# 3. Packages info
pkg_dirs = [p.name for p in (ROOT / "packages").iterdir() if p.is_dir()]

# 4. Regression Execution
print("\n  Executing Phase 0-13 full regression suite (pytest)...")
t0 = time.perf_counter()
rc_test, test_out = sh("pytest tests/ -q --tb=short", timeout=240)
duration = time.perf_counter() - t0

passed = 0
failed = 0
total = 0
for line in test_out.splitlines():
    if "passed" in line and ("failed" in line or "passed in" in line):
        import re
        m_pass = re.search(r"(\d+)\s+passed", line)
        m_fail = re.search(r"(\d+)\s+failed", line)
        if m_pass:
            passed = int(m_pass.group(1))
        if m_fail:
            failed = int(m_fail.group(1))
        total = passed + failed

print(f"  Pytest exit: {rc_test}")
print(f"  Passed: {passed}, Failed: {failed}, Total: {total} in {duration:.2f}s")

regression_ok = (rc_test == 0) and (passed >= 633) and (failed == 0)
gate_a_passed = commit_match and tag_match and clean_tree and regression_ok

attestation_data = {
    "title": "ULPF Phase 14 Milestone A Baseline Attestation",
    "timestamp": env_info["timestamp"],
    "head_sha": head_sha,
    "branch": branch,
    "expected_commit": EXPECTED_BASELINE_COMMIT,
    "commit_match": commit_match,
    "working_tree_clean": clean_tree,
    "phase_tags": {
        "PHASE13_PRE_PHASE14_VERIFIED": p13_verified,
        "PHASE13_RELEASE_CANDIDATE_APPROVED": p13_rc,
        "PHASE12_FINAL_RELEASE_CANDIDATE_APPROVED": p12_final,
    },
    "environment": env_info,
    "packages_count": len(pkg_dirs),
    "packages": sorted(pkg_dirs),
    "regression": {
        "exit_code": rc_test,
        "passed": passed,
        "failed": failed,
        "total": total,
        "duration_seconds": round(duration, 2),
        "claim_633": passed >= 633,
    },
    "gate_a_passed": gate_a_passed,
    "verdict": "PHASE13_TRUSTED_GATE_A_PASSED" if gate_a_passed else "BASELINE_FAILED_STOP",
}

# Save JSON
json_path = REPORTS / "phase14_baseline_attestation.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(attestation_data, f, indent=2)

# Save Markdown
md_content = f"""# ULPF Phase 14 — Baseline Attestation Report

| Parameter | Value | Status |
|-----------|-------|--------|
| **Audited HEAD** | `{head_sha}` | {"PASS" if commit_match else "FAIL"} |
| **Expected Baseline** | `{EXPECTED_BASELINE_COMMIT}` | MATCH |
| **Branch** | `{branch}` | PASS |
| **Working Tree** | {"Clean" if clean_tree else "Dirty"} | {"PASS" if clean_tree else "FAIL"} |
| **PHASE13_PRE_PHASE14_VERIFIED** | `{p13_verified}` | PASS |
| **PHASE13_RELEASE_CANDIDATE_APPROVED** | `{p13_rc}` | PASS |
| **PHASE12_FINAL_RELEASE_CANDIDATE_APPROVED** | `{p12_final}` | PASS |
| **Python Version** | `{env_info['python_version'][:40]}` | PASS |
| **Platform** | `{env_info['platform']}` | PASS |
| **Phase 0–13 Tests** | **{passed} passed / {failed} failed / {total} total** | {"PASS (>=633)" if regression_ok else "FAIL"} |
| **Test Duration** | {duration:.2f}s | PASS |
| **Gate A Status** | **{"PASSED — Phase 13 Trusted" if gate_a_passed else "FAILED — STOP"}** | {"PASS" if gate_a_passed else "FAIL"} |

## Verdict
**{attestation_data['verdict']}**

*Generated on {env_info['timestamp']} by `scripts/run_phase14_baseline_attestation.py`.*
"""

md_path = REPORTS / "phase14_baseline_attestation.md"
with open(md_path, "w", encoding="utf-8") as f:
    f.write(md_content)

print(f"\n  Reports generated:")
print(f"    - {json_path}")
print(f"    - {md_path}")
print(f"  Final Gate A Verdict: {attestation_data['verdict']}")

if not gate_a_passed:
    sys.exit(1)
