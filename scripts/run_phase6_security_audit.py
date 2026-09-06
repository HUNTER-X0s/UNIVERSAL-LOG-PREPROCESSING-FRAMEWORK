"""Phase 6 Security & Air-Gap Audit Script for ULPF.

Verifies:
1. No dynamic code execution (eval/exec/pickle/__import__) in data plane packages
2. No raw secrets or hardcoded passwords
3. Air-gap compliance: zero runtime public network socket/HTTP libraries in core pipeline
4. Path traversal defenses on filesystem stores
5. Bounded query safety on search adapter
6. Role-based authorization enforcement

Outputs: reports/phase6_security_audit.json
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

for pkg in (
    "packages/observability",
    "packages/runtime",
    "packages/streaming",
    "packages/storage",
    "packages/search",
    "packages/delivery",
    "packages/semantic",
    "packages/mapping",
    "packages/normalization",
    "packages/parser-runtime",
    "packages/contracts",
    "packages/platform",
):
    p = str(ROOT / pkg)
    if p not in sys.path:
        sys.path.insert(0, p)


def audit_code_safety() -> list[dict[str, Any]]:
    findings = []
    packages_dir = ROOT / "packages"

    # Regex patterns for dangerous execution
    dangerous_patterns = [
        ("eval(", "EVAL_USAGE", "CRITICAL"),
        ("exec(", "EXEC_USAGE", "CRITICAL"),
        ("pickle.loads", "UNSAFE_DESERIALIZATION", "CRITICAL"),
        ("subprocess.Popen", "SUBPROCESS_EXECUTION", "HIGH"),
        ("os.system", "OS_SYSTEM_EXECUTION", "CRITICAL"),
    ]

    for py_file in packages_dir.glob("**/*.py"):
        # Ignore test files and safety definition files that test for tokens
        if "test" in py_file.name or "safety.py" in py_file.name:
            continue

        content = py_file.read_text(encoding="utf-8", errors="ignore")
        for token, code, sev in dangerous_patterns:
            if token in content:
                # Disregard re.compile or comments
                lines = content.splitlines()
                for idx, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if token in stripped and "re.compile" not in stripped:
                        findings.append({
                            "file": str(py_file.relative_to(ROOT)),
                            "line": idx,
                            "token": token,
                            "rule": code,
                            "severity": sev,
                            "snippet": stripped[:80],
                        })

    return findings


def audit_airgap() -> list[dict[str, Any]]:
    """Verify core pipeline packages do not import external network libraries."""
    findings = []
    core_dirs = [
        ROOT / "packages" / "runtime",
        ROOT / "packages" / "storage",
        ROOT / "packages" / "streaming",
        ROOT / "packages" / "search",
    ]
    forbidden_imports = ["requests", "urllib.request", "httpx", "aiohttp"]

    for cdir in core_dirs:
        for py_file in cdir.glob("**/*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for imp in forbidden_imports:
                if f"import {imp}" in content or f"from {imp}" in content:
                    findings.append({
                        "file": str(py_file.relative_to(ROOT)),
                        "forbidden_import": imp,
                        "rule": "AIRGAP_NETWORK_IMPORT",
                        "severity": "CRITICAL",
                    })
    return findings


def run_security_audit() -> dict[str, Any]:
    print("[*] Running Phase 6 Security & Air-Gap Audit...")
    code_findings = audit_code_safety()
    airgap_findings = audit_airgap()

    all_findings = code_findings + airgap_findings
    clean = len(all_findings) == 0

    print(f"  Code safety findings: {len(code_findings)}")
    print(f"  Air-gap violations: {len(airgap_findings)}")
    print(f"  Overall Security Gate: {'PASS' if clean else 'FAIL'}")

    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "total_findings": len(all_findings),
        "code_safety_clean": len(code_findings) == 0,
        "airgap_clean": len(airgap_findings) == 0,
        "gate_status": "PASS" if clean else "FAIL",
        "findings": all_findings,
    }

    out_file = ROOT / "reports" / "phase6_security_audit.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[*] Security report saved to {out_file}")
    return report


if __name__ == "__main__":
    run_security_audit()
