"""Cross-platform developer command interface for the ULPF Phase 1 foundation."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(command: list[str]) -> None:
    """Run a fixed local tool command and fail loudly on its exit code."""
    subprocess.run(command, cwd=ROOT, check=True)


def command_for(name: str) -> list[list[str]]:
    """Map documented task names to fixed, shell-free subprocess invocations."""
    commands = {
        "format": [[PYTHON, "-m", "ruff", "format", "--check", "."]],
        "lint": [[PYTHON, "-m", "ruff", "check", "."]],
        "typecheck": [[PYTHON, "-m", "mypy", "apps", "packages"]],
        "test": [[PYTHON, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]],
        "contracts": [[PYTHON, "tools/validate_contracts.py"]],
        "security": [[PYTHON, "tools/security_scan.py"], [PYTHON, "-m", "pip", "check"]],
        "architecture": [[PYTHON, "tools/architecture_guard.py"]],
        "docs": [[PYTHON, "tools/check_docs.py"]],
        "build": [
            [
                PYTHON,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                "artifacts/build",
                ".",
            ]
        ],
        "audit": [[PYTHON, "-m", "pip_audit", "-r", "requirements.lock"]],
        "dev": [
            [
                PYTHON,
                "-m",
                "uvicorn",
                "ulpf_api.app:app",
                "--app-dir",
                "apps/api",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--log-config",
                "",
            ]
        ],
    }
    if name == "verify":
        return [
            *commands["format"],
            *commands["lint"],
            *commands["typecheck"],
            *commands["contracts"],
            *commands["test"],
            *commands["security"],
            *commands["architecture"],
            *commands["docs"],
            *commands["build"],
        ]
    if name not in commands:
        raise ValueError(f"unknown ULPF command: {name}")
    return commands[name]


def main() -> int:
    """Execute one documented task."""
    if len(sys.argv) != 2:
        print(
            "usage: python tools/ulpf.py <format|lint|typecheck|test|contracts|security|architecture|docs|build|audit|dev|verify>"
        )
        return 2
    try:
        for command in command_for(sys.argv[1]):
            run(command)
    except (subprocess.CalledProcessError, ValueError) as exc:
        print(f"ULPF command failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
