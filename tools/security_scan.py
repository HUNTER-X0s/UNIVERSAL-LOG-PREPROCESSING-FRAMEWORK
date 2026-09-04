"""Small offline safety scan for Phase 1 source and repository hygiene."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (ROOT / "apps", ROOT / "packages")
TEXT_ROOTS = (ROOT,)
EXCLUDED_PARTS = {".git", ".venv", "node_modules", "artifacts", "__pycache__"}
FORBIDDEN_CALLS = {"eval", "exec"}
SECRET_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)


def _source_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*.py") if not EXCLUDED_PARTS.intersection(path.parts)]


def _has_forbidden_call(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in FORBIDDEN_CALLS
        ):
            findings.append(
                f"{path.relative_to(ROOT)}:{node.lineno}: forbidden {node.func.id} call"
            )
    return findings


def _has_secret_literal(path: Path) -> list[str]:
    if path.suffix not in {".py", ".json", ".yml", ".yaml", ".toml", ".env", ".md"}:
        return []
    contents = path.read_text(encoding="utf-8", errors="replace")
    return (
        [f"{path.relative_to(ROOT)}: likely secret literal"]
        if SECRET_PATTERN.search(contents)
        else []
    )


def main() -> int:
    """Scan only deterministic local content; dependency audit is a separate connected-build step."""
    findings: list[str] = []
    for root in SOURCE_ROOTS:
        findings.extend(item for path in _source_files(root) for item in _has_forbidden_call(path))
    for root in TEXT_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and not EXCLUDED_PARTS.intersection(path.parts):
                findings.extend(_has_secret_literal(path))
                if path.name == ".env":
                    findings.append(f"{path.relative_to(ROOT)}: local .env must not be committed")
    if findings:
        print("security scan failed:", *findings, sep="\n")
        return 1
    print("security scan passed: no Phase 1 secret literal or unsafe evaluation found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
