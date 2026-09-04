"""Verify local Markdown links without resolving external network references."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def main() -> int:
    """Report broken relative links in tracked documentation."""
    findings: list[str] = []
    for path in ROOT.rglob("*.md"):
        if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
            continue
        content = path.read_text(encoding="utf-8")
        for target in LINK_PATTERN.findall(content):
            if "://" in target or target.startswith("#") or target.startswith("mailto:"):
                continue
            target_path = target.split("#", 1)[0]
            if target_path and not (path.parent / target_path).resolve().exists():
                findings.append(f"{path.relative_to(ROOT)} -> {target}")
    if findings:
        print("documentation link check failed:", *findings, sep="\n")
        return 1
    print("documentation link check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
