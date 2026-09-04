"""Lightweight dependency-direction checks for the Phase 1 code roots."""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ArchitectureBoundaryTests(unittest.TestCase):
    """Keep framework imports out of the domain package."""

    def test_domain_does_not_import_web_or_infrastructure_frameworks(self) -> None:
        forbidden_roots = {"fastapi", "pydantic", "sqlalchemy", "starlette", "httpx"}
        for path in (ROOT / "packages" / "domain").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imports.update(
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            with self.subTest(path=path.name):
                self.assertFalse(imports.intersection(forbidden_roots))
