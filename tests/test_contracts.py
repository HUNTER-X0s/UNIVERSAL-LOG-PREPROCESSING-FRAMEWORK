"""Contract registry tests for all frozen Phase 0 JSON Schemas."""

import json
import unittest
from pathlib import Path

from ulpf_contracts.registry import ContractRegistry

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = ROOT / "tests" / "fixtures" / "contracts"


class ContractRegistryTests(unittest.TestCase):
    """Prove schemas parse and valid/invalid root fixtures remain distinguishable."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = ContractRegistry(ROOT / "contracts" / "jsonschema")
        cls.valid = json.loads((FIXTURE_DIRECTORY / "valid.json").read_text(encoding="utf-8"))
        cls.invalid = json.loads((FIXTURE_DIRECTORY / "invalid.json").read_text(encoding="utf-8"))

    def test_all_schemas_are_syntactically_valid(self) -> None:
        self.registry.check_schemas()
        self.assertEqual(len(self.registry.names), 12)

    def test_root_contract_fixtures_are_compatible(self) -> None:
        for name in self.registry.names:
            if name == "ulpf-common.v1.schema.json":
                continue
            with self.subTest(contract=name):
                self.assertTrue(self.registry.validate(name, self.valid[name]).valid)
                self.assertFalse(self.registry.validate(name, self.invalid[name]).valid)
