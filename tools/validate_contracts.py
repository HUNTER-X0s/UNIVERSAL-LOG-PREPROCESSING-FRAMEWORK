"""Validate frozen ULPF JSON Schemas and their minimal synthetic fixtures."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "contracts"))

from ulpf_contracts.registry import ContractRegistry


def main() -> int:
    """Return non-zero if a schema or contract fixture is invalid."""
    registry = ContractRegistry(ROOT / "contracts" / "jsonschema")
    registry.check_schemas()
    fixture_directory = ROOT / "tests" / "fixtures" / "contracts"
    valid = json.loads((fixture_directory / "valid.json").read_text(encoding="utf-8"))
    invalid = json.loads((fixture_directory / "invalid.json").read_text(encoding="utf-8"))
    checked = 0
    for schema_name in registry.names:
        if schema_name == "ulpf-common.v1.schema.json":
            continue
        valid_result = registry.validate(schema_name, valid[schema_name])
        invalid_result = registry.validate(schema_name, invalid[schema_name])
        if not valid_result.valid:
            raise ValueError(f"valid fixture rejected by {schema_name}: {valid_result.errors}")
        if invalid_result.valid:
            raise ValueError(f"invalid fixture accepted by {schema_name}")
        checked += 1
    print(f"validated {checked} root contracts and 1 common-definition contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
