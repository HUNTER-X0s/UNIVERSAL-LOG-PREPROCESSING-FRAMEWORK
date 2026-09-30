# ULPF Expected Output Ground Truth Contract: Fortinet FortiGate UTM

## Parser Specification
- **Parser ID:** `parser.fortinet.fortigate`
- **Parser Version:** `1.0.0`
- **Vendor:** `Fortinet`
- **Product:** `FortiGate UTM`
- **Format:** `fortigate_kv`
- **Normalized Schema:** `contracts/jsonschema/normalized-event.v1.schema.json` (UCE v1.0.0)

## Verification Guarantees
1. **Deterministic Parsing:** Identical input bytes always produce 100% byte-for-byte identical extracted fields.
2. **Zero Loss (Residue Preservation):** Any fields not bound to core UCE canonical properties are preserved in `unmapped_fields`.
3. **Cryptographic Lineage:** Raw payload SHA-256 is tracked in `evidence.payload_sha256` and linked to `raw_event_id`.
4. **Field-Level Provenance:** Every normalized field has an immutable assertion origin (`observed`, `derived`, `inferred`, `enriched`).

## Verification Test
Run automated regression test suite:
```bash
python -m unittest tests/test_expected_output_fixtures.py -k test_fixture_fortigate
```
