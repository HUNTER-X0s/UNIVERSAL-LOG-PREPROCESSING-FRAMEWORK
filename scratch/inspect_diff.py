import sys
from pathlib import Path
repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "packages" / "semantic"))

import json
from ulpf_semantic.service import SemanticService

uce = {
    "uce_event_id": "uce-test-01",
    "raw_event_id": "raw-test-01",
    "timestamp": "2026-09-06T12:00:00Z",
    "observer": {"vendor": "Palo Alto Networks", "product": "PAN-OS"},
    "event": {"action": "deny", "category": "security", "type": "firewall", "metadata": {"vendor": "Palo Alto Networks", "product": "PAN-OS"}},
    "source": {"ip": "192.168.1.10"},
    "destination": {"ip": "8.8.8.8"},
    "user": {"name": "admin"},
    "device": {"hostname": "fw-01"},
    "unmapped": {"threat_id": "12345", "custom_policy": "strict"}
}

service = SemanticService()
res1 = service.process_uce(uce)
res2 = service.process_uce(uce)

d1 = res1.to_contract_dict()
d2 = res2.to_contract_dict()

diffs = []
for k in d1:
    if d1[k] != d2.get(k):
        diffs.append((k, d1[k], d2.get(k)))
for k in d2:
    if k not in d1:
        diffs.append((k, "MISSING_IN_D1", d2[k]))

print("Differences in to_contract_dict():")
for k, v1, v2 in diffs:
    print(f"Key: {k}\n  res1: {v1}\n  res2: {v2}")

p_diffs = []
for k in res1.projections:
    if res1.projections[k] != res2.projections.get(k):
        p_diffs.append((k, res1.projections[k], res2.projections.get(k)))
print("\nDifferences in projections:")
for k, v1, v2 in p_diffs:
    print(f"Key: {k}\n  res1: {v1}\n  res2: {v2}")
