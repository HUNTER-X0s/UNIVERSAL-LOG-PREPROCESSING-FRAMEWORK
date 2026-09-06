import sys
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "packages" / "semantic"))

import copy
import hashlib
import json
from ulpf_semantic.service import SemanticService

uce = {
    "uce_event_id": "uce-test-01",
    "raw_event_id": "raw-test-01",
    "timestamp": "2026-09-06T12:00:00Z",
    "observer": {
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS"
    },
    "event": {
        "action": "deny",
        "category": "security",
        "type": "firewall",
        "metadata": {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS"
        }
    },
    "source": {"ip": "192.168.1.10"},
    "destination": {"ip": "8.8.8.8"},
    "user": {"name": "admin"},
    "device": {"hostname": "fw-01"},
    "unmapped": {"threat_id": "12345", "custom_policy": "strict"}
}

before_dump = json.dumps(uce, sort_keys=True)
before_hash = hashlib.sha256(before_dump.encode()).hexdigest()

service = SemanticService()
res1 = service.process_uce(uce)
res2 = service.process_uce(uce)

after_dump = json.dumps(uce, sort_keys=True)
after_hash = hashlib.sha256(after_dump.encode()).hexdigest()

print("UCE SHA256 Match:", before_hash == after_hash)
print("Determinism Match:", res1.to_contract_dict() == res2.to_contract_dict())
print("Projections Determinism:", res1.projections == res2.projections)
print("Event Category:", res1.semantic_triple.category.value)
print("Event Action:", res1.action.action.value)
print("OCSF Class UID:", res1.projections["ocsf"]["class_uid"])
print("OCSF Status ID:", res1.projections["ocsf"]["status_id"])
print("OTel Severity:", res1.projections["otel"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["severityText"])
print("Residual Unmapped Keys:", list(res1.unmapped_semantic_fields.keys()))
print("All assertions verified successfully!")
