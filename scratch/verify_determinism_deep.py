import sys
from pathlib import Path
repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / "packages" / "semantic"))

from ulpf_semantic.service import SemanticService

uce = {
    "event_id": "evt-canonical-001",
    "raw_event_id": "raw-source-001",
    "timestamp": "2026-09-06T12:00:00Z",
    "observer": {"vendor": "Palo Alto Networks", "product": "PAN-OS"},
    "event": {
        "action": "deny",
        "category": "security",
        "type": "firewall",
        "time": "2026-09-06T12:00:00Z",
        "metadata": {"vendor": "Palo Alto Networks", "product": "PAN-OS"}
    },
    "source": {"ip": "192.168.1.10"},
    "destination": {"ip": "8.8.8.8"},
    "user": {"name": "admin"},
    "device": {"hostname": "fw-01"},
    "unmapped_fields": {"threat_id": "12345", "custom_policy": "strict"}
}

service = SemanticService()
res1 = service.process_uce(uce)
res2 = service.process_uce(uce)

print("Semantic Triple Match:", res1.semantic_triple.to_dict() == res2.semantic_triple.to_dict())
print("Action Match:", res1.action.to_dict() == res2.action.to_dict())
print("Result Match:", res1.result.to_dict() == res2.result.to_dict())
print("Confidence Match:", res1.confidence.to_dict() == res2.confidence.to_dict())
print("Decision Trace Match:", res1.decision_trace.to_dict() == res2.decision_trace.to_dict())
print("Risk Context Match:", res1.risk_context.to_dict() == res2.risk_context.to_dict())
print("Correlation Context Match:", res1.correlation_context.to_dict() == res2.correlation_context.to_dict())
print("Entities Match:", [e.to_dict() for e in res1.entities] == [e.to_dict() for e in res2.entities])
print("Indicators Match:", [i.to_dict() for i in res1.indicators] == [i.to_dict() for i in res2.indicators])
print("Equivalence Key:", res1.correlation_context.equivalence_key)
print("Event Fingerprint:", res1.correlation_context.event_fingerprint)
print("OCSF Class UID:", res1.projections["ocsf.v1"]["output"]["class_uid"])
print("OCSF Status ID:", res1.projections["ocsf.v1"]["output"]["status_id"])
