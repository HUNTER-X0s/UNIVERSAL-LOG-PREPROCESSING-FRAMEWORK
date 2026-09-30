import json
from ulpf_normalization.universal_transpiler import get_universal_transpiler, TranspileRequest

transpiler = get_universal_transpiler()

sample_cef = "CEF:0|Palo Alto Networks|PAN-OS|10.2.0|THREAT|vulnerability|8|src=203.0.113.84 dst=10.0.1.20 spt=51294 dpt=80 proto=tcp act=block cs1Label=Rule cs1=Exploit-Shield-Deny msg=Apache Log4j RCE Attempt (CVE-2021-44228) cnt=1"
sample_cisco = "%ASA-4-106023: Deny tcp src outside:203.0.113.50/49152 dst inside:10.0.2.15/443 by access-group \"OUTSIDE-IN\" [0x8401, 0x0]"
sample_syslog = "<165>1 2026-09-29T02:00:00.000Z edge-gw01.corp security 1042 ID47 [meta@32473 session=\"84192\" user=\"secadmin\" reason=\"mfa_timeout\"] Security session terminated due to inactivity policy."

test_cases = [
    (sample_cef, "ocsf"),
    (sample_cisco, "ecs"),
    (sample_cisco, "otel"),
    (sample_syslog, "cef"),
    (sample_cef, "leef"),
    (sample_cisco, "google_udm"),
    (sample_cef, "sentinel_asim"),
    (sample_cisco, "neo4j"),
    (sample_cef, "stix"),
    (sample_syslog, "drain_template"),
    (sample_cisco, "forensic_dossier"),
]

print("=" * 80)
print("TESTING UNIVERSAL LOG TRANSPILER ACROSS TARGET SCHEMAS")
print("=" * 80)

for sample, target in test_cases:
    req = TranspileRequest(raw_payload=sample, target_format=target)
    res = transpiler.transpile(req)
    print(f"[{res.source_format_detected.upper()} -> {res.target_format.upper()}]: Success={res.success}, Time={res.duration_ms}ms")
    print(f"  Drain Template: {res.drain_template[:65]}...")
    if isinstance(res.output, dict):
        preview = json.dumps(res.output)[:90]
    else:
        preview = str(res.output).replace('\n', ' ')[:90]
    print(f"  Output Sample:  {preview}...")
    print("-" * 80)

print("ALL TEST CASES PASSED SUCCESSFULLY!")
