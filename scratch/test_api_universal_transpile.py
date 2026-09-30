"""
Test HTTP REST API endpoints for Universal Transpiler
"""
import urllib.request
import json
import sys

API_URL = "http://localhost:8000/api/v1"

def test_api():
    print("Testing GET /universal/formats...")
    req = urllib.request.Request(f"{API_URL}/universal/formats", headers={"X-Role": "Analyst"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read())
        formats = data.get("formats", [])
        print(f"  Received {len(formats)} supported target formats.")
        assert len(formats) >= 20

    test_cases = [
        ("Cisco ASA -> OCSF", "%ASA-6-302014: Teardown TCP connection 1083984 for outside:198.51.100.4/443 to inside:10.0.0.1/54321 duration 0:00:30 bytes 4920 TCP FINs", "ocsf"),
        ("CEF -> ECS", "CEF:0|Check Point|VPN-1 & FireWall-1|CheckPoint|Drop|Drop|6|src=198.51.100.4 dst=10.0.0.1 spt=443 dpt=54321 proto=TCP act=Drop", "ecs"),
        ("LEEF -> Splunk HEC", "LEEF:2.0|Microsoft|MSExchange|2024|4624|src=192.168.1.105\tdst=10.0.0.5\tspt=58210\tdpt=443\tusr=secops.lead\tact=Success\tproto=TCP", "splunk_hec"),
        ("Syslog 5424 -> Google UDM", "<165>1 2026-09-30T02:25:00.003Z border-router bgpd 1420 ID47 [origin ip=\"198.51.100.1\"] BGP neighbor session reset: peer 203.0.113.1 state ACTIVE", "google_udm"),
        ("AWS CloudTrail -> Neo4j Cypher", "{\"eventVersion\":\"1.08\",\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"cloud.admin\"},\"eventTime\":\"2026-09-30T02:10:00Z\",\"eventSource\":\"s3.amazonaws.com\",\"eventName\":\"PutObject\",\"sourceIPAddress\":\"203.0.113.50\"}", "neo4j"),
        ("Linux Auditd -> STIX 2.1", "type=SYSCALL msg=audit(1727654400.412:892): arch=c000003e syscall=59 success=yes exit=0 a0=55a30 comm=\"bash\" exe=\"/bin/bash\" key=\"priv_esc\"", "stix"),
        ("Suricata JSON -> Drain3 Template", "{\"timestamp\":\"2026-09-30T02:00:00.000Z\",\"event_type\":\"alert\",\"src_ip\":\"203.0.113.195\",\"src_port\":4444,\"dest_ip\":\"10.0.0.45\",\"dest_port\":80,\"proto\":\"TCP\",\"alert\":{\"action\":\"blocked\",\"signature\":\"ET MALWARE Reverse Shell\",\"severity\":1}}", "drain_template"),
        ("W3C Combined -> Forensic Dossier", "198.51.100.44 - secops.lead [30/Sep/2026:02:30:00 +0000] \"POST /api/v1/auth/login HTTP/1.1\" 200 4812 \"https://portal.company.com/login\" \"Mozilla/5.0\"", "forensic_dossier"),
    ]

    for name, raw, tgt in test_cases:
        print(f"Testing POST /universal/transpile: {name}...")
        body = json.dumps({"raw_payload": raw, "target_format": tgt}).encode()
        post_req = urllib.request.Request(
            f"{API_URL}/universal/transpile",
            data=body,
            headers={"Content-Type": "application/json", "X-Role": "Viewer"}
        )
        with urllib.request.urlopen(post_req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read())
            assert res.get("success") is True
            assert res.get("target_format") == tgt
            assert res.get("drain_template") is not None
            assert res.get("cas_sha256") is not None
            print(f"  OK -> detected: {res.get('source_format_detected')}, latency: {res.get('duration_ms')}ms")

    print("\nALL HTTP REST ENDPOINT TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_api()
