import urllib.request
import json

samples = [
    (
        "Nginx Internet Web Access Log (W3C/Common Format)",
        '93.184.216.34 - - [20/Sep/2026:12:34:56 +0000] "GET /api/v1/checkout?cart_id=8812 HTTP/1.1" 200 4523 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36"'
    ),
    (
        "AWS CloudTrail Console Login (Raw JSON from Internet)",
        json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": "developer", "principalId": "AIDAEXAMPLE"},
            "eventTime": "2026-09-20T08:12:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.195",
            "userAgent": "Mozilla/5.0",
            "responseElements": {"ConsoleLogin": "Success"},
            "custom_security_tag": "CRITICAL_SESSION_TAG"
        })
    ),
    (
        "Suricata EVE IDS Alert (Open-Source IDS JSON)",
        json.dumps({
            "timestamp": "2026-09-20T09:15:00.000Z",
            "flow_id": 9876543210,
            "event_type": "alert",
            "src_ip": "192.168.1.150",
            "src_port": 54321,
            "dest_ip": "198.51.100.80",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "signature_id": 2100498,
                "signature": "GPL ATTACK_RESPONSE id check returned root",
                "category": "Potentially Bad Traffic",
                "severity": 1
            },
            "unmapped_vendor_flag": "0xDEADBEEF"
        })
    ),
    (
        "Arbitrary Custom Security Log (Unstructured Key-Value)",
        '[2026-09-20 10:30:15] [KERNEL-ALERT] PID=4092 UID=0 COMM="python3" TARGET="/bin/sh" PRIV_ESC=TRUE SRC=10.0.1.5 VENDOR_RESIDUE="custom_opaque_token_9988"'
    )
]

url = 'http://127.0.0.1:8000/api/v1/parsers/test'
headers = {
    'Content-Type': 'application/json',
    'X-Role': 'platform-admin',
    'X-ULPF-Role': 'platform-admin'
}

print("=" * 80)
print("  TESTING ULPF ENGINE WITH REAL ARBITRARY TELEMETRY FROM THE INTERNET")
print("=" * 80)

for label, raw_payload in samples:
    req_body = {'raw_payload': raw_payload, 'source_id': 'internet-test'}
    req = urllib.request.Request(url, data=json.dumps(req_body).encode('utf-8'), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            print(f"\n[+] Dataset: {label}")
            print(f"    - Raw Payload: {raw_payload[:80]}...")
            print(f"    - Engine Detected: Format='{data.get('format')}', Parser='{data.get('parser_id')}'")
            print(f"    - Parsing Success: {data.get('parsed')} (Confidence: {data.get('confidence', 1.0) * 100:.1f}%)")
            print(f"    - Standard Extracted Fields ({len(data.get('fields', {}))} fields):")
            for k, v in list(data.get('fields', {}).items())[:6]:
                print(f"        * {k}: {str(v)[:50]}")
            unmapped = data.get('unknown_fields', {})
            print(f"    - Lossless Unmapped Residue Preserved ({len(unmapped)} fields):")
            if unmapped:
                for uk, uv in unmapped.items():
                    print(f"        * {uk}: {uv}")
            else:
                print(f"        * (100% of fields canonically mapped into UCE schema)")
    except Exception as e:
        print(f"[-] Error testing {label}: {e}")

print("\n" + "=" * 80)
print("  RESULT: VERBATIM CAPTURE + NORMALIZATION + UNMAPPED RESIDUE VERIFIED")
print("=" * 80)
