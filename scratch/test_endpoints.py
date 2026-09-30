import urllib.request
import json

headers = {
    'Content-Type': 'application/json',
    'X-Role': 'platform-admin',
    'X-ULPF-Role': 'platform-admin'
}

post_tests = [
    ('/api/v1/parsers/test', {'raw_payload': '{"source": "test", "message": "ok"}', 'source_id': 's1'}),
    ('/api/v1/blockchain/anchor', {'event_id': 'evt-test-101', 'raw_payload': 'test log event line', 'source': 'TEST'}),
    ('/api/v1/copilot/test-connection', {'provider': 'gemini', 'api_key': 'test-fake-key', 'model': 'gemini-2.0-flash'}),
    ('/api/v1/copilot/chat', {'provider': 'gemini', 'model': 'gemini-2.0-flash', 'api_key': 'fake-key', 'prompt': 'hello'}),
]

for ep, payload in post_tests:
    url = f'http://127.0.0.1:8000{ep}'
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode('utf-8')
            print(f'[PASS] POST {ep} -> {resp.status} (body: {body[:80]}...)')
    except Exception as e:
        print(f'[FAIL] POST {ep} -> {e}')
