import json
import urllib.request
from ulpf_parser_runtime.registry import create_default_registry
from ulpf_parser_runtime.framing import FramedRecord

reg = create_default_registry()
p = reg.get("parser.snort.fast")
sample = '[**] [1:1000001:2] COMMUNITY WEB-MISC Cross Site Scripting attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 198.51.100.99:54120 -> 10.0.1.80:80'
rec = FramedRecord(0, sample, sample.encode(), 0, len(sample), 1)
res = p.parse(rec)
print("Parser found:", p)
print("Result status:", res.status)
print("Extracted fields count:", len(res.extracted_fields))
print("Fields:", {k: v.value for k, v in res.extracted_fields.items()})

# Now test via HTTP API
req = urllib.request.Request(
    "http://localhost:8000/api/v1/parsers/test",
    data=json.dumps({"raw_payload": sample, "source_id": "snort"}).encode("utf-8"),
    headers={"Content-Type": "application/json", "X-Role": "platform-admin"}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("API Response:", data)
