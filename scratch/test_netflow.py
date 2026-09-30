import re

def parse_netflow(text: str) -> dict:
    m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([\d\.]+)\s+([A-Za-z0-9]+)\s+([^\s:]+):(\d+)\s+->\s+([^\s:]+):(\d+)(?:\s+(\d+)\s+(\d+))?", text)
    if m:
        ts, dur, proto, src_ip, src_port, dst_ip, dst_port, pkts, bytes_cnt = m.groups()
        return {
            "timestamp": ts,
            "duration": float(dur),
            "protocol": proto,
            "src_ip": src_ip,
            "src_port": int(src_port),
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
            "packets": int(pkts) if pkts else 1,
            "bytes": int(bytes_cnt) if bytes_cnt else 0,
        }
    return {}

nf_text = "2026-09-30 00:15:02.102 1.240 TCP 192.168.1.100:51234 -> 10.0.0.5:443 14 8420 1"
print("NetFlow parsed:", parse_netflow(nf_text))
