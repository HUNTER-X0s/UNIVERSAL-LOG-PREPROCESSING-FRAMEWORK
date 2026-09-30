import re
import yaml
import json

def parse_winevent(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip()
            if k and v:
                fields[k] = v
        elif "=" in line:
            parts = line.split("=", 1)
            k = parts[0].strip()
            v = parts[1].strip()
            if k and v:
                fields[k] = v
    return fields

def parse_grok(text: str) -> dict:
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(?:\[([^\]]+)\])?\s*(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+([^\s:]+)\s*[-:]\s*(.*)$", text, re.DOTALL)
    if m:
        ts, thread, level, logger, msg = m.groups()
        f = {"timestamp": ts, "level": level, "logger": logger, "message": msg}
        if thread:
            f["thread"] = thread
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
        if len(ips) >= 1:
            f["src_ip"] = ips[0]
        if len(ips) >= 2:
            f["dst_ip"] = ips[1]
        u = re.search(r"(?:user|account|username)[\s=\'\"]+([a-zA-Z0-9_\-\.]+)", msg, re.IGNORECASE)
        if u:
            f["user"] = u.group(1)
        return f
    return {}

test_win = """Log Name: Security
Event ID: 4625
Computer: DC01.corp.local
Account Name: admin_corp
Logon Type: 3
Source Network Address: 10.0.4.15
Source Port: 52140
"""
print("WinEvent:", parse_winevent(test_win))

test_grok = "2026-09-30 00:25:14.892 [http-nio-8080-exec-4] WARN com.security.auth.AuthenticationProvider - Failed login attempt for user admin from IP 198.51.100.42 reason=INVALID_CREDENTIALS"
print("Grok:", parse_grok(test_grok))
