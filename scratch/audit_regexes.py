import re
from pathlib import Path

regex_calls = []
for p in Path("packages/semantic").rglob("*.py"):
    txt = p.read_text(encoding="utf-8")
    for m in re.finditer(r're\.compile\s*\(\s*r?([\'"].*?[\'"])', txt):
        regex_calls.append((p.name, m.group(1)))

print(f"Compiled regexes found: {len(regex_calls)}")
for fn, r in regex_calls:
    print(f"  {fn}: {r}")
