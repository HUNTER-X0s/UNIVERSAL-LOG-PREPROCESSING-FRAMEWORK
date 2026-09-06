import json
from pathlib import Path

p = Path(r"C:\Users\HUNTER\.gemini\antigravity-ide\brain\283e1444-0987-42e7-a5e1-57376fd2f1e2\.system_generated\logs\transcript.jsonl")
if p.exists():
    with open(p, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for idx, l in enumerate(reversed(lines)):
        try:
            d = json.loads(l)
            c = d.get("content", "")
            if "FINAL PHASE 4 EXIT AUDITOR" in c:
                print(f"Found FINAL PHASE 4 EXIT AUDITOR at reverse index {idx}, len {len(c)}")
                Path("scratch/phase4_exit_audit_prompt.txt").write_text(c, encoding="utf-8")
                break
        except Exception as err:
            pass
