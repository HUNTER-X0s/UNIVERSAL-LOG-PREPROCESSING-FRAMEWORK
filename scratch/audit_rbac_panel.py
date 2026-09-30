from ulpf_security.policy import ROLE_PERMISSIONS_MATRIX, PolicyEngine, IdentityContext

NAV_GROUPS = [
  {
    'group': 'OPERATIONS HUB',
    'groupPerm': None,
    'items': [
      ('/command-center', 'Command Center', 'event.read'),
      ('/ai-copilot', 'AI Pipeline Copilot', 'event.read'),
      ('/live-logs', 'Live Logs Stream', 'event.read'),
      ('/log-intake', 'Log Intake Plane', 'event.read'),
      ('/health', 'System Health & SLAs', 'event.read'),
      ('/telemetry-simulator', 'Telemetry Simulator', 'event.read'),
    ]
  },
  {
    'group': 'PARSERS & PIPELINE',
    'groupPerm': None,
    'items': [
      ('/parsers', 'Parser Registry', 'mapping.read'),
      ('/parser-workbench', 'Parser Workbench', 'mapping.read'),
      ('/parser-synthesizer', 'Parser Auto-Synthesizer', 'mapping.read'),
      ('/redos-debugger', 'ReDoS Shield & Debugger', 'mapping.read'),
      ('/pipeline-routing', 'Pipeline Routing & Replay', 'event.read'),
      ('/cost-optimizer', 'SIEM Cost & Data Reduction', 'event.read'),
      ('/agent-exporter', 'SIEM Agent Exporter', 'event.read'),
    ]
  },
  {
    'group': 'UNIFIED CORE',
    'groupPerm': None,
    'items': [
      ('/uce', 'UCE Normalization', 'uce.read'),
      ('/data-privacy', 'Data Privacy & PII Shield', 'uce.read'),
      ('/timestamp-chronos', 'Timestamp & Chronos Engine', 'uce.read'),
      ('/log-quality', 'Log Quality & Conformance', 'uce.read'),
      ('/standards', 'Standards Interoperability', 'uce.read'),
      ('/schemas-export', 'Schemas & Export', 'uce.read'),
      ('/onboarding', 'Schema Drift & Onboarding', 'config.read'),
      ('/query-translator', 'Cross-SIEM Query Translator', 'uce.read'),
    ]
  },
  {
    'group': 'SECURITY INTELLIGENCE',
    'groupPerm': 'intelligence.read',
    'items': [
      ('/alerts', 'Alerts & Detection', 'intelligence.read'),
      ('/threat-detection', 'Threat Detection', 'intelligence.read'),
      ('/threat-intelligence', 'Threat Intel & GeoIP', 'intelligence.read'),
      ('/investigation', 'Investigation Desk', 'intelligence.investigate'),
      ('/playbooks', 'Response Playbooks', 'intelligence.read'),
    ]
  },
  {
    'group': 'COMPLIANCE & FORENSICS',
    'groupPerm': None,
    'items': [
      ('/forensics', 'Forensic Lineage & §65B', 'intelligence.investigate'),
    ]
  },
  {
    'group': 'BLOCKCHAIN & TRUST',
    'groupPerm': None,
    'items': [
      ('/blockchain', 'Blockchain Ledger', 'event.read'),
    ]
  }
]

engine = PolicyEngine()

with open('scratch/rbac_audit_results.txt', 'w', encoding='utf-8') as f:
    for role in ROLE_PERMISSIONS_MATRIX:
        ident = IdentityContext(subject="u", issuer="ulpf", roles={role})
        eff = engine.get_effective_permissions(ident)
        f.write(f"=== {role.upper()} ({len(eff)} perms) ===\n")
        f.write(f"Permissions: {', '.join(sorted(eff))}\n")
        tot = 0
        for g in NAV_GROUPS:
            if g['groupPerm'] and g['groupPerm'] not in eff:
                f.write(f"  [HIDDEN GROUP] {g['group']} (Requires '{g['groupPerm']}')\n")
                continue
            v = [i for i in g['items'] if not i[2] or i[2] in eff]
            h = [i for i in g['items'] if i[2] and i[2] not in eff]
            if not v:
                f.write(f"  [EMPTY GROUP] {g['group']}\n")
                continue
            tot += len(v)
            f.write(f"  [ACTIVE] {g['group']} ({len(v)}/{len(g['items'])} items):\n")
            for item in v:
                f.write(f"    + {item[1]} ({item[0]})\n")
            for item in h:
                f.write(f"    - {item[1]} (HIDDEN - lacks {item[2]})\n")
        f.write(f"Total Visible in Left Panel: {tot} / 28\n\n")

print("File written successfully.")
