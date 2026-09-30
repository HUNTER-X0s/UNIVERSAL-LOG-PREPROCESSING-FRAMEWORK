import sys
sys.path.extend([
    'apps/api', 'apps/worker', 'packages/contracts', 'packages/domain', 'packages/ingestion',
    'packages/normalization', 'packages/parser-runtime', 'packages/platform', 'packages/semantic',
    'packages/mapping', 'packages/onboarding', 'packages/ai', 'packages/runtime', 'packages/streaming',
    'packages/storage', 'packages/search', 'packages/delivery', 'packages/observability', 'packages/security',
    'packages/intelligence', 'packages/advanced_intelligence', 'packages/mission', 'packages/blockchain'
])

from ulpf_parser_runtime.registry import create_default_registry

reg = create_default_registry()
print("Total parsers in registry:", len(reg._parsers))
for pid, p in sorted(reg._parsers.items()):
    print(f"ID: {pid:<30} Name: {p.metadata.name:<25} Format: {p.metadata.supported_formats} Vendors: {p.metadata.supported_vendors}")
