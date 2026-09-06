import subprocess
from pathlib import Path

p3_files = [
    "tests/test_format_detection.py",
    "tests/test_golden_fixtures.py",
    "tests/test_normalization.py",
    "tests/test_parser_benchmarks.py",
    "tests/test_parser_framing.py",
    "tests/test_parser_security.py",
    "tests/test_raw_intake.py",
    "tests/test_specialized_parsers.py",
    "tests/test_tier_a_parsers.py",
]

p4_files = [
    "tests/test_semantic_benchmarks.py",
    "tests/test_semantic_classification.py",
    "tests/test_semantic_cross_vendor.py",
    "tests/test_semantic_entities.py",
    "tests/test_semantic_ocsf.py",
    "tests/test_semantic_otel.py",
    "tests/test_semantic_security.py",
    "tests/test_semantic_taxonomy.py",
]

print("Running Phase 1-3 tests:")
res_p3 = subprocess.run(["python", "-m", "pytest"] + p3_files + ["-q", "--tb=no"], capture_output=True, text=True)
print(res_p3.stdout.strip().splitlines()[-1] if res_p3.stdout.strip() else res_p3.stderr)

print("\nRunning Phase 4 tests:")
res_p4 = subprocess.run(["python", "-m", "pytest"] + p4_files + ["-q", "--tb=no"], capture_output=True, text=True)
print(res_p4.stdout.strip().splitlines()[-1] if res_p4.stdout.strip() else res_p4.stderr)
