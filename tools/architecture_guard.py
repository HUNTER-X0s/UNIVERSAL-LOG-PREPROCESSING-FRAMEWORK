"""Reject selected premature data-plane implementations from the Phase 1 code roots."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_MARKERS = (
    "KafkaConsumer",
    "confluent_kafka",
    "opensearchpy",
    "OpenSearch",
    "boto3.client",
    "minio.Minio",
    "ollama",
    "openai.Chat",
)


def main() -> int:
    """Guard the Phase 1 boundary; this is not a replacement for architecture review."""
    findings: list[str] = []
    for root_name in ("apps", "packages"):
        for path in (ROOT / root_name).rglob("*.py"):
            contents = path.read_text(encoding="utf-8")
            for marker in FORBIDDEN_MARKERS:
                if marker in contents:
                    findings.append(f"{path.relative_to(ROOT)} contains deferred marker {marker}")
    if findings:
        print("Phase 1 architecture guard failed:", *findings, sep="\n")
        return 1
    print("Phase 1 architecture guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
