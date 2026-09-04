"""Small, framework-independent primitives shared across future ULPF modules."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NewType

Identifier = NewType("Identifier", str)
CorrelationId = NewType("CorrelationId", str)


@dataclass(frozen=True, slots=True)
class SemanticVersion:
    """Opaque semver value; detailed contract validation remains authoritative."""

    value: str


@dataclass(frozen=True, slots=True)
class UtcTimestamp:
    """Timezone-aware timestamp wrapper that normalizes to UTC."""

    value: datetime

    def __post_init__(self) -> None:
        if self.value.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        object.__setattr__(self, "value", self.value.astimezone(UTC))
