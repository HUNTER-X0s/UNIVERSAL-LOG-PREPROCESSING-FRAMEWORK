"""Universal Log Preprocessing Framework (ULPF) Normalization Plane.

Provides:
- CanonicalEventBuilder: Universal Canonical Event (UCE) constructor
- CanonicalEventValidator: Contract validation against JSON schemas
- DLQEventBuilder: Dead-Letter Queue event constructor
- AssertionOrigin, FieldProvenanceRecord, FieldAssertion: Provenance and assertion models
- Multi-format normalizers for timestamp, severity, network, action, and classification
"""

from ulpf_normalization.assertions import (
    AssertionOrigin,
    FieldAssertion,
    FieldProvenanceRecord,
)
from ulpf_normalization.canonical import CanonicalEventBuilder
from ulpf_normalization.dlq import DLQEventBuilder
from ulpf_normalization.normalizers import (
    classify_event,
    normalize_action,
    normalize_direction,
    normalize_ip,
    normalize_metric,
    normalize_port,
    normalize_protocol,
    normalize_severity,
    normalize_timestamp,
)
from ulpf_normalization.unknown_fields import UnknownFieldPreserver
from ulpf_normalization.validation import CanonicalEventValidator

__all__ = [
    "AssertionOrigin",
    "CanonicalEventBuilder",
    "CanonicalEventValidator",
    "DLQEventBuilder",
    "FieldAssertion",
    "FieldProvenanceRecord",
    "UnknownFieldPreserver",
    "classify_event",
    "normalize_action",
    "normalize_direction",
    "normalize_ip",
    "normalize_metric",
    "normalize_port",
    "normalize_protocol",
    "normalize_severity",
    "normalize_timestamp",
]
