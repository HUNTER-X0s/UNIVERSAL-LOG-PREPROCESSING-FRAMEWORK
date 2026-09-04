"""Phase 2 raw-intake primitives and transport adapters.

This package captures opaque bytes. Semantic parsing and normalization are
deliberately outside its dependency boundary.
"""

from ulpf_ingestion.models import CaptureAcknowledgement, RawEventEnvelope
from ulpf_ingestion.service import RawCaptureService

__all__ = ["CaptureAcknowledgement", "RawCaptureService", "RawEventEnvelope"]
