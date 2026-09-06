"""ULPF Parser Runtime Package.

Core execution engine for record framing, format and source detection,
generic parsing, and specialized parser pack execution.
"""

from ulpf_parser_runtime.encoding import DecodedPayload, EncodingStatus, prepare_payload
from ulpf_parser_runtime.errors import (
    ErrorCode,
    ErrorSeverity,
    NestingLimitExceededException,
    OversizedRecordException,
    ParseError,
    ParserException,
    ParserTimeoutException,
    SecurityPolicyViolationException,
)
from ulpf_parser_runtime.framing import FramedRecord, FramingResult, RecordFramer
from ulpf_parser_runtime.models import (
    DetectedFormat,
    DetectedSource,
    DetectionResult,
    ExtractedField,
    FieldProvenance,
    NormalizationStatus,
    Origin,
    ParserCandidate,
    ParseResult,
    ParserMetadata,
    ParserSelection,
    ParseStatus,
)

__all__ = [
    "DecodedPayload",
    "DetectedFormat",
    "DetectedSource",
    "DetectionResult",
    "EncodingStatus",
    "ErrorCode",
    "ErrorSeverity",
    "ExtractedField",
    "FieldProvenance",
    "FramedRecord",
    "FramingResult",
    "NestingLimitExceededException",
    "NormalizationStatus",
    "Origin",
    "OversizedRecordException",
    "ParseError",
    "ParseResult",
    "ParseStatus",
    "ParserCandidate",
    "ParserException",
    "ParserMetadata",
    "ParserSelection",
    "ParserTimeoutException",
    "RecordFramer",
    "SecurityPolicyViolationException",
    "prepare_payload",
]
