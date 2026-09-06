"""Safe encoding detection, preparation, and loss accounting for ULPF Phase 3.

Adheres to:
- Spec §7: Encoding Preprocessing
- Spec §5: Raw Data Preservation (raw bytes remain authoritative)
- Spec §79: Data Loss Accounting (record when lossy decoding occurs)
"""

from dataclasses import dataclass
from enum import StrEnum

UTF8_BOM = b"\xef\xbb\xbf"


class EncodingStatus(StrEnum):
    """Classification of the decoded raw payload."""

    VALID = "VALID"
    VALID_WITH_BOM = "VALID_WITH_BOM"
    LOSSY_DECODE_REQUIRED = "LOSSY_DECODE_REQUIRED"
    INVALID_ENCODING = "INVALID_ENCODING"


@dataclass(frozen=True, slots=True)
class DecodedPayload:
    """Safe, immutable decoded text representation linked to authoritative raw bytes."""

    text: str
    encoding: str
    status: EncodingStatus
    bom_detected: bool
    lossy: bool
    byte_length: int
    raw_bytes: bytes


def prepare_payload(raw_bytes: bytes, max_bytes: int = 10 * 1024 * 1024) -> DecodedPayload:
    """Decode raw bytes into safe text while preserving byte-level evidence.

    Handles UTF-8, UTF-8 with BOM, ASCII, and performs deterministic lossy replacement
    when invalid byte sequences are encountered, flagging the loss explicitly.
    """
    byte_length = len(raw_bytes)
    if byte_length > max_bytes:
        raise ValueError(
            f"Payload size {byte_length} bytes exceeds maximum allowed {max_bytes} bytes"
        )

    bom_detected = raw_bytes.startswith(UTF8_BOM)
    bytes_to_decode = raw_bytes[len(UTF8_BOM) :] if bom_detected else raw_bytes

    # Attempt clean strict UTF-8
    try:
        text = bytes_to_decode.decode("utf-8")
        status = EncodingStatus.VALID_WITH_BOM if bom_detected else EncodingStatus.VALID
        return DecodedPayload(
            text=text,
            encoding="utf-8",
            status=status,
            bom_detected=bom_detected,
            lossy=False,
            byte_length=byte_length,
            raw_bytes=raw_bytes,
        )
    except UnicodeDecodeError:
        pass

    # Attempt strict Latin-1 / ISO-8859-1 only if needed, but per spec §7:
    # "Do not silently destroy invalid bytes. If decoding is lossy: record that fact."
    # Use replacement character while marking LOSSY_DECODE_REQUIRED.
    text = bytes_to_decode.decode("utf-8", errors="replace")
    return DecodedPayload(
        text=text,
        encoding="utf-8",
        status=EncodingStatus.LOSSY_DECODE_REQUIRED,
        bom_detected=bom_detected,
        lossy=True,
        byte_length=byte_length,
        raw_bytes=raw_bytes,
    )
