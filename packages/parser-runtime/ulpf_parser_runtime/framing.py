"""Bounded record framing engine for ULPF Phase 3.

Adheres to:
- Spec §6: Record Framing (LF, CRLF, single-record, multiline, stack traces, CRI partial records)
- Spec §41: Security: Resource Bounds (bounded lines, bounded record bytes, memory safety)
- Spec §77: Application Stack Trace Handling
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

# Common multiline continuation patterns (Java, Python, generic stack traces, syslog indent)
JAVA_STACK_TRACE_LINE = re.compile(r"^\s+(?:at |Caused by:|\.\.\. \d+ more)", re.IGNORECASE)
PYTHON_TRACEBACK_LINE = re.compile(r'^\s+(?:File "[^"]+", line \d+|[a-zA-Z_]\w*: )')
INDENTED_CONTINUATION = re.compile(r"^[ \t]+")


@dataclass(frozen=True, slots=True)
class FramedRecord:
    """A bounded, coherent single record extracted from an intake stream or payload."""

    record_index: int
    text: str
    raw_bytes: bytes
    start_byte_offset: int
    end_byte_offset: int
    line_count: int
    is_multiline: bool = False
    is_truncated: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class FramingResult:
    """The outcome of framing an input payload into records."""

    records: tuple[FramedRecord, ...]
    total_records: int
    total_bytes: int
    is_truncated: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)


class RecordFramer:
    """Resource-bounded record framer supporting single-line and multiline telemetry."""

    def __init__(
        self,
        max_record_bytes: int = 1_048_576,  # 1 MB
        max_line_bytes: int = 262_144,  # 256 KB
        max_multiline_lines: int = 1_000,
        max_total_records: int = 100_000,
    ) -> None:
        self.max_record_bytes = max_record_bytes
        self.max_line_bytes = max_line_bytes
        self.max_multiline_lines = max_multiline_lines
        self.max_total_records = max_total_records

    def frame_single(self, text: str, raw_bytes: bytes | None = None) -> FramingResult:
        """Frame payload as an explicit single record (e.g. JSON document, XML tree)."""
        payload_bytes = raw_bytes if raw_bytes is not None else text.encode("utf-8")
        byte_len = len(payload_bytes)
        truncated = False
        warnings: list[str] = []

        if byte_len > self.max_record_bytes:
            truncated = True
            warnings.append(
                f"Record truncated: size {byte_len} exceeds max {self.max_record_bytes}"
            )
            payload_bytes = payload_bytes[: self.max_record_bytes]
            text = text[: self.max_record_bytes]

        record = FramedRecord(
            record_index=0,
            text=text,
            raw_bytes=payload_bytes,
            start_byte_offset=0,
            end_byte_offset=len(payload_bytes),
            line_count=text.count("\n") + 1,
            is_multiline="\n" in text,
            is_truncated=truncated,
            warnings=tuple(warnings),
        )
        return FramingResult(
            records=(record,),
            total_records=1,
            total_bytes=len(payload_bytes),
            is_truncated=truncated,
            warnings=tuple(warnings),
        )

    def frame_lines(self, text: str, raw_bytes: bytes | None = None) -> FramingResult:
        """Frame line-delimited records, supporting both LF and CRLF."""
        payload_bytes = raw_bytes if raw_bytes is not None else text.encode("utf-8")
        records: list[FramedRecord] = []
        warnings: list[str] = []
        truncated = False

        # Split preserving boundaries
        lines = text.splitlines(keepends=True)
        byte_offset = 0

        for idx, line in enumerate(lines):
            if idx >= self.max_total_records:
                warnings.append(f"Reached maximum record limit of {self.max_total_records}")
                truncated = True
                break

            line_bytes = line.encode("utf-8")
            line_len = len(line_bytes)

            line_truncated = False
            line_warnings: list[str] = []
            if line_len > self.max_line_bytes:
                line_truncated = True
                line_warnings.append(
                    f"Line {idx} truncated: size {line_len} exceeds max {self.max_line_bytes}"
                )
                line_bytes = line_bytes[: self.max_line_bytes]
                line = line[: self.max_line_bytes]

            stripped_text = line.rstrip("\r\n")
            # We preserve empty lines as valid records if they appear in streams
            record = FramedRecord(
                record_index=idx,
                text=stripped_text,
                raw_bytes=line_bytes,
                start_byte_offset=byte_offset,
                end_byte_offset=byte_offset + len(line_bytes),
                line_count=1,
                is_multiline=False,
                is_truncated=line_truncated,
                warnings=tuple(line_warnings),
            )
            records.append(record)
            byte_offset += line_len

        return FramingResult(
            records=tuple(records),
            total_records=len(records),
            total_bytes=len(payload_bytes),
            is_truncated=truncated,
            warnings=tuple(warnings),
        )

    def frame_multiline(
        self,
        text: str,
        is_continuation: Callable[[str], bool] | None = None,
        raw_bytes: bytes | None = None,
    ) -> FramingResult:
        """Frame multiline records (e.g. stack traces, continuation lines).

        Lines matching `is_continuation(line)` are appended to the preceding record,
        up to `max_multiline_lines` and `max_record_bytes`.
        """
        payload_bytes = raw_bytes if raw_bytes is not None else text.encode("utf-8")
        check_continuation = (
            is_continuation if is_continuation is not None else self.default_is_continuation
        )

        lines = text.splitlines(keepends=True)
        if not lines:
            return FramingResult(records=(), total_records=0, total_bytes=0)

        records: list[FramedRecord] = []
        warnings: list[str] = []
        truncated = False

        current_lines: list[str] = []
        current_byte_start = 0
        current_byte_len = 0
        current_line_count = 0
        record_idx = 0
        accumulated_offset = 0

        def flush_current() -> None:
            nonlocal record_idx, current_lines, current_byte_start
            nonlocal current_byte_len, current_line_count
            if not current_lines:
                return

            full_text = "".join(current_lines).rstrip("\r\n")
            rec_bytes = "".join(current_lines).encode("utf-8")
            rec_truncated = False
            rec_warnings: list[str] = []

            if len(rec_bytes) > self.max_record_bytes:
                rec_truncated = True
                msg = (
                    f"Multiline record {record_idx} truncated: "
                    f"{len(rec_bytes)} > {self.max_record_bytes}"
                )
                rec_warnings.append(msg)
                rec_bytes = rec_bytes[: self.max_record_bytes]
                full_text = full_text[: self.max_record_bytes]

            records.append(
                FramedRecord(
                    record_index=record_idx,
                    text=full_text,
                    raw_bytes=rec_bytes,
                    start_byte_offset=current_byte_start,
                    end_byte_offset=current_byte_start + current_byte_len,
                    line_count=current_line_count,
                    is_multiline=current_line_count > 1,
                    is_truncated=rec_truncated,
                    warnings=tuple(rec_warnings),
                )
            )
            record_idx += 1
            current_lines = []
            current_byte_len = 0
            current_line_count = 0

        for line in lines:
            if record_idx >= self.max_total_records:
                warnings.append(f"Reached maximum record limit of {self.max_total_records}")
                truncated = True
                break

            line_bytes_len = len(line.encode("utf-8"))
            is_cont = bool(current_lines and check_continuation(line))

            if is_cont and current_line_count < self.max_multiline_lines:
                current_lines.append(line)
                current_byte_len += line_bytes_len
                current_line_count += 1
            else:
                flush_current()
                current_byte_start = accumulated_offset
                current_lines.append(line)
                current_byte_len = line_bytes_len
                current_line_count = 1

            accumulated_offset += line_bytes_len

        flush_current()

        return FramingResult(
            records=tuple(records),
            total_records=len(records),
            total_bytes=len(payload_bytes),
            is_truncated=truncated,
            warnings=tuple(warnings),
        )

    @staticmethod
    def default_is_continuation(line: str) -> bool:
        """Heuristic check for common application stack traces and indented continuations."""
        return bool(
            JAVA_STACK_TRACE_LINE.match(line)
            or PYTHON_TRACEBACK_LINE.match(line)
            or INDENTED_CONTINUATION.match(line)
        )
