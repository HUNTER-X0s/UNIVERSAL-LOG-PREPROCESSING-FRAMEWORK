"""Linux Auditd daemon telemetry parser for ULPF Phase 3 (Tier C).

Parses Linux audit daemon messages:
  type=TYPE msg=audit(epoch.msec:serial): key=val key="val" key='val'

Extracts:
- record_type (e.g. SYSCALL, EXECVE, CWD, PATH, USER_AUTH, AVC)
- audit_epoch, audit_serial
- comm, exe, key, success, exit, arch, syscall
- auid, uid, gid, euid, ppid, pid
- command arguments (a0, a1, a2, etc.)

Adheres to:
- Spec §15: Vendor-Specific Specialized Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import re
import time
from typing import Any

from ulpf_parser_runtime.errors import ErrorCode, ErrorSeverity, ParseError
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

# Matches type=TYPE msg=audit(epoch:serial):
RE_AUDITD_HEADER = re.compile(r"^type=([A-Z0-9_]+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):")
RE_AUDITD_KV = re.compile(r'([a-zA-Z0-9_-]+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s]*))')


class LinuxAuditdParser(BaseParser):
    """Deterministic parser for Linux Auditd daemon telemetry."""

    metadata = ParserMetadata(
        parser_id="parser.linux.auditd",
        version="1.0.0",
        supported_formats=("linux_auditd", "key_value"),
        supported_vendors=("Linux", "RedHat", "Canonical", "SUSE"),
        supported_products=("auditd", "Linux Kernel Audit", "SELinux"),
        tier="C",
        description="Linux Audit daemon (auditd) security telemetry parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        match = RE_AUDITD_HEADER.search(text)
        if not match:
            err = ParseError(
                code=ErrorCode.UNKNOWN_FORMAT,
                stage="linux_auditd",
                message="Record does not match Linux auditd header pattern",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="linux_auditd",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        rec_type = match.group(1)
        epoch = match.group(2)
        serial = match.group(3)

        fields: dict[str, Any] = {
            "record_type": self.make_field(
                "record_type", rec_type, Origin.OBSERVED, raw_locator="auditd:type"
            ),
            "audit_epoch": self.make_field(
                "audit_epoch", epoch, Origin.OBSERVED, raw_locator="auditd:epoch"
            ),
            "audit_serial": self.make_field(
                "audit_serial", serial, Origin.OBSERVED, raw_locator="auditd:serial"
            ),
        }

        # Rest of record contains key=val pairs
        body = text[match.end() :].strip()
        pair_count = 0
        for kv_match in RE_AUDITD_KV.finditer(body):
            k = kv_match.group(1)
            v = (
                kv_match.group(2)
                if kv_match.group(2) is not None
                else (kv_match.group(3) if kv_match.group(3) is not None else kv_match.group(4))
            )
            v = (v or "").strip()
            fields[k] = self.make_field(k, v, Origin.OBSERVED, raw_locator=f"auditd:{k}")
            pair_count += 1
            if pair_count >= 500:
                break

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="linux_auditd",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
