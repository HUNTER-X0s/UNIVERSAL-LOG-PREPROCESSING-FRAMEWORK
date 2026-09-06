"""Combined Log Format (CLF) and Common Access Log parser for NGINX/Apache (Tier B).

Format standard:
  remote_host remote_logname remote_user [time] "request" status bytes "referer" "user_agent"

Extracts:
- client_ip / remote_host, remote_logname, remote_user
- timestamp, raw_request
- http_method, request_uri, http_version
- status_code, response_bytes
- referer, user_agent

Adheres to:
- Spec §24: Web Server Log Strategy
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

# Bounded regex for Combined Log Format
RE_COMBINED_LOG = re.compile(
    r"^([^\s]+)\s+"  # 1: remote_host / client_ip
    r"([^\s]+)\s+"  # 2: remote_logname
    r"([^\s]+)\s+"  # 3: remote_user
    r"\[([^\]]+)\]\s+"  # 4: time
    r'"([^"\\]*(?:\\.[^"\\]*)*)"\s+'  # 5: request
    r"(\d{3})\s+"  # 6: status
    r"([0-9\-]+)"  # 7: bytes
    r'(?:\s+"([^"\\]*(?:\\.[^"\\]*)*)")?'  # 8: referer (optional)
    r'(?:\s+"([^"\\]*(?:\\.[^"\\]*)*)")?',  # 9: user_agent (optional)
)


class WebAccessLogParser(BaseParser):
    """Deterministic parser for NGINX and Apache Combined/Common access logs."""

    metadata = ParserMetadata(
        parser_id="parser.web.access",
        version="1.0.0",
        supported_formats=("combined_access", "clf_access", "web_access"),
        supported_vendors=("NGINX", "Apache", "Caddy", "Web"),
        supported_products=("NGINX", "httpd", "Apache", "Web Server"),
        tier="B",
        description="NGINX and Apache Combined Log Format (CLF) web access parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        match = RE_COMBINED_LOG.match(text)
        if not match:
            err = ParseError(
                code=ErrorCode.MALFORMED_RECORD,
                stage="web_access",
                message="Record does not match Combined Log Format",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="combined_access",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        client_ip, ident, user, ts, req, status, size, referer, user_agent = match.groups()

        fields: dict[str, Any] = {
            "client_ip": self.make_field(
                "client_ip", client_ip, Origin.OBSERVED, raw_locator="clf:client_ip"
            ),
            "timestamp": self.make_field("timestamp", ts, Origin.OBSERVED, raw_locator="clf:time"),
            "status_code": self.make_field(
                "status_code", int(status), Origin.OBSERVED, raw_locator="clf:status"
            ),
        }

        if user != "-":
            fields["remote_user"] = self.make_field("remote_user", user, Origin.OBSERVED)
        if size != "-":
            fields["response_bytes"] = self.make_field("response_bytes", int(size), Origin.OBSERVED)
        if referer and referer != "-":
            fields["referer"] = self.make_field("referer", referer, Origin.OBSERVED)
        if user_agent and user_agent != "-":
            fields["user_agent"] = self.make_field("user_agent", user_agent, Origin.OBSERVED)

        # Deconstruct request line: METHOD URI HTTP/VERSION
        req_parts = req.split()
        if len(req_parts) == 3:
            fields["http_method"] = self.make_field("http_method", req_parts[0], Origin.DERIVED)
            fields["request_uri"] = self.make_field("request_uri", req_parts[1], Origin.DERIVED)
            fields["http_version"] = self.make_field("http_version", req_parts[2], Origin.DERIVED)
        else:
            fields["raw_request"] = self.make_field("raw_request", req, Origin.OBSERVED)

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="combined_access",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
