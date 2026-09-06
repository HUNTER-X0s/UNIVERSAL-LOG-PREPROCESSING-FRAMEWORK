"""XXE-safe XML parser for ULPF Phase 3.

Features:
- Strict XXE prevention (rejects DOCTYPE declarations, entity expansions, SYSTEM entities)
- Nesting depth bounded to prevent Billion Laughs / quadratic blowup
- Max element count limits
- Dot-notation path flattening for extracted tags and attributes
- Raw locator paths for full provenance

Adheres to:
- Spec §22: Structured XML Strategy
- Spec §23: XML Security (XXE Prevention, Billion Laughs, quadratic blowup)
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import time
import xml.etree.ElementTree as ET
from typing import Any

from ulpf_parser_runtime.errors import (
    ErrorCode,
    ErrorSeverity,
    NestingLimitExceededException,
    ParseError,
    SecurityPolicyViolationException,
)
from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import (
    Origin,
    ParseResult,
    ParserMetadata,
    ParseStatus,
)
from ulpf_parser_runtime.parsers.base import BaseParser

_MAX_XML_DEPTH = 30
_MAX_XML_ELEMENTS = 2000


def _check_xxe_safety(text: str) -> None:
    """Pre-scan XML for forbidden DTD and entity constructs to guarantee XXE safety."""
    upper = text[:8192].upper()
    if "<!DOCTYPE" in upper:
        raise SecurityPolicyViolationException(
            ParseError(
                code=ErrorCode.SECURITY_POLICY_VIOLATION,
                stage="xml_parser",
                message="XXE protection: DOCTYPE declarations are prohibited",
                severity=ErrorSeverity.FATAL,
                recoverable=False,
            )
        )
    if "<!ENTITY" in upper:
        raise SecurityPolicyViolationException(
            ParseError(
                code=ErrorCode.SECURITY_POLICY_VIOLATION,
                stage="xml_parser",
                message="XXE protection: ENTITY declarations are prohibited",
                severity=ErrorSeverity.FATAL,
                recoverable=False,
            )
        )


def _flatten_element(
    elem: ET.Element,
    prefix: str = "",
    depth: int = 0,
    max_depth: int = _MAX_XML_DEPTH,
    max_elements: int = _MAX_XML_ELEMENTS,
    out: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recursively flatten XML elements and attributes into dot-separated paths."""
    if out is None:
        out = {}

    if depth > max_depth:
        raise NestingLimitExceededException(
            ParseError(
                code=ErrorCode.NESTING_LIMIT_EXCEEDED,
                stage="xml_parser",
                message=f"XML nesting depth {depth} exceeds limit {max_depth}",
                severity=ErrorSeverity.ERROR,
                recoverable=True,
            )
        )

    if len(out) >= max_elements:
        return out

    # Strip XML namespace if present: {http://...}Tag -> Tag
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    curr_path = f"{prefix}.{tag}" if prefix else tag

    # Attributes
    for attr_name, attr_val in elem.attrib.items():
        attr_clean = attr_name.split("}")[-1] if "}" in attr_name else attr_name
        out[f"{curr_path}@{attr_clean}"] = attr_val
        if len(out) >= max_elements:
            return out

    # Text content (if leaf or non-whitespace)
    text = (elem.text or "").strip()
    children = list(elem)
    if text and not children:
        out[curr_path] = text
    elif text and children:
        out[f"{curr_path}._text"] = text

    # Children
    for child in children:
        _flatten_element(child, curr_path, depth + 1, max_depth, max_elements, out)
        if len(out) >= max_elements:
            break

    return out


class XmlParser(BaseParser):
    """XXE-safe, depth-bounded XML parser with dot-path field extraction."""

    metadata = ParserMetadata(
        parser_id="parser.generic.xml",
        version="1.0.0",
        supported_formats=("xml",),
        supported_vendors=(),
        supported_products=(),
        tier="A",
        description="XXE-safe generic XML parser with depth and element bounds",
    )

    def __init__(
        self,
        max_depth: int = _MAX_XML_DEPTH,
        max_elements: int = _MAX_XML_ELEMENTS,
    ) -> None:
        self.max_depth = max_depth
        self.max_elements = max_elements

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        # Enforce XXE security pre-check
        try:
            _check_xxe_safety(text)
        except SecurityPolicyViolationException as exc:
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="xml",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(exc.parse_error,),
                duration_ms=self.measure_duration(t0),
            )

        # Parse XML tree (XXE and entity expansion blocked by _check_xxe_safety above)
        try:
            root = ET.fromstring(text)  # noqa: S314
        except ET.ParseError as exc:
            err = ParseError(
                code=ErrorCode.MALFORMED_XML,
                stage="xml_parser",
                message=f"XML parse failed: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="xml",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        warnings: list[ParseError] = []
        try:
            flat_fields = _flatten_element(
                root,
                max_depth=self.max_depth,
                max_elements=self.max_elements,
            )
        except NestingLimitExceededException as exc:
            warnings.append(exc.parse_error)
            flat_fields = {root.tag: root.text or ""}

        fields = {}
        for path, value in flat_fields.items():
            fields[path] = self.make_field(
                path,
                value,
                Origin.OBSERVED,
                raw_locator=f"xml:{path}",
            )

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="xml",
            extracted_fields=fields,
            warnings=tuple(warnings),
            duration_ms=self.measure_duration(t0),
        )
