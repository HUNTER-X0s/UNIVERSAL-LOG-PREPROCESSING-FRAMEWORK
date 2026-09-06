"""Cloud audit and telemetry parser for ULPF Phase 3 (Tier C).

Parses cloud control plane and network telemetry:
- AWS CloudTrail (JSON event structure)
- AWS VPC Flow Logs (space-delimited v2/v3/v5 format)
- Azure Activity Logs / Azure NSG Flow (JSON)
- Google Cloud (GCP) Audit Logs (JSON protoPayload)

Adheres to:
- Spec §15: Vendor-Specific Specialized Parsers
- Spec §41: Resource Bounds
- Spec §45: Deterministic Parsing
"""

import json
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

# AWS VPC Flow Log default field layout (Version 2)
VPC_FLOW_FIELDS = (
    "version",
    "account_id",
    "interface_id",
    "src_addr",
    "dst_addr",
    "src_port",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
)


class CloudAuditParser(BaseParser):
    """Deterministic parser for AWS, Azure, and GCP cloud audit and flow telemetry."""

    metadata = ParserMetadata(
        parser_id="parser.cloud.audit_flow",
        version="1.0.0",
        supported_formats=("cloud_audit_json", "aws_vpc_flow", "json"),
        supported_vendors=("AWS", "Azure", "GCP", "Amazon", "Microsoft", "Google"),
        supported_products=("CloudTrail", "VPC Flow", "Activity Log", "AuditLog"),
        tier="C",
        description="AWS CloudTrail, AWS VPC Flow, Azure Activity, and GCP Audit parser",
    )

    def parse(self, record: FramedRecord) -> ParseResult:
        t0 = time.perf_counter()
        text = record.text.strip()

        # Check for AWS VPC Flow Log (space-separated starting with version number like '2 ')
        tokens = text.split()
        if len(tokens) >= 14 and tokens[0].isdigit() and tokens[0] in ("2", "3", "4", "5"):
            fields: dict[str, Any] = {}
            for idx, flow_val in enumerate(tokens[: len(VPC_FLOW_FIELDS)]):
                fname = VPC_FLOW_FIELDS[idx]
                if flow_val != "-":
                    fields[fname] = self.make_field(
                        fname,
                        flow_val,
                        Origin.OBSERVED,
                        raw_locator=f"vpcflow:{fname}",
                    )

            return ParseResult(
                status=ParseStatus.PARSED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="aws_vpc_flow",
                extracted_fields=fields,
                duration_ms=self.measure_duration(t0),
            )

        # JSON branch for CloudTrail, Azure, GCP
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            err = ParseError(
                code=ErrorCode.MALFORMED_JSON,
                stage="cloud_audit",
                message=f"Cloud audit JSON parse failed: {str(exc)[:256]}",
                severity=ErrorSeverity.ERROR,
                recoverable=False,
            )
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="cloud_audit_json",
                extracted_fields={},
                unmapped_fields={"raw_text": text},
                unparsed_fragments=(text,),
                errors=(err,),
                duration_ms=self.measure_duration(t0),
            )

        if not isinstance(data, dict):
            return ParseResult(
                status=ParseStatus.FAILED,
                parser_id=self.metadata.parser_id,
                parser_version=self.metadata.version,
                format="cloud_audit_json",
                extracted_fields={},
                unmapped_fields={"raw_value": data},
                duration_ms=self.measure_duration(t0),
            )

        fields = {}

        # 1. AWS CloudTrail detection
        if "eventSource" in data or "eventName" in data or "awsRegion" in data:
            for k in (
                "eventVersion",
                "eventTime",
                "eventSource",
                "eventName",
                "awsRegion",
                "sourceIPAddress",
                "userAgent",
                "errorCode",
                "errorMessage",
                "requestID",
                "eventType",
            ):
                if k in data and data[k] is not None:
                    fields[k] = self.make_field(
                        k, data[k], Origin.OBSERVED, raw_locator=f"cloudtrail:{k}"
                    )

            if "userIdentity" in data and isinstance(data["userIdentity"], dict):
                ui = data["userIdentity"]
                for u_key in ("type", "principalId", "arn", "accountId", "userName"):
                    if u_key in ui:
                        fields[f"userIdentity.{u_key}"] = self.make_field(
                            f"userIdentity.{u_key}",
                            ui[u_key],
                            Origin.OBSERVED,
                            raw_locator=f"cloudtrail:userIdentity.{u_key}",
                        )

            fields["cloud_provider"] = self.make_field("cloud_provider", "AWS", Origin.DERIVED)

        # 2. Azure Activity Log
        elif "operationName" in data or "resourceId" in data or "callerIpAddress" in data:
            for k in (
                "time",
                "resourceId",
                "operationName",
                "category",
                "resultType",
                "caller",
                "callerIpAddress",
                "correlationId",
                "level",
                "subscriptionId",
            ):
                if k in data and data[k] is not None:
                    fields[k] = self.make_field(
                        k, data[k], Origin.OBSERVED, raw_locator=f"azure:{k}"
                    )
            fields["cloud_provider"] = self.make_field("cloud_provider", "Azure", Origin.DERIVED)

        # 3. GCP Audit Log
        elif "protoPayload" in data or "resource" in data:
            if "protoPayload" in data and isinstance(data["protoPayload"], dict):
                proto = data["protoPayload"]
                for k in ("serviceName", "methodName", "resourceName"):
                    if k in proto:
                        fields[k] = self.make_field(
                            k, proto[k], Origin.OBSERVED, raw_locator=f"gcp:protoPayload.{k}"
                        )
                if "authenticationInfo" in proto and isinstance(proto["authenticationInfo"], dict):
                    ai = proto["authenticationInfo"]
                    if "principalEmail" in ai:
                        fields["principalEmail"] = self.make_field(
                            "principalEmail", ai["principalEmail"], Origin.OBSERVED
                        )
            for k in ("timestamp", "severity", "logName", "insertId"):
                if k in data and data[k] is not None:
                    fields[k] = self.make_field(k, data[k], Origin.OBSERVED, raw_locator=f"gcp:{k}")
            fields["cloud_provider"] = self.make_field("cloud_provider", "GCP", Origin.DERIVED)

        else:
            # Generic JSON cloud object
            for k, v in data.items():
                if not isinstance(v, dict | list):
                    fields[k] = self.make_field(k, v, Origin.OBSERVED)

        return ParseResult(
            status=ParseStatus.PARSED,
            parser_id=self.metadata.parser_id,
            parser_version=self.metadata.version,
            format="cloud_audit_json",
            extracted_fields=fields,
            duration_ms=self.measure_duration(t0),
        )
