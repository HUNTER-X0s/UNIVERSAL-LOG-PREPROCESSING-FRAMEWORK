"""Sample and Field Profiler for ULPF Phase 5 Onboarding.

Inspects raw and parsed log samples, detects formats and sources, profiles field
structural properties, and constructs typed SourceProfile models.
"""

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

from ulpf_onboarding.models import FieldProfile, SourceProfile

RE_IPV4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
RE_HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RE_ISO_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


class SampleProfiler:
    """Profiles raw and structured log samples without mutating source data."""

    @staticmethod
    def detect_format(raw_sample: str | bytes) -> str:
        """Heuristically identify log telemetry format."""
        if isinstance(raw_sample, bytes):
            text = raw_sample.decode("utf-8", errors="replace").strip()
        else:
            text = raw_sample.strip()

        if text.startswith("{") and text.endswith("}"):
            try:
                json.loads(text)
                return "json"
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        if text.startswith("<") and ">" in text[:10]:
            return "syslog.rfc5424" if re.match(r"^<\d+>\d\s", text) else "syslog.rfc3164"

        if "CEF:" in text:
            return "cef"
        if "LEEF:" in text:
            return "leef"
        if "=" in text and " " in text and not text.startswith("{"):
            return "kv"
        if "," in text and "\n" in text:
            return "csv"

        return "generic.text"

    @staticmethod
    def infer_value_type(val: Any) -> str:
        """Infer granular semantic/primitive type for a value."""
        if val is None:
            return "null"
        if isinstance(val, bool):
            return "boolean"
        if isinstance(val, int):
            return "integer"
        if isinstance(val, float):
            return "float"
        if isinstance(val, dict | list):
            return "object" if isinstance(val, dict) else "array"

        s_val = str(val).strip()
        if RE_ISO_TIMESTAMP.match(s_val):
            return "timestamp"
        if RE_IPV4.match(s_val):
            try:
                ipaddress.ip_address(s_val)
                return "ip"
            except ValueError:
                pass
        if RE_HASH_SHA256.match(s_val) or RE_HASH_MD5.match(s_val):
            return "hash"
        if RE_DOMAIN.match(s_val):
            return "domain"

        return "string"

    @classmethod
    def profile_samples(
        cls,
        samples: list[dict[str, Any]],
        vendor: str = "Unknown",
        product: str = "Telemetry",
        format_id: str | None = None,
    ) -> SourceProfile:
        """Profile a batch of parsed dictionary samples and generate a SourceProfile."""
        if not samples:
            raise ValueError("Cannot profile an empty sample set.")

        field_occurrences: dict[str, list[Any]] = {}
        for sample in samples:
            cls._extract_field_values("", sample, field_occurrences)

        total_samples = len(samples)
        field_profiles: list[FieldProfile] = []

        for f_path, vals in sorted(field_occurrences.items()):
            non_null_vals = [v for v in vals if v is not None]
            null_freq = (total_samples - len(non_null_vals)) / total_samples
            unique_vals = {str(v) for v in non_null_vals}
            cardinality = len(unique_vals)

            # Infer dominant type
            inferred = "string"
            if non_null_vals:
                type_counts: dict[str, int] = {}
                for v in non_null_vals:
                    t = cls.infer_value_type(v)
                    type_counts[t] = type_counts.get(t, 0) + 1
                inferred = max(type_counts.items(), key=lambda x: x[1])[0]

            field_profiles.append(
                FieldProfile(
                    path=f_path,
                    inferred_type=inferred,
                    null_frequency=round(null_freq, 4),
                    sample_values=tuple(sorted(list(unique_vals))[:5]),
                    cardinality=cardinality,
                )
            )

        detected_fmt = format_id or "json"
        p_id = f"profile.{vendor.lower()}.{product.lower()}".replace(" ", "_")
        now_iso = datetime.now(UTC).isoformat()

        # Checksum over field paths
        csum = hashlib.sha256("|".join(f.path for f in field_profiles).encode("utf-8")).hexdigest()

        return SourceProfile(
            profile_id=p_id,
            version="1.0.0",
            vendor=vendor,
            product=product,
            format=detected_fmt,
            fields=field_profiles,
            description=f"Generated profile for {vendor} {product} ({total_samples} samples)",
            status="ACTIVE",
            checksum=csum,
            created_at=now_iso,
            updated_at=now_iso,
        )

    @classmethod
    def _extract_field_values(
        cls,
        prefix: str,
        obj: Any,
        accumulator: dict[str, list[Any]],
    ) -> None:
        """Recursively collect values for every dotted path in the document."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    cls._extract_field_values(p, v, accumulator)
                else:
                    if p not in accumulator:
                        accumulator[p] = []
                    accumulator[p].append(v)
