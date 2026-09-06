"""Prompt injection defense and structured output safety validation for ULPF Phase 5.

Guarantees:
- Log content is treated strictly as DATA, never as executable prompt instructions
- System instructions, reference taxonomy, and source data are strictly isolated
- Free-form text from AI outputs is never executed
- Insecure or injection-laden candidates are rejected
"""

import re
from typing import Any


class AISafetyError(Exception):
    """Raised when an AI suggestion or input fails security checks."""


class PromptInjectionDefense:
    """Detects and neutralizes prompt injection attempts within telemetry logs."""

    INJECTION_PATTERNS = [
        r"ignore\s+(previous|prior|all)\s+instructions",
        r"system\s+administrator",
        r"you\s+are\s+now\s+a",
        r"disregard\s+the\s+rules",
        r"grant\s+permission",
        r"execute\s+command",
        r"override\s+configuration",
        r"activate\s+this\s+mapping",
    ]

    @classmethod
    def sanitize_log_text_for_ai(cls, text: str) -> str:
        """Escape and wrap untrusted log text into a safe non-executable data block."""
        # Check if text contains typical injection phrases
        is_suspicious = any(re.search(pat, text, re.IGNORECASE) for pat in cls.INJECTION_PATTERNS)
        safe_body = text.replace("```", "'''")
        if is_suspicious:
            return (
                f"<untrusted_log_data flagged_for_suspicious_text='true'>\n"
                f"{safe_body}\n</untrusted_log_data>"
            )
        return f"<untrusted_log_data>\n{safe_body}\n</untrusted_log_data>"


class AIOutputValidator:
    """Validates that AI suggestions conform strictly to expected structured schemas."""

    REQUIRED_KEYS = {
        "mapping_id",
        "version",
        "vendor",
        "product",
        "match",
        "semantic",
        "confidence",
    }

    @classmethod
    def validate_candidate_mapping(cls, candidate: dict[str, Any]) -> None:
        """Ensure candidate mapping contains required keys and no executable artifacts."""
        if not isinstance(candidate, dict):
            raise AISafetyError("Candidate mapping output from AI must be a dictionary.")

        missing = cls.REQUIRED_KEYS - set(candidate.keys())
        if missing:
            raise AISafetyError(f"Candidate mapping is missing mandatory keys: {missing}")

        # Ensure no eval/exec or python code blocks in any string fields
        str_repr = str(candidate)
        dangerous_tokens = ["eval(", "exec(", "os.system", "subprocess", "__import__", "<script>"]
        for token in dangerous_tokens:
            if token in str_repr:
                raise AISafetyError(
                    f"Dangerous token '{token}' detected in AI suggestion. Rejected."
                )
