"""Safe, bounded rule language operators for ULPF Phase 5.

Guarantees:
- Zero dynamic code execution (eval/exec forbidden)
- Bounded regex matching (prevents catastrophic backtracking)
- Safe deep path resolution
- Bounded expression evaluation
"""

import re
from typing import Any

from ulpf_mapping.errors import MappingSafetyError

# Bounded constraints
MAX_REGEX_PATTERN_LEN = 256
MAX_STRING_EVAL_LEN = 10000

# Bracket index notation: e.g. "items[2]"
_BRACKET_RE = re.compile(r"^([^\[]+)\[(\d+)\]$")


def get_nested_field(doc: dict[str, Any], path: str) -> Any:
    """Retrieve value from a dictionary using dot-separated notation.

    Supports:
    - Exact key: "action"
    - Dot path: "nested.a.b"
    - Dot-numeric index: "items.0"
    - Bracket index notation: "items[0]", "nested.list[1]"

    Negative indices and out-of-bounds indices return None (safe).
    Transparent fallback lookup in 'event' and 'unmapped_fields'.
    """
    if not path or not isinstance(doc, dict):
        return None

    # 1. Exact match at current level
    if path in doc:
        return doc[path]

    # 2. Hierarchical navigation (dot-separated + bracket notation)
    parts = path.split(".")
    curr: Any = doc
    found = True
    for p in parts:
        # Handle bracket notation within a segment: e.g. "items[2]"
        m = _BRACKET_RE.match(p)
        if m:
            key, raw_idx = m.group(1), m.group(2)
            idx = int(raw_idx)
            # First navigate to the key
            if isinstance(curr, dict) and key in curr:
                container = curr[key]
            else:
                found = False
                break
            # Then index (non-negative only, guard against OOB)
            if isinstance(container, (list, tuple)) and 0 <= idx < len(container):
                curr = container[idx]
            else:
                found = False
                break
        elif isinstance(curr, dict) and p in curr:
            curr = curr[p]
        elif isinstance(curr, list | tuple) and p.isdigit():
            idx = int(p)
            if 0 <= idx < len(curr):
                curr = curr[idx]
            else:
                found = False
                break
        else:
            found = False
            break
    if found:
        return curr

    # 3. Transparent lookup inside 'event' or 'unmapped_fields'
    if "event" in doc and isinstance(doc["event"], dict):
        res = get_nested_field(doc["event"], path)
        if res is not None:
            return res

    if "unmapped_fields" in doc and isinstance(doc["unmapped_fields"], dict):
        res = get_nested_field(doc["unmapped_fields"], path)
        if res is not None:
            return res

    return None


def validate_regex_safety(pattern: str) -> re.Pattern[str]:
    """Inspect regex for nested quantifiers and catastrophic backtracking patterns."""
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        raise MappingSafetyError(
            f"Regex pattern exceeds maximum allowed length of {MAX_REGEX_PATTERN_LEN} characters."
        )

    # Detect nested quantifiers such as (a+)+ or (.*)* or (\w+)*
    nested_quantifiers = [
        r"\([^)]*[+*]\)[+*]",
        r"\([^)]*\{[0-9,]+\}\)[+*]",
        r"\([^)]*[+*]\)\{[0-9,]+\}",
    ]
    for nq in nested_quantifiers:
        if re.search(nq, pattern):
            raise MappingSafetyError(
                f"Potential ReDoS vulnerability detected in pattern '{pattern}'."
            )

    try:
        return re.compile(pattern)
    except re.error as e:
        raise MappingSafetyError(f"Invalid regular expression '{pattern}': {e}") from e


def evaluate_condition(field_value: Any, op: str, target_val: Any) -> bool:
    """Safely evaluate a rule condition without dynamic code execution."""
    if op == "exists":
        return field_value is not None
    if op in ("is_null", "not_exists"):
        return field_value is None

    if field_value is None:
        return False

    # String operations
    val_str = str(field_value)
    if len(val_str) > MAX_STRING_EVAL_LEN:
        val_str = val_str[:MAX_STRING_EVAL_LEN]

    if op == "equals":
        if isinstance(target_val, int | float) and isinstance(field_value, int | float | str):
            try:
                return float(field_value) == float(target_val)
            except (ValueError, TypeError):
                pass
        return str(field_value).strip().lower() == str(target_val).strip().lower()

    if op == "not_equals":
        return str(field_value).strip().lower() != str(target_val).strip().lower()

    if op == "in":
        if isinstance(target_val, list | tuple | set):
            target_set = {str(x).strip().lower() for x in target_val}
            return str(field_value).strip().lower() in target_set
        return False

    if op == "not_in":
        if isinstance(target_val, list | tuple | set):
            target_set = {str(x).strip().lower() for x in target_val}
            return str(field_value).strip().lower() not in target_set
        return True

    if op == "contains":
        return str(target_val).strip().lower() in val_str.lower()

    if op == "prefix":
        return val_str.lower().startswith(str(target_val).strip().lower())

    if op == "suffix":
        return val_str.lower().endswith(str(target_val).strip().lower())

    if op in ("regex_bounded", "regex_match"):
        if not isinstance(target_val, str):
            return False
        compiled = validate_regex_safety(target_val)
        return bool(compiled.search(val_str))

    if op in ("greater_than", "greater_than_equal", "less_than", "less_than_equal"):
        try:
            f_num = float(field_value)
            t_num = float(target_val)
            if op == "greater_than":
                return f_num > t_num
            if op == "greater_than_equal":
                return f_num >= t_num
            if op == "less_than":
                return f_num < t_num
            if op == "less_than_equal":
                return f_num <= t_num
        except (ValueError, TypeError):
            return False

    if op == "numeric_compare":
        # target_val should be dict with {"cmp": ">", "val": 5}
        if isinstance(target_val, dict) and "cmp" in target_val and "val" in target_val:
            try:
                f_num = float(field_value)
                t_num = float(target_val["val"])
                cmp_op = target_val["cmp"]
                if cmp_op == ">":
                    return f_num > t_num
                if cmp_op == ">=":
                    return f_num >= t_num
                if cmp_op == "<":
                    return f_num < t_num
                if cmp_op == "<=":
                    return f_num <= t_num
                if cmp_op == "==":
                    return f_num == t_num
                if cmp_op == "!=":
                    return f_num != t_num
            except (ValueError, TypeError):
                return False

    return False
