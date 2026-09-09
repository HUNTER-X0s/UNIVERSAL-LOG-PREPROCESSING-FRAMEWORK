"""ULPF Phase 14 — Adaptive Parser Canarying & Semantic Differential Testing.

Fulfills Phase 14 Workstreams M, N, and O:
- Safe parser lifecycle: discovered, candidate, tested, approved, active, deprecated, rolled back
- Shadow mode & canary mode differential validation
- Semantic differential testing: compares active vs candidate parser outputs (extracted fields,
  UCE result, error rate, lineage)
- CRITICAL INVARIANT: Candidate parser MUST NOT automatically overwrite an active parser
  without explicit governance approval.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ParserDeploymentStage(str, Enum):
    """Lifecycle stages for parser versions."""

    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass(frozen=True)
class SemanticDiffItem:
    """Detailed difference for a single parsed field."""

    field_name: str
    active_value: Any
    candidate_value: Any
    diff_type: str  # "MATCH", "ADDED", "REMOVED", "VALUE_MISMATCH", "TYPE_CHANGE"


@dataclass(frozen=True)
class CanaryDifferentialReport:
    """Comprehensive semantic differential report comparing active vs candidate parser."""

    source_id: str
    active_parser_version: str
    candidate_parser_version: str
    total_samples: int
    active_success_count: int
    candidate_success_count: int
    semantic_matches: int
    semantic_divergences: int
    field_diffs: list[SemanticDiffItem]
    is_safe_for_promotion: bool
    governance_verdict: str
    timestamp: str


class ParserCanaryEngine:
    """Executes shadow and canary validation between active and candidate parsers."""

    def __init__(self, tolerance_mismatch_rate: float = 0.05) -> None:
        self.tolerance_mismatch_rate = tolerance_mismatch_rate

    def evaluate_shadow(
        self,
        source_id: str,
        active_version: str,
        candidate_version: str,
        active_parse_fn: Callable[[str], dict[str, Any] | None],
        candidate_parse_fn: Callable[[str], dict[str, Any] | None],
        sample_payloads: list[str],
    ) -> CanaryDifferentialReport:
        """Run both parsers side-by-side on live or replayed sample payloads."""
        active_success = 0
        candidate_success = 0
        matches = 0
        divergences = 0
        collected_diffs: list[SemanticDiffItem] = []

        for payload in sample_payloads:
            try:
                res_act = active_parse_fn(payload)
            except Exception:
                res_act = None

            try:
                res_cand = candidate_parse_fn(payload)
            except Exception:
                res_cand = None

            if res_act is not None:
                active_success += 1
            if res_cand is not None:
                candidate_success += 1

            # Semantic comparison
            if res_act is None and res_cand is None:
                continue
            elif res_act is None and res_cand is not None:
                divergences += 1
                collected_diffs.append(
                    SemanticDiffItem(
                        field_name="<entire_record>",
                        active_value=None,
                        candidate_value="PARSED",
                        diff_type="ADDED",
                    )
                )
            elif res_act is not None and res_cand is None:
                divergences += 1
                collected_diffs.append(
                    SemanticDiffItem(
                        field_name="<entire_record>",
                        active_value="PARSED",
                        candidate_value=None,
                        diff_type="REMOVED",
                    )
                )
            else:
                # Both parsed: compare dictionary keys and values
                all_keys = set(res_act.keys()).union(set(res_cand.keys()))
                record_diverged = False
                for k in all_keys:
                    v_act = res_act.get(k)
                    v_cand = res_cand.get(k)

                    if k not in res_act:
                        collected_diffs.append(
                            SemanticDiffItem(field_name=k, active_value=None, candidate_value=v_cand, diff_type="ADDED")
                        )
                        # Additive enrichment is preserved without counting as a regressive divergence
                    elif k not in res_cand:
                        collected_diffs.append(
                            SemanticDiffItem(field_name=k, active_value=v_act, candidate_value=None, diff_type="REMOVED")
                        )
                        record_diverged = True
                    elif type(v_act) != type(v_cand):
                        collected_diffs.append(
                            SemanticDiffItem(field_name=k, active_value=v_act, candidate_value=v_cand, diff_type="TYPE_CHANGE")
                        )
                        record_diverged = True
                    elif v_act != v_cand:
                        collected_diffs.append(
                            SemanticDiffItem(field_name=k, active_value=v_act, candidate_value=v_cand, diff_type="VALUE_MISMATCH")
                        )
                        record_diverged = True

                if record_diverged:
                    divergences += 1
                else:
                    matches += 1

        total = len(sample_payloads)
        mismatch_rate = divergences / max(1, total)
        # Safe if candidate parsed at least as many samples and mismatch rate is within tolerance
        safe = (candidate_success >= active_success) and (mismatch_rate <= self.tolerance_mismatch_rate)

        verdict = (
            "CANDIDATE_RECOMMENDED_FOR_APPROVAL"
            if safe
            else "PROMOTION_BLOCKED_EXCESSIVE_DIVERGENCE"
        )

        return CanaryDifferentialReport(
            source_id=source_id,
            active_parser_version=active_version,
            candidate_parser_version=candidate_version,
            total_samples=total,
            active_success_count=active_success,
            candidate_success_count=candidate_success,
            semantic_matches=matches,
            semantic_divergences=divergences,
            field_diffs=collected_diffs[:50],  # Bounded diff collection
            is_safe_for_promotion=safe,
            governance_verdict=verdict,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
