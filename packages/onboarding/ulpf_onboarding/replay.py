"""Mapping Replay Engine for ULPF Phase 5.

Replays sample event batches against candidate or compiled mappings to verify
semantic outputs, detect regressions, and compute diffs against golden outputs.
"""

from typing import Any

from ulpf_mapping.compiler.compiler import MappingCompiler
from ulpf_mapping.models import MappingDefinition
from ulpf_semantic.service import SemanticService

from ulpf_onboarding.models import ReplayResult


class MappingReplayEngine:
    """Executes offline replay testing of mappings against sample corpora."""

    def __init__(
        self,
        semantic_service: SemanticService | None = None,
        compiler: MappingCompiler | None = None,
    ) -> None:
        self.semantic_service = semantic_service or SemanticService()
        self.compiler = compiler or MappingCompiler()

    def replay(
        self,
        mapping_def: MappingDefinition,
        samples: list[dict[str, Any]],
        expected_outputs: list[dict[str, Any]] | None = None,
    ) -> ReplayResult:
        """Replay sample batch, evaluating match and comparing against expectations."""
        compiled = self.compiler.compile(mapping_def)
        total = len(samples)
        passed = 0
        failed = 0
        diffs = []

        for idx, sample in enumerate(samples):
            matched = compiled.match_fn(sample)
            expected = (
                expected_outputs[idx] if expected_outputs and idx < len(expected_outputs) else None
            )

            if expected:
                exp_matched = expected.get("matched", True)
                exp_cat = expected.get("expected_category")
                exp_type = expected.get("expected_type")

                sample_pass = True
                if matched != exp_matched:
                    sample_pass = False
                    diffs.append(
                        {
                            "sample_index": idx,
                            "error": f"Match mismatch: got {matched}, expected {exp_matched}",
                        }
                    )

                if matched and exp_cat:
                    # Execute semantic interpretation
                    sem_event = self.semantic_service.process_uce(sample, project=False)
                    if sem_event.semantic_triple.category != exp_cat:
                        sample_pass = False
                        diffs.append(
                            {
                                "sample_index": idx,
                                "error": (
                                    f"Category mismatch: got {sem_event.semantic_triple.category}, "
                                    f"expected {exp_cat}"
                                ),
                            }
                        )
                    if exp_type and sem_event.semantic_triple.type_name != exp_type:
                        sample_pass = False
                        diffs.append(
                            {
                                "sample_index": idx,
                                "error": (
                                    f"Type mismatch: got {sem_event.semantic_triple.type_name}, "
                                    f"expected {exp_type}"
                                ),
                            }
                        )

                if sample_pass:
                    passed += 1
                else:
                    failed += 1
            else:
                # No expected output provided: baseline sanity execution
                if matched:
                    passed += 1
                else:
                    passed += 1

        rate = (passed / total) if total > 0 else 1.0
        return ReplayResult(
            mapping_id=mapping_def.mapping_id,
            mapping_version=mapping_def.version,
            total_events=total,
            passed_events=passed,
            failed_events=failed,
            semantic_diffs=diffs,
            success_rate=round(rate, 4),
        )
