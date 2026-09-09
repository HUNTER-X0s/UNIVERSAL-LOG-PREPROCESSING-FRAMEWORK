"""Onboarding Service for ULPF Phase 5.

Coordinates end-to-end unknown-source onboarding, profiling, candidate mapping
generation, replay testing, human approval, and deterministic runtime activation.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from ulpf_ai.interfaces import AISemanticAdvisor
from ulpf_ai.providers.offline import OfflineDeterministicAdvisor
from ulpf_mapping.compiler.compiler import MappingCompiler
from ulpf_mapping.models import MappingDefinition
from ulpf_mapping.registry.registry import MappingRegistry

from ulpf_onboarding.drift import SchemaDriftDetector
from ulpf_onboarding.mapping_intel import MappingDiffEngine, MappingDiffResult, SEMANTIC_ALIAS_BANK
from ulpf_onboarding.models import DriftReport, OnboardingResult, ReplayResult, SourceProfile
from ulpf_onboarding.profiler import SampleProfiler
from ulpf_onboarding.replay import MappingReplayEngine
from ulpf_onboarding.source_intel import SourceIntelligenceDecision, UniversalSourceIntelligenceEngine


class OnboardingService:
    """High-level orchestration service for Phase 5 onboarding and mapping governance."""

    def __init__(
        self,
        registry: MappingRegistry | None = None,
        default_advisor: AISemanticAdvisor | None = None,
    ) -> None:
        self.compiler = MappingCompiler()
        self.registry = registry or MappingRegistry(compiler=self.compiler)
        self.advisor = default_advisor or OfflineDeterministicAdvisor()
        self.replay_engine = MappingReplayEngine(compiler=self.compiler)

    def onboard_sample_batch(
        self,
        raw_samples: list[str | bytes | dict[str, Any]],
        vendor_hint: str = "Unknown",
        product_hint: str = "Telemetry",
        custom_advisor: AISemanticAdvisor | None = None,
    ) -> OnboardingResult:
        """Process an unknown sample batch through profiling and candidate mapping generation."""
        if not raw_samples:
            raise ValueError("No samples provided for onboarding.")

        # 1. Normalize samples into structured dicts
        parsed_samples: list[dict[str, Any]] = []
        detected_fmt = "json"

        for s in raw_samples:
            if isinstance(s, dict):
                parsed_samples.append(s)
            elif isinstance(s, str | bytes):
                detected_fmt = SampleProfiler.detect_format(s)
                if detected_fmt == "json":
                    try:
                        parsed_samples.append(json.loads(s))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        parsed_samples.append({"raw_text": str(s)})
                else:
                    parsed_samples.append({"raw_text": str(s), "format": detected_fmt})

        sample_hash = hashlib.sha256(
            json.dumps(parsed_samples[:10], sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

        # 2. Profile Structural Fields
        profile = SampleProfiler.profile_samples(
            samples=parsed_samples,
            vendor=vendor_hint,
            product=product_hint,
            format_id=detected_fmt,
        )
        field_inventory = [f.path for f in profile.fields]

        # 3. Generate Candidate Mappings via Advisor
        advisor_to_use = custom_advisor or self.advisor
        ai_sug = advisor_to_use.suggest_mapping(
            sample_events=parsed_samples,
            source_hint={"vendor": vendor_hint, "product": product_hint},
        )

        candidates = [ai_sug.candidate_mapping]
        quality_score = round(ai_sug.confidence_breakdown.composite_confidence * 10.0, 1)

        o_id = f"onboard_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(UTC).isoformat()

        return OnboardingResult(
            onboarding_id=o_id,
            detected_format=detected_fmt,
            detected_vendor=vendor_hint,
            detected_product=product_hint,
            field_inventory=field_inventory,
            candidate_mappings=candidates,
            quality_score=quality_score,
            status="PENDING_REVIEW",
            sample_hash=sample_hash,
            sample_count=len(parsed_samples),
            warnings=ai_sug.uncertainties,
            ai_assisted=True,
            ai_metadata={
                "provider_id": advisor_to_use.provider_id,
                "model_version": advisor_to_use.model_version,
            },
            created_at=now_iso,
        )

    def replay_candidate(
        self,
        mapping_def: MappingDefinition,
        samples: list[dict[str, Any]],
        expected_outputs: list[dict[str, Any]] | None = None,
    ) -> ReplayResult:
        """Run replay validation against sample events."""
        return self.replay_engine.replay(mapping_def, samples, expected_outputs)

    def approve_and_activate(
        self,
        mapping_def: MappingDefinition,
        reviewer: str,
        comment: str = "",
    ) -> None:
        """Complete governance review: register, approve, and activate mapping."""
        # 1. Register
        self.registry.register(mapping_def, actor=reviewer)
        # 2. Validate
        self.registry.validate(mapping_def.mapping_id, mapping_def.version, actor=reviewer)
        # 3. Approve
        self.registry.approve(
            mapping_def.mapping_id, mapping_def.version, reviewer=reviewer, comment=comment
        )
        # 4. Activate
        self.registry.activate(mapping_def.mapping_id, mapping_def.version, actor=reviewer)

    def check_drift(
        self,
        baseline_profile: SourceProfile,
        new_samples: list[dict[str, Any]],
    ) -> DriftReport:
        """Evaluate structural drift against a baseline profile."""
        return SchemaDriftDetector.detect_drift(baseline_profile, new_samples)

    def analyze_source_intelligence(self, raw_sample: str | bytes) -> SourceIntelligenceDecision:
        """Phase 13 Workstream A: Explainable source family, vendor, and format identification."""
        return UniversalSourceIntelligenceEngine.analyze(raw_sample)

    def diff_mappings(self, v1: dict[str, Any], v2: dict[str, Any]) -> MappingDiffResult:
        """Phase 13 Workstream C: Compute structured field diff and impact analysis between mapping versions."""
        return MappingDiffEngine.diff(v1, v2)

    onboard_new_source = onboard_sample_batch

