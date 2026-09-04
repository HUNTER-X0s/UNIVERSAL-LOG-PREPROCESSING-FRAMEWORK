# ADR-004: AI-assisted Onboarding Is Advisory Only

**Status:** Accepted for Phase 0

## Context

Unknown formats can benefit from field inference, but AI can hallucinate, be unavailable, or be manipulated by log content. NTRO prioritizes trustworthy processing and air-gap operation.

## Decision

Use deterministic detection/rules first and optional local AI only to propose mapping/parser configuration with confidence, explanation, model/template version, validation, and human approval. Production processing remains deterministic.

## Alternatives considered

- Cloud AI as mandatory parser runtime.
- Autonomous parser publication.
- No AI capability at all.

## Pros

Improves onboarding differentiation without placing AI in the evidence path or requiring Internet access.

## Cons

Adds review UX, offline model packaging, and uncertain hardware/model-quality requirements.

## Security implications

Treat samples as untrusted; prevent prompt injection, code execution, secret exposure, and unauthorized publication.

## Operational implications

AI failure degrades only advisory workflows; bundles, prompts/templates, and model versions are governed artifacts.

## Consequences

AI output remains `inferred` and cannot become an observed fact or active parser/mapping without approval.
