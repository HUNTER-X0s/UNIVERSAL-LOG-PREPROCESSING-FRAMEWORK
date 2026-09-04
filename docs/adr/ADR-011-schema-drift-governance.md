# ADR-011: Schema Drift Detection and Governance

**Status:** Accepted for Phase 0

## Context

Vendors may add/remove/rename fields, change types, delimiters, timestamps, structure, or vocabulary. Silent drift invalidates analytics and hides parser degradation.

## Decision

Compare live observations against versioned source/profile expectations, record candidate drift with samples and impact analysis, create a governed change candidate, test/review/publish a new version, and optionally replay history for comparison.

## Alternatives considered

- Ignore unknown/new fields.
- Update parsing configuration automatically.
- Freeze sources on any deviation.

## Pros

Visibility, controlled remediation, preserved evidence, and regression/replay evidence.

## Cons

Threshold tuning and review queues can introduce noise/operational work.

## Security implications

Prevents attacker-controlled source content from silently changing parser semantics; changes remain approved/audited.

## Operational implications

Drift signals, source health, candidate states, alert policy, and rollback/replay procedures must be monitored.

## Consequences

Drift is a data-quality/control-plane event, not a reason to discard raw evidence or silently alter production interpretation.
