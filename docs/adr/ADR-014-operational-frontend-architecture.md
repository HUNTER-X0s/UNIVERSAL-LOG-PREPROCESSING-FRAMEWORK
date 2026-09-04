# ADR-014: Operational Frontend Architecture

**Status:** Accepted for Phase 0

## Context

ULPF must provide unified visibility, onboarding, traceability, quality, replay, and air-gap status while keeping user actions safe and auditable.

## Decision

Plan a React and TypeScript frontend consuming versioned API contracts, with route-level domains, server-state caching, bounded real-time status, accessible dense investigation views, and explicit raw/parsed/normalized/lineage comparison.

## Alternatives considered

- Server-rendered admin pages only.
- A generic visual dashboard with hidden evidence details.
- Direct database access from the UI.

## Pros

Reusable components, clear contract boundary, rich operational workflows, and strong ecosystem for testing/accessibility.

## Cons

Client state and dependency management require discipline; it is another technology stack for the team.

## Security implications

No direct datastore access, OIDC/RBAC enforcement, safe rendering, masked evidence, explicit confirmation, and audit-aware UI paths.

## Operational implications

UI shows degraded/deferred status rather than assuming a command succeeded; long jobs are tracked by status resources.

## Consequences

The MVP prioritizes source onboarding and evidence trace over decorative dashboards or full SOC workflows.
