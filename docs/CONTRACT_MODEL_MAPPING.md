# Contract and Type Model Mapping

The frozen Phase 0 JSON Schemas in contracts/jsonschema are the sole source of truth for RawEvent, ParsedEvent, UCE NormalizedEvent, Source, Parser, Mapping, Schema, Lineage, DLQEvent, ReplayJob, AuditEvent, and shared definitions. Phase 1 does not hand-copy those large business contracts into Pydantic classes because that would create two authorities and invite semantic drift.

| Representation | Source of truth | Phase 1 use |
| --- | --- | --- |
| JSON Schema contracts | contracts/jsonschema | loaded and checked by ulpf_contracts.ContractRegistry |
| JSON Schema examples | tests/fixtures/contracts | minimal synthetic valid and invalid compatibility fixtures |
| Typed foundation response models | ulpf_contracts.foundation | health, metadata, and error envelopes only |
| Framework-independent primitives | ulpf_domain.primitives | identifiers, semantic-version wrapper, UTC timestamp wrapper |
| Future full typed business models | derived from reviewed contract change | not implemented yet |

The validator resolves local schema IDs through an in-memory registry and validates date-time formats. Contract tests fail when a schema no longer parses, a valid synthetic fixture is rejected, or an invalid fixture is accepted. The common schema is a definitions library rather than a root payload; its root is parsed and its definitions are exercised through referencing contracts.
