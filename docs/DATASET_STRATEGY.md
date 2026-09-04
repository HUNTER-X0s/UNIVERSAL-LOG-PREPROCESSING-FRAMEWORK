# Dataset and Test Corpus Strategy

## Purpose and honesty rule

The NTRO problem statement does not prescribe a public dataset. ULPF therefore uses a reproducible, licensed, provenance-recorded corpus strategy rather than claiming support or benchmark performance from unnamed logs. Phase 0 does not download datasets, invent vendor support, or create benchmark results.

The corpus exists to test format handling, losslessness, normalization, onboarding, drift, failures, security boundaries, replay, and performance fairly. It is not a substitute for authorized hardware-generated perimeter logs in a final demonstration.

## Corpus composition

| Corpus class | Planned content | Purpose |
| --- | --- | --- |
| known-format fixtures | Syslog, JSON, CEF, LEEF, XML, CSV, key=value, structured and semi-structured examples | deterministic parsers, mappings, canonical schema tests |
| perimeter-security fixtures | carefully authorized/de-identified firewall, router, VPN, IDS/IPS, WAF, proxy, gateway style samples where obtainable | validate product boundary and demo relevance |
| synthetic fixtures | documented generated logs with known ground truth and generator version/seed | fill coverage gaps without claiming a real vendor source |
| malformed/adversarial fixtures | broken syntax, large records, Unicode, invalid encoding, nested/unbalanced data, regex stress, path/archive input cases | safety, DLQ, fuzz and resource-limit behavior |
| unknown/proprietary-style fixtures | deliberately unmapped structures and fields | unknown-log onboarding and no-code mapping workflow |
| drift fixtures | missing/new/renamed fields, type/value/delimiter/timestamp/structural changes | schema-drift detection, versioned repair/replay |
| stream-behavior fixtures | duplicates, out-of-order, late events, reconnect/batch framing | idempotency, ordering and timestamp behavior |

## Provenance and license manifest

Every imported corpus item has a metadata manifest containing: immutable corpus/fixture ID and version; source URL or authorized origin; acquisition date; license/terms and attribution requirements; permitted use; source/vendor claim level; whether data is public, synthetic, de-identified, or restricted; checksum; redaction method if used; format; expected classification; parser/schema/mapping target; and known limitations.

No dataset is accepted merely because it is publicly downloadable. Licenses must permit the intended storage, modification, demonstration, and redistribution. Restricted or sensitive data lives outside the repository in an access-controlled location; the repository can retain only a manifest and authorized minimal derivatives. A manual reviewer approves any handling of personal, production, classified, or third-party-confidential data.

## Planned repository layout

The following is a future layout, not a request to add sample data during Phase 0:

```text
datasets/
  manifests/                 # provenance/license metadata, no restricted payloads
  fixtures/
    <format-or-source>/
      valid/
      malformed/
      unknown/
      drift/
      expected/
  synthetic/
    generators/              # deterministic generator specifications
    manifests/
  benchmarks/
    workload-manifests/      # configuration, not unsupported results
  restricted/                # ignored, access-controlled, never committed
```

Expected outputs are versioned assertions: parsed fields, normalized fields/origin classes, unmapped-field expectations, quality/error state, raw byte hash, and lineage/version expectations. They do not embed raw material beyond what the license and data policy allows.

## Acquisition and curation workflow

1. Define coverage gap and required format/security scenario.
2. Identify a candidate with usable license/provenance or create a transparently synthetic fixture.
3. Obtain required human authorization and preserve original acquisition details.
4. Scan/classify/de-identify according to policy while preserving an approved provenance record.
5. Calculate checksum, assign a corpus version, author expected outcomes, and record test purpose.
6. Review license, security, and reproducibility information before use in automated tests or demo.
7. Freeze benchmark corpus versions for a measurement; later additions create a new corpus version.

## Synthetic-data rules

Synthetic data is valuable for repeatable edge cases, unknown formats, drift, volume distributions, and malicious input. It must be labelled synthetic, retain generator/template/seed/version, and never be described as a vendor log or production traffic. Ground truth should distinguish observed-like fields intentionally encoded in the fixture from expected derived/inferred/enriched output. Synthetic examples may illustrate a log style but cannot substantiate a claim of actual device compatibility.

## Benchmark corpus controls

Benchmark manifests declare corpus composition, byte/event distributions, submit rate, ordering/duplicate/late-event behavior, payload limits, expected outcomes, and generator seeds. A correctness pass—raw hash retention, lineage completeness, parsing/normalization quality, error/DLQ state—precedes performance reporting. Results identify corpus version, environment, topology, software revisions, and limitations as defined in [Performance Strategy](PERFORMANCE_STRATEGY.md).

## Security and privacy controls

Production evidence should not be copied into test fixtures by default. Sensitive fields may be de-identified through an approved documented transformation for test use, while the original stays in controlled evidence storage. Secrets, private IP/topology information, credentials, host identifiers, and personal data receive special review. Malicious fixtures are isolated, never executed as code, and have safe naming/handling instructions.

## Manual tasks and acceptance

Human work is required to source authorized device logs, verify licenses, approve handling of sensitive telemetry, obtain any restricted datasets, and record final provenance. These tasks are listed in the broader manual-task register. This strategy is accepted when each required format/behavior has a traceable corpus plan, every fixture has a provenance/license manifest, expected outcomes preserve origin/unknown/error semantics, and no dataset claim exceeds the evidence actually held.
