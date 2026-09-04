# Manual Tasks

This document identifies work that needs a human because it requires external authority, physical access, legal judgement, or a final presentation action. None is requested during Phase 0; each becomes due only in its named phase.

| Task | Why a human is needed | When | Exact expected input | Repository destination | Required? |
|---|---|---|---|---|---|
| Initialize repository governance | The blank workspace has no Git history, remote, branch protection, or collaborator policy | Before Phase 1 implementation | approved remote/organization, team access policy, initial commit approval | repository root / hosting service | Required |
| Acquire public log datasets | Licensing, terms, provenance, and sensitive-data review require human accountability | Phase 1/15 before benchmarks | source URL, license/terms, version/date, checksum, allowed use, attribution | `test-corpus/external/<dataset>/MANIFEST.md`; raw data excluded/controlled as policy requires | Optional; synthetic fixtures can start MVP |
| Obtain authorized device logs | Only owner/operator can provide hardware-generated telemetry and approve redaction | Phase 2/3 | written authorization, device/product/version, collection method, redaction record, classification | approved restricted corpus location; manifest reference in `test-corpus/` | Optional, but valuable for validation |
| Define classification/retention policy | Evidence sensitivity, retention, legal hold, and export policy are organization decisions | Before handling non-synthetic data | data classification, retention, backup, deletion, legal-hold, export rules | `config/policy/` future non-secret configuration; policy reference in docs | Required before real data |
| Provision credentials/certificates | Private keys, identity configuration, and network trust cannot safely be invented by an agent | Phase 1/10/16 | local IdP admin bootstrap, TLS cert/key source, service credentials, signing-key custody plan | secrets manager/orchestrator secret store, never the repository | Required for secured deployment |
| Obtain/approve hardware or local infrastructure | Capacity, network segmentation, storage, and air-gap host decisions require real resources | Phase 7/8/16 | host inventory, operating-system approval, storage/network allocation, operator contact | deployment inventory outside repository; sanitized profile in `deploy/` | Optional for demo; required for production-like test |
| Prepare air-gap transfer media/process | Physical transfer, malware scanning, chain of custody, and trusted key import are operational duties | Phase 10/16 | approved removable-media process, trusted public keys, bundle sign-off, scan evidence | `deploy/airgap/` manifests; actual keys/media outside Git | Required for air-gap proof |
| Curate local AI/enrichment packs | Model/feed licenses, suitability, hardware, and threat-intelligence terms need review | Phase 5/6/13 | model/feed source/version/license, checksum, hardware compatibility, security review | `bundles/` or restricted artifact registry; manifest in `deploy/airgap/` | Optional |
| Conduct measured benchmark run | Hardware conditions, load isolation, operator observation, and evidence of results need human oversight | Phase 15 | corpus manifest, hardware spec, deployment profile, command/run ID, raw measurements | `benchmarks/runs/<run-id>/` (do not fabricate results) | Required before performance claims |
| Conduct security review / threat exercise | Risk acceptance and attack-surface decisions need accountable reviewers | Phase 10/16 | review scope, findings, mitigations, sign-off or exceptions | `docs/security-reviews/` future sanitized record | Required before production-like deployment |
| Record demo video and presentation | Recording, narration, visual permissions, and final timing are human creative/accountable work | Final submission phase | approved script, local recording, captions if required, final 2-minute video and 5-slide deck | `submission/` only if policy permits binaries; otherwise external release reference | Required for SIH submission |
| Submit SIH portal entry | Portal account, declaration, intellectual-property acceptance, and final upload require the team | Final submission phase | final approved artifacts and official portal access | external SIH portal; release manifest in repository | Required for competition submission |

## Non-negotiable handling rules

Never commit raw credentials, private keys, proprietary/sensitive logs, portal tokens, personal data, or unlicensed datasets. Every imported dataset, parser pack, schema bundle, model, and deployment artifact needs a provenance/checksum manifest and the relevant approval record.

## Phase 1 status update

| Task | Phase 1 state | Remaining human action |
| --- | --- | --- |
| Initialize local repository metadata | Completed locally | Select an approved remote, branch-protection policy, and collaborator access before shared work begins. |
| Install target runtime | Completed locally | Python 3.12.10 is installed and the local verification suite passed; allow the configured CI workflow to run after the first commit. |
| Run local validation | Completed | Team members should run the documented verify command from a clean environment before contributing. |
| Prove container profile | Not yet performed | Configure authorized Docker access, build the API image, and record the bounded result; no production-stack claim is implied. |
| Provision credentials/certificates | Not required by the Phase 1 shell | Provide organization-approved secret/identity material before any secured or externally reachable deployment. |
| Acquire datasets/logs | Not performed by design | Follow the existing provenance and authorization tasks before any non-synthetic fixture or real evidence is used. |

