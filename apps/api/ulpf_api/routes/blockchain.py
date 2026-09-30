"""
Blockchain REST API routes for the ULPF permissioned blockchain.

Endpoints:
    GET  /api/v1/blockchain/stats          — chain statistics dashboard
    GET  /api/v1/blockchain/chain          — full chain block list (explorer)
    GET  /api/v1/blockchain/block/{index}  — single block detail + transactions
    GET  /api/v1/blockchain/genesis        — genesis block info
    POST /api/v1/blockchain/anchor         — manually anchor a log event
    GET  /api/v1/blockchain/verify/{id}    — Merkle proof verification
    POST /api/v1/blockchain/verify         — verify from request body
    GET  /api/v1/blockchain/validate       — run full chain integrity check
    GET  /api/v1/blockchain/flush          — manually seal pending events into block
    GET  /api/v1/blockchain/contracts      — list smart contract rules
    GET  /api/v1/blockchain/authority      — authority node information
"""

from __future__ import annotations

import datetime
import uuid
from hashlib import sha256
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ulpf_blockchain.anchoring_service import BlockchainAnchoringService
from ulpf_blockchain.models import AnchorReceipt, ChainStats, VerificationResult

router = APIRouter(prefix="/blockchain", tags=["Blockchain"])

# ---------------------------------------------------------------------------
# Singleton service — initialized once, shared across all requests
# ---------------------------------------------------------------------------
_anchoring_service: BlockchainAnchoringService | None = None


def get_service() -> BlockchainAnchoringService:
    """Return the singleton anchoring service, creating it if needed."""
    global _anchoring_service
    if _anchoring_service is None:
        _anchoring_service = BlockchainAnchoringService(
            batch_size=50,
            flush_interval=30.0,
        )
        _anchoring_service.start()
        # Seed a demo block with realistic initial events on first boot
        _seed_demo_events(_anchoring_service)
    return _anchoring_service


def _seed_demo_events(service: BlockchainAnchoringService) -> None:
    """Seed realistic demo blockchain data for hackathon demonstration."""
    demo_events = [
        {
            "event_id": "a1b2c3d4-0001-4000-8000-000000000001",
            "sha256": sha256(b"CISCO-ASA-Deny-TCP-192.168.1.5-443").hexdigest(),
            "source": "CISCO_ASA",
            "description": "Cisco ASA Firewall — Deny TCP 443 inbound",
        },
        {
            "event_id": "a1b2c3d4-0002-4000-8000-000000000002",
            "sha256": sha256(b"Snort-Alert-ET-MALWARE-CnC-Callback").hexdigest(),
            "source": "SNORT",
            "description": "Snort IDS — ET MALWARE CnC Callback detected",
        },
        {
            "event_id": "a1b2c3d4-0003-4000-8000-000000000003",
            "sha256": sha256(b"Windows-4625-Failed-Logon-ADMIN").hexdigest(),
            "source": "WINEVENT",
            "description": "Windows Event 4625 — Failed Logon attempt",
        },
        {
            "event_id": "a1b2c3d4-0004-4000-8000-000000000004",
            "sha256": sha256(b"Okta-User-MFA-Bypass-Detected").hexdigest(),
            "source": "OKTA",
            "description": "Okta — MFA bypass attempt detected",
        },
        {
            "event_id": "a1b2c3d4-0005-4000-8000-000000000005",
            "sha256": sha256(b"PaloAlto-Threat-Brute-Force-SSH").hexdigest(),
            "source": "PALO_ALTO",
            "description": "Palo Alto — SSH brute-force threat blocked",
        },
        {
            "event_id": "a1b2c3d4-0006-4000-8000-000000000006",
            "sha256": sha256(b"AWS-CloudTrail-IAM-Policy-Change").hexdigest(),
            "source": "AWS_CLOUDTRAIL",
            "description": "AWS CloudTrail — IAM policy modification",
        },
        {
            "event_id": "a1b2c3d4-0007-4000-8000-000000000007",
            "sha256": sha256(b"Fortinet-IPS-SQL-Injection-Block").hexdigest(),
            "source": "FORTINET",
            "description": "Fortinet IPS — SQL injection attempt blocked",
        },
        {
            "event_id": "a1b2c3d4-0008-4000-8000-000000000008",
            "sha256": sha256(b"CrowdStrike-Ransomware-ProcessHollowing").hexdigest(),
            "source": "CROWDSTRIKE",
            "description": "CrowdStrike EDR — Process hollowing / ransomware",
        },
    ]
    receipts = service.anchor_batch(demo_events)
    # Force-seal the demo block immediately
    service.flush_now()

    # Second block with additional events
    more_events = [
        {
            "event_id": "b2c3d4e5-0009-4000-8000-000000000009",
            "sha256": sha256(b"Kubernetes-Pod-Privilege-Escalation").hexdigest(),
            "source": "KUBERNETES",
            "description": "K8s — Pod privilege escalation attempt",
        },
        {
            "event_id": "b2c3d4e5-0010-4000-8000-000000000010",
            "sha256": sha256(b"Suricata-Lateral-Movement-SMB").hexdigest(),
            "source": "SURICATA",
            "description": "Suricata — Lateral movement via SMB detected",
        },
        {
            "event_id": "b2c3d4e5-0011-4000-8000-000000000011",
            "sha256": sha256(b"AD-Admin-Group-Modification").hexdigest(),
            "source": "ACTIVE_DIRECTORY",
            "description": "AD — Domain Admin group modification",
        },
        {
            "event_id": "b2c3d4e5-0012-4000-8000-000000000012",
            "sha256": sha256(b"GitHub-Audit-Secrets-Pushed").hexdigest(),
            "source": "GITHUB_AUDIT",
            "description": "GitHub Audit — Secrets pushed to public repo",
        },
    ]
    service.anchor_batch(more_events)
    service.flush_now()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AnchorRequest(BaseModel):
    event_id: str | None = None
    sha256: str | None = None
    source: str = "GENERIC_SYSLOG"
    raw_payload: str | None = None
    description: str = ""


class VerifyRequest(BaseModel):
    event_id: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=dict)
async def get_chain_stats() -> dict[str, Any]:
    """Return blockchain statistics for the command center dashboard."""
    service = get_service()
    stats = service.get_chain_stats()
    return stats.model_dump()


@router.get("/chain", response_model=list)
async def get_chain() -> list[dict[str, Any]]:
    """Return all block headers for the Block Explorer."""
    service = get_service()
    return service.get_full_chain()


@router.get("/genesis")
async def get_genesis_block() -> dict[str, Any]:
    """Return the genesis block — the origin of the chain of custody."""
    service = get_service()
    block = service.get_block_detail(0)
    if block is None:
        raise HTTPException(status_code=404, detail="Genesis block not found.")
    return block


@router.get("/block/{index}")
async def get_block(index: int) -> dict[str, Any]:
    """Return full block detail including all transaction hashes."""
    service = get_service()
    block = service.get_block_detail(index)
    if block is None:
        raise HTTPException(status_code=404, detail=f"Block {index} not found.")
    return block


@router.post("/anchor", response_model=dict)
async def anchor_event(request: AnchorRequest) -> dict[str, Any]:
    """
    Anchor a log event to the blockchain.

    If sha256 is not provided, it is computed from raw_payload.
    If event_id is not provided, a UUID is generated.
    """
    service = get_service()

    # Resolve SHA-256
    if request.sha256:
        hash_value = request.sha256
    elif request.raw_payload:
        hash_value = sha256(request.raw_payload.encode("utf-8")).hexdigest()
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'sha256' or 'raw_payload'."
        )

    event_id = request.event_id or str(uuid.uuid4())
    receipt = service.anchor_event(
        event_id=event_id,
        sha256_hash=hash_value,
        source=request.source,
        description=request.description,
    )
    return receipt.model_dump()


@router.get("/verify/{event_id}")
async def verify_event(event_id: str) -> dict[str, Any]:
    """Verify a log event's Merkle inclusion proof in the blockchain."""
    service = get_service()
    result = service.verify_event(event_id)
    return result.model_dump()


@router.post("/verify")
async def verify_event_post(request: VerifyRequest) -> dict[str, Any]:
    """Verify a log event's inclusion via POST (body)."""
    service = get_service()
    result = service.verify_event(request.event_id)
    return result.model_dump()


@router.get("/validate")
async def validate_chain() -> dict[str, Any]:
    """Run a full cryptographic integrity check of the entire blockchain."""
    service = get_service()
    return service.validate_full_chain()


@router.get("/flush")
async def flush_pending() -> dict[str, Any]:
    """Manually seal pending events into a new block."""
    service = get_service()
    count = service.flush_now()
    stats = service.get_chain_stats()
    return {
        "sealed_events": count,
        "new_chain_height": stats.chain_height,
        "message": f"Sealed {count} pending events into block #{stats.chain_height - 1}",
    }


@router.get("/contracts")
async def get_contract_rules() -> list[dict[str, str]]:
    """List all smart contract policy rules enforced by the blockchain."""
    service = get_service()
    return service.get_contract_rules()


class SimulateContractRequest(BaseModel):
    payload: dict[str, Any]


@router.post("/contracts/simulate")
async def simulate_contract_execution(request: SimulateContractRequest) -> dict[str, Any]:
    """Simulate smart contract execution against test event telemetry."""
    service = get_service()
    return service.simulate_contract(request.payload)


@router.get("/authority")
async def get_authority_info() -> dict[str, str]:
    """Return Proof of Authority node information."""
    service = get_service()
    return service.get_authority_info()
