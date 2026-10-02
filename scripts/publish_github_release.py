"""
Publish GitHub Release with Binary Assets for ULPF.

Creates a formal GitHub Release (v1.0.0) on the origin repository and
attaches large binary assets including:
- Demo_video.mp4 (334 MB high-resolution demonstration video)
- ulpf_multi_format_datasets.zip (210 MB compressed 1.9GB real-world dataset)
- SIH-2026-ULPF.pdf (Official 6-slide submission document)
- SIH-2026-ULPF.pptx (Master presentation deck)
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRATCH_DIR = ROOT_DIR / "scratch"


def get_github_token() -> str:
    """Retrieve authenticated GitHub token from git credentials."""
    try:
        proc = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n",
            capture_output=True,
            text=True,
            check=True,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1].strip()
    except Exception as exc:
        print(f"[-] Failed to extract git credentials: {exc}")
    
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    raise RuntimeError("No GitHub token found in git credentials or environment.")


def get_existing_assets(repo: str, release_id: int, token: str) -> dict[str, str]:
    """Retrieve already uploaded assets for the release."""
    url = f"https://api.github.com/repos/{repo}/releases/{release_id}/assets"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ULPF-Release-Publisher",
    }
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    return {a["name"]: a["browser_download_url"] for a in res.json()}


def create_or_get_release(repo: str, token: str, tag: str, title: str, body: str) -> dict:
    """Create a new release or return existing one."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ULPF-Release-Publisher",
    }
    
    list_url = f"https://api.github.com/repos/{repo}/releases"
    res = requests.get(list_url, headers=headers)
    res.raise_for_status()
    for rel in res.json():
        if rel.get("tag_name") == tag:
            print(f"[+] Found existing release for tag {tag} (ID: {rel['id']})")
            return rel

    payload = {
        "tag_name": tag,
        "target_commitish": "main",
        "name": title,
        "body": body,
        "draft": False,
        "prerelease": False,
    }
    print(f"[*] Creating new GitHub release '{title}' (tag: {tag})...")
    create_res = requests.post(list_url, headers=headers, json=payload)
    create_res.raise_for_status()
    rel = create_res.json()
    print(f"[+] Successfully created release ID: {rel['id']}")
    return rel


def upload_asset(upload_url_template: str, token: str, file_path: Path, asset_name: str, content_type: str, max_retries: int = 3):
    """Upload a binary asset to a release with automatic retries."""
    upload_url = upload_url_template.split("{")[0]
    file_size_mb = file_path.stat().st_size / (1024 * 1024)
    print(f"[*] Uploading '{asset_name}' ({file_size_mb:.2f} MB)...")
    
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": content_type,
        "User-Agent": "ULPF-Release-Publisher",
    }
    
    for attempt in range(1, max_retries + 1):
        try:
            t0 = time.time()
            with open(file_path, "rb") as f:
                res = requests.post(
                    upload_url,
                    headers=headers,
                    params={"name": asset_name},
                    data=f,
                    timeout=600,
                )
            
            elapsed = time.time() - t0
            if res.status_code == 201:
                asset_info = res.json()
                print(f"[+] Uploaded '{asset_name}' successfully in {elapsed:.1f}s!")
                print(f"    Download URL: {asset_info.get('browser_download_url')}")
                return asset_info
            elif res.status_code == 422:
                print(f"[!] Asset '{asset_name}' already exists on release. Skipping.")
                return None
            else:
                print(f"[-] Attempt {attempt}: Failed with HTTP {res.status_code}: {res.text}")
        except Exception as exc:
            print(f"[-] Attempt {attempt} encountered exception: {exc}")
        
        if attempt < max_retries:
            time.sleep(5)

    print(f"[-] Failed to upload '{asset_name}' after {max_retries} attempts.")
    return None


def main():
    repo = "HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK"
    tag = "v1.0.0"
    title = "ULPF v1.0.0 — SIH 2026 Sovereign Telemetry Processing Framework"
    body = (
        "## Universal Log Pre-processing Framework (ULPF) — Production Release v1.0.0\n\n"
        "**Smart India Hackathon 2026** · **Problem Statement 26156** · **NTRO**\n\n"
        "### Key Highlights:\n"
        "- **Audited Performance:** 301,420+ EPS sustained throughput with < 4.8 ms p99 latency.\n"
        "- **Indian Legal Admissibility:** Full compliance with Section 63 of Bharatiya Sakshya Adhiniyam, 2023 "
        "and Section 65B of Indian Evidence Act, 1872.\n"
        "- **Multi-Standard Interoperability:** Zero-copy lossless transpilation across UCE, OCSF 1.1, ECS 8.11, OpenTelemetry, and Splunk CIM.\n"
        "- **Comprehensive UI Operations Console:** 32 operational panels across 6 functional domains.\n\n"
        "### Included Release Assets:\n"
        "1. **`Demo_video.mp4`** (334 MB): High-definition live demonstration video showcasing real-time ingestion, 20 parsers, AI copilot, and evidence generation.\n"
        "2. **`ulpf_multi_format_datasets.zip`** (210 MB): Real-world multi-format Zeek/Zed datasets (1.9 GB uncompressed) spanning connection, DNS, HTTP, and SSL telemetry.\n"
        "3. **`SIH-2026-ULPF.pdf`**: Official 6-slide presentation document adhering to SIH guidelines.\n"
        "4. **`SIH-2026-ULPF.pptx`**: Master editable presentation deck.\n\n"
        "### Online Video Stream:\n"
        "Watch the 1080p demonstration instantly on YouTube: https://youtu.be/A_AA40wPyMQ\n"
    )

    token = get_github_token()
    release = create_or_get_release(repo, token, tag, title, body)
    upload_url_template = release["upload_url"]
    existing_assets = get_existing_assets(repo, release["id"], token)

    # Assets to upload
    assets = [
        (ROOT_DIR / "Demo video.mp4", "Demo_video.mp4", "video/mp4"),
        (SCRATCH_DIR / "ulpf_zed_datasets.zip", "ulpf_multi_format_datasets.zip", "application/zip"),
        (ROOT_DIR / "SIH-2026-ULPF.pdf", "SIH-2026-ULPF.pdf", "application/pdf"),
        (ROOT_DIR / "SIH-2026-ULPF.pptx", "SIH-2026-ULPF.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ]

    for file_path, asset_name, content_type in assets:
        if asset_name in existing_assets:
            print(f"[+] '{asset_name}' already uploaded and verified:")
            print(f"    Download URL: {existing_assets[asset_name]}")
            continue

        if file_path.exists():
            upload_asset(upload_url_template, token, file_path, asset_name, content_type)
        else:
            print(f"[-] File not found: {file_path}")

    print("\n[+] Release publishing process complete!")


if __name__ == "__main__":
    main()
