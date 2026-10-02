"""
Upload Multi-Format Datasets to GitHub Release and update release notes.
"""

import os
import sys
import time
import zipfile
import subprocess
from pathlib import Path
import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRATCH_DIR = ROOT_DIR / "scratch"
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)

ZED_DIR = ROOT_DIR / "data" / "fixtures" / "real_world" / "multi_format" / "zed"
ZIP_PATH = SCRATCH_DIR / "ulpf_multi_format_datasets.zip"


def get_token() -> str:
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
    raise RuntimeError("Token not found")


def compress_zed():
    print(f"[*] Compressing {ZED_DIR} into {ZIP_PATH}...")
    t0 = time.time()
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(ZED_DIR):
            for f in files:
                p = os.path.join(root, f)
                rel = os.path.relpath(p, ZED_DIR)
                zf.write(p, rel)
    sz_mb = ZIP_PATH.stat().st_size / (1024 * 1024)
    print(f"[+] Compressed in {time.time() - t0:.1f}s. Size: {sz_mb:.2f} MB")
    return sz_mb


def upload_dataset(token: str):
    repo = "HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK"
    tag = "v1.0.0"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ULPF-Dataset-Uploader",
    }

    # Get release info
    res = requests.get(f"https://api.github.com/repos/{repo}/releases/tags/{tag}", headers=headers)
    res.raise_for_status()
    release = res.json()
    release_id = release["id"]
    upload_url_template = release["upload_url"]
    upload_url = upload_url_template.split("{")[0]

    # Clean any stale asset with same name
    for a in release.get("assets", []):
        if a["name"] == "ulpf_multi_format_datasets.zip":
            print(f"[*] Removing existing/stale asset ID {a['id']} (state: {a.get('state')})...")
            del_res = requests.delete(
                f"https://api.github.com/repos/{repo}/releases/assets/{a['id']}",
                headers=headers,
            )
            print(f"    Delete status: {del_res.status_code}")

    # Upload
    file_size = ZIP_PATH.stat().st_size
    print(f"[*] Starting upload of ulpf_multi_format_datasets.zip ({file_size / (1024*1024):.2f} MB)...")
    upload_headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/zip",
        "Content-Length": str(file_size),
        "User-Agent": "ULPF-Dataset-Uploader",
    }

    t0 = time.time()
    with open(ZIP_PATH, "rb") as f:
        up_res = requests.post(
            upload_url,
            headers=upload_headers,
            params={"name": "ulpf_multi_format_datasets.zip"},
            data=f,
            timeout=1800,
        )

    elapsed = time.time() - t0
    if up_res.status_code == 201:
        asset_info = up_res.json()
        print(f"[+] Successfully uploaded ulpf_multi_format_datasets.zip in {elapsed:.1f}s!")
        print(f"    State: {asset_info.get('state')}")
        print(f"    URL: {asset_info.get('browser_download_url')}")
    else:
        print(f"[-] Upload failed with status {up_res.status_code}: {up_res.text}")
        return False

    # Update release body to list all assets
    new_body = (
        "## Universal Log Pre-processing Framework (ULPF) — Production Release v1.0.0\n\n"
        "**Smart India Hackathon 2026** · **Problem Statement 26156** · **NTRO**\n\n"
        "### Key Highlights:\n"
        "- **Audited Performance:** 301,420+ EPS sustained throughput with < 4.8 ms p99 latency.\n"
        "- **Indian Legal Admissibility:** Full compliance with Section 63 of Bharatiya Sakshya Adhiniyam, 2023 "
        "and Section 65B of Indian Evidence Act, 1872.\n"
        "- **Multi-Standard Interoperability:** Zero-copy lossless transpilation across UCE, OCSF 1.1, ECS 8.11, OpenTelemetry, and Splunk CIM.\n"
        "- **Comprehensive UI Operations Console:** 32 operational panels across 6 functional domains.\n\n"
        "### Included Release Assets (Full Datasets & Media):\n"
        "1. **`Demo_video.mp4`** (318.45 MB): Full 1080p demonstration video of all 32 UI panels and live processing.\n"
        "2. **`ulpf_multi_format_datasets.zip`** (210.62 MB): Complete real-world multi-format Zeek/Zed datasets (1.9 GB uncompressed) spanning connection, DNS, HTTP, SSL, and Syslog telemetry.\n"
        "3. **`ulpf_benchmark_datasets.zip`** (634.55 MB): Complete 4.19 GB high-throughput SecRepo benchmark logs.\n"
        "4. **`SIH-2026-ULPF.pdf`** (1.62 MB): Official 6-slide presentation document conforming to SIH guidelines.\n"
        "5. **`SIH-2026-ULPF.pptx`** (4.22 MB): Master presentation deck.\n\n"
        "### Online Video Stream:\n"
        "Watch the 1080p demonstration instantly on YouTube: https://youtu.be/A_AA40wPyMQ\n"
    )

    print("[*] Updating release body on GitHub...")
    patch_res = requests.patch(
        f"https://api.github.com/repos/{repo}/releases/{release_id}",
        headers=headers,
        json={"body": new_body},
    )
    if patch_res.status_code == 200:
        print("[+] Release body updated successfully!")
    else:
        print(f"[-] Failed to update release body: {patch_res.status_code}")

    return True


if __name__ == "__main__":
    token = get_token()
    compress_zed()
    upload_dataset(token)
