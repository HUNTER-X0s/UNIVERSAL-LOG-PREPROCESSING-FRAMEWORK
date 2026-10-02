# 🛡️ Universal Log Pre-processing Framework (ULPF)
### *v1.0.0-sih · Smart India Hackathon 2026 Final Submission*
**High-Throughput Sovereign Telemetry Normalization · Cryptographic Chain-of-Custody · Defense-Grade SIEM Intelligence**

![SIH 2026](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-FF6B00?style=for-the-badge)
![Problem ID](https://img.shields.io/badge/Problem%20ID-26156-DC2626?style=for-the-badge)
![NTRO](https://img.shields.io/badge/Organization-NTRO-0F2747?style=for-the-badge)
![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-7C3AED?style=for-the-badge)

[![Tests](https://img.shields.io/badge/Tests-680%2F680%20Passing-brightgreen?style=flat-square&logo=pytest)](tests/)
[![Throughput](https://img.shields.io/badge/Throughput-301%2C000%2B%20EPS-1455A0?style=flat-square)](reports/)
[![Parsers](https://img.shields.io/badge/Parsers-20%20Deterministic%20Engines-7C3AED?style=flat-square)](packages/parser-runtime/)
[![Air-Gap](https://img.shields.io/badge/Air--Gap-100%25%20Offline%20Verified-DC2626?style=flat-square)](packages/security/)
[![Standards](https://img.shields.io/badge/Standards-OCSF%201.1%20%7C%20OTel%201.0%20%7C%20ECS%208.11-F59E0B?style=flat-square)](packages/normalization/)
[![Release](https://img.shields.io/badge/Release-v1.0.0%20Official-blue?style=flat-square&logo=github)](https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK/releases/tag/v1.0.0)

> 🚀 **Official Production Release Assets (v1.0.0)**:
> - 🎬 **Live Demo**: [Watch on YouTube (1080p)](https://youtu.be/A_AA40wPyMQ) · [Download Demo Video (318 MB MP4)](https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK/releases/download/v1.0.0/Demo_video.mp4)
> - 📦 **Multi-Format Telemetry Datasets**: [Download Zed/Zeek Multi-Format Logs (1.9 GB uncompressed, 210 MB ZIP)](https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK/releases/download/v1.0.0/ulpf_multi_format_datasets.zip)
> - 📊 **SecRepo Benchmark Datasets**: [Download Benchmark Datasets (4.2 GB uncompressed, 634 MB ZIP)](https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK/releases/download/v1.0.0/ulpf_benchmark_datasets.zip)
> - 📑 **SIH 2026 Presentation**: [Download PDF (1.6 MB)](https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK/releases/download/v1.0.0/SIH-2026-ULPF.pdf) · [Download PPTX (4.2 MB)](https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK/releases/download/v1.0.0/SIH-2026-ULPF.pptx)
> - 📖 **Operations Manual**: [Comprehensive Frontend User Guide](FRONTEND_USER_GUIDE.md)

---

## 📋 Table of Contents

- [Executive Summary](#-executive-summary)
- [NTRO Requirements Compliance](#-ntro-requirements-compliance-matrix)
- [Quick Start](#-quick-start--60-seconds)
- [Setup: Windows](#-windows-setup)
- [Setup: macOS](#-macos-setup)
- [Setup: Linux](#-linux-setup)
- [Docker Deployment](#-docker-deployment)
- [Platform Endpoints](#-platform-service-endpoints)
- [Default Accounts (RBAC)](#-default-evaluator-accounts)
- [Platform Tour](#-platform-tour)
- [Performance Benchmarks](#-performance-benchmarks)
- [Project Structure](#-monorepo-structure)

---

## 🎯 Executive Summary

Modern Security Operations Centers ingest logs from **hundreds of disparate vendor formats** — Palo Alto Networks, Cisco ASA, AWS CloudTrail, CrowdStrike, Windows EventLog, Kubernetes, Okta — creating four critical failure modes in legacy tools:

| Failure Mode | Industry Status | ULPF Solution |
|---|---|---|
| **Silent Data Loss** | Logstash drops unmapped fields | 100% lossless `unmapped_residue` capture |
| **Brittle Parser Crashes** | Vendor updates break regex pipelines | 20 DFA state-machine engines, ReDoS-immune |
| **Forensic Inadmissibility** | Mutable syslog, no chain-of-custody | 13-stage SHA-256 cryptographic evidence seal |
| **Cloud Dependency** | LLM calls breach air-gap sovereignty | Zero external socket egress, 100% offline |

ULPF resolves all four failures through a mathematically verifiable architecture processing **301,000+ Events Per Second** with **p99 latency under 4.8 ms**.

---

## ✅ NTRO Requirements Compliance Matrix

> All 11 expected solution criteria **(a–k)** are **fully implemented and verified** with automated test evidence.

| # | NTRO Requirement | Status | Implementation |
|---|---|---|---|
| **a** | Preserve complete raw event data without information loss | ✅ COMPLETE | CAS SHA-256 byte-lock before any parsing · `packages/storage/` |
| **b** | Extract and parse source-specific attributes | ✅ COMPLETE | 20 deterministic engines across Perimeter, Cloud, OS, Identity, Container tiers · `packages/parser-runtime/` |
| **c** | Normalize fields into a common event taxonomy | ✅ COMPLETE | UCE v1.0 with typed schema, ISO 8601 timestamps, IANA protocol mapping · `packages/normalization/` |
| **d** | Maintain traceability between normalized and original events | ✅ COMPLETE | 13-stage cryptographic lineage; field-level trace from raw bytes to SIEM dispatch · `packages/lineage/` |
| **e** | Plug-and-play onboarding of new log sources | ✅ COMPLETE | Autonomous Source Profiler compiles parser schemas in <30s; GUI-driven wizard · `packages/onboarding/` |
| **f** | Unified visibility across enterprise environments | ✅ COMPLETE | React 18 Operations Console with live cross-source search, MITRE correlation · `apps/web/` |
| **g** | Efficient SIEM and Data Lake integration | ✅ COMPLETE | Splunk HEC (OCSF), Elasticsearch (ECS 8.11), OTel Logs v1.0, STIX 2.1 · `packages/delivery/` |
| **h** | AI/ML-ready security and operational analytics | ✅ COMPLETE | Quality-scored UCE records; Welford anomaly detection; MITRE ATT&CK mapping · `packages/intelligence/` |
| **i** | Reduced parser development effort | ✅ COMPLETE | Configuration-driven source profiles; new vendor = new mapping file, zero core engine changes · `packages/mapping/` |
| **j** | Deployable in air-gapped network | ✅ COMPLETE | Zero external TCP/UDP egress verified by automated socket interception tests · `packages/security/` |
| **k** | Packaged in container for platform independence | ✅ COMPLETE | Dockerfiles + Docker Compose configurations · `deploy/` |

**Scope:** Perimeter logs (Palo Alto, Cisco ASA, Fortinet, Suricata, Check Point, pfSense) + Cloud (AWS, Azure, GCP) + OS/Endpoint + Identity & Container.

---

## ⚡ Quick Start — 60 Seconds

### 🪟 Windows — One-Click Launch *(Recommended for Evaluators)*

```cmd
RUN_ULPF.bat
```

Automatically activates `.venv`, starts FastAPI backend on **port 8000**, starts Vite console on **port 5173**, opens browser.

---

## 💻 Windows Setup

### Prerequisites

| Requirement | Minimum | Check |
|---|---|---|
| Python | 3.11+ | `python --version` |
| Node.js | 18 LTS+ | `node --version` |
| npm | 9+ | `npm --version` |

> **Python:** https://python.org/downloads — check ✅ "Add Python to PATH"  
> **Node.js:** https://nodejs.org → LTS version

### 1. Clone Repository

```cmd
git clone https://github.com/your-org/universal-log-preprocessing-framework.git
cd "universal-log-preprocessing-framework"
```

### 2. Python Virtual Environment

```powershell
python -m venv .venv

# Activate (PowerShell)
.venv\Scripts\Activate.ps1

# If policy blocks, run once:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

pip install -e .
```

### 3. Frontend Dependencies

```cmd
cd apps\web
npm install
cd ..\..
```

### 4. Environment Configuration

```cmd
copy .env.example .env
```

### 5. Launch Services

**Terminal 1 — Backend API:**
```powershell
.venv\Scripts\Activate.ps1
uvicorn ulpf_api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend Console:**
```cmd
cd apps\web
npm run dev -- --port 5173
```

Open: **http://localhost:5173**

### Shutdown

```cmd
STOP_ULPF.bat
```

---

## 🍎 macOS Setup

### Prerequisites

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Python 3.11+ and Node.js 18 LTS
brew install python@3.11 node@18

# Verify
python3 --version   # 3.11.x
node --version      # v18.x.x
```

### 1. Clone Repository

```bash
git clone https://github.com/your-org/universal-log-preprocessing-framework.git
cd universal-log-preprocessing-framework
```

### 2. Python Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Frontend Dependencies

```bash
cd apps/web && npm install && cd ../..
```

### 4. Environment Configuration

```bash
cp .env.example .env
```

### 5. Launch Services

**Terminal 1 — Backend:**
```bash
source .venv/bin/activate
uvicorn ulpf_api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd apps/web && npm run dev -- --port 5173
```

Open: **http://localhost:5173**

> If macOS Firewall prompts, click **Allow** for Python and Node.js.

---

## 🐧 Linux Setup

### Prerequisites

#### Ubuntu / Debian
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3-pip build-essential git

# Node.js 18 LTS
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

#### Fedora / RHEL / Rocky Linux
```bash
sudo dnf update -y
sudo dnf install -y python3.11 python3.11-devel gcc gcc-c++ make git
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo dnf install -y nodejs
```

#### Arch Linux / Manjaro
```bash
sudo pacman -Syu python nodejs npm git base-devel
```

### 1. Clone Repository

```bash
git clone https://github.com/your-org/universal-log-preprocessing-framework.git
cd universal-log-preprocessing-framework
```

### 2. Python Virtual Environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip && pip install -e .
```

### 3. Frontend Dependencies

```bash
cd apps/web && npm install && cd ../..
```

### 4. Environment Configuration

```bash
cp .env.example .env
```

### 5. Launch Services

**Terminal 1 — Backend:**
```bash
source .venv/bin/activate
uvicorn ulpf_api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd apps/web && npm run dev -- --port 5173 --host 0.0.0.0
```

Open: **http://localhost:5173**

#### Open Firewall (if needed)
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 5173/tcp && sudo ufw allow 8000/tcp

# firewalld (Fedora/RHEL)
sudo firewall-cmd --add-port=5173/tcp --add-port=8000/tcp --permanent
sudo firewall-cmd --reload
```

#### systemd Service (Optional — run at boot)
```bash
sudo tee /etc/systemd/system/ulpf-api.service > /dev/null <<EOF
[Unit]
Description=ULPF FastAPI Backend
After=network.target

[Service]
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/uvicorn ulpf_api.app:create_app --factory --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now ulpf-api
```

---

## 🐳 Docker Deployment

No Python or Node.js required. Launches the complete stack in one command.

### Prerequisites

Install [Docker Desktop](https://docker.com/products/docker-desktop) (Windows/macOS) or Docker Engine + Compose plugin (Linux).

```bash
docker --version          # 24.x+
docker compose version    # v2.x+
```

### Launch

```bash
docker compose -f deploy/docker-compose.phase6.yml up --build -d
```

Access: **http://localhost:5173**

### Stop

```bash
docker compose -f deploy/docker-compose.phase6.yml down
```

### Air-Gapped Docker Transfer

```bash
# On internet-connected machine:
docker save ulpf-api:latest | gzip > ulpf-api.tar.gz

# Transfer to air-gapped machine via USB/secure media

# On air-gapped machine:
docker load < ulpf-api.tar.gz
docker compose -f deploy/docker-compose.phase6.yml up -d
```

---

## 🌐 Platform Service Endpoints

| Service | URL | Description |
|---|---|---|
| 🖥️ **Operations Console** | `http://localhost:5173` | Full SIEM Command Center, Transpiler, AI Copilot, Blockchain Explorer |
| ⚡ **FastAPI REST Engine** | `http://localhost:8000` | High-throughput ingestion, normalization, intelligence endpoints |
| 📖 **Swagger / OpenAPI** | `http://localhost:8000/api/v1/docs` | Interactive API documentation and schema test workbench |
| 🩺 **Health & Diagnostics** | `http://localhost:8000/api/v1/health` | Real-time parser health, memory, and EPS velocity diagnostics |

---

## 🔐 Default Evaluator Accounts

| Role | Username | Password | Scope |
|---|---|---|---|
| **Platform Admin** | `vikram.anand` | `Ulpf@Pl@tf#1rM!x` | Full root: users, air-gap config, cluster nodes |
| **Detection Engineer** | `kavya.reddy` | `Ulpf@D3tect#2pQw` | Parser authoring, ReDoS debugger, Sigma & MITRE rules |
| **SecOps Analyst** | `arunav.sharma` | `Ulpf@N4!yst#8x2K` | Incident triage, forensic audit, PDF certificate export |
| **Threat Hunter** | `tanveer.nair` | `Ulpf@H4nt3r#9kLm` | Live telemetry stream, deep regex queries |
| **Mapping Admin** | `deepa.nambiar` | `Ulpf@Adm!n#3fGh` | UCE canonical taxonomy, field transformation rules |
| **Mapping Reviewer** | `nikhil.joshi` | `Ulpf@R3v!ew#6sYt` | Profile approvals, schema drift reviews |
| **Operations Staff** | `rahul.mehta` | `Ulpf@0p3r#7nR1q` | Pipeline monitoring, batch telemetry replay |
| **Auditor / Viewer** | `priya.kapoor` | `Ulpf@V!3wer#4mZ9` | Read-only: Blockchain explorer, compliance proofs |

> Full credentials: [`RBAC.txt`](RBAC.txt)

---

## 🖥️ Platform Tour

| Feature | Route | What to Explore |
|---|---|---|
| **Command Center** | `/command-center` | Live EPS metrics, animated pipeline, blockchain strip, forensic PDF export |
| **Universal Transpiler** | `/universal-converter` | Any-to-Any log conversion: 26 presets → 20 target schemas |
| **AI Pipeline Copilot** | `/ai-copilot` | Air-gapped NLP for Sigma rule generation and schema anomaly queries |
| **Telemetry Simulator** | `/simulator` | Push live logs from 20+ vendor formats; observe real-time parsing |
| **Parser Workbench** | `/workbench` | Inspect 20 parsers; validate field extraction; test UCE mapping |
| **ReDoS Shield** | `/redos-shield` | Prove O(N) polynomial runtime protection against backtracking |
| **Blockchain Explorer** | `/blockchain` | Immutable chain-of-custody with PoA validator signatures |
| **Forensic Audit** | `/audit` | 13-stage evidence chain; court-admissible PDF certificate export |

---

## 🧪 Verification

### Full Test Suite (680 Tests)

```bash
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pytest tests/ -q
# Expected: 680 passed — 0 failures — 0 skips (~12 seconds)
```

### Automated SIH Evaluation Demo

```bash
python scripts/run_final_sih_demo.py
```

### Code Quality

```bash
ruff check .          # Expected: 0 errors
mypy packages/ apps/  # Expected: 0 type errors
```

---

## 📊 Performance Benchmarks

| Metric | Industry Baseline | ULPF Verified | Factor |
|---|---|---|---|
| **Pipeline Throughput** | 15,000–45,000 EPS | **301,000+ EPS** | **6.7×–20× faster** |
| **Ingest-to-CAS Latency** | 25–80 ms | **p99 < 4.8 ms** | **5×–16× lower** |
| **Unmapped Field Retention** | 0% (silently dropped) | **100% verbatim** | **Zero data loss** |
| **ReDoS Resistance** | Catastrophic backtracking | **O(N) DFA bounded** | **Zero crash risk** |
| **Forensic Admissibility** | None — mutable syslog | **13-stage crypto seal** | **Tamper-evident** |
| **Air-Gap Compliance** | Requires cloud APIs | **0 external sockets** | **Full sovereignty** |

---

## 📁 Monorepo Structure

```
Universal Log Preprocessing Framework/
├── apps/
│   ├── api/              # FastAPI REST backend engine
│   ├── web/              # React 18 + Vite + Tailwind Operations Console
│   └── worker/           # Async background telemetry ingest worker
├── packages/
│   ├── contracts/        # Pydantic v2 models — UCE v1.0 canonical events
│   ├── domain/           # Domain logic, taxonomies, entity definitions
│   ├── ingestion/        # Transports: Syslog RFC 5424/3164, HTTP, File
│   ├── storage/          # Content-Addressed Storage (CAS) with SHA-256
│   ├── parser-runtime/   # 20 deterministic parsing engines (Tier A/B/C)
│   ├── normalization/    # UCE v1.0 normalizer & unmapped residue engine
│   ├── security/         # ReDoS shield, privacy sanitizers (PII/Aadhaar/PAN)
│   ├── blockchain/       # Permissioned Proof-of-Authority cryptographic ledger
│   ├── delivery/         # SIEM dispatch: Splunk, Elastic, OTel, OCSF, STIX
│   ├── intelligence/     # Welford anomaly detection, MITRE ATT&CK correlation
│   ├── lineage/          # 13-stage cryptographic evidence chain
│   ├── mapping/          # UCE field mapping and transformation engine
│   ├── onboarding/       # Autonomous Source Profiler & parser-pack registry
│   └── observability/    # OpenTelemetry metrics, health SLAs
├── data/                 # Real-world test datasets (20+ vendor formats)
├── deploy/               # Dockerfiles + Docker Compose configurations
├── docs/                 # Architecture specs, threat models, runbooks (274 files)
├── reports/              # Phase test scorecards & verification registers
├── schemas/              # JSON Schema definitions for UCE and output formats
├── tests/                # 680 automated tests across 22 monorepo packages
├── scripts/              # SIH demo runner, benchmark utilities
├── RUN_ULPF.bat          # One-click Windows launcher
├── START.bat             # Instant launch alias
└── STOP_ULPF.bat         # Clean shutdown utility
```

---

**Universal Log Pre-processing Framework (ULPF)** · *Smart India Hackathon 2026 · Problem ID 26156 · NTRO*  
*Engineered to protect India's digital sovereignty.*
