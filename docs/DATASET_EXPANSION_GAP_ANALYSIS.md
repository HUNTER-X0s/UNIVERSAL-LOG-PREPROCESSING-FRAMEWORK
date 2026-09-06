# ULPF Dataset Expansion Gap Analysis (Post-Expansion)

**Document ID:** ULPF-DOC-DATA-GAP-002  
**Status:** RESOLVED & VERIFIED  

---

## 1. Resolution of Pre-Expansion Gaps

In the initial audit (`docs/DATASET_GAP_ANALYSIS.md`), four critical gaps were identified. The expansion resolves all four:

1. **Perimeter Firewall Telemetry (RESOLVED):**
   - Added Palo Alto Networks PAN-OS (Traffic and Threat).
   - Added Fortinet FortiGate (Forward traffic, drops, UTM virus inspection).
   - Added Cisco ASA (Connection, drop, and spoof syslogs).
   - Added Check Point Gaia (FireWall-1 audit logs).
2. **Dedicated Network IDS/IPS Telemetry (RESOLVED):**
   - Added Suricata EVE-JSON (Alerts and protocol streams).
   - Added Snort fast-alert format.
3. **Cloud & Cloud-Native Audit Telemetry (RESOLVED):**
   - Added AWS CloudTrail management audit events.
   - Added AWS VPC Flow network flow logs.
   - Added Kubernetes API server structured audit events.
4. **Adversarial & Malformed Log Fixtures (RESOLVED):**
   - Added malformed JSON, truncated streams, null-byte injections, and regex backtracking stress vectors.

---

## 2. Evaluation of UWF-ZeekData Releases (Phase 13)

The UWF-ZeekData corpus releases (UWF-ZeekData22, UWF-ZeekData24) were thoroughly investigated:
- **Corpus Characteristics:** UWF releases provide multi-hundred-gigabyte PCAP and raw Zeek TSV exports from university lab networks with MITRE ATT&CK labels.
- **Incremental Value Assessment:** The ULPF repository already holds:
  - **4.17 GB of Bro/Zeek attack/defense logs** in `data/benchmarks/secrepo/`.
  - **1.90 GB of 4-way multi-format Zeek logs** in `data/fixtures/real_world/multi_format/zed/`.
- **Determination:** Downloading multi-hundred-gigabyte UWF archives would provide zero incremental format diversity while severely bloating storage. UWF is therefore classified as **EXTERNAL_BENCHMARK_OPTIONAL** (documented for future scale tests, not ingested into Git).

---

## 3. Remaining Future Gaps (Documented for Phase 4/5)

| Telemetry Class | Current Status | Target Phase | Acquisition Strategy |
| :--- | :--- | :---: | :--- |
| **Hardware Appliance Live Feeds**| Representative fixtures present | Phase 4/5 | Authorized NTRO hardware lab capture |
| **NetFlow v9 / IPFIX Binary Wire**| Zeek flow logs present | Phase 4 | Binary UDP collector ingestion test |
| **Azure Activity / GCP Audit** | AWS CloudTrail present | Phase 4 | Public cloud provider sample exports |
