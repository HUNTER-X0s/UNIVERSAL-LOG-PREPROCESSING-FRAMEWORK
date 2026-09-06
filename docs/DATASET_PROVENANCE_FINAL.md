# ULPF Final Dataset Provenance & Upstream Traceability

**Document ID:** ULPF-DOC-PROVENANCE-FINAL  
**Corpus Version:** v3.1.0  

---

### 1. Authoritative Upstream Registries

1. **LogHub (LogPAI Team, Chinese University of Hong Kong):**
   - *Upstream URL:* `https://github.com/logpai/loghub`
   - *Research Paper:* J. Zhu et al., "Tools and Benchmarks for Automated Log Parsing," ICSE 2019.
   - *DOI:* `10.5281/zenodo.3227177`
   - *Integrity:* Cryptographically verified against Zenodo published hashes.

2. **SecRepo (Security Repository Benchmark):**
   - *Upstream URL:* `https://www.secrepo.com/`
   - *Origin:* Mid-Atlantic Collegiate Cyber Defense Competition (MACCDC) 2012 pcap exports.
   - *Integrity:* SHA-256 verified for `conn.log` and `http.log`.

3. **BrimData Zed (WRCCDC 2018 Telemetry Corpus):**
   - *Upstream URL:* `https://github.com/brimdata/zed-sample-data`
   - *Origin:* Western Regional Collegiate Cyber Defense Competition 2018 parsed with Zeek v6.2.0.
   - *Integrity:* Multi-format cross-verified across `.sup`, `.bsup`, and `.json`.

4. **LUK Telemetry Benchmark:**
   - *Upstream URL:* Published academic benchmark on telecom network alarm management.
   - *Origin:* Operational router and switch alarms from Cisco and Huawei carrier networks.
