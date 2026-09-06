# ULPF Manifest Forensic Audit & Bidirectional Verification

**Document ID:** ULPF-DOC-MANIFEST-FORENSIC-AUDIT  
**Corpus Version:** v3.1.0  

---

### 1. Bidirectional Consistency

- **Total Registered Datasets:** 39 families.
- **Manifest -> Filesystem Check:** 39/39 dataset canonical paths exist on disk (0 missing paths).
- **Filesystem -> Manifest Check:** Every telemetry file in `data/` belongs to a registered dataset family or governed benchmark path.
- **Schema Validation:** Valid JSON adhering to `https://ulpf.internal/schemas/dataset-manifest.json`.
- **Governed Summary:**
  - Total files: 344
  - Total bytes: 6,409,481,418
  - Payload bytes: 6,409,385,655
  - Metadata bytes: 95,763
