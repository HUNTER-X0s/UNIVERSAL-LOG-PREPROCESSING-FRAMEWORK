"""
Preserve 100% of the exact existing content in Slide 6.
Convert raw URLs to clean blue underlined links ('link' / 'IEEE paper').
Add 'link' to Box 5 and Box 6 without altering any sentences.
"""
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Pt

SRC_PPTX = "SIH-2026-ULPF.backup.pptx"
OUT_PPTX = "SIH-2026-ULPF_PERFECT.pptx"
TARGET_PPTX = "SIH-2026-ULPF.pptx"

BLUE_LINK = RGBColor(14, 116, 222)   # Clean hyperlink blue #0E74DE
DARK_NAVY = RGBColor(10, 25, 47)     # #0A192F
TEXT_DARK = RGBColor(30, 41, 59)     # #1E293B

# Exact data mappings matching the user's exact existing wording
exact_quadrants = {
    5: [ # Shape 5 = Text 7 (Box 1: Gap & Problem Identification)
        (
            "Empirical Telemetry Gaps: ",
            "CERT-In Annual Cyber Security Reports document an 84% rise in APT attacks exploiting unmonitored log blindspots. ",
            "link",
            "https://www.cert-in.org.in/"
        ),
        (
            "ReDoS Vulnerability Prevalence: ",
            'Davis et al., "Why Aren\'t Regular Expressions a Solved Problem?" (IEEE S&P) proves 73% of industrial regex parsers exhibit O(2^N) backtracking. ',
            "IEEE paper",
            "https://doi.org/10.1109/SP.2018.00030"
        ),
        (
            "Judicial Precedents for Electronic Evidence: ",
            "Supreme Court of India rulings in State vs. Mohd. Afzal (2005) and Arjun Khotkar vs. Kailash Kushanrao (2020) mandate strict Section 65B electronic chain-of-custody. ",
            "link",
            "https://indiankanoon.org/doc/1769138/"
        ),
    ],
    11: [ # Shape 11 = Text 13 (Box 2: Literature Survey & Competitive Analysis)
        (
            "Open Cybersecurity Schema Framework: ",
            "OCSF v1.1 Schema Specification, Linux Foundation & AWS / Splunk. ",
            "link",
            "https://schema.ocsf.io/"
        ),
        (
            "High-Speed Log Engine Benchmarking: ",
            "ACM SIGCOMM CCR empirical survey comparing Logstash, Vector, and Fluent Bit ingestion architectures. ",
            "link",
            "https://arxiv.org/abs/1811.03509"
        ),
        (
            "Automata-Based Tokenization: ",
            "Aho-Corasick and Glushkov DFA tokenization techniques for high-speed network telemetry (ACM TACO). ",
            "link",
            "https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm"
        ),
    ],
    17: [ # Shape 17 = Text 19 (Box 3: Technology Benchmarking & Algorithmic Complexity)
        (
            "Complexity Bounds: ",
            "Proven algorithmic bounds: Traditional PCRE parsers run in O(2^N) time; ULPF's deterministic finite automata guarantee linear O(N) execution time. ",
            "link",
            "https://en.wikipedia.org/wiki/Time_complexity"
        ),
        (
            "Cryptographic Batch Verification: ",
            'Bellare et al., "Fast Batch Verification for Digital Signatures" (EUROCRYPT). ',
            "link",
            "https://doi.org/10.1007/3-540-49649-1_17"
        ),
        (
            "Zero-Copy Memory Semantics: ",
            "Linux Kernel io_uring and DPDK user-space buffer ring memory management. ",
            "link",
            "https://man7.org/linux/man-pages/man7/io_uring.7.html"
        ),
    ],
    8: [ # Shape 8 = Text 10 (Box 4: Economic & Strategic Landscape)
        (
            "SIEM Cost Escalation: ",
            'Gartner Research: "Predicts 2026: Cybersecurity Operations & Cloud Telemetry Ingestion Overruns" (over 60% of SOC budgets are consumed by ingestion licenses). ',
            "link",
            "https://www.gartner.com/"
        ),
        (
            "Indian Cybersecurity Market Size: ",
            "Data Security Council of India (DSCI) Cyber Security Market Report projects the Indian cybersecurity domain to surpass INR 42,000 Crore by 2028. ",
            "link",
            "https://www.dsci.in/"
        ),
        (
            "Air-Gap Critical Infrastructure: ",
            "NCIIPC Guidelines for Critical Information Infrastructure Protection (Section 70A, IT Act 2000). ",
            "link",
            "https://nciipc.gov.in/"
        ),
    ],
    14: [ # Shape 14 = Text 16 (Box 5: Field Tests & Simulation Results)
        (
            "Rigorous Load Tests: ",
            "Stress testing across 10,000,000 synthetic multi-format records (Syslog RFC 5424, AWS CloudTrail, Cisco ASA, Kubernetes audit logs) verified 301,420 EPS sustained. ",
            "link",
            "https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK"
        ),
        (
            "Zero Data Loss Integrity: ",
            "Validation testing confirmed 0.000% dropped records across 680 unit and end-to-end integration tests. ",
            "link",
            "https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK"
        ),
        (
            "Hash Verification Benchmarks: ",
            "Merkle tree verification confirmed 1,000,000 records validated in < 1.2 seconds using multithreaded SHA-256 SIMD intrinsics. ",
            "link",
            "https://github.com/HUNTER-X0s/UNIVERSAL-LOG-PREPROCESSING-FRAMEWORK"
        ),
    ],
    20: [ # Shape 20 = Text 22 (Box 6: Policy & Statutory Alignment)
        (
            "Section 65B Indian Evidence Act / Section 63 BSA 2023: ",
            "Automated certificate generation ensures hash integrity and non-repudiation in court. ",
            "link",
            "https://indiankanoon.org/doc/1769138/"
        ),
        (
            "CERT-In Cyber Security Directions (2022): ",
            "Mandatory 180-day log preservation and synchronization with national time servers (NPL/NTP). ",
            "link",
            "https://www.cert-in.org.in/Directions2022.jsp"
        ),
        (
            "DPDP Act 2023 (Digital Personal Data Protection Act): ",
            "Built-in automated PII masking engine scrubs IP addresses, Aadhaar, PAN, and credentials before long-term storage. ",
            "link",
            "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023"
        ),
    ],
}

def apply_exact_links():
    prs = Presentation(SRC_PPTX)
    slide6 = prs.slides[5]

    for shape_idx, items in exact_quadrants.items():
        shape = slide6.shapes[shape_idx]
        tf = shape.text_frame
        tf.word_wrap = True

        # Clear existing paragraphs by keeping paragraph[0]
        p0 = tf.paragraphs[0]
        p0.text = ""

        # Remove extra paragraphs
        while len(tf.paragraphs) > 1:
            p_elem = tf.paragraphs[-1]._p
            p_elem.getparent().remove(p_elem)

        for idx, (anchor, body, link_text, link_url) in enumerate(items):
            p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
            p.space_after = Pt(4)
            p.line_spacing = 1.15

            # Bullet run
            r_bullet = p.add_run()
            r_bullet.text = chr(8226) + " "
            r_bullet.font.name = "Arial"
            r_bullet.font.size = Pt(9.5)
            r_bullet.font.color.rgb = DARK_NAVY

            # Bold Anchor
            r_anchor = p.add_run()
            r_anchor.text = anchor
            r_anchor.font.name = "Arial"
            r_anchor.font.size = Pt(9.5)
            r_anchor.font.bold = True
            r_anchor.font.color.rgb = DARK_NAVY

            # Body text (100% exact original content)
            r_body = p.add_run()
            r_body.text = body
            r_body.font.name = "Arial"
            r_body.font.size = Pt(9.5)
            r_body.font.color.rgb = TEXT_DARK

            # Clean blue link
            r_link = p.add_run()
            r_link.text = link_text
            r_link.font.name = "Arial"
            r_link.font.size = Pt(9.5)
            r_link.font.bold = True
            r_link.font.color.rgb = BLUE_LINK
            r_link.font.underline = True
            r_link.hyperlink.address = link_url

    prs.save(OUT_PPTX)
    print(f"SUCCESS: Saved exact-content presentation to {OUT_PPTX}")

    try:
        prs.save(TARGET_PPTX)
        print(f"SUCCESS: Updated {TARGET_PPTX} in-place!")
    except Exception as e:
        print(f"NOTE: {TARGET_PPTX} locked by PowerPoint ({e}). {OUT_PPTX} is ready!")

if __name__ == "__main__":
    apply_exact_links()
