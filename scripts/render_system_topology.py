"""
ULPF — Sovereign System Architecture & Implementation Pipeline Renderer
Production-grade visual generator for 4K architectural schematics detailing the monorepo
runtime layers, Glushkov DFA engines, UCE v1.0 canonical projection, and PoA Merkle ledger.
"""

import os
import sys
import argparse
import textwrap
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_4K_PATH = os.path.join(ROOT_DIR, "SLIDE3_TECHNICAL_ARCHITECTURE_4K.png")
DEFAULT_STD_PATH = os.path.join(ROOT_DIR, "SLIDE3_TECHNICAL_ARCHITECTURE.png")

FONT_BOLD = "C:/Windows/Fonts/segoeuib.ttf"
FONT_SEMI = "C:/Windows/Fonts/seguisb.ttf"
FONT_REG  = "C:/Windows/Fonts/segoeui.ttf"
FONT_BAHN = "C:/Windows/Fonts/bahnschrift.ttf"


def get_font(path: str, size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def draw_arrow_right(draw: ImageDraw.ImageDraw, x1: int, y: int, x2: int, color=(14, 116, 222), width: int = 7):
    draw.line((x1, y, x2, y), fill=color, width=width)
    ah = 16
    aw = 20
    draw.polygon([(x2, y), (x2 - aw, y - ah), (x2 - aw, y + ah)], fill=color)


def render_system_topology(output_4k: str = DEFAULT_4K_PATH, output_std: str = DEFAULT_STD_PATH):
    """
    Renders the defense-grade 5-tier architecture and 6-step implementation pipeline at 3200x2270 (300 DPI).
    """
    W, H = 3200, 2270
    img = Image.new("RGBA", (W, H), (255, 255, 255, 255))
    draw = ImageDraw.Draw(img)

    # 1. Outer Container Border
    draw.rounded_rectangle((10, 10, W - 10, H - 10), radius=32, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=4)

    # Top Header Banner
    banner_h = 135
    draw.rounded_rectangle((28, 28, W - 28, banner_h), radius=18, fill=(10, 25, 47, 255)) # Deep Navy
    f_title = get_font(FONT_BAHN, 52)
    f_sub = get_font(FONT_BOLD, 26)
    draw.text((65, 82), "SOVEREIGN TELEMETRY PIPELINE & 5-TIER SYSTEM ARCHITECTURE", fill=(255, 255, 255), font=f_title, anchor="lm")
    
    # Header Right Badge
    draw.rounded_rectangle((W - 540, 52, W - 60, 112), radius=12, fill=(16, 185, 129))
    draw.text((W - 300, 82), "TRL 8/8 WORKING PROTOTYPE", fill=(255, 255, 255), font=f_sub, anchor="mm")

    # ==========================================================================
    # SECTION 1: 6-STEP METHODOLOGY PIPELINE (UPPER HALF)
    # ==========================================================================
    p_y = 155
    p_h = 995
    draw.rounded_rectangle((28, p_y, W - 28, p_y + p_h), radius=22, fill=(248, 250, 252), outline=(226, 232, 240), width=3)

    # Section Title & Badge
    f_sec = get_font(FONT_BAHN, 38)
    draw.text((65, p_y + 44), "METHODOLOGY AND PROCESS FOR IMPLEMENTATION (6-STEP LINEAR PIPELINE)", fill=(30, 41, 59), font=f_sec, anchor="lm")
    
    f_badge = get_font(FONT_BOLD, 24)
    draw.rounded_rectangle((W - 440, p_y + 20, W - 65, p_y + 68), radius=10, fill=(209, 250, 229), outline=(4, 120, 87), width=2)
    draw.text((W - 252, p_y + 44), "DETERMINISTIC LINEAR O(N)", fill=(4, 120, 87), font=f_badge, anchor="mm")

    steps = [
        {
            "step": "STEP 1",
            "name": "Multi-Protocol Ingest & Buffer",
            "tech": "UDP/TCP 514 · Windows EVTX · Kafka · CAS Atomic WORM",
            "bullets": [
                ("• Zero-Copy Ingest: ", "High-speed UDP/TCP 514, EVTX, and Kafka listeners."),
                ("• Lock-Free Ring Spool: ", "Atomic circular ring buffers eliminate thread contention."),
                ("• Instant WORM Seal: ", "CAS buffer hashes raw bytes via SHA-256 upon arrival.")
            ],
            "metric": "0.000% LOSS GUARANTEE · 1,000,000+ EPS BURST SPOOL",
            "color": (2, 132, 199), # Blue
            "bg": (238, 242, 255),
        },
        {
            "step": "STEP 2",
            "name": "20 Deterministic DFA Engines",
            "tech": "Glushkov Automata · Aho-Corasick · C++20 SIMD AVX2",
            "bullets": [
                ("• ReDoS Attack Immunity: ", "Pre-compiled DFAs eliminate CPU-freezing risks."),
                ("• Vectorized Micro-Kernels: ", "SIMD AVX2 parses 301,420+ EPS in strict linear O(N)."),
                ("• Autonomous Profiler: ", "Heuristic engine infers custom schemas in <30 seconds.")
            ],
            "metric": "ZERO ReDoS · STRICT LINEAR O(N) · < 1.8 µs PER RECORD",
            "color": (16, 185, 129), # Green
            "bg": (236, 253, 245),
        },
        {
            "step": "STEP 3",
            "name": "Lossless Canonical Projection",
            "tech": "UCE v1.0 · OCSF 1.1 · OpenTelemetry Logs · Elastic ECS",
            "bullets": [
                ("• Canonical Normalization: ", "Maps raw logs into unified UCE v1.0 standard schema."),
                ("• Zero-Drop Residue Vault: ", "Unmapped fields routed to metadata.unmapped vault."),
                ("• Cross-Schema Federation: ", "Lossless bidirectional bridges across OCSF, OTel, ECS.")
            ],
            "metric": "100% FORENSIC RETENTION · ZERO SILENT DROPS",
            "color": (124, 58, 237), # Purple
            "bg": (243, 232, 255),
        },
        {
            "step": "STEP 4",
            "name": "PII Masking & Anomaly Detection",
            "tech": "DPDP Act 2023 · Streaming Welford Algorithm · O(1) Variance",
            "bullets": [
                ("• DPDP 2023 Redaction: ", "In-line regex/DFA masking of Aadhaar, PAN & credentials."),
                ("• Streaming Anomaly Scoring: ", "Online variance calculation flags zero-day anomalies."),
                ("• Forensic Tokenization: ", "Maintains causality while obfuscating sensitive payloads.")
            ],
            "metric": "100% DPDP STATUTORY PRIVACY PRESERVATION",
            "color": (217, 119, 6), # Amber
            "bg": (254, 243, 199),
        },
        {
            "step": "STEP 5",
            "name": "PoA Merkle Ledger Sealing",
            "tech": "SHA-256 Merkle-DAG · Ed25519 Micro-Batching · §63 BSA 2023",
            "bullets": [
                ("• Cryptographic Tree Sealing: ", "Batches 1,000 logs into Merkle trees with Ed25519."),
                ("• Court Evidence Admissibility: ", "Auto-generates §63 BSA 2023 legal certificates."),
                ("• Non-Repudiation Proof: ", "Mathematical proof of log integrity without leaks.")
            ],
            "metric": "TAMPER-EVIDENT FORENSIC CHAIN-OF-CUSTODY",
            "color": (220, 38, 38), # Red
            "bg": (254, 226, 226),
        },
        {
            "step": "STEP 6",
            "name": "Sovereign Egress & Archival",
            "tech": "ZSTD-7 Apache Parquet · Splunk HEC · Elastic · Air-Gapped",
            "bullets": [
                ("• ESG Columnar Storage: ", "85% storage reduction, slashing datacenter power 70%."),
                ("• Multi-SIEM Ingestion Cut: ", "Multi-casts normalized logs with 80% volume drop."),
                ("• 100% Air-Gapped Sovereignty: ", "Full on-prem execution with zero cloud egress.")
            ],
            "metric": "85% STORAGE SAVING · 80% SIEM INGESTION CUT",
            "color": (14, 116, 222), # Tech Blue
            "bg": (239, 246, 255),
        },
    ]

    col_w = (W - 190) // 3
    row_h = 422
    f_step_num = get_font(FONT_BAHN, 32)
    f_step_title = get_font(FONT_BOLD, 37)
    f_step_tech = get_font(FONT_BOLD, 27)
    f_step_bullet_bold = get_font(FONT_BOLD, 28)
    f_step_bullet_reg = get_font(FONT_SEMI, 27)
    f_step_met = get_font(FONT_BAHN, 28)

    for i, s in enumerate(steps):
        col = i % 3
        row = i // 3
        bx = 55 + col * (col_w + 40)
        by = p_y + 78 + row * (row_h + 40)

        # Card Base with Drop Shadow
        draw.rounded_rectangle((bx + 3, by + 3, bx + col_w + 3, by + row_h + 3), radius=18, fill=(226, 232, 240))
        draw.rounded_rectangle((bx, by, bx + col_w, by + row_h), radius=18, fill=(255, 255, 255), outline=s["color"], width=3)
        
        # Left Thick Accent Stripe
        draw.rounded_rectangle((bx, by, bx + 16, by + row_h), radius=6, fill=s["color"])

        # Top Step Pill (Large & Bold)
        draw.rounded_rectangle((bx + 26, by + 16, bx + 165, by + 64), radius=10, fill=s["color"])
        draw.text((bx + 95, by + 40), s["step"], fill=(255, 255, 255), font=f_step_num, anchor="mm")

        # Step Title (Bold & Large)
        draw.text((bx + 180, by + 40), s["name"], fill=(10, 25, 47), font=f_step_title, anchor="lm")

        # Tech Badge Row (Wide & Prominent)
        draw.rounded_rectangle((bx + 26, by + 74, bx + col_w - 26, by + 118), radius=10, fill=s["bg"], outline=s["color"], width=1)
        draw.text((bx + 40, by + 96), s["tech"], fill=s["color"], font=f_step_tech, anchor="lm")

        # 3 Deep Bullets (Filling the Center with Large, Bold, High-Contrast Typography)
        cur_y = by + 130
        for b_lead, b_body in s["bullets"]:
            lead_w = draw.textlength(b_lead, font=f_step_bullet_bold)
            draw.text((bx + 26, cur_y), b_lead, fill=(10, 25, 47), font=f_step_bullet_bold, anchor="lt")
            
            body_lines = textwrap.wrap(b_body, width=42)
            if body_lines:
                draw.text((bx + 26 + lead_w, cur_y), body_lines[0], fill=(30, 41, 59), font=f_step_bullet_reg, anchor="lt")
                cur_y += 36
                for rem_line in body_lines[1:]:
                    draw.text((bx + 48, cur_y), rem_line, fill=(30, 41, 59), font=f_step_bullet_reg, anchor="lt")
                    cur_y += 36
            else:
                cur_y += 36
            cur_y += 8 # Clean spacing between bullets

        # Bottom Metric Seal Box (Prominent & High Contrast)
        draw.rounded_rectangle((bx + 26, by + row_h - 66, bx + col_w - 26, by + row_h - 14), radius=10, fill=s["bg"], outline=s["color"], width=2)
        draw.text((bx + col_w // 2, by + row_h - 40), s["metric"], fill=s["color"], font=f_step_met, anchor="mm")

        # Connecting Horizontal Arrows (Col 0 -> 1, Col 1 -> 2)
        if col < 2:
            draw_arrow_right(draw, bx + col_w + 6, by + row_h // 2, bx + col_w + 34, color=(14, 116, 222), width=7)

    # Clean Transition Indicator between Stage 3 and Stage 4
    r1_b = p_y + 78 + row_h
    r2_t = p_y + 78 + row_h + 40
    mid_y = (r1_b + r2_t) // 2
    f_flow = get_font(FONT_BOLD, 20)
    draw.rounded_rectangle((W - 650, mid_y - 18, W - 65, mid_y + 18), radius=14, fill=(238, 242, 255), outline=(124, 58, 237), width=2)
    draw.text((W - 357, mid_y), "▼ CONTINUOUS PIPELINE FLOW: STAGES 1-3  →  STAGES 4-6 ▼", fill=(124, 58, 237), font=f_flow, anchor="mm")

    # ==========================================================================
    # SECTION 2: 5-TIER SOVEREIGN ARCHITECTURE STACK (4-ZONE BALANCED GRID)
    # ==========================================================================
    t_y = 1175
    t_h = 945
    draw.rounded_rectangle((28, t_y, W - 28, t_y + t_h), radius=22, fill=(240, 249, 255), outline=(14, 116, 222), width=3)

    # Section Title & Air-Gap Badge
    draw.text((65, t_y + 44), "VISUAL 5-TIER SOVEREIGN ARCHITECTURE STACK (DEFENSE-GRADE MONOREPO)", fill=(30, 41, 59), font=f_sec, anchor="lm")
    
    draw.rounded_rectangle((W - 440, t_y + 20, W - 65, t_y + 68), radius=10, fill=(209, 250, 229), outline=(4, 120, 87), width=2)
    draw.text((W - 252, t_y + 44), "100% AIR-GAP ISOLATION", fill=(4, 120, 87), font=f_badge, anchor="mm")

    tiers = [
        {
            "tier": "TIER 5",
            "scope": "APPLICATION / EGRESS",
            "name": "Application & Strategic Egress Plane",
            "modules": "React 18 Console · Splunk HEC · Elastic ECS · OpenTelemetry Logs v1.0 · STIX 2.1 Threat Feeds",
            "role": "Delivers real-time SOC pane, MITRE ATT&CK correlation, and federated multi-SIEM dispatch with 80% volume drop.",
            "tag": "[ENTERPRISE SOC INTEGRATION]",
            "stat": "80% SIEM NOISE CUT",
            "sla": "MULTI-SIEM FEDERATION",
            "color": (2, 132, 199),
            "bg": (238, 242, 255),
        },
        {
            "tier": "TIER 4",
            "scope": "IMMUTABLE LEDGER",
            "name": "Cryptographic Lineage & Blockchain Ledger",
            "modules": "SHA-256 Merkle-DAG · Ed25519 Micro-Batching · §63 BSA 2023 & §65B IEA Automated Attestation Certificates",
            "role": "Guarantees mathematical non-repudiation, tamper-evident audit trails, and court-admissible electronic digital evidence.",
            "tag": "[JUDICIAL DIGITAL EVIDENCE PROOF]",
            "stat": "§63 BSA 2023 PROOF",
            "sla": "Ed25519 MERKLE-DAG",
            "color": (124, 58, 237),
            "bg": (243, 232, 255),
        },
        {
            "tier": "TIER 3",
            "scope": "CANONICAL / PRIVACY",
            "name": "Canonical Normalization & Data Privacy",
            "modules": "Universal Canonical Envelope (UCE v1.0) · Lossless metadata.unmapped Vault · DPDP Act 2023 Scrubbing Engine",
            "role": "Zero-drop schema projection with in-line scrubbing of Aadhaar, PAN, credentials & IPs with 100% forensic recovery.",
            "tag": "[STATUTORY PRIVACY & ZERO LOSS]",
            "stat": "100% ZERO-DROP",
            "sla": "DPDP PRIVACY SHIELD",
            "color": (16, 185, 129),
            "bg": (236, 253, 245),
        },
        {
            "tier": "TIER 2",
            "scope": "PARSER EXECUTION",
            "name": "Deterministic DFA Parser Execution Core",
            "modules": "20 Compiled Glushkov & Aho-Corasick DFAs · Autonomous <30s Profiler · C++20 / Rust AVX2 Micro-Kernels",
            "role": "Guarantees strict linear O(N) compute time permanently eliminating ReDoS CPU-starvation denial-of-service risks.",
            "tag": "[DETERMINISTIC SIMD COMPUTE]",
            "stat": "ZERO ReDoS RISKS",
            "sla": "LINEAR O(N) LINE RATE",
            "color": (217, 119, 6),
            "bg": (254, 243, 199),
        },
        {
            "tier": "TIER 1",
            "scope": "INGESTION / STORAGE",
            "name": "High-Speed Ingestion & Sovereign Storage",
            "modules": "Lock-Free Ring Spooling · Zero-Copy io_uring Sockets · ZSTD Columnar Apache Parquet · SQLite Metadata Indexer",
            "role": "Absorbs 1,000,000+ EPS bursts; cold-archives query-ready Parquet with 85% storage drop and 70% power reduction.",
            "tag": "[LINE-RATE STORAGE REDUCTION]",
            "stat": "301,420+ EPS RATE",
            "sla": "85% STORAGE SAVING",
            "color": (10, 25, 47),
            "bg": (241, 245, 249),
        },
    ]

    tier_h = 152
    f_tnum = get_font(FONT_BAHN, 32)
    f_tscope = get_font(FONT_BOLD, 21)
    f_tname = get_font(FONT_BOLD, 34)
    f_col_hdr = get_font(FONT_BOLD, 22)
    f_tmod = get_font(FONT_BOLD, 25)
    f_trole = get_font(FONT_SEMI, 24)
    f_ttag = get_font(FONT_BOLD, 20)
    f_tstat = get_font(FONT_BAHN, 36)
    f_tsla = get_font(FONT_BOLD, 24)

    for j, tr in enumerate(tiers):
        ty = t_y + 75 + j * (tier_h + 16)
        tx = 55
        tw = W - 110

        # Tier Base Card with Drop Shadow
        draw.rounded_rectangle((tx + 2, ty + 2, tx + tw + 2, ty + tier_h + 2), radius=16, fill=(219, 234, 254))
        draw.rounded_rectangle((tx, ty, tx + tw, ty + tier_h), radius=16, fill=(255, 255, 255), outline=tr["color"], width=2)
        
        # Left Thick Stripe
        draw.rounded_rectangle((tx, ty, tx + 16, ty + tier_h), radius=6, fill=tr["color"])

        # ----------------------------------------------------------------------
        # ZONE 1: LEFT IDENTITY (TIER PILL + SCOPE BADGE) - width = 270 px
        # ----------------------------------------------------------------------
        z1_w = 270
        draw.rounded_rectangle((tx + 28, ty + 16, tx + 28 + z1_w, ty + 74), radius=10, fill=tr["color"])
        draw.text((tx + 28 + z1_w // 2, ty + 45), tr["tier"], fill=(255, 255, 255), font=f_tnum, anchor="mm")

        draw.rounded_rectangle((tx + 28, ty + 82, tx + 28 + z1_w, ty + 136), radius=8, fill=tr["bg"], outline=tr["color"], width=1)
        draw.text((tx + 28 + z1_w // 2, ty + 109), tr["scope"], fill=tr["color"], font=f_tscope, anchor="mm")

        # Divider 1: between Zone 1 and Zone 2A
        div1_x = tx + 28 + z1_w + 18
        draw.line((div1_x, ty + 14, div1_x, ty + tier_h - 14), fill=(226, 232, 240), width=2)

        # ----------------------------------------------------------------------
        # ZONE 2A: ARCHITECTURE MODULES & STANDARDS (MIDDLE-LEFT, width = 1000 px)
        # ----------------------------------------------------------------------
        z2a_x = div1_x + 18
        # Tier Title
        draw.text((z2a_x, ty + 28), tr["name"], fill=(10, 25, 47), font=f_tname, anchor="lm")

        # Modules Sub-Header
        draw.text((z2a_x, ty + 68), "ENGINE MODULES & PROTOCOLS:", fill=tr["color"], font=f_col_hdr, anchor="lm")
        
        # Modules Content (Wrapped neatly to fill the column)
        mod_lines = textwrap.wrap(tr["modules"], width=48)
        m_y = ty + 98
        for m_line in mod_lines[:2]:
            draw.text((z2a_x, m_y), m_line, fill=(15, 23, 42), font=f_tmod, anchor="lm")
            m_y += 30

        # Divider 2: between Zone 2A and Zone 2B
        div2_x = z2a_x + 1010
        draw.line((div2_x, ty + 14, div2_x, ty + tier_h - 14), fill=(226, 232, 240), width=2)

        # ----------------------------------------------------------------------
        # ZONE 2B: SECURITY CAPABILITY & IMPACT (MIDDLE-RIGHT, width = 1060 px)
        # ----------------------------------------------------------------------
        z2b_x = div2_x + 18
        
        # Capability Header & Standard Pill on the same line!
        draw.text((z2b_x, ty + 28), "SECURITY CAPABILITY & IMPACT:", fill=(5, 150, 105), font=f_col_hdr, anchor="lm")
        tag_w = draw.textlength(tr["tag"], font=f_ttag)
        draw.rounded_rectangle((z2b_x + 360, ty + 10, z2b_x + 375 + tag_w, ty + 44), radius=6, fill=tr["bg"], outline=tr["color"], width=1)
        draw.text((z2b_x + 368 + tag_w // 2, ty + 27), tr["tag"], fill=tr["color"], font=f_ttag, anchor="mm")

        # Capability Role Text (Wrapped neatly to fill middle-right completely)
        role_lines = textwrap.wrap(tr["role"], width=54)
        r_y = ty + 68
        for r_line in role_lines[:2]:
            draw.text((z2b_x, r_y), r_line, fill=(51, 65, 85), font=f_trole, anchor="lm")
            r_y += 30
        
        # Sub-status metric line with a solid emerald circular dot
        draw.ellipse((z2b_x, ty + 118, z2b_x + 12, ty + 130), fill=(16, 185, 129))
        draw.text((z2b_x + 20, ty + 124), "AIR-GAPPED DEFENSE KERNEL · MONOREPO PRODUCTION CERTIFIED", fill=(16, 185, 129), font=get_font(FONT_BOLD, 19), anchor="lm")

        # Divider 3: between Zone 2B and Zone 3
        div3_x = z2b_x + 1070
        draw.line((div3_x, ty + 14, div3_x, ty + tier_h - 14), fill=(226, 232, 240), width=2)

        # ----------------------------------------------------------------------
        # ZONE 3: RIGHT ENCLOSED SLA SEAL CONTAINER (width = 595 px)
        # ----------------------------------------------------------------------
        z3_x = div3_x + 18
        z3_w = tx + tw - z3_x - 14
        draw.rounded_rectangle((z3_x, ty + 14, z3_x + z3_w, ty + tier_h - 14), radius=12, fill=tr["bg"], outline=tr["color"], width=2)
        draw.text((z3_x + z3_w // 2, ty + 46), tr["stat"], fill=tr["color"], font=f_tstat, anchor="mm")
        
        draw.rounded_rectangle((z3_x + 20, ty + 74, z3_x + z3_w - 20, ty + 122), radius=8, fill=(255, 255, 255), outline=tr["color"], width=1)
        draw.text((z3_x + z3_w // 2, ty + 98), tr["sla"], fill=tr["color"], font=f_tsla, anchor="mm")

    # ==========================================================================
    # BOTTOM TRUST & PERFORMANCE RIBBON
    # ==========================================================================
    rf_y = H - 110
    draw.rounded_rectangle((28, rf_y, W - 28, H - 28), radius=16, fill=(10, 25, 47))
    f_rib = get_font(FONT_BAHN, 32)
    draw.text((W // 2, rf_y + 40), "AUDITED PERFORMANCE: 301,420+ EPS SUSTAINED  |  < 4.8 ms p99 LATENCY  |  680/680 TESTS PASSING (100%)  |  TRL 8 GATE", fill=(52, 211, 153), font=f_rib, anchor="mm")

    os.makedirs(os.path.dirname(os.path.abspath(output_4k)), exist_ok=True)
    img.save(output_4k, "PNG", dpi=(300, 300))
    img.save(output_std, "PNG", dpi=(300, 300))
    print(f"[RENDER] Sovereign System Topology -> {output_4k} ({W}x{H} @ 300 DPI)")
    print(f"[RENDER] Standard Asset -> {output_std}")


def main():
    parser = argparse.ArgumentParser(description="Render ULPF 5-Tier Sovereign System Architecture & Implementation Pipeline")
    parser.add_argument("--out-4k", default=DEFAULT_4K_PATH, help="Path for 4K master topology diagram")
    parser.add_argument("--out-std", default=DEFAULT_STD_PATH, help="Path for standard diagram")
    args = parser.parse_args()
    render_system_topology(args.out_4k, args.out_std)


if __name__ == "__main__":
    main()
