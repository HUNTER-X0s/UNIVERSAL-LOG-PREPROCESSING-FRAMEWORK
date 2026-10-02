"""
ULPF — Sovereign Telemetry Pipeline Architecture Visualizer
Production-grade renderer for high-resolution system topology schematics,
illustrating heterogeneous multi-vendor intake, atomic ring spooling,
deterministic DFA normalization, Merkle DAG ledger verification, and unified egress.
"""

import os
import sys
import argparse
import textwrap
from PIL import Image, ImageDraw, ImageFont

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_4K_PATH = os.path.join(ROOT_DIR, "SLIDE2_ARCHITECTURE_DIAGRAM_4K.png")
DEFAULT_STD_PATH = os.path.join(ROOT_DIR, "SLIDE2_ARCHITECTURE_DIAGRAM.png")

FONT_BOLD = "C:/Windows/Fonts/segoeuib.ttf"
FONT_SEMI = "C:/Windows/Fonts/seguisb.ttf"
FONT_REG  = "C:/Windows/Fonts/segoeui.ttf"
FONT_BAHN = "C:/Windows/Fonts/bahnschrift.ttf"


def get_font(path: str, size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def draw_arrow(draw: ImageDraw.ImageDraw, cx: int, y1: int, y2: int, color=(14, 116, 222), width: int = 7):
    draw.line((cx, y1, cx, y2), fill=color, width=width)
    ah = 24
    aw = 20
    draw.polygon([(cx, y2), (cx - aw, y2 - ah), (cx + aw, y2 - ah)], fill=color)


def render_pipeline_architecture(output_4k: str = DEFAULT_4K_PATH, output_std: str = DEFAULT_STD_PATH):
    """
    Renders the complete sovereign telemetry pipeline diagram at 2160x3450 (300 DPI).
    """
    W, H = 2160, 3450
    img = Image.new("RGBA", (W, H), (255, 255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Outer Container Border
    draw.rounded_rectangle((12, 12, W - 12, H - 12), radius=36, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=4)

    # ==========================================================================
    # 1. TOP EXECUTIVE HEADER BANNER
    # ==========================================================================
    banner_h = 200
    draw.rounded_rectangle((35, 35, W - 35, banner_h), radius=22, fill=(10, 25, 47, 255)) # Deep Navy
    
    f_title = get_font(FONT_BAHN, 62)
    f_sub = get_font(FONT_BOLD, 28)
    draw.text((W // 2, 88), "SOVEREIGN TELEMETRY PIPELINE", fill=(255, 255, 255), font=f_title, anchor="mm")
    draw.text((W // 2, 155), "END-TO-END TELEMETRY NORMALIZATION & FORENSIC ASSURANCE", fill=(56, 189, 248), font=f_sub, anchor="mm")

    # ==========================================================================
    # TIER 1: MULTI-VENDOR RAW INTAKE (CHAOS -> ORDER)
    # ==========================================================================
    t1_y = 235
    t1_h = 515
    draw.rounded_rectangle((45, t1_y, W - 45, t1_y + t1_h), radius=26, fill=(248, 250, 252), outline=(203, 213, 225), width=3)

    # Section Title & Badge
    f_sec = get_font(FONT_BAHN, 40)
    draw.text((80, t1_y + 48), "1. HETEROGENEOUS MULTI-VENDOR INTAKE", fill=(30, 41, 59), font=f_sec, anchor="lm")

    f_badge = get_font(FONT_BOLD, 26)
    draw.rounded_rectangle((W - 440, t1_y + 22, W - 80, t1_y + 76), radius=12, fill=(254, 226, 226), outline=(220, 38, 38), width=2)
    draw.text((W - 260, t1_y + 49), "50+ VENDOR FORMATS", fill=(185, 28, 28), font=f_badge, anchor="mm")

    # 4 Large, Vibrant Format Blocks (2x2 Grid)
    formats = [
        ("SYSLOG TELEMETRY", "RFC 3164 / 5424 · Linux & Switches", "UDP/TCP 514", (2, 132, 199), (238, 242, 255)),
        ("WINDOWS EVENTLOG", "EVTX XML · Security & Sysmon Telemetry", "CHANNEL BIND", (13, 148, 136), (204, 251, 241)),
        ("CLOUD TELEMETRY", "AWS CloudTrail · GCP Audit · Azure Monitor", "API STREAM", (217, 119, 6), (254, 243, 199)),
        ("PERIMETER FIREWALLS", "Palo Alto · Cisco ASA · Fortinet · Check Point", "DEEP FLOW", (220, 38, 38), (254, 226, 226)),
    ]

    f_fhdr = get_font(FONT_BOLD, 36)
    f_fsub = get_font(FONT_SEMI, 25)
    f_fpill = get_font(FONT_BOLD, 23)
    card_w = (W - 190) // 2
    card_h = 172

    for i, (f_h, f_s, f_p, color, bg) in enumerate(formats):
        col = i % 2
        row = i // 2
        fx = 80 + col * (card_w + 30)
        fy = t1_y + 115 + row * (card_h + 26)

        # Card shadow & base
        draw.rounded_rectangle((fx + 3, fy + 3, fx + card_w + 3, fy + card_h + 3), radius=18, fill=(226, 232, 240))
        draw.rounded_rectangle((fx, fy, fx + card_w, fy + card_h), radius=18, fill=bg, outline=color, width=2)
        # Left color bar
        draw.rounded_rectangle((fx, fy, fx + 16, fy + card_h), radius=6, fill=color)

        # Title
        draw.text((fx + 40, fy + 52), f_h, fill=color, font=f_fhdr, anchor="lm")
        # Subtitle
        draw.text((fx + 40, fy + 114), f_s, fill=(51, 65, 85), font=f_fsub, anchor="lm")

        # Right Pill Badge inside card
        pb_w = 205
        draw.rounded_rectangle((fx + card_w - pb_w - 25, fy + 28, fx + card_w - 25, fy + 78), radius=10, fill=(255, 255, 255), outline=color, width=2)
        draw.text((fx + card_w - pb_w // 2 - 25, fy + 53), f_p, fill=color, font=f_fpill, anchor="mm")

    # Arrow Tier 1 -> Tier 2
    draw_arrow(draw, W // 2, t1_y + t1_h + 6, t1_y + t1_h + 52, color=(14, 116, 222), width=8)

    # ==========================================================================
    # TIER 2: ULPF SOVEREIGN PROCESSING CORE
    # ==========================================================================
    t2_y = 808
    t2_h = 1445
    draw.rounded_rectangle((45, t2_y, W - 45, t2_y + t2_h), radius=26, fill=(240, 249, 255), outline=(14, 116, 222), width=3)

    # Header Bar
    t2_hdr_h = 92
    draw.rounded_rectangle((45, t2_y, W - 45, t2_y + t2_hdr_h), radius=22, fill=(14, 116, 222))
    f_core_hdr = get_font(FONT_BAHN, 40)
    draw.text((W // 2, t2_y + 46), "2. ULPF SOVEREIGN PROCESSING CORE", fill=(255, 255, 255), font=f_core_hdr, anchor="mm")

    draw.rounded_rectangle((W - 350, t2_y + 18, W - 75, t2_y + 72), radius=10, fill=(16, 185, 129))
    draw.text((W - 212, t2_y + 45), "TRL 8/8 GATEWAY", fill=(255, 255, 255), font=get_font(FONT_BOLD, 22), anchor="mm")

    # 4 CORE STAGES (3-ZONE BALANCED LAYOUT)
    stages = [
        {
            "stage": "STAGE 1",
            "tag": "boost::lockfree CAS",
            "title": "Lock-Free CAS Memory Spooling",
            "bullets": [
                "• Pre-allocated circular ring buffers absorb massive telemetry bursts with zero packet loss.",
                "• Content-Addressed Storage (CAS) immediately seals verbatim raw bytes in memory via SHA-256."
            ],
            "sla_title": "INTAKE RATE",
            "sla_val": "1,000,000+",
            "sla_sub": "EPS PEAK BURST",
            "sla_badge": "0.000% LOSS GUARANTEE",
            "color": (2, 132, 199),
            "bg": (238, 242, 255),
        },
        {
            "stage": "STAGE 2",
            "tag": "Glushkov & Aho-Corasick",
            "title": "20 Deterministic DFA Parsing Engines",
            "bullets": [
                "• Pre-compiled state automata replace regex, permanently eliminating ReDoS CPU freezing.",
                "• Strict linear O(N) execution parses logs in < 1.8 µs with zero CPU thread starvation."
            ],
            "sla_title": "COMPUTE SLA",
            "sla_val": "ZERO ReDoS",
            "sla_sub": "STRICT LINEAR O(N)",
            "sla_badge": "< 1.8 µs PER RECORD",
            "color": (16, 185, 129),
            "bg": (236, 253, 245),
        },
        {
            "stage": "STAGE 3",
            "tag": "UCE v1.0 / OCSF 1.1",
            "title": "Canonical Envelope (UCE v1.0) & Vault",
            "bullets": [
                "• Bidirectional schema projection maps tokens to OCSF 1.1, OpenTelemetry, and ECS 8.11.",
                "• 100% Zero-Drop Guarantee: Unmapped vendor attributes routed to indexed residue vault."
            ],
            "sla_title": "DATA INTEGRITY",
            "sla_val": "100% RETENTION",
            "sla_sub": "ZERO-DROP SCHEMAS",
            "sla_badge": "metadata.unmapped VAULT",
            "color": (124, 58, 237),
            "bg": (243, 232, 255),
        },
        {
            "stage": "STAGE 4",
            "tag": "SHA-256 / Ed25519",
            "title": "PoA Merkle Blockchain Ledger",
            "bullets": [
                "• Micro-batches 1,000 events into cryptographic Merkle trees with Ed25519 digital signatures.",
                "• Generates automated legal attestation certs admissible under Section 63 BSA 2023 / §65B IEA."
            ],
            "sla_title": "COURT EVIDENCE",
            "sla_val": "§63 BSA 2023",
            "sla_sub": "TAMPER-EVIDENT DAG",
            "sla_badge": "Ed25519 NON-REPUDIATION",
            "color": (217, 119, 6),
            "bg": (254, 243, 199),
        },
    ]

    s_card_w = W - 160
    s_card_h = 280
    f_s_tag = get_font(FONT_BOLD, 22)
    f_s_num = get_font(FONT_BAHN, 26)
    f_s_title = get_font(FONT_BOLD, 36)
    f_s_bullet = get_font(FONT_BOLD, 26)
    f_sla_t = get_font(FONT_BOLD, 21)
    f_sla_v = get_font(FONT_BAHN, 36)
    f_sla_s = get_font(FONT_BOLD, 20)
    f_sla_b = get_font(FONT_BOLD, 20)

    for idx, stg in enumerate(stages):
        sy = t2_y + 115 + idx * (s_card_h + 22)
        sx = 80

        # Card drop shadow & base
        draw.rounded_rectangle((sx + 3, sy + 3, sx + s_card_w + 3, sy + s_card_h + 3), radius=18, fill=(226, 232, 240))
        draw.rounded_rectangle((sx, sy, sx + s_card_w, sy + s_card_h), radius=18, fill=(255, 255, 255), outline=stg["color"], width=2)
        # Left Thick Accent Bar
        draw.rounded_rectangle((sx, sy, sx + 18, sy + s_card_h), radius=6, fill=stg["color"])

        # ----------------------------------------------------------------------
        # ZONE 1: LEFT IDENTITY PILL (Width = 300)
        # ----------------------------------------------------------------------
        z1_w = 300
        draw.rounded_rectangle((sx + 35, sy + 35, sx + 35 + z1_w, sy + 105), radius=12, fill=stg["color"])
        draw.text((sx + 35 + z1_w // 2, sy + 70), stg["stage"], fill=(255, 255, 255), font=f_s_num, anchor="mm")

        draw.rounded_rectangle((sx + 35, sy + 125, sx + 35 + z1_w, sy + 175), radius=8, fill=stg["bg"], outline=stg["color"], width=1)
        draw.text((sx + 35 + z1_w // 2, sy + 150), stg["tag"], fill=stg["color"], font=f_s_tag, anchor="mm")

        # Vertical Divider 1
        draw.line((sx + 35 + z1_w + 30, sy + 25, sx + 35 + z1_w + 30, sy + s_card_h - 25), fill=(226, 232, 240), width=2)

        # ----------------------------------------------------------------------
        # ZONE 2: MIDDLE ENGINE SPECIFICATION (Width = 1100 px - ZERO EMPTY VOID!)
        # ----------------------------------------------------------------------
        z2_x = sx + 35 + z1_w + 55
        draw.text((z2_x, sy + 48), stg["title"], fill=(10, 25, 47), font=f_s_title, anchor="lm")

        cur_by = sy + 98
        for b_text in stg["bullets"]:
            lines = textwrap.wrap(b_text, width=54)
            for l_idx, l_str in enumerate(lines):
                draw.text((z2_x, cur_by), l_str, fill=(15, 23, 42), font=f_s_bullet, anchor="lm")
                cur_by += 34
            cur_by += 6

        # Vertical Divider 2
        z3_w = 380
        z3_x = sx + s_card_w - z3_w - 30
        draw.line((z3_x - 30, sy + 25, z3_x - 30, sy + s_card_h - 25), fill=(226, 232, 240), width=2)

        # ----------------------------------------------------------------------
        # ZONE 3: RIGHT ENCLOSED SLA SEAL BOX (Width = 380 px)
        # ----------------------------------------------------------------------
        draw.rounded_rectangle((z3_x, sy + 25, z3_x + z3_w, sy + s_card_h - 25), radius=16, fill=stg["bg"], outline=stg["color"], width=2)
        draw.text((z3_x + z3_w // 2, sy + 58), stg["sla_title"], fill=(100, 116, 139), font=f_sla_t, anchor="mm")
        draw.text((z3_x + z3_w // 2, sy + 104), stg["sla_val"], fill=stg["color"], font=f_sla_v, anchor="mm")
        draw.text((z3_x + z3_w // 2, sy + 144), stg["sla_sub"], fill=(71, 85, 105), font=f_sla_s, anchor="mm")

        # Bottom inner badge
        draw.rounded_rectangle((z3_x + 20, sy + 172, z3_x + z3_w - 20, sy + 218), radius=8, fill=(255, 255, 255), outline=stg["color"], width=1)
        draw.text((z3_x + z3_w // 2, sy + 195), stg["sla_badge"], fill=stg["color"], font=f_sla_b, anchor="mm")

    # Bottom Core Performance Ribbon
    p_rib_y = t2_y + t2_h - 88
    draw.rounded_rectangle((65, p_rib_y, W - 65, t2_y + t2_h - 18), radius=14, fill=(10, 25, 47))
    f_prib = get_font(FONT_BAHN, 28)
    draw.text((W // 2, p_rib_y + 35), "AUDITED PERFORMANCE: 301,420+ EPS SUSTAINED  |  < 4.8 ms p99 LATENCY  |  TRL 8 GATE", fill=(52, 211, 153), font=f_prib, anchor="mm")

    # Arrow Tier 2 -> Tier 3
    draw_arrow(draw, W // 2, t2_y + t2_h + 6, t2_y + t2_h + 52, color=(14, 116, 222), width=8)

    # ==========================================================================
    # TIER 3: UNIFIED DEFENSE VALUE & COMPLIANCE EGRESS
    # ==========================================================================
    t3_y = 2315
    t3_h = 945
    draw.rounded_rectangle((45, t3_y, W - 45, t3_y + t3_h), radius=26, fill=(248, 250, 252), outline=(203, 213, 225), width=3)

    # Section Title & Air-Gap Badge
    draw.text((80, t3_y + 48), "3. UNIFIED DEFENSE VALUE & COMPLIANCE EGRESS", fill=(30, 41, 59), font=f_sec, anchor="lm")

    draw.rounded_rectangle((W - 460, t3_y + 22, W - 80, t3_y + 76), radius=12, fill=(209, 250, 229), outline=(4, 120, 87), width=2)
    draw.text((W - 270, t3_y + 49), "100% AIR-GAPPED EGRESS", fill=(4, 120, 87), font=f_badge, anchor="mm")

    # 3 High-Impact Egress Cards
    egress_cards = [
        {
            "top_label": "SOVEREIGN SIEM INGEST",
            "val": "80% VOLUME CUT",
            "sub": "OCSF 1.1 / OTel / ECS Schema",
            "body": "Saves INR 1.80 Cr annually per 10 TB/day SOC. Eliminates foreign vendor lock-in.",
            "proof": "PRODUCTION VERIFIED",
            "color": (2, 132, 199),
            "bg": (238, 242, 255),
        },
        {
            "top_label": "AIR-GAP PARQUET VAULT",
            "val": "85% FOOTPRINT DROP",
            "sub": "Apache Parquet Columnar Storage",
            "body": "Cuts 10 TB/day to 1.5 TB query-ready. Slashes data-center power & carbon by 70%.",
            "proof": "PRODUCTION VERIFIED",
            "color": (16, 185, 129),
            "bg": (236, 253, 245),
        },
        {
            "top_label": "JUDICIAL FORENSIC PROOF",
            "val": "§63 BSA 2023 CERTIFICATE",
            "sub": "Tamper-Evident Ed25519 Chain",
            "body": "Generates court-admissible electronic evidence certificates under §63 BSA / §65B IEA.",
            "proof": "PRODUCTION VERIFIED",
            "color": (124, 58, 237),
            "bg": (243, 232, 255),
        },
    ]

    e_card_w = (W - 220) // 3
    e_card_h = 675
    f_e_top = get_font(FONT_BOLD, 24)
    f_e_val = get_font(FONT_BAHN, 40)
    f_e_sub = get_font(FONT_BOLD, 24)
    f_e_body = get_font(FONT_SEMI, 27)
    f_e_prf = get_font(FONT_BOLD, 22)

    for k, ec in enumerate(egress_cards):
        ex = 80 + k * (e_card_w + 30)
        ey = t3_y + 115

        # Card shadow & base
        draw.rounded_rectangle((ex + 3, ey + 3, ex + e_card_w + 3, ey + e_card_h + 3), radius=20, fill=(226, 232, 240))
        draw.rounded_rectangle((ex, ey, ex + e_card_w, ey + e_card_h), radius=20, fill=(255, 255, 255), outline=ec["color"], width=2)

        # Top Header Pill
        draw.rounded_rectangle((ex + 25, ey + 25, ex + e_card_w - 25, ey + 82), radius=10, fill=ec["color"])
        draw.text((ex + e_card_w // 2, ey + 53), ec["top_label"], fill=(255, 255, 255), font=f_e_top, anchor="mm")

        # Stat Value
        draw.text((ex + e_card_w // 2, ey + 155), ec["val"], fill=ec["color"], font=f_e_val, anchor="mm")
        # Subtitle
        draw.text((ex + e_card_w // 2, ey + 215), ec["sub"], fill=(15, 23, 42), font=f_e_sub, anchor="mm")

        # Divider line
        draw.line((ex + 35, ey + 255, ex + e_card_w - 35, ey + 255), fill=(226, 232, 240), width=2)

        # Body text
        cur_ey = ey + 300
        for b_line in textwrap.wrap(ec["body"], width=32):
            draw.text((ex + 35, cur_ey), b_line, fill=(51, 65, 85), font=f_e_body, anchor="lt")
            cur_ey += 40

        # Bottom Verification Seal
        draw.rounded_rectangle((ex + 25, ey + e_card_h - 85, ex + e_card_w - 25, ey + e_card_h - 25), radius=10, fill=ec["bg"], outline=ec["color"], width=2)
        draw.text((ex + e_card_w // 2, ey + e_card_h - 55), ec["proof"], fill=ec["color"], font=f_e_prf, anchor="mm")

    # Bottom Master Trust Ribbon
    rf_y = t3_y + t3_h - 105
    draw.rounded_rectangle((65, rf_y, W - 65, t3_y + t3_h - 25), radius=14, fill=(10, 25, 47))
    f_rib = get_font(FONT_BAHN, 28)
    draw.text((W // 2, rf_y + 40), "SHIELDED AIR-GAP SOVEREIGNTY  |  ZERO VENDOR LOCK-IN  |  ATMANIRBHAR BHARAT DEFENSE", fill=(255, 255, 255), font=f_rib, anchor="mm")

    # Save high-res assets
    os.makedirs(os.path.dirname(os.path.abspath(output_4k)), exist_ok=True)
    img.save(output_4k, "PNG", dpi=(300, 300))
    img.save(output_std, "PNG", dpi=(300, 300))
    print(f"[RENDER] Sovereign Pipeline Architecture -> {output_4k} ({W}x{H} @ 300 DPI)")
    print(f"[RENDER] Standard Asset -> {output_std}")


def main():
    parser = argparse.ArgumentParser(description="Render ULPF Sovereign Telemetry Pipeline Architecture")
    parser.add_argument("--out-4k", default=DEFAULT_4K_PATH, help="Path for 4K master diagram")
    parser.add_argument("--out-std", default=DEFAULT_STD_PATH, help="Path for standard diagram")
    args = parser.parse_args()
    render_pipeline_architecture(args.out_4k, args.out_std)


if __name__ == "__main__":
    main()
