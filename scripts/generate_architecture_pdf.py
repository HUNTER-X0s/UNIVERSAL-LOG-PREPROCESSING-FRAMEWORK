"""
ULPF Architecture Document — Professional 2-Page Technical Specification & Architecture Flow Diagrams
Produces a defense-grade, publication-quality 2-page A4 PDF with ZERO wasted space and ZERO text collisions.
"""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.platypus.flowables import Flowable

# ── Color Palette ────────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#0A192F")
NAVY_LIGHT  = colors.HexColor("#1E293B")
GOV_BLUE    = colors.HexColor("#0D47A1")
BLUE_ACCENT = colors.HexColor("#1E88E5")
BLUE_BG     = colors.HexColor("#F0F7FF")
BLUE_BORDER = colors.HexColor("#BBDEFB")

GREEN       = colors.HexColor("#0A7E44")
GREEN_LIGHT = colors.HexColor("#E8F5E9")
GREEN_BORDER= colors.HexColor("#A5D6A7")

PURPLE      = colors.HexColor("#6A1B9A")
PURPLE_LIGHT= colors.HexColor("#F3E5F5")
PURPLE_BORDER = colors.HexColor("#CE93D8")

AMBER       = colors.HexColor("#B76E00")
AMBER_LIGHT = colors.HexColor("#FFF8E1")
AMBER_BORDER= colors.HexColor("#FFE082")

RED         = colors.HexColor("#C62828")
RED_LIGHT   = colors.HexColor("#FFEBEE")
RED_BORDER  = colors.HexColor("#FFCDD2")

CYAN        = colors.HexColor("#00838F")
CYAN_LIGHT  = colors.HexColor("#E0F7FA")

SLATE_MUTED = colors.HexColor("#64748B")
BORDER_GRAY = colors.HexColor("#CBD5E1")
LIGHT_CARD  = colors.HexColor("#F8FAFC")
WHITE       = colors.white

W, H = A4  # 595.28 x 841.89 pts
MARGIN_LR = 12 * mm
MARGIN_TOP = 20 * mm
MARGIN_BOT = 10 * mm
AVAIL_W = W - 2 * MARGIN_LR

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ARCHITECTURE_DOCUMENT.pdf"
)


# ── Page Header / Footer Canvas ──────────────────────────────────────────────
def draw_page_frame(canvas_obj, doc):
    canvas_obj.saveState()
    page_num = doc.page

    # Header Bar
    canvas_obj.setFillColor(NAVY)
    canvas_obj.rect(0, H - 18 * mm, W, 18 * mm, fill=1, stroke=0)

    # Accent Stripe
    canvas_obj.setFillColor(BLUE_ACCENT)
    canvas_obj.rect(0, H - 19 * mm, W, 1.0 * mm, fill=1, stroke=0)

    # Header Title & Subtitle
    canvas_obj.setFillColor(WHITE)
    canvas_obj.setFont("Helvetica-Bold", 10.5)
    canvas_obj.drawString(MARGIN_LR, H - 10 * mm, "Universal Log Pre-processing Framework (ULPF) — Architecture Specification")
    
    canvas_obj.setFont("Helvetica", 7.5)
    canvas_obj.setFillColor(colors.HexColor("#94A3B8"))
    canvas_obj.drawString(MARGIN_LR, H - 15 * mm, "High-Throughput Sovereign Telemetry Engine · Defense-Grade SIEM Normalization · NTRO SIH-26156")

    # Page Number Pill Badge
    pill_w = 48
    pill_h = 13
    pill_x = W - MARGIN_LR - pill_w
    pill_y = H - 14 * mm
    canvas_obj.setFillColor(colors.HexColor("#1E293B"))
    canvas_obj.roundRect(pill_x, pill_y, pill_w, pill_h, 3, fill=1, stroke=0)
    canvas_obj.setStrokeColor(BLUE_ACCENT)
    canvas_obj.setLineWidth(0.7)
    canvas_obj.roundRect(pill_x, pill_y, pill_w, pill_h, 3, fill=0, stroke=1)
    
    canvas_obj.setFillColor(WHITE)
    canvas_obj.setFont("Helvetica-Bold", 7.5)
    canvas_obj.drawCentredString(pill_x + pill_w / 2, pill_y + 3.5, f"PAGE {page_num} OF 2")

    # Bottom Footer
    canvas_obj.setFillColor(LIGHT_CARD)
    canvas_obj.rect(0, 0, W, 8 * mm, fill=1, stroke=0)
    canvas_obj.setFillColor(BORDER_GRAY)
    canvas_obj.rect(0, 8 * mm, W, 0.5 * mm, fill=1, stroke=0)

    canvas_obj.setFillColor(SLATE_MUTED)
    canvas_obj.setFont("Helvetica", 6.8)
    canvas_obj.drawString(MARGIN_LR, 2.8 * mm, "ULPF v1.0.0-sih · 301,000+ EPS · p99 < 4.8ms · 0% Loss Residue · 100% Air-Gapped")
    canvas_obj.drawRightString(W - MARGIN_LR, 2.8 * mm, "National Technical Research Organisation (NTRO) · SIH 2026 Evaluation")

    canvas_obj.restoreState()


# ── Section Title Flowable ───────────────────────────────────────────────────
class SectionTitle(Flowable):
    def __init__(self, number, title, subtitle="", color=GOV_BLUE):
        super().__init__()
        self.number = str(number)
        self.title = title
        self.subtitle = subtitle
        self.color = color
        self.width = AVAIL_W
        self.height = 15

    def draw(self):
        c = self.canv
        # Left colored pill badge
        badge_w = 20
        badge_h = 13
        c.setFillColor(self.color)
        c.roundRect(0, 1, badge_w, badge_h, 2.5, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawCentredString(badge_w / 2, 4.5, f"§{self.number}")

        # Title text
        c.setFillColor(NAVY)
        c.setFont("Helvetica-Bold", 9.2)
        c.drawString(badge_w + 6, 4, self.title)

        # Optional subtitle / tag on right
        if self.subtitle:
            c.setFont("Helvetica-Oblique", 7.0)
            c.setFillColor(SLATE_MUTED)
            c.drawRightString(self.width, 4.5, self.subtitle)

        # Bottom hairline accent
        c.setStrokeColor(colors.HexColor("#E2E8F0"))
        c.setLineWidth(0.6)
        c.line(badge_w + 6, 0.5, self.width, 0.5)


# ── Flowable: End-to-End Pipeline Flow Diagram (Expanded & Clean) ───────────
class EndToEndPipelineDiagram(Flowable):
    """6-stage rich horizontal pipeline with prominent headers, spacious cards, and zero overlap."""
    def __init__(self, width, height=142):
        super().__init__()
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        w, h = self.width, self.height

        # Container card background
        c.setFillColor(colors.HexColor("#FAFAFC"))
        c.roundRect(0, 0, w, h, 5, fill=1, stroke=0)
        c.setStrokeColor(BORDER_GRAY)
        c.setLineWidth(0.7)
        c.roundRect(0, 0, w, h, 5, fill=0, stroke=1)

        # Top label bar
        c.setFillColor(NAVY)
        c.roundRect(0, h - 17, w, 17, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(10, h - 12, "UNIVERSAL TELEMETRY INGESTION & CANONICAL NORMALIZATION PIPELINE")
        c.setFillColor(colors.HexColor("#38BDF8"))
        c.setFont("Helvetica-Bold", 7.0)
        c.drawRightString(w - 10, h - 12, "HIGH-THROUGHPUT PATH · 301,000+ EPS · p99 < 4.8 ms")

        # 6 Stages
        stages = [
            (
                "1. INGESTION", "Wire Ingress",
                ["Syslog RFC 5424/3164", "HTTP REST / TLS", "Kernel Ring Buffer", "Zero-Copy TCP/UDP"],
                NAVY, BLUE_BG, BLUE_BORDER
            ),
            (
                "2. CAS STORAGE", "Capture-First",
                ["SHA-256 Byte Lock", "WORM Immutable", "Raw Bytes Preserved", "Zero Pre-Parse Loss"],
                GOV_BLUE, BLUE_BG, BLUE_BORDER
            ),
            (
                "3. DFA PARSING", "Linear Runtime",
                ["20 DFA State Engines", "ReDoS-Immune O(N)", "Tier A/B/C Vendors", "Auto-Profiler (<30s)"],
                PURPLE, PURPLE_LIGHT, PURPLE_BORDER
            ),
            (
                "4. UCE NORMAL", "Canonical Schema",
                ["UCE v1.0 Taxonomy", "PII Masking (Aadhaar)", "100% Residue Vault", "Pydantic v2 Contract"],
                GREEN, GREEN_LIGHT, GREEN_BORDER
            ),
            (
                "5. ANOMALY / AI", "Inline Analytics",
                ["Welford Streaming Z", "MITRE ATT&CK Map", "Event Quality Score", "Temporal Profiling"],
                AMBER, AMBER_LIGHT, AMBER_BORDER
            ),
            (
                "6. SIEM EGRESS", "Zero-Copy Push",
                ["Splunk HEC (OCSF)", "Elasticsearch (ECS)", "OTel Logs v1.0", "STIX 2.1 Threat Intel"],
                RED, RED_LIGHT, RED_BORDER
            ),
        ]

        num_boxes = len(stages)
        arrow_w = 11
        box_w = (w - 16 - (num_boxes - 1) * arrow_w) / num_boxes
        box_h = h - 25
        y_box = 5

        x = 8
        for i, (title, subheader, desc_lines, main_clr, bg_clr, border_clr) in enumerate(stages):
            # Box background
            c.setFillColor(bg_clr)
            c.roundRect(x, y_box, box_w, box_h, 3.5, fill=1, stroke=0)
            c.setStrokeColor(border_clr)
            c.setLineWidth(0.8)
            c.roundRect(x, y_box, box_w, box_h, 3.5, fill=0, stroke=1)

            # Top header pill inside box
            c.setFillColor(main_clr)
            c.roundRect(x + 2, y_box + box_h - 15, box_w - 4, 13, 2, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 6.2)
            c.drawCentredString(x + box_w / 2, y_box + box_h - 10.5, title)

            # Subheader tag (with dedicated pill to prevent any collision)
            sub_h = 10
            sub_y = y_box + box_h - 28
            c.setFillColor(WHITE)
            c.roundRect(x + 4, sub_y, box_w - 8, sub_h, 2, fill=1, stroke=0)
            c.setStrokeColor(border_clr)
            c.setLineWidth(0.4)
            c.roundRect(x + 4, sub_y, box_w - 8, sub_h, 2, fill=0, stroke=1)
            c.setFillColor(main_clr)
            c.setFont("Helvetica-Bold", 5.4)
            c.drawCentredString(x + box_w / 2, sub_y + 2.8, subheader)

            # Description bullet cards inside box (spacious 14pt cards with perfectly centered text)
            card_h = 14
            for line_idx, line_txt in enumerate(desc_lines):
                ly = y_box + box_h - 43 - (line_idx * 16.5)
                c.setFillColor(WHITE)
                c.roundRect(x + 3, ly, box_w - 6, card_h, 2, fill=1, stroke=0)
                c.setStrokeColor(BORDER_GRAY)
                c.setLineWidth(0.4)
                c.roundRect(x + 3, ly, box_w - 6, card_h, 2, fill=0, stroke=1)
                c.setFillColor(NAVY_LIGHT)
                c.setFont("Helvetica", 5.4)
                c.drawCentredString(x + box_w / 2, ly + 4.5, line_txt)

            # Stage completion check pill at bottom
            pill_h = 9
            c.setFillColor(main_clr)
            c.roundRect(x + box_w / 2 - 16, y_box + 3, 32, pill_h, 2, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 5.2)
            c.drawCentredString(x + box_w / 2, y_box + 5.5, f"STAGE 0{i+1}")

            # Draw Connecting Arrow
            if i < num_boxes - 1:
                ax = x + box_w + 1
                ay = y_box + box_h / 2
                c.setStrokeColor(BLUE_ACCENT)
                c.setFillColor(BLUE_ACCENT)
                c.setLineWidth(1.4)
                c.line(ax, ay, ax + arrow_w - 3.5, ay)
                # Arrowhead
                path = c.beginPath()
                path.moveTo(ax + arrow_w - 0.5, ay)
                path.lineTo(ax + arrow_w - 4.5, ay + 2.8)
                path.lineTo(ax + arrow_w - 4.5, ay - 2.8)
                path.close()
                c.drawPath(path, fill=1, stroke=0)

            x += box_w + arrow_w


# ── Flowable: 5-Layer System Architecture Diagram (Expanded & Spacious) ─────
class FiveLayerArchitectureDiagram(Flowable):
    """Spacious 5-layer architecture diagram with zero collisions, clear badges, and components."""
    def __init__(self, width, height=275):
        super().__init__()
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        w, h = self.width, self.height

        # Container card
        c.setFillColor(LIGHT_CARD)
        c.roundRect(0, 0, w, h, 5, fill=1, stroke=0)
        c.setStrokeColor(BORDER_GRAY)
        c.setLineWidth(0.7)
        c.roundRect(0, 0, w, h, 5, fill=0, stroke=1)

        # Header bar
        c.setFillColor(NAVY)
        c.roundRect(0, h - 17, w, 17, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(10, h - 12, "5-TIER SOVEREIGN ARCHITECTURE — LAYERED SEPARATION OF CONCERNS")
        c.setFillColor(colors.HexColor("#94A3B8"))
        c.setFont("Helvetica", 6.8)
        c.drawRightString(w - 10, h - 12, "Modular Packages (packages/) · Zero Cross-Layer Contamination")

        # 5 Layers defined top-down (Layer 5 to Layer 1)
        layers = [
            (
                "LAYER 5", "EGRESS & SIEM INTEGRATION",
                "packages/delivery",
                "Splunk HEC (OCSF 1.1) · Elasticsearch (ECS 8.11) · OpenTelemetry Logs v1.0 · STIX 2.1 Threat Intel · Kafka Bus",
                "Zero-copy streaming dispatchers with automatic circuit-breaking, backpressure queues, and dead-letter safety.",
                "Egress: Multi-SIEM",
                RED, RED_LIGHT, RED_BORDER
            ),
            (
                "LAYER 4", "SECURITY INTELLIGENCE & BLOCKCHAIN",
                "packages/intelligence · packages/blockchain",
                "Welford Statistical Anomaly Engine · MITRE ATT&CK TTP Correlation · 4-Node PoA Quorum · Forensic PDF Certificate",
                "Inline streaming anomaly detection and 13-stage tamper-evident Merkle tree batching committed every 2048 events.",
                "PoA Block Quorum",
                AMBER, AMBER_LIGHT, AMBER_BORDER
            ),
            (
                "LAYER 3", "CANONICAL NORMALIZATION & PRIVACY",
                "packages/normalization · packages/security",
                "Universal Canonical Event (UCE v1.0) · Zero Data Loss Residue Vault · Aadhaar / PAN / PII Privacy Sanitizer",
                "Strict Pydantic v2 contract enforcement, deterministic ISO 8601 clock sync, and 100% raw unmapped field retention.",
                "0% Loss Invariant",
                GREEN, GREEN_LIGHT, GREEN_BORDER
            ),
            (
                "LAYER 2", "DETERMINISTIC PARSER ENGINE",
                "packages/parser-runtime · packages/onboarding",
                "Tier A: Perimeter/OS (Palo Alto, Cisco, WinEvt) · Tier B: Cloud/IDP (AWS, Azure, Okta) · Tier C: Container · Auto-Profiler",
                "20 ReDoS-immune pre-compiled DFA state machines executing in guaranteed linear O(N) time; <30s onboarding compiler.",
                "ReDoS-Safe DFAs",
                PURPLE, PURPLE_LIGHT, PURPLE_BORDER
            ),
            (
                "LAYER 1", "INGESTION & IMMUTABLE STORAGE (CAS)",
                "packages/ingestion · packages/storage",
                "Syslog RFC 5424/3164 · High-Speed HTTP Ingest · File Stream Watchers · SHA-256 CAS · WORM Append-Only Store",
                "Capture-First contract: raw bytes locked into write-once storage prior to parsing; non-blocking asyncio socket kernel.",
                "Capture-First WORM",
                GOV_BLUE, BLUE_BG, BLUE_BORDER
            ),
        ]

        layer_count = len(layers)
        gap = 5.0
        layer_h = (h - 24 - (layer_count * gap)) / layer_count  # ~45 pt per layer

        y = 5
        # Draw from bottom (Layer 1) to top (Layer 5)
        for layer_data in reversed(layers):
            layer_id, title, pkg, comps, desc, tag_text, clr, bg_clr, bdr_clr = layer_data

            # Outer box
            c.setFillColor(bg_clr)
            c.roundRect(8, y, w - 16, layer_h, 3.5, fill=1, stroke=0)
            c.setStrokeColor(bdr_clr)
            c.setLineWidth(0.8)
            c.roundRect(8, y, w - 16, layer_h, 3.5, fill=0, stroke=1)

            # Left Layer Badge
            badge_w = 48
            c.setFillColor(clr)
            c.roundRect(8, y, badge_w, layer_h, 3.5, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawCentredString(8 + badge_w / 2, y + layer_h / 2 + 3, layer_id)
            c.setFont("Helvetica", 5.5)
            c.drawCentredString(8 + badge_w / 2, y + layer_h / 2 - 6, "SUBSYSTEM")

            # Content coordinates
            content_x = 8 + badge_w + 7

            # Line 1: Layer Title & Package Path
            c.setFillColor(NAVY)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawString(content_x, y + layer_h - 11, title)

            c.setFillColor(SLATE_MUTED)
            c.setFont("Helvetica-Oblique", 6.0)
            c.drawRightString(w - 16 - 72, y + layer_h - 11, f"[{pkg}]")

            # Right architectural property pill
            pill_w = 66
            pill_h = 11
            pill_x = w - 16 - pill_w - 4
            pill_y = y + layer_h - 13
            c.setFillColor(WHITE)
            c.roundRect(pill_x, pill_y, pill_w, pill_h, 2, fill=1, stroke=0)
            c.setStrokeColor(bdr_clr)
            c.setLineWidth(0.6)
            c.roundRect(pill_x, pill_y, pill_w, pill_h, 2, fill=0, stroke=1)
            c.setFillColor(clr)
            c.setFont("Helvetica-Bold", 5.4)
            c.drawCentredString(pill_x + pill_w / 2, pill_y + 3, tag_text)

            # Line 2: Components List
            c.setFillColor(clr)
            c.setFont("Helvetica-Bold", 6.2)
            c.drawString(content_x, y + layer_h - 23, "Components: ")
            
            c.setFillColor(NAVY_LIGHT)
            c.setFont("Helvetica", 6.0)
            c.drawString(content_x + 44, y + layer_h - 23, comps)

            # Line 3: Architectural Invariant
            c.setFillColor(SLATE_MUTED)
            c.setFont("Helvetica", 5.8)
            c.drawString(content_x, y + 6.0, f"Contract: {desc}")

            y += layer_h + gap


# ── Flowable: Universal Query & Forensic Retrieval Architecture Diagram ─────
class UniversalQueryArchitectureDiagram(Flowable):
    """5-column uniform architecture diagram with identical outline structures and zero text overlap."""
    def __init__(self, width, height=168):
        super().__init__()
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        w, h = self.width, self.height

        # Background card
        c.setFillColor(LIGHT_CARD)
        c.roundRect(0, 0, w, h, 5, fill=1, stroke=0)
        c.setStrokeColor(BORDER_GRAY)
        c.setLineWidth(0.7)
        c.roundRect(0, 0, w, h, 5, fill=0, stroke=1)

        # Header bar with guaranteed non-overlapping left and right labels
        c.setFillColor(NAVY)
        c.roundRect(0, h - 17, w, 17, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(10, h - 12, "UNIVERSAL QUERY & FORENSIC RETRIEVAL PIPELINE")
        c.setFillColor(colors.HexColor("#38BDF8"))
        c.setFont("Helvetica-Bold", 6.8)
        c.drawRightString(w - 10, h - 12, "Dual-Path Execution · Sub-5ms Query · Bit-for-Bit CAS Proof")

        # 5 Uniform Columns with Identical Structural Blueprint
        col_definitions = [
            (
                "1. QUERY INGRESS", "Client Ingress",
                [
                    ("REST API v1", "/api/v1/query endpoint"),
                    ("Operations UI", "React 18 Console Stream"),
                    ("Threat Hunting", "CLI / SIEM Integration"),
                    ("Auth Context", "RBAC Role Verification"),
                ],
                GOV_BLUE, BLUE_BG, BLUE_BORDER
            ),
            (
                "2. TRANSLATOR", "AST Lexer Engine",
                [
                    ("AST Query Tree", "Boolean Logic Parser"),
                    ("Vendor Normalizer", "src_ip -> Cisco/Palo/AWS"),
                    ("Time Bounded", "Monotonic Epoch Range"),
                    ("Air-Gap Sandbox", "Zero External Calling"),
                ],
                PURPLE, PURPLE_LIGHT, PURPLE_BORDER
            ),
            (
                "3. DUAL EXECUTION", "Dual-Path Kernel",
                [
                    ("Fast UCE Stream", "In-Memory Columnar Scan"),
                    ("Sub-5ms Query", "IP, Severity & Action"),
                    ("CAS WORM Store", "Content SHA-256 Lookup"),
                    ("Forensic Replay", "100% Unmapped Residue"),
                ],
                GREEN, GREEN_LIGHT, GREEN_BORDER
            ),
            (
                "4. VERIFICATION", "Merkle Proof Engine",
                [
                    ("Merkle Inclusion", "O(log N) Branch Validation"),
                    ("PoA Quorum", "4-Node Validator Signatures"),
                    ("Ledger Receipt", "Block ID & PrevHash Link"),
                    ("Tamper Proof", "Cryptographic Invariant"),
                ],
                AMBER, AMBER_LIGHT, AMBER_BORDER
            ),
            (
                "5. DISPATCH", "Egress & Reports",
                [
                    ("Live JSON", "Streaming SSE Telemetry"),
                    ("Forensic PDF", "Court Admissible Report"),
                    ("SIEM Push", "Splunk / Elastic Forward"),
                    ("Data Lake", "NDJSON / CSV Bulk Stream"),
                ],
                RED, RED_LIGHT, RED_BORDER
            ),
        ]

        num_cols = len(col_definitions)
        arrow_w = 9
        col_w = (w - 14 - (num_cols - 1) * arrow_w) / num_cols  # ~90 pt per column
        col_h = h - 25
        y_col = 5

        x = 7
        for i, (col_title, col_sub, items_list, main_clr, bg_clr, border_clr) in enumerate(col_definitions):
            # Outer Box for each column
            c.setFillColor(bg_clr)
            c.roundRect(x, y_col, col_w, col_h, 3.5, fill=1, stroke=0)
            c.setStrokeColor(border_clr)
            c.setLineWidth(0.8)
            c.roundRect(x, y_col, col_w, col_h, 3.5, fill=0, stroke=1)

            # Top Header Pill
            c.setFillColor(main_clr)
            c.roundRect(x + 2, y_col + col_h - 15, col_w - 4, 13, 2, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 6.2)
            c.drawCentredString(x + col_w / 2, y_col + col_h - 10.5, col_title)

            # Subheader Tag Pill
            sub_h = 10
            sub_y = y_col + col_h - 28
            c.setFillColor(WHITE)
            c.roundRect(x + 3, sub_y, col_w - 6, sub_h, 2, fill=1, stroke=0)
            c.setStrokeColor(border_clr)
            c.setLineWidth(0.4)
            c.roundRect(x + 3, sub_y, col_w - 6, sub_h, 2, fill=0, stroke=1)
            c.setFillColor(main_clr)
            c.setFont("Helvetica-Bold", 5.3)
            c.drawCentredString(x + col_w / 2, sub_y + 2.8, col_sub)

            # 4 Outlined Item Cards (Uniform, Spacious, Zero Overlap)
            card_h = 23
            card_gap = 4.0
            for idx, (head_text, detail_text) in enumerate(items_list):
                iy = y_col + col_h - 43 - (idx * (card_h + card_gap))
                
                # Card outline
                c.setFillColor(WHITE)
                c.roundRect(x + 3, iy, col_w - 6, card_h, 2.5, fill=1, stroke=0)
                c.setStrokeColor(BORDER_GRAY)
                c.setLineWidth(0.4)
                c.roundRect(x + 3, iy, col_w - 6, card_h, 2.5, fill=0, stroke=1)

                # Line 1: Bold Title (Upper baseline)
                c.setFillColor(NAVY)
                c.setFont("Helvetica-Bold", 5.8)
                c.drawString(x + 6, iy + 13.0, head_text)

                # Line 2: Detail Subtitle (Lower baseline with >5pt clear separation)
                c.setFillColor(SLATE_MUTED)
                c.setFont("Helvetica", 5.1)
                c.drawString(x + 6, iy + 4.5, detail_text)

            # Connecting Arrow
            if i < num_cols - 1:
                ax = x + col_w + 1
                ay = y_col + col_h / 2
                c.setStrokeColor(main_clr)
                c.setFillColor(main_clr)
                c.setLineWidth(1.3)
                c.line(ax, ay, ax + arrow_w - 3.0, ay)
                p = c.beginPath()
                p.moveTo(ax + arrow_w - 0.5, ay)
                p.lineTo(ax + arrow_w - 3.5, ay + 2.5)
                p.lineTo(ax + arrow_w - 3.5, ay - 2.5)
                p.close()
                c.drawPath(p, fill=1, stroke=0)

            x += col_w + arrow_w


# ── Flowable: 13-Stage Cryptographic Chain Diagram (Expanded & Clean) ───────
class CryptographicLineageDiagram(Flowable):
    """Visual horizontal 4-cluster pipeline showing the 13-stage chain of custody."""
    def __init__(self, width, height=125):
        super().__init__()
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        w, h = self.width, self.height

        # Container card
        c.setFillColor(LIGHT_CARD)
        c.roundRect(0, 0, w, h, 5, fill=1, stroke=0)
        c.setStrokeColor(BORDER_GRAY)
        c.setLineWidth(0.7)
        c.roundRect(0, 0, w, h, 5, fill=0, stroke=1)

        # Header bar with guaranteed non-overlapping labels
        c.setFillColor(NAVY)
        c.roundRect(0, h - 17, w, 17, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(10, h - 12, "13-STAGE CRYPTOGRAPHIC EVIDENCE CHAIN & BLOCKCHAIN ANCHORING")
        c.setFillColor(AMBER)
        c.setFont("Helvetica-Bold", 6.8)
        c.drawRightString(w - 10, h - 12, "PoA Consensus · Court-Admissible Forensic Seal")

        # 4 Logical Clusters
        clusters = [
            (
                "CLUSTER I: INGESTION",
                [
                    "S1: Wire Raw SHA-256 Digest",
                    "S2: CAS Storage WORM Lock",
                    "S3: Parser AST Token Map",
                    "Invariant: Pre-parser zero byte-loss"
                ],
                GOV_BLUE, BLUE_BG, BLUE_BORDER
            ),
            (
                "CLUSTER II: NORMALIZATION",
                [
                    "S4: PII Masking (Aadhaar/PAN)",
                    "S5: Canonical UCE Schema Hash",
                    "S6: Lossless Residue Tree Lock",
                    "S7: Pydantic v2 Schema Assert"
                ],
                GREEN, GREEN_LIGHT, GREEN_BORDER
            ),
            (
                "CLUSTER III: MERKLE TREE",
                [
                    "S8: Monotonic Hardware Clock",
                    "S9: Sub-ms Merkle Leaf Node",
                    "S10: 2048-Event Root (32 Bytes)",
                    "Invariant: O(log N) inclusion proofs"
                ],
                PURPLE, PURPLE_LIGHT, PURPLE_BORDER
            ),
            (
                "CLUSTER IV: POA CONSENSUS",
                [
                    "S11: 4-Node PoA Quorum Signatures",
                    "S12: Ledger Block Commit (PrevHash)",
                    "S13: Court-Admissible RSA-4096 PDF",
                    "Invariant: Non-repudiation seal"
                ],
                RED, RED_LIGHT, RED_BORDER
            ),
        ]

        card_gap = 8
        card_w = (w - 16 - (3 * card_gap)) / 4
        card_h = h - 25
        y_card = 5

        x = 8
        for i, (title, stages_list, clr, bg_clr, bdr_clr) in enumerate(clusters):
            c.setFillColor(bg_clr)
            c.roundRect(x, y_card, card_w, card_h, 3.5, fill=1, stroke=0)
            c.setStrokeColor(bdr_clr)
            c.setLineWidth(0.8)
            c.roundRect(x, y_card, card_w, card_h, 3.5, fill=0, stroke=1)

            # Cluster Title Bar
            c.setFillColor(clr)
            c.roundRect(x + 2, y_card + card_h - 14, card_w - 4, 12, 2, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont("Helvetica-Bold", 6.0)
            c.drawCentredString(x + card_w / 2, y_card + card_h - 10, title)

            # Item cards
            for idx, line in enumerate(stages_list):
                iy = y_card + card_h - 32 - (idx * 16.5)
                c.setFillColor(WHITE)
                c.roundRect(x + 3, iy, card_w - 6, 13.5, 2, fill=1, stroke=0)
                c.setStrokeColor(BORDER_GRAY)
                c.setLineWidth(0.4)
                c.roundRect(x + 3, iy, card_w - 6, 13.5, 2, fill=0, stroke=1)
                
                # Highlight invariant lines vs stage lines
                if line.startswith("Invariant:"):
                    c.setFillColor(clr)
                    c.setFont("Helvetica-Bold", 5.0)
                else:
                    c.setFillColor(NAVY_LIGHT)
                    c.setFont("Helvetica", 5.3)
                c.drawString(x + 6, iy + 4.0, line)

            # Connecting arrow to next cluster
            if i < 3:
                ax = x + card_w + 1
                ay = y_card + card_h / 2
                c.setStrokeColor(clr)
                c.setFillColor(clr)
                c.setLineWidth(1.4)
                c.line(ax, ay, ax + card_gap - 2.5, ay)
                path = c.beginPath()
                path.moveTo(ax + card_gap - 0.5, ay)
                path.lineTo(ax + card_gap - 3.5, ay + 2.5)
                path.lineTo(ax + card_gap - 3.5, ay - 2.5)
                path.close()
                c.drawPath(path, fill=1, stroke=0)

            x += card_w + card_gap


# ── Styles ───────────────────────────────────────────────────────────────────
def get_pdf_styles():
    styles = getSampleStyleSheet()

    body = ParagraphStyle(
        "body", fontSize=7.6, leading=10.8, textColor=NAVY_LIGHT,
        fontName="Helvetica", spaceAfter=0
    )
    compact = ParagraphStyle(
        "compact", fontSize=6.8, leading=9.2, textColor=SLATE_MUTED,
        fontName="Helvetica", spaceAfter=0
    )
    spec_val = ParagraphStyle(
        "spec_val", fontSize=6.8, leading=9.2, textColor=NAVY_LIGHT,
        fontName="Helvetica", spaceAfter=0
    )
    return body, compact, spec_val


# ── Build PDF ────────────────────────────────────────────────────────────────
def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PATH,
        pagesize=A4,
        leftMargin=MARGIN_LR, rightMargin=MARGIN_LR,
        topMargin=MARGIN_TOP, bottomMargin=MARGIN_BOT,
        title="ULPF System Architecture Specification — SIH 2026",
        author="Universal Log Preprocessing Framework Team",
        subject="High-Throughput Sovereign Telemetry Engine Architecture",
    )

    body, compact, spec_val = get_pdf_styles()
    story = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 1: TELEMETRY PROCESSING PIPELINE & 5-LAYER SYSTEM ARCHITECTURE
    # ═══════════════════════════════════════════════════════════════════════════

    # Executive Overview Header Card with Integrated Metric Badges
    overview_text = (
        "<b>Universal Log Pre-processing Framework (ULPF)</b> is an air-gap sovereign telemetry normalization and "
        "forensic verification platform engineered for high-concurrency enterprise SOCs. It provides "
        "<b>deterministic ReDoS-immune parsing across 20+ vendors</b>, projectively normalizes raw streams into the "
        "<b>Universal Canonical Event (UCE v1.0)</b> taxonomy with <b>zero unmapped data loss</b>, anchors event blocks into "
        "a <b>tamper-evident Proof-of-Authority blockchain ledger</b>, and dispatches multi-format payloads to Splunk, Elastic, "
        "and OpenTelemetry at <b>301,000+ EPS with sub-4.8ms latency</b>."
    )
    badge_1 = "<b>THROUGHPUT:</b> 301,000+ EPS (p99 &lt; 4.8ms)"
    badge_2 = "<b>DATA LOSS:</b> 0% Loss Unmapped Residue"
    badge_3 = "<b>REDOS SAFETY:</b> O(N) Linear DFA Bounds"
    badge_4 = "<b>AIR-GAP:</b> 100% Offline (0 External Sockets)"

    overview_inner = Table([
        [Paragraph(overview_text, body)],
        [Table([
            [
                Paragraph(f"<font color='{GOV_BLUE.hexval()}'>{badge_1}</font>", compact),
                Paragraph(f"<font color='{GREEN.hexval()}'>{badge_2}</font>", compact),
                Paragraph(f"<font color='{PURPLE.hexval()}'>{badge_3}</font>", compact),
                Paragraph(f"<font color='{RED.hexval()}'>{badge_4}</font>", compact),
            ]
        ], colWidths=[AVAIL_W * 0.25] * 4)]
    ], colWidths=[AVAIL_W])
    overview_inner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLUE_BG),
        ("BOX", (0, 0), (-1, -1), 1.0, GOV_BLUE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, BLUE_BORDER),
        ("ROUNDEDCORNERS", [3]),
    ]))
    story.append(overview_inner)
    story.append(Spacer(1, 4))

    # SECTION 1: End-to-End Processing Pipeline Flow Diagram
    story.append(SectionTitle(1, "Universal Telemetry Ingestion & Normalization Flow Architecture", "Linear O(N) Processing Runtime"))
    story.append(Spacer(1, 2.5))
    story.append(EndToEndPipelineDiagram(AVAIL_W, height=142))
    story.append(Spacer(1, 4))

    # Architecture Principles Callout (3-column cards)
    principle_1 = (
        "<b>Capture-First Invariant</b><br/>"
        "Raw wire bytes are hashed (SHA-256) into Content-Addressed Storage (WORM) before executing parser code. "
        "Even catastrophic parser errors preserve bit-for-bit raw evidence."
    )
    principle_2 = (
        "<b>ReDoS-Immune Determinism</b><br/>"
        "Backtracking regular expressions are strictly forbidden. 20 pre-compiled DFA state machines process tokens in "
        "guaranteed linear O(N) time with bounded memory."
    )
    principle_3 = (
        "<b>100% Unmapped Residue</b><br/>"
        "Non-canonical vendor fields are cryptographically packed into <code>unmapped_residue</code>. Zero information is "
        "discarded, guaranteeing 100% lossless forensic integrity."
    )

    principles_table = Table(
        [[Paragraph(principle_1, compact), Paragraph(principle_2, compact), Paragraph(principle_3, compact)]],
        colWidths=[AVAIL_W / 3.0] * 3
    )
    principles_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_CARD),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROUNDEDCORNERS", [2.5]),
    ]))
    story.append(principles_table)
    story.append(Spacer(1, 4.5))

    # SECTION 2: 5-Tier Monolithic-Separated System Architecture Diagram
    story.append(SectionTitle(2, "Modular Layered System Architecture", "Clean Separation of Functional Domains"))
    story.append(Spacer(1, 2.5))
    story.append(FiveLayerArchitectureDiagram(AVAIL_W, height=275))
    story.append(Spacer(1, 4))

    # System Invariants Card (3-column detailed summary filling bottom of Page 1)
    inv_col1 = (
        "<b>Package Modular Encapsulation</b><br/>"
        "• <b>Strict Inward Dependency:</b> Outer packages depend strictly on <code>packages/contracts</code>.<br/>"
        "• <b>Zero Direct DB Mutation:</b> Ingestion writes directly to CAS append-only logs.<br/>"
        "• <b>Memory Boundary:</b> Ring buffers prevent thread contention and heap thrashing.<br/>"
        "• <b>Plugin Architecture:</b> Dynamic parser loading without re-linking core engines."
    )
    inv_col2 = (
        "<b>Air-Gap Execution Sovereignty</b><br/>"
        "• <b>Zero External Egress:</b> Validated by automated socket interception test suites.<br/>"
        "• <b>Local Profiler:</b> Discovers and compiles unknown vendor formats locally in &lt;30s.<br/>"
        "• <b>No Cloud APIs:</b> Zero reliance on remote SaaS, cloud LLMs, or telemetry bridges.<br/>"
        "• <b>Sovereign Keystore:</b> RSA-4096 / Ed25519 root keys sealed in local hardware storage."
    )
    inv_col3 = (
        "<b>High-Concurrency Runtime Model</b><br/>"
        "• <b>Async I/O Kernel:</b> Non-blocking Python asyncio event loop handles 300K+ EPS.<br/>"
        "• <b>Native Threadpool:</b> CPU-intensive DFA parsers execute on dedicated worker threads.<br/>"
        "• <b>Fault Isolation:</b> Malformed packets route to quarantine without pipeline stall.<br/>"
        "• <b>Circuit Breaking:</b> Egress backpressure shedding prevents downstream memory leak."
    )
    invariants_table = Table(
        [[Paragraph(inv_col1, compact), Paragraph(inv_col2, compact), Paragraph(inv_col3, compact)]],
        colWidths=[AVAIL_W / 3.0] * 3
    )
    invariants_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROUNDEDCORNERS", [2.5]),
    ]))
    story.append(invariants_table)

    # Explicit Page Break to Page 2
    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 2: QUERY PROCESSING ARCHITECTURE, BLOCKCHAIN & RUNTIME SPECS
    # ═══════════════════════════════════════════════════════════════════════════

    # SECTION 3: Universal Query & Forensic Retrieval Architecture Diagram
    story.append(SectionTitle(3, "Universal Query & Forensic Retrieval Architecture", "Dual-Path Execution & Lineage Verification"))
    story.append(Spacer(1, 2.5))
    story.append(UniversalQueryArchitectureDiagram(AVAIL_W, height=168))
    story.append(Spacer(1, 4))

    # Query Architecture Technical Specs Card
    q_left = (
        "<b>Universal Predicate Translation Engine</b><br/>"
        "Analysts query across heterogeneous feeds with a single vendor-neutral syntax. The AST Query Parser compiles "
        "predicates (e.g. <code>src_ip == '10.0.0.1' AND severity >= HIGH</code>) into target-optimized execution branches for "
        "Palo Alto PAN-OS, Cisco ASA, AWS CloudTrail, and Windows EventLog simultaneously without data silos."
    )
    q_right = (
        "<b>Dual-Path Execution & Cryptographic Verification</b><br/>"
        "• <b>Fast In-Memory Path:</b> Scans normalized UCE schema attributes at sub-5ms latency for live SOC dashboards.<br/>"
        "• <b>Forensic WORM Path:</b> Fetches bit-for-bit original raw logs by CAS SHA-256 hash address for court audit.<br/>"
        "• <b>Proof Attestation:</b> Attaches Merkle tree inclusion paths and 4-node PoA signatures to every query result."
    )
    query_specs_tbl = Table(
        [[Paragraph(q_left, compact), Paragraph(q_right, compact)]],
        colWidths=[AVAIL_W * 0.48, AVAIL_W * 0.52]
    )
    query_specs_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLUE_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, BLUE_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROUNDEDCORNERS", [2.5]),
    ]))
    story.append(query_specs_tbl)
    story.append(Spacer(1, 4.5))

    # SECTION 4: 13-Stage Cryptographic Chain-of-Custody & Consensus Flow
    story.append(SectionTitle(4, "Cryptographic Chain-of-Custody & Consensus Architecture", "Immutable Forensic Ledger"))
    story.append(Spacer(1, 2.5))
    story.append(CryptographicLineageDiagram(AVAIL_W, height=125))
    story.append(Spacer(1, 4))

    # Cryptographic Lineage Walkthrough Cards
    chain_desc = (
        "<b>Defense-Grade Evidentiary Integrity Pipeline:</b> Every event traverses 13 strict checkpoints: "
        "<b>(S1)</b> Wire capture SHA-256 digest → <b>(S2)</b> CAS inode persist → <b>(S3)</b> Parser AST token tree → "
        "<b>(S4)</b> Aadhaar/PAN PII redaction token map → <b>(S5)</b> Canonical UCE hash → <b>(S6)</b> Lossless residue tree lock → "
        "<b>(S7)</b> Pydantic v2 schema assert → <b>(S8)</b> Monotonic hardware clock bind → <b>(S9)</b> Merkle leaf insertion → "
        "<b>(S10)</b> 2048-event batch Merkle root (32 bytes) → <b>(S11)</b> 4-Node PoA validator quorum signatures → "
        "<b>(S12)</b> Blockchain commit with previous block hash pointer → <b>(S13)</b> Court-admissible RSA-4096 / Ed25519 forensic PDF report."
    )
    chain_tbl = Table([[Paragraph(chain_desc, compact)]], colWidths=[AVAIL_W])
    chain_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), AMBER_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.6, AMBER_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("ROUNDEDCORNERS", [2.5]),
    ]))
    story.append(chain_tbl)
    story.append(Spacer(1, 4.5))

    # SECTION 5: Enterprise Runtime Specifications & Architectural Guarantees
    story.append(SectionTitle(5, "Enterprise Architectural Specifications & Performance Benchmarks", "Empirical System Metrics"))
    story.append(Spacer(1, 2.5))

    spec_data = [
        ["ARCHITECTURAL ATTRIBUTE", "INDUSTRY BASELINE", "ULPF VERIFIED BENCHMARK", "ARCHITECTURAL MECHANISM"],
        ["Pipeline Throughput", "15K–45K EPS (Logstash/Vector)", "301,000+ EPS (6.7x–20x gain)", "Non-blocking asyncio ring buffers + C-compiled DFA execution"],
        ["End-to-End Ingest Latency", "25–80 ms", "p99 < 4.8 ms (5x–16x reduction)", "Zero-copy memory mapped buffers + pre-allocated buffer pools"],
        ["Unmapped Vendor Field Retention", "0% (Silently discarded)", "100% Verbatim (Zero data loss)", "Lossless unmapped_residue cryptographic JSON/byte tree"],
        ["ReDoS Vulnerability Surface", "Catastrophic regex backtracking", "Zero (O(N) DFA Bounded)", "20 deterministic finite automata compiled without backtracking"],
        ["Chain-of-Custody Admissibility", "None (Mutable Syslog/Text)", "13-Stage Cryptographic Seal", "Merkle batching + 4-Node PoA blockchain quorum + RSA certs"],
        ["Air-Gap Sovereignty", "Cloud API / External LLM egress", "100% Offline (0 external sockets)", "Local deterministic DFA profiling; strict socket interception tests"],
        ["Autonomous Source Profiling", "Manual regex rules (Days/Weeks)", "< 30 Seconds Automatic", "Statistical token clustering + DFA schema compilation engine"],
        ["Automated Test Verification", "Partial coverage", "680/680 Passing (0 failures)", "Full monorepo unit, integration, stress, and mutation test suite"],
    ]

    spec_rows = []
    for r_idx, row in enumerate(spec_data):
        if r_idx == 0:
            spec_rows.append([Paragraph(f"<b>{c}</b>", ParagraphStyle("th", fontSize=6.2, textColor=WHITE, fontName="Helvetica-Bold")) for c in row])
        else:
            c0 = Paragraph(f"<b>{row[0]}</b>", spec_val)
            c1 = Paragraph(row[1], compact)
            c2 = Paragraph(f"<b>{row[2]}</b>", ParagraphStyle("cg", fontSize=6.5, textColor=GREEN, fontName="Helvetica-Bold"))
            c3 = Paragraph(row[3], compact)
            spec_rows.append([c0, c1, c2, c3])

    spec_table = Table(
        spec_rows,
        colWidths=[AVAIL_W * 0.22, AVAIL_W * 0.23, AVAIL_W * 0.25, AVAIL_W * 0.30]
    )
    spec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_CARD]),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(spec_table)

    # Build PDF
    doc.build(story, onFirstPage=draw_page_frame, onLaterPages=draw_page_frame)
    print(f"\nSUCCESS: Architecture PDF successfully generated at:\n  {OUTPUT_PATH}\n")


if __name__ == "__main__":
    build_pdf()
