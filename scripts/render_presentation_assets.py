"""
ULPF — Presentation & Documentation Asset Render Pipeline
Production-grade utility for rendering high-resolution visual assets from
technical presentation decks and specification documents.
Cross-platform implementation utilizing PyMuPDF (fitz) with zero external runtime dependencies.
"""

import os
import sys
import argparse
from typing import List, Optional

try:
    import pymupdf as fitz
except ImportError:
    try:
        import fitz
    except ImportError:
        print("Error: PyMuPDF is required. Install via 'pip install pymupdf'.", file=sys.stderr)
        sys.exit(1)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PDF = os.path.join(ROOT_DIR, "SIH-2026-ULPF.pdf")


def render_slide_asset(
    pdf_path: str,
    slide_number: int,
    output_path: str,
    dpi: int = 300
) -> bool:
    """
    Renders a specific 1-indexed slide from the PDF document as a high-resolution PNG image.
    """
    if not os.path.exists(pdf_path):
        print(f"[ERROR] Source document not found: {pdf_path}", file=sys.stderr)
        return False

    doc = fitz.open(pdf_path)
    total_pages = len(doc)
    if slide_number < 1 or slide_number > total_pages:
        print(f"[ERROR] Invalid slide index: {slide_number}. Document contains {total_pages} pages.", file=sys.stderr)
        return False

    page = doc[slide_number - 1]
    pix = page.get_pixmap(dpi=dpi)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    pix.save(output_path)
    print(f"[RENDER] Slide {slide_number}/{total_pages} -> {output_path} ({pix.width}x{pix.height} @ {dpi} DPI)")
    return True


def render_all_slides(
    pdf_path: str,
    output_dir: str,
    dpi: int = 300,
    prefix: str = "SLIDE"
) -> List[str]:
    """
    Renders all slides in the PDF document to the specified output directory.
    """
    if not os.path.exists(pdf_path):
        print(f"[ERROR] Source document not found: {pdf_path}", file=sys.stderr)
        return []

    doc = fitz.open(pdf_path)
    total_pages = len(doc)
    os.makedirs(output_dir, exist_ok=True)
    generated_files = []

    for idx, page in enumerate(doc, start=1):
        out_name = f"{prefix}{idx}_EXPORT_VERIFY.png" if prefix == "SLIDE" else f"{prefix}_{idx}.png"
        out_path = os.path.join(output_dir, out_name)
        pix = page.get_pixmap(dpi=dpi)
        pix.save(out_path)
        generated_files.append(out_path)
        print(f"[RENDER] Slide {idx}/{total_pages} -> {out_path} ({pix.width}x{pix.height} @ {dpi} DPI)")

    return generated_files


def main():
    parser = argparse.ArgumentParser(
        description="ULPF Presentation Asset Export Utility (Replaces legacy COM/PS1 scripts)"
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_PDF,
        help="Path to source presentation PDF (default: SIH-2026-ULPF.pdf)"
    )
    parser.add_argument(
        "--slide",
        type=int,
        default=None,
        help="Specific slide number to export (1-indexed). If omitted, exports verification assets for Slides 2 & 3."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Export all slides in the deck"
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=300,
        help="Render resolution in DPI (default: 300 DPI for publication quality)"
    )
    parser.add_argument(
        "--out-dir",
        default=ROOT_DIR,
        help="Output directory for exported images (default: workspace root)"
    )

    args = parser.parse_args()

    if args.all:
        render_all_slides(args.source, args.out_dir, dpi=args.dpi)
    elif args.slide is not None:
        out_path = os.path.join(args.out_dir, f"SLIDE{args.slide}_EXPORT_VERIFY.png")
        render_slide_asset(args.source, args.slide, out_path, dpi=args.dpi)
    else:
        # Default workflow: Render verification assets for key architecture slides (2 and 3)
        s2_out = os.path.join(args.out_dir, "SLIDE2_EXPORT_VERIFY.png")
        s3_out = os.path.join(args.out_dir, "SLIDE3_EXPORT_VERIFY.png")
        render_slide_asset(args.source, 2, s2_out, dpi=args.dpi)
        render_slide_asset(args.source, 3, s3_out, dpi=args.dpi)


if __name__ == "__main__":
    main()
