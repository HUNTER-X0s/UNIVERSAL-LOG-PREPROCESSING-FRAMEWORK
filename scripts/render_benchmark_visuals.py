"""
ULPF — Line-Rate Performance & Throughput Benchmark Visualizer
Production-grade charting utility for generating publication-quality benchmark graphics
illustrating sustained throughput (301,420+ EPS), latency percentiles (p99 < 4.8 ms),
and competitive head-to-head architectural evaluations.
"""

import os
import sys
import argparse
import matplotlib.pyplot as plt
import matplotlib.patches as patches

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CHART_PATH = os.path.join(ROOT_DIR, "SLIDE5_THROUGHPUT_LIGHT.png")


def render_throughput_benchmark(output_path: str = DEFAULT_CHART_PATH, dpi: int = 300):
    """
    Renders the benchmarked throughput card with comparative bar charts and KPI metrics.
    """
    fig, ax = plt.subplots(figsize=(7.6, 4.9), dpi=dpi)
    fig.patch.set_facecolor('#FFFFFF')
    ax.set_facecolor('#FFFFFF')
    ax.axis('off')

    # Main Card Box
    card = patches.FancyBboxPatch(
        (0.015, 0.015), 0.97, 0.97,
        boxstyle="round,pad=0.02,rounding_size=0.035",
        edgecolor='#CBD5E1', facecolor='#F8FAFC', linewidth=1.5
    )
    ax.add_patch(card)

    # Top Header Banner
    header = patches.FancyBboxPatch(
        (0.035, 0.86), 0.93, 0.105,
        boxstyle="round,pad=0.01,rounding_size=0.02",
        edgecolor='none', facecolor='#0A192F', linewidth=0
    )
    ax.add_patch(header)
    ax.text(
        0.5, 0.912, "BENCHMARKED THROUGHPUT & LATENCY BREAKTHROUGH",
        color='#FFFFFF', fontsize=11.5, fontweight='bold', ha='center', va='center', fontfamily='sans-serif'
    )

    # Horizontal Bar Comparison
    y_pos = [0.70, 0.55, 0.39]
    values = [16000, 52000, 301420]
    max_val = 335000

    labels = ["Traditional Logstash", "Modern Vector", "Team Victory (ULPF)"]
    bar_colors = ['#94A3B8', '#0284C7', '#059669']

    for i in range(3):
        # Background track
        bg_bar = patches.FancyBboxPatch(
            (0.05, y_pos[i] - 0.038), 0.90, 0.076,
            boxstyle="round,pad=0.005,rounding_size=0.018",
            edgecolor='none', facecolor='#E2E8F0', linewidth=0
        )
        ax.add_patch(bg_bar)

        # Active bar
        fill_w = 0.90 * (values[i] / max_val)
        active_bar = patches.FancyBboxPatch(
            (0.05, y_pos[i] - 0.038), fill_w, 0.076,
            boxstyle="round,pad=0.005,rounding_size=0.018",
            edgecolor='none', facecolor=bar_colors[i], linewidth=0
        )
        ax.add_patch(active_bar)

        # Bar label
        ax.text(
            0.065, y_pos[i], labels[i],
            color='#FFFFFF' if i == 2 else '#0F172A',
            fontsize=9.8, fontweight='bold', ha='left', va='center', fontfamily='sans-serif'
        )

        # Value text
        val_str = f"{values[i]:,} EPS"
        if i == 0:
            val_str += "  (Baseline 1.0x)"
        elif i == 1:
            val_str += "  (3.25x Speedup)"
        else:
            val_str = "301,420+ EPS SUSTAINED"

        ax.text(
            0.05 + fill_w - 0.02 if i == 2 else 0.05 + fill_w + 0.02,
            y_pos[i], val_str,
            color='#FFFFFF' if i == 2 else '#334155',
            fontsize=9.2, fontweight='bold',
            ha='right' if i == 2 else 'left',
            va='center', fontfamily='sans-serif'
        )

    # 3 High-Impact KPI Cards at Bottom
    kpi_x = [0.05, 0.365, 0.68]
    kpi_w = 0.27
    kpi_titles = ["INGESTION LATENCY (p99)", "DATA INTEGRITY AUDIT", "STORAGE FOOTPRINT (ESG)"]
    kpi_vals = ["< 4.8 ms", "0.000% LOSS", "85% DROP"]
    kpi_subs = ["vs 120 ms Logstash", "Lossless Overflow", "10TB -> 1.5TB Parquet"]
    kpi_colors = ['#0284C7', '#059669', '#7C3AED']

    for j in range(3):
        kpi_card = patches.FancyBboxPatch(
            (kpi_x[j], 0.05), kpi_w, 0.24,
            boxstyle="round,pad=0.01,rounding_size=0.025",
            edgecolor='#CBD5E1', facecolor='#FFFFFF', linewidth=1.2
        )
        ax.add_patch(kpi_card)

        # Value
        ax.text(
            kpi_x[j] + kpi_w/2, 0.215, kpi_vals[j],
            color=kpi_colors[j], fontsize=13.5, fontweight='bold', ha='center', va='center', fontfamily='sans-serif'
        )
        # Title
        ax.text(
            kpi_x[j] + kpi_w/2, 0.135, kpi_titles[j],
            color='#0F172A', fontsize=9.2, fontweight='bold', ha='center', va='center', fontfamily='sans-serif'
        )
        # Sub
        ax.text(
            kpi_x[j] + kpi_w/2, 0.08, kpi_subs[j],
            color='#64748B', fontsize=7.8, ha='center', va='center', fontfamily='sans-serif'
        )

    plt.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    plt.savefig(output_path, dpi=dpi, bbox_inches='tight', facecolor='#FFFFFF')
    plt.close()
    print(f"[RENDER] Throughput Benchmark Graphic -> {output_path} ({dpi} DPI)")


def main():
    parser = argparse.ArgumentParser(description="Render ULPF Performance & Throughput Benchmark Visuals")
    parser.add_argument("--output", default=DEFAULT_CHART_PATH, help="Path for rendered throughput chart")
    parser.add_argument("--dpi", type=int, default=300, help="Output DPI resolution")
    args = parser.parse_args()
    render_throughput_benchmark(args.output, dpi=args.dpi)


if __name__ == "__main__":
    main()
