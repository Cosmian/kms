#!/usr/bin/env python3
"""
combine_flamegraphs.py — Combine per-worker-count flamegraph SVGs into one
                          CPU-scaling overview HTML file.

Usage:
    python3 combine_flamegraphs.py <output.html> [throughput_table.tsv] \
        <w1.svg> <w2.svg> ...

The throughput_table.tsv (optional) is a two-column TSV:
    <bench_name>\t<rps>
produced by bench_run_flamegraph.sh from the bencher-format output.

The script produces a single self-contained HTML file with:
  - A throughput scaling SVG bar chart (req/s vs worker count, where
    worker count is derived from the SVG filename *_w<N>.svg)
  - All per-worker flamegraphs embedded inline (preserving JavaScript
    interactivity) and stacked vertically with labelled headers.
"""

import re
import sys
import pathlib
import html
from typing import Optional


# ── helpers ────────────────────────────────────────────────────────────────

def _worker_count_from_path(p: pathlib.Path) -> Optional[int]:
    """Extract the worker count N from a filename like ecdsa_sign_w<N>.svg."""
    m = re.search(r"_w(\d+)\.svg$", p.name)
    return int(m.group(1)) if m else None


def _svg_dimensions(svg_text: str) -> tuple[int, int]:
    """Return (width, height) from a flamegraph SVG, defaulting to (1200, 600)."""
    mw = re.search(r'<svg[^>]+\bwidth=["\'](\d+)', svg_text)
    mh = re.search(r'<svg[^>]+\bheight=["\'](\d+)', svg_text)
    w = int(mw.group(1)) if mw else 1200
    h = int(mh.group(1)) if mh else 600
    return w, h


def _throughput_chart_svg(data: list[tuple[int, float]], width: int = 800,
                           height: int = 220, bar_color: str = "#4A90D9") -> str:
    """Generate a simple horizontal bar chart as an SVG string.

    data: list of (worker_count, rps) sorted by worker_count
    """
    if not data:
        return ""

    pad_l, pad_r, pad_t, pad_b = 80, 30, 30, 50
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b

    max_rps = max(rps for _, rps in data) or 1
    n_bars = len(data)
    bar_gap = 12
    bar_w = max(10, (chart_w - bar_gap * (n_bars + 1)) // n_bars)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'style="font-family:sans-serif;background:#fff">',
        # axes
        f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{pad_t+chart_h+8}" '
        f'stroke="#666" stroke-width="1.5"/>',
        f'<line x1="{pad_l-8}" y1="{pad_t+chart_h}" x2="{pad_l+chart_w}" y2="{pad_t+chart_h}" '
        f'stroke="#666" stroke-width="1.5"/>',
        # title
        f'<text x="{width//2}" y="18" text-anchor="middle" font-size="13" fill="#333">'
        f'Throughput vs Worker Count (req/s)</text>',
        # y-axis label
        f'<text x="10" y="{pad_t + chart_h//2}" text-anchor="middle" font-size="11" '
        f'fill="#555" transform="rotate(-90 10 {pad_t + chart_h//2})">req/s</text>',
    ]

    # y gridlines + labels (4 steps)
    for step in range(5):
        val = max_rps * step / 4
        y_pos = pad_t + chart_h - int(chart_h * step / 4)
        parts.append(
            f'<line x1="{pad_l-4}" y1="{y_pos}" x2="{pad_l+chart_w}" y2="{y_pos}" '
            f'stroke="#ddd" stroke-width="0.8" stroke-dasharray="4,3"/>'
        )
        label = f"{val/1000:.1f}k" if val >= 1000 else f"{int(val)}"
        parts.append(
            f'<text x="{pad_l-8}" y="{y_pos+4}" text-anchor="end" font-size="10" fill="#666">'
            f'{label}</text>'
        )

    # bars
    for i, (workers, rps) in enumerate(sorted(data, key=lambda x: x[0])):
        x = pad_l + bar_gap + i * (bar_w + bar_gap)
        bar_h = int(chart_h * rps / max_rps)
        y = pad_t + chart_h - bar_h
        # ideal-linear baseline bar (semi-transparent)
        baseline_rps = data[0][1] * workers / data[0][0] if data[0][0] > 0 else rps
        base_h = int(chart_h * min(baseline_rps, max_rps * 1.05) / max_rps)
        base_y = pad_t + chart_h - base_h
        parts.append(
            f'<rect x="{x}" y="{base_y}" width="{bar_w}" height="{base_h}" '
            f'fill="{bar_color}" opacity="0.18"/>'
        )
        # actual bar
        parts.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" '
            f'fill="{bar_color}" opacity="0.85"/>'
        )
        # rps label on top of bar
        label_rps = f"{rps/1000:.1f}k" if rps >= 1000 else f"{int(rps)}"
        parts.append(
            f'<text x="{x + bar_w//2}" y="{y - 4}" text-anchor="middle" font-size="11" '
            f'fill="#333">{label_rps}</text>'
        )
        # x-axis worker count label
        parts.append(
            f'<text x="{x + bar_w//2}" y="{pad_t+chart_h+18}" text-anchor="middle" '
            f'font-size="11" fill="#555">{workers}w</text>'
        )

    # legend note
    parts.append(
        f'<text x="{pad_l+chart_w}" y="{pad_t+chart_h+40}" text-anchor="end" '
        f'font-size="10" fill="#999">pale bars = ideal linear scaling</text>'
    )

    parts.append('</svg>')
    return "\n".join(parts)


def _inline_svg(svg_path: pathlib.Path) -> str:
    """Return the SVG file content, normalising the root <svg> element so it
    can be embedded directly in HTML without namespace conflicts."""
    txt = svg_path.read_text(encoding="utf-8")
    # Remove the XML declaration if present
    txt = re.sub(r"<\?xml[^?]*\?>\s*", "", txt)
    # Remove DOCTYPE if present
    txt = re.sub(r"<!DOCTYPE[^>]*>\s*", "", txt)
    txt = txt.strip()
    return txt


# ── main ───────────────────────────────────────────────────────────────────

def main(args: list[str]) -> None:
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)

    output_html = pathlib.Path(args[0])

    # Optional TSV of throughput data
    throughput_tsv: Optional[pathlib.Path] = None
    svg_paths: list[pathlib.Path] = []
    for a in args[1:]:
        p = pathlib.Path(a)
        if p.suffix == ".tsv" and p.exists():
            throughput_tsv = p
        elif p.suffix == ".svg":
            svg_paths.append(p)
        # silently skip non-existent files

    svg_paths = [p for p in svg_paths if p.exists()]
    if not svg_paths:
        print("No SVG files found – nothing to combine.", file=sys.stderr)
        sys.exit(0)

    # Sort by worker count (ascending)
    svg_paths.sort(key=lambda p: (_worker_count_from_path(p) or 0, p.name))

    # ── Throughput data ────────────────────────────────────────────────────
    throughput_data: list[tuple[int, float]] = []
    if throughput_tsv:
        for line in throughput_tsv.read_text().splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                try:
                    # Try to extract worker count from the bench name
                    m = re.search(r"(\d+)\s*workers?", parts[0], re.IGNORECASE)
                    wc = int(m.group(1)) if m else 0
                    rps = float(parts[1])
                    if wc > 0 and rps > 0:
                        throughput_data.append((wc, rps))
                except (ValueError, AttributeError):
                    continue

    # Fallback: try to extract scaling info from SVG filenames
    if not throughput_data:
        for p in svg_paths:
            wc = _worker_count_from_path(p)
            if wc is not None:
                throughput_data.append((wc, 0.0))

    # ── Build HTML ────────────────────────────────────────────────────────
    chart_svg = ""
    if any(rps > 0 for _, rps in throughput_data):
        chart_svg = _throughput_chart_svg(throughput_data)

    section_parts: list[str] = []
    for svg_path in svg_paths:
        wc = _worker_count_from_path(svg_path)
        label = f"{wc} worker{'s' if wc != 1 else ''}" if wc else svg_path.stem
        w, h = _svg_dimensions(svg_path.read_text(encoding="utf-8"))
        inline = _inline_svg(svg_path)
        section_parts.append(
            f'<section class="flame-section" id="w{wc}">'
            f'<h2 class="flame-label">{html.escape(label)}</h2>'
            f'<div class="flame-wrap" style="max-width:{w}px;height:{h}px">'
            f'{inline}'
            f'</div>'
            f'</section>'
        )

    nav_links = " ".join(
        f'<a href="#w{_worker_count_from_path(p)}">'
        f'{_worker_count_from_path(p)}w</a>'
        for p in svg_paths
        if _worker_count_from_path(p) is not None
    )

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KMS CPU Scaling — Flamegraph Overview</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: sans-serif; background: #f7f7f7; color: #222; }}
  header {{ background: #1a1a2e; color: #fff; padding: 18px 24px; }}
  header h1 {{ font-size: 1.4em; }}
  header p {{ font-size: 0.9em; color: #aaa; margin-top: 4px; }}
  nav {{ background: #16213e; padding: 8px 24px; display: flex; gap: 12px; flex-wrap: wrap; }}
  nav a {{ color: #7eb8f7; text-decoration: none; font-size: 0.9em;
           padding: 3px 10px; border-radius: 4px; background: rgba(255,255,255,0.07); }}
  nav a:hover {{ background: rgba(255,255,255,0.15); }}
  .chart-wrap {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.1);
                 margin: 20px auto; max-width: 860px; padding: 20px 24px; }}
  .chart-wrap h2 {{ font-size: 1em; color: #444; margin-bottom: 12px; }}
  .flame-section {{ background: #fff; border-radius: 8px;
                    box-shadow: 0 1px 4px rgba(0,0,0,.1);
                    margin: 20px auto; max-width: 1400px; padding: 16px 20px; }}
  .flame-label {{ font-size: 1.1em; color: #333; margin-bottom: 10px;
                  border-bottom: 2px solid #4A90D9; padding-bottom: 6px; }}
  .flame-wrap {{ width: 100%; overflow-x: auto; }}
  .flame-wrap svg {{ width: 100%; height: 100%; display: block; }}
</style>
</head>
<body>
<header>
  <h1>Cosmian KMS — CPU Scaling Flamegraph Overview</h1>
  <p>Per-worker-count flamegraphs for ECDSA P-256 sign. Paler bars in the chart = ideal linear scaling.</p>
</header>
<nav>
  <strong style="color:#ccc;align-self:center">Jump to:</strong>
  {nav_links}
</nav>

{'<div class="chart-wrap"><h2>Throughput (req/s) vs Worker Count</h2>' + chart_svg + '</div>' if chart_svg else ''}

{''.join(section_parts)}

</body>
</html>
"""

    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_out, encoding="utf-8")
    print(f"Combined scaling overview written: {output_html}")


if __name__ == "__main__":
    main(sys.argv[1:])
