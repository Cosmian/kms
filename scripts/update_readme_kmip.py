#!/usr/bin/env python3
"""
Inject documentation/docs/KMIP_support.md into README.md between KMIP_SUPPORT markers.

Usage:
  python scripts/update_readme_kmip.py [--readme PATH] [--source PATH]

Defaults:
  --readme: README.md at repo root
  --source: documentation/docs/KMIP_support.md
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


START_MARKER = "<!-- KMIP_SUPPORT_START -->"
END_MARKER = "<!-- KMIP_SUPPORT_END -->"


def inject(readme_path: Path, source_path: Path) -> int:
    if not readme_path.exists():
        print(f"error: README not found: {readme_path}", file=sys.stderr)
        return 2
    if not source_path.exists():
        print(f"error: source not found: {source_path}", file=sys.stderr)
        return 3

    readme_text = readme_path.read_text(encoding="utf-8")
    src_text = source_path.read_text(encoding="utf-8").rstrip() + "\n"

    start_idx = readme_text.find(START_MARKER)
    end_idx = readme_text.find(END_MARKER)
    if start_idx == -1 or end_idx == -1 or end_idx < start_idx:
        print("error: KMIP support markers not found or malformed in README.md", file=sys.stderr)
        return 4

    # Determine insertion positions at line boundaries
    # Keep the existing line that mentions auto-generation as-is (it's between the markers already).
    # We replace any content between START and END markers (exclusive) with:
    #   START
    #   existing auto-gen comment (if any) remains in README
    #   <inserted KMIP_support.md content>
    #   END
    # To keep it simple and robust, we replace the full region from START to END (inclusive),
    # rebuilding it with START + auto-gen line (if present) + content + END.

    # Extract any line immediately after START that warns about auto-generation to preserve it.
    # We'll look for a comment line between START and END that includes 'auto-generated'.
    between = readme_text[start_idx:end_idx]
    preserved_line = None
    for line in between.splitlines():
        if "auto-generated" in line:
            preserved_line = line
            break

    # Build replacement block
    lines = [START_MARKER]
    if preserved_line:
        lines.append(preserved_line)
    lines.append(src_text.rstrip())
    lines.append(END_MARKER)
    replacement_block = "\n".join(lines) + "\n"

    new_text = readme_text[:start_idx] + replacement_block + readme_text[end_idx + len(END_MARKER):]
    readme_path.write_text(new_text, encoding="utf-8")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readme", type=Path, default=Path("README.md"))
    parser.add_argument(
        "--source", type=Path, default=Path("documentation/docs/KMIP_support.md")
    )
    args = parser.parse_args(argv)

    return inject(args.readme, args.source)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
#!/usr/bin/env python3
"""
Update README.md by embedding the content of documentation/docs/KMIP_support.md
between well-defined markers, without duplicating the source of truth.

Usage:
  python scripts/update_readme_kmip.py

Notes:
  - Headings in KMIP_support.md are shifted one level deeper to fit under README's H1.
  - Do not edit the generated block in README.md directly; edit KMIP_support.md instead.
"""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "README.md"
KMIP_PATH = ROOT / "documentation" / "docs" / "KMIP_support.md"

START_MARK = "<!-- KMIP_SUPPORT_START -->"
END_MARK = "<!-- KMIP_SUPPORT_END -->"


def shift_headings(md: str) -> str:
    """Increase all at-line-start markdown heading levels by 1 (# -> ##),
    leaving non-heading lines intact.
    """
    out_lines = []
    for line in md.splitlines():
        if line.startswith("#"):
            # Preserve spacing after hashes
            m = re.match(r"^(#+)(\s*)(.*)$", line)
            if m:
                hashes, space, rest = m.groups()
                out_lines.append("#" + hashes + space + rest)
            else:
                out_lines.append("#" + line)
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + "\n"


def ensure_markers(readme_text: str) -> str:
    """Ensure README contains start/end markers. If missing, append a new section with markers."""
    if START_MARK in readme_text and END_MARK in readme_text:
        return readme_text

    block = (
        "\n\n## KMIP support (auto-generated)\n\n"
        f"{START_MARK}\n"
        "This section is auto-generated from `documentation/docs/KMIP_support.md`.\n"
        "Do not edit this block manually.\n"
        f"{END_MARK}\n"
    )
    return readme_text.rstrip() + block


def main() -> int:
    readme = README_PATH.read_text(encoding="utf-8")
    readme = ensure_markers(readme)

    kmip = KMIP_PATH.read_text(encoding="utf-8")
    kmip_shifted = shift_headings(kmip)

    generated = (
        "\n"
        "<!-- BEGIN AUTO-GENERATED: Do not edit. Source: documentation/docs/KMIP_support.md -->\n"
        "\n"
        f"{kmip_shifted}"
        "\n"
        "<!-- END AUTO-GENERATED -->\n"
    )

    # Replace content between markers
    pattern = re.compile(
        rf"{re.escape(START_MARK)}.*?{re.escape(END_MARK)}",
        flags=re.DOTALL,
    )
    new_readme = pattern.sub(f"{START_MARK}{generated}{END_MARK}", readme)

    if new_readme != readme:
        README_PATH.write_text(new_readme, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
