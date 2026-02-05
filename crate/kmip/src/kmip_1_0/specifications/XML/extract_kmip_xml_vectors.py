#!/usr/bin/env python3
"""Extract KMIP XML test vectors embedded in OASIS profile HTML.

This repository vendors the OASIS KMIP profile specifications as HTML files
(e.g. `crate/kmip/src/kmip_1_0/KMIP Asymmetric Key Lifecycle Profile Version 1.0.html`).
Those documents embed each test case as a two-column HTML table:
- left column: line numbers (class KMIPXMLCELL)
- right column: the XML content itself, split across many <p class="KMIPXMLCELL"> lines
  with entities like &lt; and &gt;.

This script reconstructs each XML test case and writes it as a standalone `.xml`
file under:
  crate/kmip/src/kmip_1_0/specifications/XML/{mandatory,optional}

Naming convention follows KMIP 1.4 vectors already in the repo:
  <LABEL>.xml, where LABEL looks like AKLC-M-1-10 or OMOS-O-1-10.

Usage:
  python3 crate/kmip/src/kmip_1_4/specifications/XML/extract_kmip_xml_vectors.py \
    --html crate/kmip/src/kmip_1_0/KMIP\ Asymmetric\ Key\ Lifecycle\ Profile\ Version\ 1.0.html \
    --out-root crate/kmip/src/kmip_1_0/specifications/XML

Notes:
- The script is intentionally dependency-free (stdlib only).
- It is conservative: it only writes vectors it can parse into a well-formed XML
  document (via xml.etree.ElementTree).
"""

from __future__ import annotations

import argparse
import html as html_lib
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

LABEL_RE = re.compile(r"^\s*(?:\d+(?:\.\d+)*)?\s*([A-Z0-9][A-Z0-9\-]*-(?:M|O)-\d+-\d+)\s*$")
H3_RE = re.compile(r"<h3[^>]*>(.*?)</h3>", re.IGNORECASE | re.DOTALL)
H3_STRIP_TAGS_RE = re.compile(r"<[^>]+>")
P_XMLCELL_RE = re.compile(
    r"<p\s+class=(?:\"KMIPXMLCELL\"|KMIPXMLCELL)\b[^>]*>(.*?)</p>",
    re.IGNORECASE | re.DOTALL,
)


def _normalize_ws(s: str) -> str:
    # Word HTML uses <span> wrappers and &nbsp; indentation.
    # We need to preserve the textual XML tokens inside spans.
    # 1) Strip tags first (keeps &lt;...&gt; text as plain characters)
    s = H3_STRIP_TAGS_RE.sub("", s)
    # 2) Decode entities
    s = html_lib.unescape(s)
    # 3) Normalize NBSP
    s = s.replace("\u00A0", " ")
    return s


def _extract_label_from_h3(h3_inner_html: str) -> str | None:
    text = _normalize_ws(h3_inner_html)
    text = " ".join(text.split())
    m = LABEL_RE.match(text)
    if not m:
        return None
    return m.group(1)


def _classify_label(label: str) -> str:
    # Mandatory contains "-M-" in the middle; optional contains "-O-".
    if "-M-" in label:
        return "mandatory"
    if "-O-" in label:
        return "optional"
    raise ValueError(f"Cannot classify label (missing -M-/-O-): {label}")


def _find_next_table_block(html: str, start_idx: int) -> tuple[str, int] | None:
    """Return (table_html, end_idx) for the first <table ...>...</table> after start_idx."""
    table_start = html.lower().find("<table", start_idx)
    if table_start == -1:
        return None

    # Naive but effective for Word HTML: find the first matching </table>.
    table_end = html.lower().find("</table>", table_start)
    if table_end == -1:
        return None

    table_end += len("</table>")
    return html[table_start:table_end], table_end


def _reconstruct_xml_from_table(table_html: str) -> str | None:
    """Reconstruct the XML content from the KMIPXMLCELL table.

    We collect all <p class="KMIPXMLCELL">...</p> entries, normalize them, and
    then heuristically drop the leading line-number column by taking the first
    slice starting at the first line that contains a '<' after unescaping.
    """

    cells = [m.group(1) for m in P_XMLCELL_RE.finditer(table_html)]
    if not cells:
        return None

    lines: list[str] = []
    for raw in cells:
        txt = _normalize_ws(raw)
        txt = txt.rstrip("\r\n")
        # Word inserts empty paragraphs as &nbsp;
        if txt.strip() == "":
            lines.append("")
            continue
        # Timing markers are not part of XML and must be removed.
        if txt.lstrip().startswith("#"):
            continue
        # Word table includes a left column with line numbers; depending on how the
        # HTML is exported, those can leak into the text stream as standalone digits.
        if txt.strip().isdigit():
            continue
        lines.append(txt)

    # Locate first XML-looking line
    first_xml_idx = None
    for i, line in enumerate(lines):
        if "<" in line and ">" in line:
            first_xml_idx = i
            break
    if first_xml_idx is None:
        return None

    xml_lines = lines[first_xml_idx:]

    # Drop any remaining numeric-only lines inside the XML region.
    xml_lines = [ln for ln in xml_lines if not ln.strip().isdigit()]

    # Remove any trailing line-number-only noise after the XML ends.
    # We stop after we have seen a closing ResponseMessage (or RequestMessage)
    # and then encounter a long tail of blank lines.
    xml_text = "\n".join(xml_lines).strip()
    if not xml_text:
        return None

    # Ensure it looks like a KMIP test vector document.
    if "<RequestMessage" not in xml_text and "<ResponseMessage" not in xml_text:
        return None

    return xml_text + "\n"


def _wrap_for_parsing(xml_text: str) -> str:
    # Many OASIS vectors embed multiple top-level documents (e.g. RequestMessage + ResponseMessage)
    # back-to-back without a single enclosing root. Wrap for parsing/pretty-printing.
    return f"<KmipTestCase>\n{xml_text}\n</KmipTestCase>"


def _parse_or_raise(xml_text: str) -> ET.Element:
    return ET.fromstring(_wrap_for_parsing(xml_text))


def _indent(elem: ET.Element, level: int = 0) -> None:
    """In-place pretty indentation for ElementTree (Python 3.9+ compatible)."""
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            _indent(child, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def _pretty_reindent(xml_text: str) -> str:
    """Validate and return a conventionally indented XML test case.

    Output is a single well-formed XML document on disk by keeping the
    synthetic wrapper root.
    """
    root = _parse_or_raise(xml_text)
    _indent(root)
    return ET.tostring(root, encoding="unicode").strip() + "\n"


def extract_vectors(html_path: str) -> dict[str, str]:
    """Return mapping {label: xml_text}."""
    with open(html_path, "r", encoding="windows-1252", errors="replace") as f:
        html = f.read()

    vectors: dict[str, str] = {}

    for h3_match in H3_RE.finditer(html):
        h3_inner = h3_match.group(1)
        label = _extract_label_from_h3(h3_inner)
        if not label:
            continue

        # Find the first table after the h3 (Word doc structure places the XML there)
        table_info = _find_next_table_block(html, h3_match.end())
        if not table_info:
            continue
        table_html, _end = table_info

        xml_text = _reconstruct_xml_from_table(table_html)
        if not xml_text:
            continue

        try:
            vectors[label] = _pretty_reindent(xml_text)
        except ET.ParseError:
            # Skip invalid XML blocks.
            continue

    return vectors


def write_vectors(vectors: dict[str, str], out_root: str) -> tuple[int, int]:
    os.makedirs(out_root, exist_ok=True)
    mandatory_dir = os.path.join(out_root, "mandatory")
    optional_dir = os.path.join(out_root, "optional")
    os.makedirs(mandatory_dir, exist_ok=True)
    os.makedirs(optional_dir, exist_ok=True)

    mand = opt = 0
    for label, xml_text in sorted(vectors.items()):
        bucket = _classify_label(label)
        out_dir = mandatory_dir if bucket == "mandatory" else optional_dir
        out_path = os.path.join(out_dir, f"{label}.xml")

        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(xml_text)

        if bucket == "mandatory":
            mand += 1
        else:
            opt += 1

    return mand, opt


def _iter_html_files(html_dir: Path) -> Iterable[Path]:
    for p in sorted(html_dir.iterdir()):
        if p.is_file() and p.suffix.lower() == ".html":
            yield p


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--html",
        help="Path to a single OASIS KMIP profile HTML file (mutually exclusive with --html-dir)",
    )
    ap.add_argument(
        "--html-dir",
        default=str(Path(__file__).parent),
        help="Directory containing OASIS KMIP profile HTML files (default: this script's folder)",
    )
    ap.add_argument(
        "--out-root",
        default=str(Path(__file__).parent),
        help="Output root dir; will create mandatory/optional under it (default: this script's folder)",
    )
    args = ap.parse_args(argv)

    out_root = str(Path(args.out_root))

    vectors: dict[str, str] = {}
    sources: list[Path] = []

    if args.html:
        html_path = Path(args.html)
        if not html_path.is_file():
            print(f"HTML file not found: {html_path}", file=sys.stderr)
            return 2
        sources = [html_path]
    else:
        html_dir = Path(args.html_dir)
        if not html_dir.is_dir():
            print(f"HTML dir not found: {html_dir}", file=sys.stderr)
            return 2
        sources = list(_iter_html_files(html_dir))

    for src in sources:
        extracted = extract_vectors(str(src))
        # Merge; later files overwrite earlier on label collision
        vectors.update(extracted)

    mand, opt = write_vectors(vectors, out_root)

    print(f"Extracted {mand + opt} vectors: mandatory={mand} optional={opt}")
    if mand + opt == 0:
        print("No vectors extracted. The HTML structure may have changed.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
