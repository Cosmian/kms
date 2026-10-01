#!/usr/bin/env python3
"""Flatten the mdBook nav tree into a single pandoc-ready markdown document.

``documentation/nav.yml`` is the authoritative page ordering (the mdBook
``SUMMARY.md`` is generated externally, see ``documentation/README.md``).  This
script walks that tree and emits one concatenated markdown file whose heading
levels mirror the nav hierarchy, so pandoc can produce a book with chapters.

Per-page preprocessing:
  * drop the page's own H1 (the nav title becomes the section heading)
  * demote the remaining headings to sit under the nav heading
  * mdbook admonitions (``!!! type "Title"``)  -> pandoc fenced divs
  * mdbook tabs (``=== "Label"``)              -> bold labels
  * mermaid code blocks                        -> omitted-in-PDF placeholder
  * ``<details>/<summary>``                    -> bold summary heading
  * internal ``*.md`` links                    -> plain text (dead in a PDF)
  * image paths rewritten relative to the ``documentation/`` root;
    referenced SVGs are converted to PNG (LaTeX cannot embed SVG).

Usage:
  python3 combine.py -o docs/_pdf.md
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent  # documentation/
DOCS = ROOT / "docs"
NAV = ROOT / "nav.yml"
BUILD_SVG = ROOT / "build" / "svg"  # SVG->PNG conversions (gitignored)

IMAGE_RE = re.compile(r'!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\s*\)')
MD_LINK_RE = re.compile(r'(?<!!)\[([^\]]+)\]\(([^)]+)\)')
ADMON_RE = re.compile(r"^!!!\s*([a-zA-Z]+)\s*(.*)$")
TAB_RE = re.compile(r'^===\s+"([^"]+)"\s*$')
FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})")
TITLE_FENCE_RE = re.compile(r'^([ \t]*)(`{3,}|~{3,})([^\s`~]*)\s+title="([^"]*)"\s*$')

MD_FILE_RE = re.compile(r"\.md(#.*)?$")


def svg_to_png(svg: Path, rel_to_docs: Path) -> Path:
    """Convert an SVG to a PNG under ``build/svg/`` (LaTeX cannot embed SVG)."""
    png = BUILD_SVG / rel_to_docs.with_suffix(".png")
    if png.exists():
        return png
    png.parent.mkdir(parents=True, exist_ok=True)
    if shutil.which("rsvg-convert"):
        subprocess.run(
            ["rsvg-convert", "-o", str(png), str(svg)],
            check=True,
            capture_output=True,
        )
        return png
    # No converter: leave the SVG as-is rather than crash the build.
    sys.stderr.write(f"WARN: rsvg-convert missing, leaving {svg} untouched\n")
    return svg


def rewrite_image_path(src: str, page_rel: Path) -> str:
    """Rewrite an image src so it resolves from the documentation/ root."""
    if re.match(r"^(https?://|data:|mailto:|/|#)", src):
        return src
    path_part, _, frag = src.partition("#")
    if not path_part:
        return src  # pure fragment
    abs_path = ((DOCS / page_rel).parent / path_part).resolve()
    if abs_path.suffix.lower() == ".svg" and abs_path.exists():
        rel_to_docs = abs_path.relative_to(DOCS)
        abs_path = svg_to_png(abs_path, rel_to_docs)
    try:
        rel = abs_path.relative_to(ROOT)
    except ValueError:
        rel = Path("docs") / abs_path.relative_to(DOCS)
    return f"{rel}#{frag}" if frag else str(rel)


def inline_rewrite(text: str, page_rel: Path) -> str:
    """Rewrite image paths and neutralise internal .md links."""
    text = IMAGE_RE.sub(
        lambda m: f"![{m.group(1)}]({rewrite_image_path(m.group(2).strip(), page_rel)})",
        text,
    )

    def link_repl(m):
        target = m.group(2).strip()
        if re.match(r"^(https?://|mailto:|data:)", target):
            return m.group(0)
        if MD_FILE_RE.search(target):
            return m.group(1)  # internal doc link -> keep the label only
        return m.group(0)

    return MD_LINK_RE.sub(link_repl, text)


def preprocess(text: str) -> str:
    """Convert mdbook-only constructs to pandoc-friendly markdown."""
    lines = text.split("\n")
    out = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]

        if line.strip().startswith("```mermaid"):
            j = i + 1
            while j < n and not lines[j].strip().startswith("```"):
                j += 1
            out.extend(["", "*[Diagram omitted in the PDF]*", ""])
            i = j + 1
            continue

        if line.strip() in ("<details>", "</details>"):
            i += 1
            continue

        m = re.match(r"^\s*<summary>(.*)</summary>\s*$", line)
        if m:
            out.append(f"**{m.group(1).strip()}**")
            i += 1
            continue

        am = ADMON_RE.match(line)
        if am:
            atype = am.group(1).lower()
            rest = am.group(2).strip()
            title = ""
            if rest.startswith('"') and '"' in rest[1:]:
                title = rest[1 : rest.index('"', 1)]
            else:
                title = rest
            title = title.replace('"', "'")
            body = []
            j = i + 1
            while j < n:
                l = lines[j]
                if l.strip() == "":
                    body.append("")
                    j += 1
                elif l[:1].isspace():
                    body.append(l[4:] if l.startswith("    ") else l.lstrip())
                    j += 1
                else:
                    break
            while body and body[-1].strip() == "":
                body.pop()
            out.append(f'::: {{.admonition type="{atype}" title="{title}"}}')
            out.extend(body)
            out.append(":::")
            i = j
            continue

        tm = TAB_RE.match(line)
        if tm:
            label = tm.group(1)
            body = []
            j = i + 1
            while j < n:
                l = lines[j]
                if TAB_RE.match(l):
                    break
                if l.strip() == "" or l[:1].isspace():
                    body.append(l)
                    j += 1
                else:
                    break
            indents = [len(l) - len(l.lstrip(" ")) for l in body if l.strip()]
            mindent = min(indents) if indents else 0
            out.append(f"**{label}**")
            out.append("")
            for l in body:
                out.append("" if l.strip() == "" else l[mindent:])
            i = j
            continue

        out.append(line)
        i += 1
    return "\n".join(out)


def drop_h1(text: str) -> str:
    """Remove the page's own top-level title heading."""
    lines = text.split("\n")
    for idx, line in enumerate(lines):
        if re.match(r"^#\s+", line):
            del lines[idx]
            break
    return "\n".join(lines)


def strip_fence_titles(text: str) -> str:
    """Rewrite mdbook `` ```lang title="X"`` fences into a bold label + fence.

    Pandoc does not understand the mdbook ``title="..."`` fence attribute and
    treats the whole block as inline code, turning the body's ``#`` lines into
    headings.  Emit the title as a bold label and keep the plain fence.
    """
    out = []
    for line in text.split("\n"):
        m = TITLE_FENCE_RE.match(line)
        if m:
            indent, fence, lang, title = m.groups()
            out.append(f"**{title}**")
            out.append("")
            out.append(f"{indent}{fence}{lang}")
        else:
            out.append(line)
    return "\n".join(out)


HR_RE = re.compile(r"^(-{3,}|\*{3,}|_{3,})\s*$")

LONG_TOKEN_LIMIT = 200  # non-space chars; longer runs are unreadable in print
LONG_TOKEN_KEEP = 120
LONG_TOKEN_RE = re.compile(r"\S{%d,}" % (LONG_TOKEN_LIMIT + 1))


def _fenced_lines(text: str):
    """Yield ``(in_code, line)`` pairs with pandoc-style fence matching.

    A fence opened with ``N`` backticks/tildes closes only on a run of the same
    character of length ``>= N`` (the pandoc rule).  A naive toggle mis-reads
    ````toml` blocks that embed ``` sub-blocks, demoting the TOML ``#`` comments
    into headings.
    """
    open_char = None
    open_len = 0
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if m:
            run = m.group(1)
            char = run[0]
            length = len(run)
            stripped = line.strip()
            pure = stripped != "" and all(c == char for c in stripped)
            if open_char is None:
                open_char, open_len = char, length
                yield False, line
            elif char == open_char and length >= open_len and pure:
                open_char, open_len = None, 0
                yield False, line
            else:
                # a nested/shorter fence inside the open block: still code
                yield True, line
            continue
        yield (open_char is not None), line


def elide_long_tokens(text: str) -> str:
    """Truncate pathologically long tokens inside fenced code blocks.

    Base64/hex dumps (e.g. the CSR in ``_certify.md``) are emitted by pandoc as
    a single ``\\StringTok{...}`` argument, which fvextra cannot break and which
    crashes XeLaTeX.  Keep a short prefix plus an ellipsis instead.
    """
    out = []
    for in_code, line in _fenced_lines(text):
        if in_code:
            line = LONG_TOKEN_RE.sub(
                lambda m: m.group(0)[:LONG_TOKEN_KEEP] + "\u2026", line
            )
        out.append(line)
    return "\n".join(out)


def demote(text: str, depth: int) -> str:
    """Shift headings down by ``depth`` levels and drop horizontal rules,
    both outside fenced code blocks.

    Standalone ``---`` rules are HTML-only separators; pandoc mis-reads them
    as YAML metadata delimiters when followed by an image, so they must go.
    """
    out = []
    for in_code, line in _fenced_lines(text):
        if in_code:
            out.append(line)
            continue
        if HR_RE.match(line):
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = min(6, len(m.group(1)) + depth)
            line = "#" * level + " " + m.group(2)
        out.append(line)
    return "\n".join(out)


def flatten(items, depth=0):
    """Return an ordered list of ``(depth, title, file_or_None)`` tuples."""
    result = []
    for item in items:
        (title, value), = item.items()
        if isinstance(value, str):
            result.append((depth, title, value))
        elif isinstance(value, list):
            same, children = None, []
            for child in value:
                (ctitle, cval), = child.items()
                if isinstance(cval, str) and ctitle == title and same is None:
                    same = (ctitle, cval)
                else:
                    children.append(child)
            result.append((depth, title, same[1] if same else None))
            result.extend(flatten(children, depth + 1))
        else:
            raise SystemExit(f"Unexpected nav value for {title!r}: {type(value)}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="-")
    args = ap.parse_args()

    data = yaml.safe_load(NAV.read_text(encoding="utf-8"))
    chunks = []
    for depth, title, rel in flatten(data["nav"]):
        level = min(6, depth + 1)
        heading = "#" * level + " " + title
        if rel is None:
            chunks.append(heading + "\n")
            continue
        page = Path(rel)
        full = DOCS / page
        if not full.exists():
            sys.stderr.write(f"WARN: missing page {rel}\n")
            chunks.append(heading + "\n")
            continue
        text = preprocess(full.read_text(encoding="utf-8"))
        text = strip_fence_titles(text)
        text = inline_rewrite(text, page)
        text = drop_h1(text)
        text = demote(text, depth)
        text = elide_long_tokens(text)
        chunks.append(heading + "\n\n" + text.strip() + "\n")

    result = "\n".join(chunks)
    if args.output == "-":
        sys.stdout.write(result)
    else:
        Path(args.output).write_text(result, encoding="utf-8")


if __name__ == "__main__":
    main()
