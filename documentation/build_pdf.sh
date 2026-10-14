#!/usr/bin/env bash
# Build the KMS documentation as a single PDF.
#
# mdBook has no PDF backend. This pipeline flattens the mdBook nav tree
# (documentation/nav.yml is the authoritative page ordering) into one pandoc
# markdown document and renders it through the vendored Eisvogel LaTeX template.
#
# Output: documentation/build/KMS.pdf
set -euo pipefail

DOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DOC_DIR/.." && pwd)"
BUILD_DIR="$DOC_DIR/build"
OUT="$BUILD_DIR/KMS.pdf"
COMBINED="$BUILD_DIR/_combined.md"

VERSION="$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*= *"\(.*\)".*/\1/')"
TITLE="Eviden Key Management System"
mkdir -p "$BUILD_DIR"

cd "$DOC_DIR"

# 1. Regenerate the LaTeX macros shared with the mdBook katex macros.
./build_macros.sh

# 2. Branded title-page logo (Eisvogel cannot embed SVG under XeLaTeX).
rsvg-convert -w 512 docs/eviden-logo-orange.svg -o "$BUILD_DIR/eviden-logo-orange.png"

# 3. Flatten the nav tree into one markdown document.
python3 pandoc/combine.py -o "$COMBINED"

# 4. Render with pandoc + XeLaTeX.
pandoc "$COMBINED" \
  --from=markdown+smart+tex_math_dollars+fenced_divs \
  --to=pdf \
  --pdf-engine=xelatex \
  --template=pandoc/eisvogel.tex \
  --lua-filter=pandoc/pdf.lua \
  --include-in-header=pandoc/pdf-header.tex \
  --metadata book=true \
  --top-level-division=chapter \
  --metadata title="$TITLE" \
  --metadata subtitle="Documentation" \
  --metadata author="Eviden" \
  --metadata version="$VERSION" \
  --metadata lang=en \
  --metadata titlepage=true \
  --metadata titlepage-logo=build/eviden-logo-orange.png \
  --metadata logo-width=45mm \
  --metadata titlepage-rule-color=FF6D43 \
  --metadata titlepage-rule-height=3 \
  --metadata titlepage-text-color=5F5F5F \
  --metadata table-use-row-colors=true \
  --number-sections \
  --toc \
  --toc-depth=2 \
  --metadata toc-own-page=true \
  --output "$OUT"

echo "PDF written to: $OUT"
