#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build.sh — Regenerate the Eviden KMS presentation (HTML + PDF)
#
# Usage:
#   ./build.sh            # build HTML + PDF (default)
#   ./build.sh --html     # HTML only
#   ./build.sh --pdf      # PDF only
#   ./build.sh --diagrams # re-render Mermaid diagrams only
#
# Dependencies (checked at runtime):
#   - mmdc   : @mermaid-js/mermaid-cli  (brew install mermaid-js/mermaid-cli/mmdc
#              or: npm install -g @mermaid-js/mermaid-cli)
#   - marp   : @marp-team/marp-cli      (npx — no global install needed)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIAGRAMS_DIR="${SCRIPT_DIR}/diagrams"
SLIDES="${SCRIPT_DIR}/slides.md"
OUTPUT_HTML="${SCRIPT_DIR}/kms-presentation.html"
OUTPUT_PDF="${SCRIPT_DIR}/kms-presentation.pdf"

# ── Parse arguments ───────────────────────────────────────────────────────────
BUILD_HTML=true
BUILD_PDF=true
BUILD_DIAGRAMS=true

if [[ $# -gt 0 ]]; then
  BUILD_HTML=false
  BUILD_PDF=false
  BUILD_DIAGRAMS=false
  for arg in "$@"; do
    case "$arg" in
      --html) BUILD_HTML=true ;;
      --pdf) BUILD_PDF=true ;;
      --diagrams) BUILD_DIAGRAMS=true ;;
      *)
        echo "Unknown option: $arg" >&2
        echo "Usage: $0 [--html] [--pdf] [--diagrams]" >&2
        exit 1
        ;;
    esac
  done
fi

# ── Colour helpers ────────────────────────────────────────────────────────────
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red() { printf '\033[0;31m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;34m▶ %s\033[0m\n' "$*"; }

# ── Dependency checks ─────────────────────────────────────────────────────────
step "Checking dependencies"

if ! command -v mmdc &>/dev/null; then
  red "mmdc not found."
  yellow "Install with:  npm install -g @mermaid-js/mermaid-cli"
  yellow "           or: brew install mermaid-js/mermaid-cli/mmdc"
  exit 1
fi
green "mmdc:  $(mmdc --version 2>/dev/null || echo 'found')"

if ! command -v npx &>/dev/null; then
  red "npx not found — install Node.js first: https://nodejs.org"
  exit 1
fi
green "npx:   $(npx --version)"

# ── Step 1: Pre-render Mermaid diagrams ───────────────────────────────────────
if [[ "$BUILD_DIAGRAMS" == true ]]; then
  step "Rendering Mermaid diagrams → SVG"
  cd "${DIAGRAMS_DIR}"

  DIAGRAMS=(
    key_lifecycle
    cloud_integrations
    pki_chain
    hsm_arch
    auth_flow
  )

  for name in "${DIAGRAMS[@]}"; do
    src="${name}.mmd"
    out="${name}.svg"
    if [[ ! -f "$src" ]]; then
      red "Source not found: ${DIAGRAMS_DIR}/${src}"
      exit 1
    fi
    mmdc -i "$src" -o "$out" -b transparent
    green "  ✓ ${out}"
  done

  cd "${SCRIPT_DIR}"
fi

# ── Step 2: Build HTML ────────────────────────────────────────────────────────
if [[ "$BUILD_HTML" == true ]]; then
  step "Building HTML preview → $(basename "${OUTPUT_HTML}")"
  npx --yes @marp-team/marp-cli \
    "${SLIDES}" \
    --html \
    --allow-local-files \
    -o "${OUTPUT_HTML}" 2>&1 | grep -v -E "^npm warn|Insecure local file"
  green "  ✓ ${OUTPUT_HTML}"
fi

# ── Step 3: Build PDF ─────────────────────────────────────────────────────────
if [[ "$BUILD_PDF" == true ]]; then
  step "Building PDF → $(basename "${OUTPUT_PDF}")"
  npx @marp-team/marp-cli \
    "${SLIDES}" \
    --pdf \
    --allow-local-files \
    -o "${OUTPUT_PDF}" 2>&1 | grep -v -E "^npm warn|Insecure local file"

  SIZE=$(du -sh "${OUTPUT_PDF}" | cut -f1)
  PAGES=$(pdfinfo "${OUTPUT_PDF}" 2>/dev/null | awk '/^Pages:/{print $2}' || echo "?")
  green "  ✓ ${OUTPUT_PDF}  (${SIZE}, ${PAGES} pages)"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
printf '\n'
green "Done. Output files:"
[[ "$BUILD_HTML" == true ]] && echo "  ${OUTPUT_HTML}"
[[ "$BUILD_PDF" == true ]] && echo "  ${OUTPUT_PDF}"
