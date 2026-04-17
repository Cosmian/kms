#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — Unified Security Audit Entry Point
# =============================================================================
# Runs both audit sub-scripts in sequence:
#   1. owasp.sh          — OWASP Top 10 / ASVS checks (code-level, per-finding)
#   2. multi_framework.sh — NIST CSF 2.0/SSDF · CIS Controls v8 · ISO 27034 · OSSTMM
#
# Usage: bash .github/scripts/audit/audit.sh [options]
#
# Options forwarded to owasp.sh:
#   --output-dir <dir>   Output directory for per-tool files
#   --geiger             Also run cargo-geiger
#   --fail-on-warn       Exit 1 on warnings too
#
# Options for multi_framework.sh:
#   --verbose            Show additional grep detail
#
# Exit code: 0 if all checks pass/warn; 1 if any check fails.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
BOLD=$'\e[1m'
RESET=$'\e[0m'

OWASP_ARGS=()
MF_ARGS=()

for arg in "$@"; do
  case "$arg" in
  --verbose) MF_ARGS+=("$arg") ;;
  *) OWASP_ARGS+=("$arg") ;;
  esac
done

OWASP_EXIT=0
MF_EXIT=0

echo "${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo "${BOLD}  Cosmian KMS — OWASP Security Audit${RESET}"
echo "${BOLD}════════════════════════════════════════════════════════════${RESET}"
bash "$SCRIPT_DIR/owasp.sh" "${OWASP_ARGS[@]}" || OWASP_EXIT=$?

echo
echo "${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo "${BOLD}  Cosmian KMS — Multi-Framework Security Audit${RESET}"
echo "${BOLD}  (NIST CSF 2.0/SSDF · CIS Controls v8 · ISO 27034 · OSSTMM)${RESET}"
echo "${BOLD}════════════════════════════════════════════════════════════${RESET}"
bash "$SCRIPT_DIR/multi_framework.sh" "${MF_ARGS[@]}" || MF_EXIT=$?

echo
echo "${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo "${BOLD}  Unified Audit Summary${RESET}"
echo "${BOLD}════════════════════════════════════════════════════════════${RESET}"

if [[ "$OWASP_EXIT" -eq 0 && "$MF_EXIT" -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}ALL CHECKS PASSED${RESET}"
  exit 0
else
  [[ "$OWASP_EXIT" -ne 0 ]] && echo -e "${RED}${BOLD}OWASP audit: FAILED (exit $OWASP_EXIT)${RESET}"
  [[ "$MF_EXIT" -ne 0 ]] && echo -e "${YELLOW}${BOLD}Multi-framework audit: FAILED (exit $MF_EXIT)${RESET}"
  exit 1
fi
