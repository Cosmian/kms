#!/usr/bin/env bash
# Shared terminal color variables and print helpers.
#
# Usage:
#   source "$(cd "$(dirname "$0")/.." && pwd)/shared/colors.sh"   # from a subdir script
#   source "$SCRIPT_DIR/shared/colors.sh"                         # from .github/scripts/ root

# Prevent double-sourcing
[ -n "${_COLORS_SH_LOADED:-}" ] && return 0
_COLORS_SH_LOADED=1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  $*  ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

# print_error exits with status 1 after printing.
print_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    exit 1
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $*"
}
