#!/bin/bash
# Synology DSM KMIP Integration Test Runner
# Simulates the KMIP operation sequence that Synology DSM 7.x performs
# when configuring an external KMS server for NAS volume encryption.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DSM_SCRIPT=".github/scripts/pykmip/synology_dsm_client.py"
PYKMIP_CONF=".github/scripts/pykmip/pykmip.conf"
PYTHON_CMD="python" # Will use python from venv after activation

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

check_prerequisites() {
    print_status "Checking prerequisites..."

    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crate/server" ]]; then
        print_error "Please run this script from the root of the KMS project"
        exit 1
    fi

    if [[ ! -d ".venv" ]]; then
        print_error "Virtual environment not found. Run: .github/scripts/pykmip/setup_pykmip.sh"
        exit 1
    fi

    print_status "Activating virtual environment..."
    source .venv/bin/activate

    python_major=$($PYTHON_CMD -c "import sys; print(sys.version_info.major)")
    python_minor=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")
    python_version="${python_major}.${python_minor}"

    if [[ "$python_major" -eq 3 && "$python_minor" -ge 12 ]]; then
        print_error "Python ${python_version} detected. PyKMIP requires Python 3.11 or earlier."
        print_error "Install Python 3.11: brew install python@3.11 (macOS) or via pyenv"
        print_error "Recreate venv: rm -rf .venv && python3.11 -m venv .venv && pip install PyKMIP"
        exit 1
    fi

    print_success "Python ${python_version} is compatible with PyKMIP"

    if [[ ! -f "$DSM_SCRIPT" ]]; then
        print_error "Synology DSM simulation script not found: $DSM_SCRIPT"
        exit 1
    fi

    if [[ ! -f "$PYKMIP_CONF" ]]; then
        print_error "PyKMIP configuration not found: $PYKMIP_CONF"
        exit 1
    fi

    print_success "All prerequisites met"
}

run_synology_dsm_simulation() {
    print_status "Running Synology DSM KMIP simulation..."
    print_status "Configuration: $PYKMIP_CONF"
    print_status "Script: $DSM_SCRIPT"
    echo ""

    local verbose_flag=""
    if [[ "${VERBOSE:-}" == "1" ]] || [[ "${1:-}" == "--verbose" ]] || [[ "${1:-}" == "-v" ]]; then
        verbose_flag="--verbose"
        print_status "Verbose output enabled"
    fi

    if env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
        "$PYTHON_CMD" "$DSM_SCRIPT" \
        --configuration "$PYKMIP_CONF" \
        --key-name "synology-dsm-ci-test-$(date +%s)" \
        $verbose_flag; then
        echo ""
        print_success "Synology DSM simulation completed successfully"
        return 0
    else
        echo ""
        print_error "Synology DSM simulation FAILED"
        return 1
    fi
}

usage() {
    echo "Usage: $0 [simulate|help] [--verbose|-v]"
    echo ""
    echo "Commands:"
    echo "  simulate   Run the full Synology DSM KMIP operation sequence (default)"
    echo "  help       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  VERBOSE=1          Enable verbose output"
    echo "  PYKMIP_CONF=<path> Override PyKMIP configuration file (default: .github/scripts/pykmip/pykmip.conf)"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 simulate"
    echo "  $0 simulate --verbose"
    echo "  VERBOSE=1 $0 simulate"
}

main() {
    local cmd="${1:-simulate}"
    shift || true

    case "$cmd" in
    simulate | all)
        check_prerequisites
        run_synology_dsm_simulation "$@"
        ;;
    help | --help | -h)
        usage
        ;;
    *)
        print_error "Unknown command: $cmd"
        usage
        exit 1
        ;;
    esac
}

main "$@"
