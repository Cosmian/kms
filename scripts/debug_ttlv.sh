#!/bin/bash

# TTLV Debug Test Runner
# Runs debug scripts to analyze the TTLV parsing issue

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check if we're in the right directory
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crate/server" ]]; then
        print_error "Please run this script from the root of the KMS project"
        exit 1
    fi

    # Check if virtual environment exists
    if [[ ! -d ".venv" ]]; then
        print_error "Virtual environment not found. Run: scripts/setup_pykmip.sh"
        exit 1
    fi

    # Activate virtual environment
    print_status "Activating virtual environment..."
    source .venv/bin/activate

    # Check if PyKMIP is installed
    if ! python -c "import kmip" &> /dev/null; then
        print_error "PyKMIP is not installed in virtual environment"
        exit 1
    fi

    print_status "Prerequisites satisfied"
}

# Run simple debug
run_simple_debug() {
    print_header "RUNNING SIMPLE KMIP COMPATIBILITY DEBUG"
    
    if source .venv/bin/activate && python scripts/simple_debug.py; then
        print_status "Simple debug completed"
    else
        print_error "Simple debug failed"
        return 1
    fi
}

# Run TTLV debug
run_ttlv_debug() {
    print_header "RUNNING DETAILED TTLV STRUCTURE DEBUG"
       
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if source .venv/bin/activate && python scripts/ttlv_debug.py; then
            print_status "TTLV debug completed"
        else
            print_error "TTLV debug failed (this is expected - it shows us the parsing issue)"
            return 1
        fi
    else
        print_status "TTLV debug skipped"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Debug tools for analyzing PyKMIP TTLV parsing issues"
    echo ""
    echo "Commands:"
    echo "  simple       Run simple KMIP version compatibility test"
    echo "  ttlv         Run detailed TTLV structure analysis (shows binary data)"
    echo "  both         Run both debug tools"
    echo "  help         Show this help message"
    echo ""
    echo "Prerequisites:"
    echo "  - KMS server must be running"
    echo "  - Virtual environment must be set up (scripts/setup_pykmip.sh)"
    echo ""
    echo "Example:"
    echo "  $0 simple    # Quick compatibility test"
    echo "  $0 ttlv      # Detailed TTLV analysis"
    echo "  $0 both      # Run both tests"
}

# Main script logic
main() {
    local command=${1:-help}
    
    case $command in
        simple)
            check_prerequisites
            run_simple_debug
            ;;
        ttlv)
            check_prerequisites
            run_ttlv_debug
            ;;
        both)
            check_prerequisites
            run_simple_debug
            echo
            run_ttlv_debug
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
