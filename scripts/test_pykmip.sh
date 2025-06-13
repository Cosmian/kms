#!/bin/bash

# PyKMIP Integration Test Runner
# This script helps run PyKMIP tests against the Cosmian KMS server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PYKMIP_SCRIPT="scripts/pykmip_client.py"
PYKMIP_CONF="scripts/pykmip.conf"
PYTHON_CMD="python"  # Will use python from venv after activation

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
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

    # Check if Python is available in venv
    if ! command -v python &> /dev/null; then
        print_error "Python is not available in virtual environment"
        exit 1
    fi

    # Check if PyKMIP is installed in venv
    if ! python -c "import kmip" &> /dev/null; then
        print_error "PyKMIP is not installed in virtual environment"
        print_warning "Run: scripts/setup_pykmip.sh"
        exit 1
    fi

    # Check if PyKMIP script exists
    if [[ ! -f "$PYKMIP_SCRIPT" ]]; then
        print_error "PyKMIP client script not found: $PYKMIP_SCRIPT"
        exit 1
    fi    
    
    # Check if PyKMIP CONF exists
    if [[ ! -f "$PYKMIP_CONF" ]]; then
        print_error "PyKMIP client configuration not found: $PYKMIP_CONF"
        exit 1
    fi

    print_status "All prerequisites satisfied"
}


# Function to run a PyKMIP operation
run_operation() {
    local operation=$1
    local verbose=${2:-false}
    
    print_status "Running PyKMIP $operation operation..."
    
    local cmd_args=(
        "$PYKMIP_SCRIPT"
        "--configuration" "$PYKMIP_CONF"
        "--operation" "$operation"
    )
    
    if [[ "$verbose" == "true" ]]; then
        cmd_args+=("--verbose")
    fi

    print_status "Executing: ${cmd_args[*]}"
    
    # Capture both stdout and stderr
    local output
    output=$(python "${cmd_args[@]}" 2>&1)
    
    echo "$output"
    
    # Check if the response contains status: error
    if echo "$output" | grep -q '"status": "error"'; then
        print_error "$operation operation failed - KMIP response status is error"
        return 1
    fi
    
    print_status "$operation operation completed successfully"
    return 0
}

# Function to run all operations
run_all_operations() {
    local verbose=${1:-false}
    
    operations=("query" "create" "get" "destroy" "encrypt_decrypt" "create_keypair" "locate")
    failed_operations=()
    
    for op in "${operations[@]}"; do
        if ! run_operation "$op" "$verbose"; then
            print_error "Operation $op failed, stopping"
            failed_operations+=("$op")
        fi
        echo
    done
    
    # Report final results
    if [ ${#failed_operations[@]} -eq 0 ]; then
        print_status "All PyKMIP operations completed successfully"
    else
        print_error "${#failed_operations[@]} out of ${#operations[@]} operations failed:"
        for failed_op in "${failed_operations[@]}"; do
            print_error "  - $failed_op"
        done
        exit 1
    fi
}

# Function to run Rust tests
run_rust_tests() {
    print_status "Running Rust PyKMIP integration tests..."
    
    if cargo test test_pykmip --package cosmian_kms_server; then
        print_status "Rust PyKMIP tests passed"
    else
        print_error "Rust PyKMIP tests failed"
        exit 1
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "This script tests PyKMIP integration with Cosmian KMS server."
    echo "It automatically activates the virtual environment (.venv) before running tests."
    echo ""
    echo "Commands:"
    echo "  check            Check prerequisites and connectivity"
    echo "  query            Run PyKMIP query operation"
    echo "  create           Run PyKMIP create operation"
    echo "  get              Run PyKMIP get operation"
    echo "  destroy          Run PyKMIP destroy operation"
    echo "  encrypt_decrypt  Run PyKMIP encrypt/decrypt test"
    echo "  create_keypair   Run PyKMIP create key pair operation"
    echo "  locate           Run PyKMIP locate operation"
    echo "  all              Run all PyKMIP operations"
    echo "  rust-test        Run Rust PyKMIP integration tests"
    echo "  help             Show this help message"
    echo ""
    echo "Options:"
    echo "  -v, --verbose   Enable verbose output"
    echo ""
    echo "Prerequisites:"
    echo "  1. Run: scripts/setup_pykmip.sh (sets up virtual environment)"
    echo "  2. Start KMS server: COSMIAN_KMS_CONF=./scripts/kms.toml cargo run --bin cosmian_kms"
    echo ""
    echo "Examples:"
    echo "  $0 check                    # Check prerequisites"
    echo "  $0 query                    # Run query operation"
    echo "  $0 all --verbose           # Run all operations with verbose output"
    echo "  $0 rust-test               # Run Rust tests"
}

# Main script logic
main() {
    local command=${1:-help}
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help|help)
                show_usage
                exit 0
                ;;
            check|query|create|get|destroy|encrypt_decrypt|create_keypair|locate|all|rust-test)
                command=$1
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    case $command in
        check)
            check_prerequisites
            ;;
        query|create|get|destroy|encrypt_decrypt|create_keypair|locate)
            check_prerequisites
            run_operation "$command" "$verbose"
            ;;
        all)
            check_prerequisites
            run_all_operations "$verbose"
            ;;
        rust-test)
            check_prerequisites
            run_rust_tests
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
