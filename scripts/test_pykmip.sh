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

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
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

    # Check if PyKMIP script exists
    if [[ ! -f "$PYKMIP_SCRIPT" ]]; then
        print_error "PyKMIP script not found: $PYKMIP_SCRIPT"
        exit 1
    fi

    # Check if the configuration exists
    if [[ ! -f "$PYKMIP_CONF" ]]; then
        print_error "PyKMIP configuration not found: $PYKMIP_CONF"
        exit 1
    fi

    print_success "All prerequisites satisfied"
}

# Function to run a PyKMIP operation
run_operation() {
    local operation=$1
    local verbose=${2:-false}
    
    print_status "Running PyKMIP $operation operation..."
    
    local cmd_args=(
        "$PYTHON_CMD"
        "$PYKMIP_SCRIPT"
        "--configuration" "$PYKMIP_CONF"
        "--operation" "$operation"
    )
    
    if [[ "$verbose" == "true" ]]; then
        cmd_args+=("--verbose")
    fi

    print_status "Executing: ${cmd_args[*]}"
    
    # Capture both stdout and stderr with timeout
    local output=""
    local exit_code=0
    
    # Use timeout to prevent hanging operations
    if command -v timeout >/dev/null 2>&1; then
        output=$(timeout 30 "${cmd_args[@]}" 2>&1)
        exit_code=$?
        
        if [[ $exit_code -eq 124 ]]; then
            print_error "$operation operation timed out after 30 seconds"
            return 1
        fi
    else
        # Fallback for systems without timeout command
        output=$("${cmd_args[@]}" 2>&1)
        exit_code=$?
    fi
    
    # Always show the output first
    echo ""
    echo "=== $operation OPERATION OUTPUT ==="
    echo "$output"
    echo "=================================="
    echo ""
    
    # Initialize failure detection
    local failure_detected=false
    local failure_reason=""
    
    # Check for empty output (might indicate hanging or crash)
    if [[ -z "$output" ]]; then
        failure_detected=true
        failure_reason="no output received"
    fi
    
    # Check if command failed with non-zero exit code
    if [[ $exit_code -ne 0 ]] && [[ $exit_code -ne 124 ]]; then
        failure_detected=true
        failure_reason="command exit code: $exit_code"
    fi
    
    # Check for JSON with error status (most important check)
    if echo "$output" | grep -q '"status": "error"'; then
        failure_detected=true
        failure_reason="KMIP response status is error"
    fi
    
    # Check for Python errors/exceptions that aren't JSON formatted
    if echo "$output" | grep -qi "traceback\|exception.*error"; then
        if ! echo "$output" | grep -q '"status":'; then
            failure_detected=true
            failure_reason="Python exception detected"
        fi
    fi
    
    # Report results
    if [[ "$failure_detected" == "true" ]]; then
        print_error "$operation operation FAILED - $failure_reason"
        return 1
    else
        print_success "$operation operation SUCCEEDED"
        return 0
    fi
}

# Function to run all operations
run_all_operations() {
    local verbose=${1:-false}
    
    operations=("activate" "create" "create_keypair" "decrypt" "destroy" "discover_versions" "encrypt" "get" "locate" "mac" "query" "revoke")
    failed_operations=()
    successful_operations=()
    
    print_status "Running all PyKMIP operations..."
    echo ""
    
    for op in "${operations[@]}"; do
        echo "######################################"
        echo "# TESTING OPERATION: $op"
        echo "######################################"
        
        if run_operation "$op" "$verbose"; then
            successful_operations+=("$op")
        else
            failed_operations+=("$op")
        fi
        
        echo ""
        echo "######################################"
        echo ""
    done
    
    # Report final results
    echo "======================================"
    echo "FINAL TEST RESULTS SUMMARY"
    echo "======================================"
    
    if [[ ${#successful_operations[@]} -gt 0 ]]; then
        print_success "SUCCESSFUL operations (${#successful_operations[@]}/${#operations[@]}):"
        for op in "${successful_operations[@]}"; do
            echo "  ✅ $op"
        done
        echo ""
    fi
    
    if [[ ${#failed_operations[@]} -gt 0 ]]; then
        print_error "FAILED operations (${#failed_operations[@]}/${#operations[@]}):"
        for op in "${failed_operations[@]}"; do
            echo "  ❌ $op"
        done
        echo ""
        
        return 1
    else
        print_success "ALL operations completed successfully!"
        return 0
    fi
}

# Function to run Rust tests
run_rust_tests() {
    print_status "Running Rust PyKMIP integration tests..."
    
    if cargo test test_pykmip --package cosmian_kms_server; then
        print_success "Rust PyKMIP tests passed"
    else
        print_error "Rust PyKMIP tests failed"
        return 1
    fi
}

# Function to show usage
# Certify is not directly implemented by PyKMIP client, so it's commented out for now
# the pykmip_certify.py is a workaround but it invokes Operations not supported by the Cosmian KMS
show_usage() {
    echo "PyKMIP Integration Test Runner"
    echo ""
    echo "This script tests PyKMIP integration with the Cosmian KMS server."
    echo "It automatically activates the virtual environment (.venv) before running tests."
    echo ""
    echo "Commands:"
    echo "  check            Check prerequisites and connectivity"
    echo "  activate         Run PyKMIP activate operation"
    # echo "  certify          Run PyKMIP certify operation"
    echo "  create           Run PyKMIP create operation"
    echo "  create_keypair   Run PyKMIP create key pair operation"
    echo "  decrypt          Run PyKMIP encrypt/decrypt test"
    echo "  destroy          Run PyKMIP destroy operation"
    echo "  discover_versions Run PyKMIP discover versions operation"
    echo "  encrypt          Run PyKMIP encrypt operation"
    echo "  get              Run PyKMIP get operation"
    echo "  locate           Run PyKMIP locate operation"
    echo "  mac              Run PyKMIP MAC operation"
    echo "  query            Run PyKMIP query operation"
    echo "  revoke           Run PyKMIP revoke operation"
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
    echo "  ./scripts/test_pykmip.sh all"
    echo "  ./scripts/test_pykmip.sh query -v"
    echo "  ./scripts/test_pykmip.sh check"
}

# Main function
main() {
    local command=""
    local verbose="false"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                verbose="true"
                shift
                ;;
            -h|--help|help)
                show_usage
                exit 0
                ;;
            all|activate|check|create|create_keypair|decrypt|destroy|discover_versions|encrypt|get|locate|mac|query|revoke|rust-test)
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
        activate|create|create_keypair|decrypt|destroy|discover_versions|encrypt|get|locate|mac|query|revoke)
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
