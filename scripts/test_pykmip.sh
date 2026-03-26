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
DSM_SCRIPT="scripts/synology_dsm_client.py"
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

    # Check Python version compatibility
    python_version=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    python_major=$($PYTHON_CMD -c "import sys; print(sys.version_info.major)")
    python_minor=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")

    if [[ "$python_major" -eq 3 && "$python_minor" -ge 12 ]]; then
        print_error "Python ${python_version} detected. PyKMIP requires Python 3.11 or earlier due to ssl.wrap_socket deprecation."
        print_error "The ssl.wrap_socket method was removed in Python 3.12, but PyKMIP still uses it."
        print_error ""
        print_error "To fix this issue:"
        print_error "1. Install Python 3.11: brew install python@3.11 (on macOS)"
        print_error "2. Recreate virtual environment: rm -rf .venv && python3.11 -m venv .venv"
        print_error "3. Run setup again: ./scripts/setup_pykmip.sh"
        print_error ""
        print_error "Alternative: Use pyenv to manage Python versions:"
        print_error "  pyenv install 3.11.9"
        print_error "  pyenv local 3.11.9"
        print_error "  rm -rf .venv && python -m venv .venv"
        exit 1
    fi

    print_success "Python ${python_version} is compatible with PyKMIP"

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

    # Check for Python errors/exceptions (improved detection)
    if echo "$output" | grep -qi "traceback\|exception\|error:" && ! echo "$output" | grep -q '"status":'; then
        failure_detected=true
        failure_reason="Python exception detected"
    fi

    # Check for specific Python error patterns
    if echo "$output" | grep -qi "attributeerror\|typeerror\|valueerror\|keyerror\|importerror\|modulenotfounderror"; then
        failure_detected=true
        failure_reason="Python error detected"
    fi

    # Check if output doesn't contain valid JSON (might indicate crash)
    if ! echo "$output" | python -m json.tool >/dev/null 2>&1; then
        # Only flag as error if it's not just verbose output mixed with JSON
        if ! echo "$output" | tail -20 | python -m json.tool >/dev/null 2>&1; then
            failure_detected=true
            failure_reason="invalid or missing JSON output"
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

    operations=("activate" "create" "create_keypair" "decrypt" "destroy" "discover_versions" "encrypt" "get" "get_attribute_list" "get_attributes" "locate" "mac" "modify_attribute" "query" "revoke" "sign" "signature_verify")
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

# Function to run the Synology DSM simulation (end-to-end integration test)
run_dsm_simulation() {
    local verbose=${1:-false}

    print_status "Running Synology DSM KMIP end-to-end simulation..."

    if [[ ! -f "$DSM_SCRIPT" ]]; then
        print_error "Synology DSM script not found: $DSM_SCRIPT"
        return 1
    fi

    local cmd_args=(
        "$PYTHON_CMD"
        "$DSM_SCRIPT"
        "--configuration" "$PYKMIP_CONF"
    )

    if [[ "$verbose" == "true" ]]; then
        cmd_args+=("--verbose")
    fi

    local output=""
    local exit_code=0

    # Temporarily disable set -e so a non-zero exit from the Python script
    # does not abort the shell before we can echo the captured output.
    set +e
    if command -v timeout >/dev/null 2>&1; then
        output=$(timeout 60 "${cmd_args[@]}" 2>&1)
        exit_code=$?
    else
        output=$("${cmd_args[@]}" 2>&1)
        exit_code=$?
    fi
    set -e

    if [[ $exit_code -eq 124 ]]; then
        print_error "Synology DSM simulation timed out after 60 seconds"
        return 1
    fi

    echo ""
    echo "=== SYNOLOGY DSM SIMULATION OUTPUT ==="
    echo "$output"
    echo "======================================="
    echo ""

    if [[ $exit_code -eq 0 ]] && echo "$output" | grep -q "ALL SYNOLOGY DSM SIMULATION STEPS PASSED"; then
        print_success "Synology DSM simulation SUCCEEDED"
        return 0
    else
        print_error "Synology DSM simulation FAILED"
        return 1
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
    echo "  check               Check prerequisites and connectivity"
    echo "  activate            Run PyKMIP activate operation"
    echo "  create              Run PyKMIP create operation"
    echo "  create_keypair      Run PyKMIP create key pair operation"
    echo "  decrypt             Run PyKMIP encrypt/decrypt test"
    echo "  destroy             Run PyKMIP destroy operation"
    echo "  discover_versions   Run PyKMIP discover versions operation"
    echo "  encrypt             Run PyKMIP encrypt operation"
    echo "  get                 Run PyKMIP get operation"
    echo "  get_attribute_list  Run PyKMIP get attribute list operation"
    echo "  get_attributes      Run PyKMIP get attributes operation"
    echo "  locate              Run PyKMIP locate operation"
    echo "  mac                 Run PyKMIP MAC operation"
    echo "  modify_attribute    Run PyKMIP modify attribute operation (issue #760)"
    echo "  query               Run PyKMIP query operation"
    echo "  revoke              Run PyKMIP revoke operation"
    echo "  sign                Run PyKMIP sign operation (RSA-SHA256)"
    echo "  signature_verify    Run PyKMIP sign + signature verify (RSA-SHA256)"
    echo "  dsm_simulation      Run Synology DSM end-to-end KMIP simulation"
    echo "  all                 Run all PyKMIP operations + Synology DSM simulation"
    echo "  rust-test           Run Rust PyKMIP integration tests"
    echo "  help                Show this help message"
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
    echo "  ./scripts/test_pykmip.sh modify_attribute -v"
    echo "  ./scripts/test_pykmip.sh dsm_simulation"
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
            all|activate|check|create|create_keypair|decrypt|destroy|discover_versions|encrypt|get|get_attribute_list|get_attributes|locate|mac|modify_attribute|query|revoke|sign|signature_verify|dsm_simulation|rust-test)
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
        activate|create|create_keypair|decrypt|destroy|discover_versions|encrypt|get|get_attribute_list|get_attributes|locate|mac|modify_attribute|query|revoke|sign|signature_verify)
            check_prerequisites
            run_operation "$command" "$verbose"
            ;;
        dsm_simulation)
            check_prerequisites
            run_dsm_simulation "$verbose"
            ;;
        all)
            check_prerequisites
            run_all_operations "$verbose"
            failed_ops=$?
            echo ""
            echo "######################################"
            echo "# TESTING: Synology DSM end-to-end simulation"
            echo "######################################"
            run_dsm_simulation "$verbose"
            dsm_status=$?
            if [[ $failed_ops -ne 0 ]] || [[ $dsm_status -ne 0 ]]; then
                print_error "SOME TESTS FAILED"
                exit 1
            else
                print_success "ALL TESTS PASSED (PyKMIP operations + Synology DSM simulation)"
            fi
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
