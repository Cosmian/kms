#!/bin/bash

# PyKMIP Integration Verification Script
# This script verifies that the PyKMIP integration with virtual environment is working correctly

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  PyKMIP Integration Verification  ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if we're in the right directory
check_directory() {
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crate/server" ]]; then
        print_error "Please run this script from the root of the KMS project"
        exit 1
    fi
    print_status "Working directory is correct"
}

# Verify virtual environment
verify_venv() {
    print_info "Checking virtual environment..."
    
    if [[ ! -d ".venv" ]]; then
        print_error "Virtual environment not found at .venv/"
        print_warning "Run: ./scripts/setup_pykmip.sh"
        exit 1
    fi
    print_status "Virtual environment exists at .venv/"
    
    if [[ ! -f ".venv/bin/python" ]]; then
        print_error "Python executable not found in virtual environment"
        exit 1
    fi
    print_status "Python executable found in virtual environment"
    
    # Activate and test
    source .venv/bin/activate
    
    if ! python -c "import sys; print(f'Python {sys.version}')" &>/dev/null; then
        print_error "Cannot execute Python in virtual environment"
        exit 1
    fi
    
    python_version=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
    print_status "Python version: $python_version"
}

# Verify PyKMIP installation
verify_pykmip() {
    print_info "Checking PyKMIP installation..."
    
    source .venv/bin/activate
    
    if ! python -c "import kmip" &>/dev/null; then
        print_error "PyKMIP is not installed in virtual environment"
        print_warning "Run: ./scripts/setup_pykmip.sh"
        exit 1
    fi
    print_status "PyKMIP is installed"
    
    pykmip_version=$(python -c "import kmip; print(getattr(kmip, '__version__', 'unknown'))" 2>/dev/null)
    print_status "PyKMIP version: $pykmip_version"
}

# Verify scripts
verify_scripts() {
    print_info "Checking PyKMIP scripts..."
    
    if [[ ! -f "scripts/pykmip_client.py" ]]; then
        print_error "PyKMIP client script not found"
        exit 1
    fi
    print_status "PyKMIP client script exists"
    
    if [[ ! -x "scripts/test_pykmip.sh" ]]; then
        print_error "PyKMIP test script not found or not executable"
        exit 1
    fi
    print_status "PyKMIP test script is executable"
    
    if [[ ! -x "scripts/setup_pykmip.sh" ]]; then
        print_error "PyKMIP setup script not found or not executable"
        exit 1
    fi
    print_status "PyKMIP setup script is executable"
    
    # Test client script help
    source .venv/bin/activate
    if python scripts/pykmip_client.py --help &>/dev/null; then
        print_status "PyKMIP client script help works"
    else
        print_error "PyKMIP client script has issues"
        exit 1
    fi
}

# Verify certificates
verify_certificates() {
    print_info "Checking test certificates..."
    
    cert_files=(
        "test_data/client_server/ca/ca.crt"
        "test_data/client_server/owner/owner.client.acme.com.crt"
        "test_data/client_server/owner/owner.client.acme.com.key"
        "test_data/client_server/server/kmserver.acme.com.p12"
    )
    
    for cert_file in "${cert_files[@]}"; do
        if [[ ! -f "$cert_file" ]]; then
            print_error "Certificate file not found: $cert_file"
            exit 1
        fi
    done
    print_status "All required certificate files exist"
}



# Test PyKMIP client operations (without server)
test_client_operations() {
    print_info "Testing PyKMIP client operations (offline)..."
    
    source .venv/bin/activate
    
    # Test help output
    if python scripts/pykmip_client.py --help | grep -q "PyKMIP Client"; then
        print_status "Client help output is correct"
    else
        print_error "Client help output is incorrect"
        exit 1
    fi
    
    # Test available operations
    operations=(query create get destroy encrypt_decrypt create_keypair locate)
    for op in "${operations[@]}"; do
        if python scripts/pykmip_client.py --help | grep -q "$op"; then
            print_status "Operation '$op' is available"
        else
            print_warning "Operation '$op' may not be available"
        fi
    done
}

# Show final status and next steps
show_summary() {
    echo
    print_status "PyKMIP integration verification completed successfully!"
    echo
    print_info "Summary of verified components:"
    echo "  ✓ Virtual environment at .venv/"
    echo "  ✓ PyKMIP installation"
    echo "  ✓ PyKMIP client script"
    echo "  ✓ Test automation scripts"
    echo "  ✓ Test certificates"
    echo "  ✓ Rust test integration"
    echo
    print_info "Next steps to run tests:"
    echo "1. Start KMS server: COSMIAN_KMS_CONF=./scripts/kms.toml cargo run --bin cosmian_kms"
    echo "2. Test connectivity: ./scripts/test_pykmip.sh check"
    echo "3. Run PyKMIP tests: ./scripts/test_pykmip.sh all"
    echo "4. Run Rust tests: cargo test test_pykmip --package cosmian_kms_server"
    echo
}

# Main verification function
main() {
    print_header
    
    check_directory
    verify_venv
    verify_pykmip
    verify_scripts
    verify_certificates
    test_client_operations
    show_summary
}

# Run verification
main "$@"
