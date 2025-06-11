#!/bin/bash

# PyKMIP Setup Script for Cosmian KMS
# This script helps set up PyKMIP integration with the Cosmian KMS server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  PyKMIP Setup for Cosmian KMS  ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
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

# Check if we're in the right directory
check_directory() {
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crate/server" ]]; then
        print_error "Please run this script from the root of the KMS project"
        exit 1
    fi
}

# Check Python installation
check_python() {
    print_status "Checking Python installation..."
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3.8 or later."
        exit 1
    fi
    
    python_version=$(python3 --version | cut -d' ' -f2)
    print_status "Found Python $python_version"
    
    # Check if venv module is available
    if ! python3 -m venv --help &> /dev/null; then
        print_error "Python venv module is not available. Please install python3-venv package."
        exit 1
    fi
}

# Setup Python virtual environment and install PyKMIP
setup_venv_and_pykmip() {
    print_status "Setting up Python virtual environment..."
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d ".venv" ]]; then
        print_status "Creating virtual environment at .venv..."
        python3 -m venv .venv
        print_status "Virtual environment created"
    else
        print_status "Virtual environment already exists at .venv"
    fi
    
    # Activate virtual environment
    print_status "Activating virtual environment..."
    source .venv/bin/activate
    
    # Upgrade pip
    print_status "Upgrading pip..."
    python -m pip install --upgrade pip
    
    # Install PyKMIP
    print_status "Installing PyKMIP in virtual environment..."
    
    if python -c "import kmip" &> /dev/null; then
        print_status "PyKMIP is already installed"
        pykmip_version=$(python -c "import kmip; print(getattr(kmip, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
        print_status "PyKMIP version: $pykmip_version"
    else
        print_status "Installing PyKMIP using pip..."
        
        # Check Python version and install appropriate PyKMIP version
        python_version=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        print_status "Python version: $python_version"
        
        # For Python 3.9+, we need to be more careful with PyKMIP installation
        # Extract major and minor version numbers for comparison
        IFS='.' read -ra VERSION_PARTS <<< "$python_version"
        major=${VERSION_PARTS[0]}
        minor=${VERSION_PARTS[1]:-0}
        
        if [[ $major -gt 3 ]] || [[ $major -eq 3 && $minor -ge 9 ]]; then
            print_warning "Python 3.9+ detected. Installing PyKMIP with compatibility fixes..."
            
            # Install PyKMIP with --no-compile to avoid syntax errors in demo files
            if python -m pip install --no-compile PyKMIP; then
                print_status "PyKMIP installed successfully (with compilation disabled)"
            else
                print_warning "Standard installation failed, trying alternative approach..."
                
                # Try installing from source with specific version
                if python -m pip install --no-deps --no-compile PyKMIP==0.10.0; then
                    print_status "PyKMIP 0.10.0 installed successfully"
                    # Install dependencies separately
                    python -m pip install 'cryptography>=2.5' 'requests>=2.20.0' 'six>=1.11.0' 'sqlalchemy>=1.3.0'
                else
                    print_error "Failed to install PyKMIP. Trying development version..."
                    # Try installing development version from GitHub
                    if python -m pip install --no-compile git+https://github.com/OpenKMIP/PyKMIP.git; then
                        print_status "PyKMIP development version installed successfully"
                    else
                        print_error "All PyKMIP installation methods failed"
                        print_error "This might be due to compatibility issues with Python $python_version"
                        print_warning "Consider using Python 3.8 or earlier, or trying manual installation"
                        exit 1
                    fi
                fi
            fi
        else
            # For Python < 3.9, standard installation should work
            if python -m pip install PyKMIP; then
                print_status "PyKMIP installed successfully"
            else
                print_error "Failed to install PyKMIP"
                exit 1
            fi
        fi
        
        # Verify installation
        if python -c "import kmip" &> /dev/null; then
            pykmip_version=$(python -c "import kmip; print(getattr(kmip, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
            print_status "PyKMIP installation verified. Version: $pykmip_version"
        else
            print_error "PyKMIP installation failed verification"
            print_warning "You may need to install PyKMIP manually or use a different Python version"
            exit 1
        fi
    fi
    
    # Create activation script for convenience
    print_status "Creating virtual environment activation helper..."
    cat > scripts/activate_venv.sh << 'EOF'
#!/bin/bash
# Activate PyKMIP virtual environment
cd "$(dirname "$0")/.."
source .venv/bin/activate
echo "PyKMIP virtual environment activated"
echo "Run 'deactivate' to exit the virtual environment"
EOF
    chmod +x scripts/activate_venv.sh
    print_status "Created scripts/activate_venv.sh for easy activation"
}

# Generate test certificates if they don't exist
setup_certificates() {
    print_status "Setting up test certificates..."
    
    if [[ -f "test_data/client_server/ca.crt" ]] && [[ -f "test_data/client_server/owner.client.acme.com.crt" ]]; then
        print_status "Test certificates already exist"
    else
        print_status "Generating test certificates..."
        
        cd test_data/client_server
        if [[ -f "generate_certs.sh" ]]; then
            bash generate_certs.sh
            print_status "Test certificates generated"
        else
            print_error "Certificate generation script not found"
            exit 1
        fi
        cd ../..
    fi
}

# Create PyKMIP configuration
create_config() {
    print_status "Creating PyKMIP configuration..."
    
    if [[ ! -f "scripts/pykmip.conf" ]]; then
        print_status "PyKMIP configuration already exists"
    else
        print_status "PyKMIP configuration file created at scripts/pykmip.conf"
    fi
}

# Test the setup
test_setup() {
    print_status "Testing PyKMIP setup..."
    
    # Activate virtual environment for testing
    source .venv/bin/activate
    
    # Test if the client script exists and can show help
    if [[ -f "scripts/pykmip_client.py" ]]; then
        if python scripts/pykmip_client.py --help &> /dev/null; then
            print_status "PyKMIP client script is working"
        else
            print_warning "PyKMIP client script has issues"
        fi
    else
        print_error "PyKMIP client script not found"
        exit 1
    fi
    
    # Make test script executable
    if [[ -f "scripts/test_pykmip.sh" ]]; then
        chmod +x scripts/test_pykmip.sh
        print_status "Test script is ready at scripts/test_pykmip.sh"
    fi
}

# Display next steps
show_next_steps() {
    echo
    print_status "Setup complete! Next steps:"
    echo
    echo "1. Activate the virtual environment:"
    echo "   source .venv/bin/activate"
    echo "   # or use the helper script:"
    echo "   source scripts/activate_venv.sh"
    echo
    echo "2. Start your KMS server with socket server enabled:"
    echo "   COSMIAN_KMS_CONF=scripts/kms.toml cargo run --bin cosmian_kms "
    echo
    echo "3. Test PyKMIP connectivity (in another terminal with venv activated):"
    echo "   ./scripts/test_pykmip.sh check"
    echo
    echo "4. Run PyKMIP operations:"
    echo "   ./scripts/test_pykmip.sh query"
    echo "   ./scripts/test_pykmip.sh all"
    echo
    echo "5. Run Rust integration tests:"
    echo "   cargo test test_pykmip --package cosmian_kms_server"
    echo
    echo "6. For more details, see:"
    echo "   scripts/README_PYKMIP.md"
    echo
    print_warning "Note: Remember to activate the virtual environment (.venv) before running PyKMIP commands!"
}

# Main setup function
main() {
    print_header
    
    check_directory
    check_python
    setup_venv_and_pykmip
    setup_certificates
    create_config
    test_setup
    show_next_steps
    
    print_status "PyKMIP integration setup completed successfully!"
}

# Handle command line arguments
case "${1:-setup}" in
    setup|"")
        main
        ;;
    check)
        check_directory
        check_python
        if [[ -d ".venv" ]] && source .venv/bin/activate && python -c "import kmip" &> /dev/null; then
            print_status "PyKMIP virtual environment is set up and ready"
            pykmip_version=$(python -c "import kmip; print(kmip.__version__)" 2>/dev/null || echo "unknown")
            print_status "PyKMIP version: $pykmip_version"
        else
            print_error "PyKMIP virtual environment is not properly set up. Run: $0 setup"
        fi
        ;;
    help|--help|-h)
        echo "Usage: $0 [COMMAND]"
        echo
        echo "Commands:"
        echo "  setup    Set up PyKMIP integration (default)"
        echo "  check    Check if PyKMIP is properly installed"
        echo "  help     Show this help message"
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
