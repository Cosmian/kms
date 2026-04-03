
The Cosmian KMS strives to be compatible with the PyKMIP client library, which is widely used for KMIP protocol interactions.
This document provides a comprehensive guide to testing and validating PyKMIP compatibility with the Cosmian KMS server.

[TOC]

## Purpose of PyKMIP compatibility tests

The PyKMIP compatibility tests serve to:

- Verify that our KMS server correctly implements the KMIP protocol standard
- Ensure interoperability with existing KMIP client implementations
- Catch any regression issues that might break compatibility with PyKMIP clients
- Validate that common KMIP operations work as expected across different client implementations
- Test edge cases and error handling for unsupported operations

## Prerequisites

- Python 3.x installed on your system
- PyKMIP library (will be installed by setup script)
- Cosmian KMS server running and accessible with KMIP socket server enabled
- All scripts must be executed from the **project root directory** (not from within the `scripts/` directory)
- Virtual environment (.venv) set up and activated for Python dependencies

## Quick Start

The fastest way to test PyKMIP compatibility is to use the automated test runner:

```bash
# 1. Set up the environment (from project root)
./scripts/setup_pykmip.sh

# 2. Start the KMS server (in another terminal)\
pkill -f cosmian_kms  # Stop any existing instance
COSMIAN_KMS_CONF=./scripts/kms.toml cargo run --bin cosmian_kms --features non-fips

# 3. Run all compatibility tests
./scripts/test_pykmip.sh all

# 4. Or run specific operations
./scripts/test_pykmip.sh query -v
./scripts/test_pykmip.sh create
./scripts/test_pykmip.sh check
```

The test runner automatically:

- Activates the Python virtual environment
- Validates prerequisites and connectivity
- Executes the requested operations with proper error handling
- Provides detailed output and status reporting
- Runs with timeout protection to prevent hanging tests

## Supported Operations

The current test suite supports the following KMIP operations:

### Core Operations

- **query** - Discover server capabilities and protocol versions
- **create** - Create symmetric keys
- **create_keypair** - Create RSA key pairs
- **get** - Retrieve an object
- **get_attributes** - Retrieve object attributes
- **destroy** - Delete objects from the server
- **locate** - Find objects by search criteria

### Cryptographic Operations

- **encrypt** - Encrypt data using managed keys
- **decrypt** - Decrypt data using managed keys
- **mac** - Generate Message Authentication Codes
- **activate** - Activate objects for use

### Management Operations

- **revoke** - Revoke objects and certificates
- **discover_versions** - Discover supported KMIP protocol versions

### Special Commands

- **all** - Execute all supported operations in sequence
- **check** - Validate prerequisites and connectivity
- **rust-test** - Run Rust-based PyKMIP integration tests

### Experimental/Unsupported Operations

- **certify** - Certificate signing (implemented via separate module `pykmip_certify.py`, uses operations not yet
  supported by Cosmian KMS)

Note: Some operations may fail due to server limitations or KMIP 1.x compatibility constraints. The test runner handles
these gracefully and provides detailed error reporting.

## Understanding Test Results

The test script provides comprehensive output for each operation with clear status indicators:

### Success Case

Operations that complete successfully will show:

```json
{
  "operation": "Create",
  "status": "success",
  "unique_identifier": "abc123-def456-789",
  "additional_info": {
    ...
  }
}
```

### Failure Case

Operations that fail will show:

```json
{
  "operation": "MAC",
  "status": "error",
  "error": "Invalid parameter provided",
  "details": "Cryptographic algorithm not supported"
}
```

### Test Summary

After running all operations, you'll see a summary like:

```text
======================================
FINAL TEST RESULTS SUMMARY
======================================
✅ SUCCESSFUL operations (12/13):
  ✅ query
  ✅ create
  ✅ get_attributes
  ✅ get
  ✅ destroy
  ✅ encrypt
  ✅ decrypt
  ✅ locate
  ✅ discover_versions
  ✅ mac
  ✅ activate
  ✅ revoke
  ✅ create_keypair
  🔍 certify (not supported in PyKMIP - workaround under study)
```

### Operation Status Types

- **✅ SUCCESS**: Operation completed and returned successful status
- **❌ FAILED**: Operation returned error status or threw exception
- **⚠️ TIMEOUT**: Operation timed out after 30 seconds
- **🔍 UNSUPPORTED**: Operation not supported by server or KMIP version

## Troubleshooting

### Common Issues

1. **Script execution fails**: Ensure you're running from the project root, not from `scripts/`

   ```bash
   # Wrong - don't do this
   cd scripts && ./test_pykmip.sh

   # Correct - run from project root
   ./scripts/test_pykmip.sh all
   ```

2. **PyKMIP import errors**: Run `setup_pykmip.sh` to install dependencies

   ```text
   Error: No module named 'kmip'
   Solution: ./scripts/setup_pykmip.sh
   ```

3. **Connection refused**: Verify the KMS server is running with KMIP socket server enabled

   ```text
   Error: Connection refused on port 5696
   Solution: Check server is running and socket_server_start = true in config
   ```

4. **Virtual environment not found**: The test runner requires a .venv directory

   ```text
   Error: Virtual environment not found
   Solution: Run ./scripts/setup_pykmip.sh to create .venv
   ```

5. **TLS/Certificate errors**: Verify certificate paths and validity

   ```text
   Error: [SSL: CERTIFICATE_VERIFY_FAILED]
   Solution: Check certificate files in test_data/certificates/client_server/
   ```

6. **Operation timeouts**: Some operations may timeout due to server processing time

   ```text
   Error: Operation timed out after 30 seconds
   Solution: Check server logs, increase timeout, or use -v for verbose output
   ```

### Advanced Troubleshooting

Enable verbose output to see detailed operation information:

```bash
./scripts/test_pykmip.sh query -v
```

Check server logs while running tests:

```bash
# In another terminal
tail -f logs/server.log
```

Test connectivity manually:

```bash
./scripts/test_pykmip.sh check
```

Run individual operations to isolate issues:

```bash
./scripts/test_pykmip.sh create -v
./scripts/test_pykmip.sh get -v
```

## File Structure

The PyKMIP test suite consists of the following files:

```text
scripts/
├── README_PYKMIP.md              # Additional documentation
├── setup_pykmip.sh               # Environment setup script
├── verify_pykmip.sh              # Configuration verification script
├── test_pykmip.sh                # Main compatibility test runner
├── pykmip_client.py              # PyKMIP client implementation (12 operations)
├── pykmip_certify.py             # Separate certify operation module
├── pykmip.conf                   # PyKMIP configuration file
├── kms.toml                      # KMS server configuration for testing
├── activate_venv.sh              # Virtual environment activation helper
└── certify_implementation_summary.py  # Certify operation analysis script
```

### Key Files

- **`test_pykmip.sh`**: Main test runner with colored output, timeout protection, and comprehensive error handling
- **`pykmip_client.py`**: Core client implementing 12 KMIP operations with JSON output formatting
- **`pykmip_certify.py`**: Modular implementation of certificate-related operations (experimental)
- **`pykmip.conf`**: Configuration file with TLS settings, authentication, and server connection details
- **`kms.toml`**: KMS server configuration optimized for PyKMIP compatibility testing

## Configuration

The `pykmip.conf` file contains the connection settings for the PyKMIP client. Key configuration sections:

### Server Connection

```ini
[server]
host=127.0.0.1
port=5696
```

### TLS Configuration

```ini
[tls]
client_cert_file=test_data/certificates/client_server/owner/owner.client.acme.com.crt
client_key_file=test_data/certificates/client_server/owner/owner.client.acme.com.key
ca_cert_file=test_data/certificates/client_server/ca/ca.crt
```

### Protocol Settings

```ini
[protocol]
kmip_version=1.0
```

Ensure these parameters match your KMS server setup:

- Server hostname/IP and port (default: 127.0.0.1:5696)
- TLS certificate paths (must exist and be valid)
- KMIP protocol version compatibility

### KMS Server Configuration

Your KMS server must be configured to accept KMIP connections. Key settings in `scripts/kms.toml`:

```toml
[server]
# Enable KMIP socket server
socket_server_start = true
socket_server_port = 5696
socket_server_hostname = "0.0.0.0"

[tls]
# Server certificate and key
# For FIPS mode (default build):
tls_cert_file = "test_data/certificates/client_server/server/kmserver.acme.com.crt"
tls_key_file = "test_data/certificates/client_server/server/kmserver.acme.com.key"

# For non-FIPS mode:
# tls_p12_file = "test_data/certificates/client_server/server/kmserver.acme.com.p12"
# tls_p12_password = "password"
clients_ca_cert_file = "test_data/certificates/client_server/ca/ca.crt"
```

## Contributing

When adding new PyKMIP compatibility tests:

1. **Add new operations** to the `operations` array in `test_pykmip.sh`:

   ```bash
   operations=("activate" "create" "create_keypair" "decrypt" "destroy"
               "discover_versions" "encrypt" "get" "locate" "mac" "query" "revoke")
   ```

2. **Implement operation functions** in `pykmip_client.py`:

   ```python
   def perform_new_operation(proxy, verbose=False):
       """Implement new KMIP operation"""
       if verbose:
           print("Performing new operation...")
       # Implementation here
       return {"operation": "NewOperation", "status": "success"}
   ```

3. **Add to argument parser** choices in `pykmip_client.py`:

   ```python
   parser.add_argument('--operation', default='query',
                       choices=['activate', 'create', ..., 'new_operation'],
                       help='KMIP operation to perform')
   ```

4. **Update help text** in `test_pykmip.sh` to include the new operation

5. **Handle modular operations** like certify by creating separate files:
    - Create `pykmip_operation.py` for complex operations
    - Import and call from main client: `from pykmip_operation import perform_operation`

6. **Test both success and failure scenarios** to ensure proper error handling

7. **Update this README** if new setup steps or dependencies are required

### Testing Best Practices

- Always test with both verbose (`-v`) and normal output modes
- Verify operations work individually and in the "all" test suite
- Check for JSON serialization issues with complex data types
- Ensure timeout handling works correctly for long-running operations
- Document any server limitations or KMIP version constraints

## Available Operations (Detailed Examples)

### Using the Test Runner (Recommended)

The test runner (`test_pykmip.sh`) automatically handles environment setup and provides consistent output formatting:

```bash
# Run all operations with summary report
./scripts/test_pykmip.sh all

# Run specific operation with verbose output
./scripts/test_pykmip.sh query -v

# Check prerequisites and connectivity
./scripts/test_pykmip.sh check

# Run individual operations
./scripts/test_pykmip.sh create
./scripts/test_pykmip.sh encrypt
./scripts/test_pykmip.sh mac
```

### Manual Client Usage (Advanced)

For direct client access with custom parameters:

#### 1. Query Server Capabilities

```bash
source .venv/bin/activate
python scripts/pykmip_client.py \
    --configuration scripts/pykmip.conf \
    --operation query \
    --verbose
```

#### 2. Create Symmetric Key

```bash
source .venv/bin/activate
python scripts/pykmip_client.py \
    --configuration scripts/pykmip.conf \
    --operation create
```

#### 3. Create RSA Key Pair

```bash
source .venv/bin/activate
python scripts/pykmip_client.py \
    --configuration scripts/pykmip.conf \
    --operation create_keypair
```

#### 4. Test Encryption/Decryption

```bash
source .venv/bin/activate
python scripts/pykmip_client.py \
    --configuration scripts/pykmip.conf \
    --operation encrypt

python scripts/pykmip_client.py \
    --configuration scripts/pykmip.conf \
    --operation decrypt
```

#### 5. Activate Objects

```bash
source .venv/bin/activate
python scripts/pykmip_client.py \
    --configuration scripts/pykmip.conf \
    --operation activate
```

## Related Documentation

- [KMIP Protocol Support](../certifications_and_compliance/cryptographic_algorithms/algorithms.md)
- [TLS Configuration](../configuration/tls.md)
- [Authentication](../configuration/authentication.md)
- [PyKMIP Official Documentation](https://pykmip.readthedocs.io/)
- [Cosmian KMS Server Documentation](../index.md)
