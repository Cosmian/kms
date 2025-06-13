# PyKMIP Compatibility Testing

This directory contains scripts and configuration files for testing compatibility between the Cosmian KMS server and the PyKMIP client library. These tests ensure that our KMS implementation correctly handles KMIP protocol operations when interfaced with third-party KMIP clients.

## Purpose

The PyKMIP compatibility tests serve to:
- Verify that our KMS server correctly implements the KMIP protocol standard
- Ensure interoperability with existing KMIP client implementations
- Catch any regression issues that might break compatibility with PyKMIP clients
- Validate that common KMIP operations work as expected across different client implementations

## Prerequisites

- Python 3.x installed on your system
- PyKMIP library (will be installed by setup script)
- Cosmian KMS server running and accessible
- All scripts must be executed from the **project root directory** (not from within the `scripts/` directory)

## Testing Workflow

The PyKMIP compatibility testing follows a structured workflow. Each step must be executed in order to ensure proper setup and validation.

### 1. Query Server Status

Before running any PyKMIP tests, verify that your KMS server is running and accessible:

```bash
# Check if the KMS server is running
curl -f http://localhost:9998/status || echo "KMS server not accessible"

# Or check the server logs to ensure it's properly started
tail -f /path/to/kms/server.log
```

Ensure the server is:
- Running and accepting connections
- Properly configured for KMIP protocol support
- Accessible on the expected host and port

You can also perform a basic KMIP query operation to test connectivity:

```bash
# Run from project root - test basic KMIP connectivity
./scripts/pykmip_client.py --configuration scripts/pykmip.conf --operation query
```

This initial query will:
- Test the KMIP protocol handshake
- Verify authentication is working
- Confirm the server supports the required KMIP operations
- Report server capabilities and supported protocol versions

If this query fails, resolve connectivity and configuration issues before proceeding to the next steps.

### 2. Setup PyKMIP Environment

```bash
# Run from project root
./scripts/setup_pykmip.sh
```

This script will:
- Install the PyKMIP library and its dependencies
- Set up the Python virtual environment if needed
- Prepare the necessary configuration files
- Verify that all required components are properly installed

### 3. Verify PyKMIP Configuration (Optional but Recommended)

```bash
# Run from project root
./scripts/verify_pykmip.sh
```

This verification script will:
- Check that the PyKMIP client can connect to the KMS server
- Validate the configuration file settings
- Perform basic connectivity tests
- Ensure the server is responding to KMIP requests correctly
- Report any configuration issues that need to be addressed

### 4. Run Compatibility Tests

```bash
# Run from project root
./scripts/test_pykmip.sh
```

This comprehensive test script will:
- Execute a series of KMIP operations using the PyKMIP client
- Test common operations such as:
  - Key creation and management
  - Encryption and decryption operations
  - Certificate handling
  - Attribute management
- Validate that all responses have successful status codes
- Continue running all tests even if individual operations fail
- Provide a detailed summary of test results

## Understanding Test Results

The test script will output detailed information for each operation:

- **Success case**: Operation completes with `"status": "success"` in the JSON response
- **Failure case**: Operation returns `"status": "error"` or encounters an exception

Example successful output:
```json
{
  "operation": "CreateKeyPair",
  "status": "success",
  "unique_identifier": "abc123-def456-789"
}
```

Example failure output:
```json
{
  "operation": "EncryptDecrypt", 
  "status": "error",
  "error": "Invalid parameter provided"
}
```

## Troubleshooting

### Common Issues

1. **Script execution fails**: Ensure you're running from the project root, not from `scripts/`
2. **PyKMIP import errors**: Run `setup_pykmip.sh` to install dependencies
3. **Connection refused**: Verify the KMS server is running and accessible
4. **Configuration errors**: Check `scripts/pykmip.conf` for correct server settings

### File Structure

```
scripts/
├── README_PYKMIP.md          # This documentation
├── setup_pykmip.sh           # Environment setup script
├── verify_pykmip.sh          # Configuration verification script  
├── test_pykmip.sh            # Main compatibility test suite
├── pykmip_client.py          # PyKMIP client wrapper
└── pykmip.conf               # PyKMIP configuration file
```

## Configuration

The `pykmip.conf` file contains the connection settings for the PyKMIP client. Ensure the following parameters match your KMS server setup:
- Server hostname/IP address
- Port number
- Authentication credentials
- TLS/SSL settings

## Contributing

When adding new PyKMIP compatibility tests:
1. Add new operations to the `operations` array in `test_pykmip.sh`
2. Ensure proper error handling and status checking
3. Update this README if new setup steps are required
4. Test both success and failure scenarios

## Available Operations

The following operations are currently supported by the PyKMIP client script:

### 1. Query

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner/owner.client.acme.com.crt \
    --key test_data/client_server/owner/owner.client.acme.com.key \
    --ca test_data/client_server/ca/ca.crt \
    --operation query
```

### 2. Create

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner/owner.client.acme.com.crt \
    --key test_data/client_server/owner/owner.client.acme.com.key \
    --ca test_data/client_server/ca/ca.crt \
    --operation create
```

### 3. Get
Retrieves attributes for an object:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner/owner.client.acme.com.crt \
    --key test_data/client_server/owner/owner.client.acme.com.key \
    --ca test_data/client_server/ca/ca.crt \
    --operation get
```

### 4. Destroy
Creates and then destroys a key:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner/owner.client.acme.com.crt \
    --key test_data/client_server/owner/owner.client.acme.com.key \
    --ca test_data/client_server/ca/ca.crt \
    --operation destroy
```


## Troubleshooting

### Common Issues

1. **PyKMIP not installed**
   ```
   Error: No module named 'kmip'
   ```
   Solution: Run `./scripts/setup_pykmip.sh` to set up the virtual environment

2. **Virtual environment not activated**
   ```
   Error: python: command not found
   ```
   Solution: Activate the virtual environment with `source .venv/bin/activate`

3. **Certificate issues**
   ```
   Error: [SSL: CERTIFICATE_VERIFY_FAILED]
   ```
   Solution: Ensure certificates are generated and paths are correct

4. **Server not running**
   ```
   Error: Connection refused
   ```
   Solution: Make sure the KMS server is running with socket server enabled

5. **Port conflicts**
   ```
   Error: Address already in use
   ```
   Solution: Use a different port or stop conflicting services

### Debugging

Enable verbose output:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner/owner.client.acme.com.crt \
    --key test_data/client_server/owner/owner.client.acme.com.key \
    --ca test_data/client_server/ca/ca.crt \
    --operation query \
    --verbose
```

## Server Configuration

To enable PyKMIP clients, your KMS server must have the socket server enabled:

```toml
[socket_server]
socket_server_start = true
socket_server_port = 5696
socket_server_hostname = "0.0.0.0"

[tls]
tls_p12_file = "test_data/client_server/server/kmserver.acme.com.p12"
tls_p12_password = "password"
clients_ca_cert_file = "test_data/client_server/ca/ca.crt"
```

## Advanced Usage

### Custom Operations

Extend the PyKMIP client script to support additional operations:

```python
def perform_encrypt(proxy, plaintext, uid):
    """Encrypt data using a specific key"""
    result = proxy.encrypt(
        uid,
        plaintext.encode(),
        cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
        cryptographic_parameters={
            'block_cipher_mode': enums.BlockCipherMode.CBC,
            'padding_method': enums.PaddingMethod.PKCS5
        }
    )
    return result
```

### Batch Operations

PyKMIP supports batch operations for efficiency:

```python
def perform_batch_operations(proxy):
    """Perform multiple operations in a single request"""
    operations = [
        ('create', {...}),
        ('get', {...}),
        ('destroy', {...})
    ]
    return proxy.batch(operations)
```

## Integration with CI/CD

Add PyKMIP tests to your continuous integration:

```yaml
# .github/workflows/test.yml
- name: Setup PyKMIP virtual environment
  run: ./scripts/setup_pykmip.sh

- name: Run PyKMIP integration tests
  run: cargo test test_pykmip --package cosmian_kms_server
```

## Related Documentation

- [KMIP Protocol Support](../documentation/docs/kmip/index.md)
- [TLS Configuration](../documentation/docs/tls.md)
- [Authentication](../documentation/docs/authentication.md)
- [PyKMIP Official Documentation](https://pykmip.readthedocs.io/)
