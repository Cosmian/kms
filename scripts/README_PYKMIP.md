# PyKMIP Integration with Cosmian KMS

This guide shows how to run PyKMIP clients from Rust to test your Cosmian KMS server.

## Overview

[PyKMIP](https://github.com/OpenKMIP/PyKMIP) is a Python implementation of the Key Management Interoperability Protocol (KMIP). This integration allows you to:

1. Test your KMS server against a reference KMIP client implementation
2. Validate KMIP protocol compliance
3. Perform interoperability testing
4. Use PyKMIP as a test harness for your KMS

## Prerequisites

### 1. Setup PyKMIP Virtual Environment

Run the setup script to create a virtual environment and install PyKMIP:

```bash
./scripts/setup_pykmip.sh
```

This will:
- Create a virtual environment at `.venv/`
- Install PyKMIP in the virtual environment
- Set up test certificates
- Create helper scripts

### 2. Activate Virtual Environment (when needed)

```bash
# Option 1: Direct activation
source .venv/bin/activate

# Option 2: Use helper script
source scripts/activate_venv.sh

# Deactivate when done
deactivate
```

The test certificates are already available in the `test_data/client_server/` directory:

- `ca.crt` - Certificate Authority
- `owner.client.acme.com.crt` - Client certificate
- `owner.client.acme.com.key` - Client private key

## Running PyKMIP from Rust

### Method 1: Using std::process::Command

This is the simplest approach, demonstrated in the test files:

```rust
use std::process::Command;

const PYTHON_INTERPRETER: &str = ".venv/bin/python";  // Use venv Python
const PYKMIP_CLIENT_SCRIPT: &str = "scripts/pykmip_client.py";

fn run_pykmip_query() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(PYTHON_INTERPRETER)
        .arg(PYKMIP_CLIENT_SCRIPT)
        .arg("--host").arg("127.0.0.1")
        .arg("--port").arg("5696")
        .arg("--cert").arg("test_data/client_server/owner.client.acme.com.crt")
        .arg("--key").arg("test_data/client_server/owner.client.acme.com.key")
        .arg("--ca").arg("test_data/client_server/ca.crt")
        .arg("--operation").arg("query")
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("PyKMIP failed: {}", stderr).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
```

### Method 2: Using the PyKmipClient struct

For more structured interactions:

```rust
use crate::examples::pykmip_integration::PyKmipClient;

let client = PyKmipClient::new(
    "127.0.0.1".to_string(),
    5696,
    "test_data/client_server/owner.client.acme.com.crt".to_string(),
    "test_data/client_server/owner.client.acme.com.key".to_string(),
    "test_data/client_server/ca.crt".to_string(),
);

// Query server capabilities
let query_result = client.query()?;

// Create a symmetric key
let create_result = client.create_symmetric_key("AES", 256)?;

// Get the created key
let uid = create_result["uid"].as_str().unwrap();
let get_result = client.get_object(uid)?;
```

## Available Operations

The PyKMIP client script supports these operations:

### 1. Query
Discovers server capabilities and supported operations:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner.client.acme.com.crt \
    --key test_data/client_server/owner.client.acme.com.key \
    --ca test_data/client_server/ca.crt \
    --operation query
```

### 2. Create
Creates a new symmetric key:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner.client.acme.com.crt \
    --key test_data/client_server/owner.client.acme.com.key \
    --ca test_data/client_server/ca.crt \
    --operation create
```

### 3. Get
Retrieves attributes for an object:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner.client.acme.com.crt \
    --key test_data/client_server/owner.client.acme.com.key \
    --ca test_data/client_server/ca.crt \
    --operation get
```

### 4. Destroy
Creates and then destroys a key:

```bash
# Activate virtual environment first
source .venv/bin/activate

python scripts/pykmip_client.py \
    --host 127.0.0.1 --port 5696 \
    --cert test_data/client_server/owner.client.acme.com.crt \
    --key test_data/client_server/owner.client.acme.com.key \
    --ca test_data/client_server/ca.crt \
    --operation destroy
```

## Running Tests

### Unit Tests

Run the PyKMIP integration tests:

```bash
cargo test test_pykmip --package cosmian_kms_server
```

### Individual Operation Tests

```bash
# Test query operation
cargo test test_query --package cosmian_kms_server

# Test create operation  
cargo test test_pykmip_create_symmetric_key --package cosmian_kms_server

# Test get attributes
cargo test test_pykmip_get_attributes --package cosmian_kms_server

# Test destroy operation
cargo test test_pykmip_destroy --package cosmian_kms_server
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
    --cert test_data/client_server/owner.client.acme.com.crt \
    --key test_data/client_server/owner.client.acme.com.key \
    --ca test_data/client_server/ca.crt \
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
tls_p12_file = "test_data/client_server/kmserver.acme.com.p12"
tls_p12_password = "password"
clients_ca_cert_file = "test_data/client_server/ca.crt"
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
