# Cosmian KMS Client

The **KMS Client** crate provides a high-level Rust client library for communicating with the Cosmian KMS server. It offers a convenient and type-safe interface for all KMS operations.

## Overview

This crate provides a comprehensive client library that handles:

- **HTTP Communication**: Secure HTTPS communication with the KMS server
- **Authentication**: Support for various authentication mechanisms
- **Request/Response Handling**: Automatic serialization and deserialization
- **Error Management**: Comprehensive error handling and reporting
- **Configuration Management**: Flexible client configuration options

## Features

### Core Functionality

- **Key Management**: Generate, import, export, and manage cryptographic keys
- **Certificate Operations**: Handle X.509 certificates and PKI operations
- **Cryptographic Operations**: Encryption, decryption, signing, and verification
- **Batch Operations**: Efficient bulk operations for large datasets
- **Object Management**: Store and retrieve arbitrary cryptographic objects

### Authentication Support

- **API Keys**: Simple API key authentication
- **OAuth 2.0**: Integration with OAuth 2.0 providers
- **Certificate Authentication**: Client certificate-based authentication
- **Custom Headers**: Support for custom authentication headers

### Communication Features

- **HTTPS**: Secure communication with TLS/SSL
- **Connection Pooling**: Efficient connection reuse
- **Timeout Configuration**: Configurable request timeouts
- **Retry Logic**: Automatic retry for transient failures
- **Compression**: Optional response compression

## Quick Start

### Basic Usage

```rust
use cosmian_kms_client::{KmsClient, KmsClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client configuration
    let config = KmsClientConfig {
        server_url: "https://kms.example.com".to_string(),
        api_key: Some("your-api-key".to_string()),
        ..Default::default()
    };

    // Create the client
    let client = KmsClient::new(config)?;

    // Generate a symmetric key
    let key_id = client.create_symmetric_key(256, "AES").await?;

    println!("Created key: {}", key_id);

    Ok(())
}
```

### Advanced Configuration

```rust
use cosmian_kms_client::{KmsClient, KmsClientConfig};
use std::time::Duration;

let config = KmsClientConfig {
    server_url: "https://kms.example.com".to_string(),
    api_key: Some("your-api-key".to_string()),
    timeout: Duration::from_secs(30),
    verify_cert: true,
    ca_cert_path: Some("/path/to/ca.pem".to_string()),
    client_cert_path: Some("/path/to/client.pem".to_string()),
    client_key_path: Some("/path/to/client.key".to_string()),
    ..Default::default()
};

let client = KmsClient::new(config)?;
```

## Operations

### Key Management

```rust
// Generate symmetric key
let key_id = client.create_symmetric_key(256, "AES").await?;

// Generate RSA key pair
let (private_key_id, public_key_id) = client.create_rsa_key_pair(2048).await?;

// Import existing key
let imported_key_id = client.import_key(key_data, "PEM").await?;

// Export key
let key_data = client.export_key(&key_id, "PEM", None).await?;
```

### Cryptographic Operations

```rust
// Encrypt data
let encrypted = client.encrypt(&key_id, b"Hello, World!", "AES_GCM").await?;

// Decrypt data
let decrypted = client.decrypt(&key_id, &encrypted, "AES_GCM").await?;

// Sign data
let signature = client.sign(&private_key_id, b"Message", "RSA_PKCS1").await?;

// Verify signature
let is_valid = client.verify(&public_key_id, b"Message", &signature, "RSA_PKCS1").await?;
```

### Certificate Operations

```rust
// Generate certificate
let cert_id = client.create_certificate(&key_id, "CN=Test Certificate").await?;

// Import certificate
let imported_cert_id = client.import_certificate(cert_data, "PEM").await?;

// Export certificate
let cert_data = client.export_certificate(&cert_id, "PEM").await?;
```

### Object Management

```rust
// Store secret data
let secret_id = client.store_secret_data(b"My Secret", "password").await?;

// Retrieve secret data
let secret = client.get_secret_data(&secret_id).await?;

// Search for objects
let results = client.locate_objects(&attributes).await?;
```

## Configuration

### Environment Variables

The client can be configured using environment variables:

- `COSMIAN_KMS_SERVER_URL`: KMS server URL
- `COSMIAN_KMS_API_KEY`: API key for authentication
- `COSMIAN_KMS_CLIENT_CERT`: Path to client certificate
- `COSMIAN_KMS_CLIENT_KEY`: Path to client private key
- `COSMIAN_KMS_CA_CERT`: Path to CA certificate

### Configuration File

```toml
[kms]
server_url = "https://kms.example.com"
api_key = "your-api-key"
timeout = 30
verify_cert = true
ca_cert_path = "/path/to/ca.pem"
client_cert_path = "/path/to/client.pem"
client_key_path = "/path/to/client.key"
```

## Error Handling

The client provides comprehensive error handling:

```rust
use cosmian_kms_client::{KmsClient, KmsClientError};

match client.create_symmetric_key(256, "AES").await {
    Ok(key_id) => println!("Created key: {}", key_id),
    Err(KmsClientError::Authentication(msg)) => {
        eprintln!("Authentication failed: {}", msg);
    }
    Err(KmsClientError::Network(msg)) => {
        eprintln!("Network error: {}", msg);
    }
    Err(KmsClientError::Protocol(msg)) => {
        eprintln!("Protocol error: {}", msg);
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Dependencies

### Core Dependencies

- **cosmian_kms_client_utils**: Shared client utilities
- **cosmian_kmip**: KMIP protocol implementation
- **reqwest**: HTTP client library
- **tokio**: Async runtime
- **serde**: Serialization framework

### Optional Dependencies

- **rustls**: TLS implementation
- **native-tls**: Native TLS support
- **cosmian_config_utils**: Configuration utilities

## Feature Flags

- **`rustls`**: Use rustls for TLS (default)
- **`native-tls`**: Use system TLS implementation
- **`non-fips`**: Enable non-FIPS features

## Building

```bash
# Default build
cargo build

# With native TLS
cargo build --features native-tls

# With non-FIPS features
cargo build --features non-fips
```

## Testing

```bash
# Run unit tests
cargo test --lib

# Run integration tests (requires running KMS server)
cargo test --test integration_tests
```

## Examples

See the `examples/` directory for more comprehensive examples:

- **Basic Operations**: Simple key management operations
- **Batch Operations**: Bulk import/export operations
- **Certificate Management**: PKI operations
- **Custom Authentication**: Advanced authentication scenarios

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
