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
