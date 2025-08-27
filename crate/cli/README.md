# Cosmian KMS CLI

This command line interface (CLI) crate is a component primarily used for testing the KMS server and use in [CLI repository](https://github.com/Cosmian/cli).

## Important Note

⚠️ **The main Cosmian CLI is now maintained in a separate repository**: <https://github.com/Cosmian/cli>

For production use, please install the CLI from:

- [Cosmian packages](https://package.cosmian.com/cli/)
- Cargo: `cargo install cosmian_cli`
- [GitHub releases](https://github.com/Cosmian/cli/releases)

## Current Status

This crate in the KMS repository serves the following purposes:

- **Testing Infrastructure**: Provides CLI functionality for KMS integration tests
- **Development Support**: Enables testing KMS features during development

## Features

### KMS Operations

- **Key Management**: Generate, import, export, and manage cryptographic keys
- **Encryption/Decryption**: Symmetric and asymmetric encryption operations
- **Digital Signatures**: Create and verify digital signatures
- **Certificate Operations**: Handle X.509 certificates and PKI operations
- **Access Control**: Manage user permissions and access rights

### Testing Capabilities

- **Integration Tests**: Comprehensive test coverage for KMS operations
- **Performance Testing**: Benchmark KMS operations
- **Error Handling**: Test error conditions and edge cases
- **Multi-Database Testing**: Test with different database backends

## Build

### Development Build

```sh
cargo build --bin cosmian
```

### Release Build

```sh
cargo build --bin cosmian --release
```

### With Features

```sh
# Enable non-FIPS features for testing
cargo build --bin cosmian --features non-fips
```

## Usage

### Basic Commands

```sh
# Display help
./target/debug/cosmian --help

# Server version
./target/debug/cosmian kms server-version

# Generate a symmetric key
./target/debug/cosmian kms sym keys create --algorithm aes --key-length 256
```

### Testing Environment

```sh
# Start required services
docker compose up -d

# Build the CLI
cargo build --bin cosmian

# Run integration tests
cargo test -p cosmian_kms_cli
```

## Configuration

The CLI can be configured using:

- **Configuration File**: `~/.cosmian/cosmian.toml`
- **Environment Variables**: Various `COSMIAN_*` variables
- **Command Line Arguments**: Override settings per command

### Example Configuration

```toml
[kms]
server_url = "http://localhost:9998"
access_token = "your-access-token"
```

## Testing

### Unit Tests

```sh
cargo test -p cosmian_kms_cli --lib
```

### Integration Tests

```sh
# Start test environment
docker compose up -d

# Run all tests
cargo test -p cosmian_kms_cli

# Run specific test
cargo test -p cosmian_kms_cli test_symmetric_key_creation
```

### Test Databases

Set the `KMS_TEST_DB` environment variable:

```sh
# Test with SQLite
KMS_TEST_DB=sqlite cargo test -p cosmian_kms_cli

# Test with PostgreSQL
KMS_TEST_DB=postgresql cargo test -p cosmian_kms_cli

# Test with MySQL
KMS_TEST_DB=mysql cargo test -p cosmian_kms_cli

# Test with Redis + Findex
KMS_TEST_DB=redis-findex cargo test -p cosmian_kms_cli
```

## Dependencies

### Core Dependencies

- **cosmian_kms_client**: KMS client library
- **cosmian_kmip**: KMIP protocol implementation
- **clap**: Command-line argument parsing
- **tokio**: Async runtime

### Testing Dependencies

- **test_kms_server**: Programmatic KMS server instantiation
- **tempfile**: Temporary file handling for tests
- **assert_cmd**: Command-line testing utilities

## Migration Guide

If you're using this legacy CLI, consider migrating to the new CLI:

1. **Install the new CLI**: `cargo install cosmian_cli`
2. **Update scripts**: Replace `cosmian` with the new binary path
3. **Configuration**: Migrate configuration files if needed
4. **Test thoroughly**: Ensure all functionality works as expected

## Documentation

- **Full Documentation**: [docs.cosmian.com](https://docs.cosmian.com/cosmian_cli/)
- **API Reference**: [docs.rs](https://docs.rs/cosmian_kms_cli/)
- **Examples**: See the `/examples` directory

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
