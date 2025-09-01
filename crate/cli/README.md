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
cargo build --package cosmian_kms_cli
```

### Release Build

```sh
cargo build --package cosmian_kms_cli --release
```

### With Features

```sh
# Enable non-FIPS features for testing
cargo build --package cosmian_kms_cli --features non-fips
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

## Documentation

- **Full Documentation**: [docs.cosmian.com](https://docs.cosmian.com/cosmian_cli/)
- **API Reference**: [docs.rs](https://docs.rs/cosmian_kms_cli/)

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
