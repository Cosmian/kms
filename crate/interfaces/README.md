# Cosmian KMS Interfaces

This crate provides the core interfaces and APIs for plugins and extensions to the Cosmian Key Management System (KMS). It defines the contracts that external systems must implement to integrate with the KMS server.

## Overview

The `cosmian_kms_interfaces` crate is designed to enable extensibility of the Cosmian KMS through well-defined plugin interfaces. It provides abstractions for:

- **Hardware Security Modules (HSMs)** - Integration with PKCS#11 compatible HSMs
- **Object Stores** - Custom storage backends for cryptographic objects
- **Encryption Oracles** - External encryption/decryption services
- **Permission Systems** - Access control and authorization mechanisms

## Key Components

### HSM Interface

The HSM interface (`hsm` module) provides:

- **HSM Trait**: Core interface for Hardware Security Module integration
- **Key Management**: Support for AES symmetric keys and RSA key pairs
- **Encryption Oracle**: HSM-backed encryption and decryption operations
- **Object Storage**: Secure storage of cryptographic objects within HSMs

Supported algorithms:

- **Symmetric**: AES keys
- **Asymmetric**: RSA key pairs

### Object Store Interface

The stores interface (`stores` module) provides:

- **ObjectsStore Trait**: Persistent storage of KMIP objects
- **PermissionsStore Trait**: Access control and permission management
- **Atomic Operations**: Transactional database operations
- **Metadata Management**: Rich metadata support for stored objects

### Encryption Oracle Interface

The encryption oracle interface provides:

- **EncryptionOracle Trait**: External encryption/decryption services
- **Algorithm Support**: Pluggable cryptographic algorithm implementations
- **Key Metadata**: Rich key material metadata and capabilities

## Usage

This crate is primarily intended for:

1. **HSM Vendors**: Implementing PKCS#11 adapters for specific HSM hardware
2. **Storage Backends**: Creating custom object storage implementations
3. **Crypto Providers**: Adding support for specialized cryptographic algorithms
4. **Access Control**: Implementing custom authorization mechanisms

## Plugin Development

> **Note**: The plugin API is currently in early development and subject to change. No stable public API is currently guaranteed.

To implement a plugin:

1. Add a dependency on `cosmian_kms_interfaces`
2. Implement the relevant traits (`HSM`, `ObjectsStore`, `EncryptionOracle`, etc.)
3. Handle the specific error types defined in `InterfaceError`
4. Follow the async patterns using `async-trait`

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                  Cosmian KMS Server                         │
├─────────────────────────────────────────────────────────────┤
│                 cosmian_kms_interfaces                      │
├─────────────────────────────────────────────────────────────┤
│  HSM Interface  │  Storage Interface  │  Encryption Oracle  │
├─────────────────┼─────────────────────┼─────────────────────┤
│   PKCS#11 HSMs  │   Database Backends │   Crypto Providers  │
│   - Utimaco     │   - SQLite          │   - Custom Algos    │
│   - SoftHSM     │   - PostgreSQL      │   - External APIs   │
│   - Proteccio   │   - MySQL           │                     │
└─────────────────┴─────────────────────┴─────────────────────┘
```

## Error Handling

All interface methods return `InterfaceResult<T>` which wraps the standard `Result<T, InterfaceError>`. The `InterfaceError` enum provides structured error information for:

- HSM operation failures
- Storage backend errors
- Cryptographic operation errors
- Permission and access control violations

## Features

- **Async Support**: All interfaces use `async-trait` for non-blocking operations
- **KMIP Integration**: Full compatibility with KMIP 2.1 object model
- **Security**: Built-in support for secure key material handling with zeroization
- **Extensibility**: Clean separation of concerns for easy plugin development

## Examples

See the existing implementations in the KMS codebase:

- **HSM Integration**: `crate/hsm/base_hsm/`, `crate/hsm/utimaco/`, etc.
- **Database Stores**: `crate/server_database/`
- **Encryption Oracles**: HSM-based implementations

## Future Development

Planned features include:

- Stabilized plugin API with versioning
- Enhanced algorithm support
- Improved error diagnostics
- Plugin discovery and loading mechanisms
- Configuration management for plugins

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
