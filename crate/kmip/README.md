# Cosmian KMIP

The **KMIP** crate provides a comprehensive implementation of the Key Management Interoperability Protocol (KMIP) standard versions 1.0 through 2.1, including the TTLV (Tag-Type-Length-Value) serialization format.

## Overview

This crate implements the complete KMIP specification, providing:

- **Protocol Support**: KMIP versions 1.0, 1.1, 1.2, 1.3, 1.4, 2.0, and 2.1
- **Serialization**: TTLV binary format and JSON representation
- **Type Safety**: Rust type system ensures protocol compliance
- **OpenSSL Integration**: Seamless conversion between KMIP and OpenSSL objects
- **Extensibility**: Support for custom attributes and operations

## Features

### KMIP Protocol Implementation

- **Complete Coverage**: All KMIP operations, attributes, and object types
- **Version Compatibility**: Support for multiple KMIP versions
- **Standards Compliance**: Strict adherence to OASIS KMIP specifications
- **Extensible Design**: Easy addition of custom operations and attributes

### Serialization Formats

- **TTLV Binary**: Efficient binary serialization format
- **JSON**: Human-readable format for debugging and logging
- **Bi-directional**: Convert between binary and JSON representations
- **Validation**: Automatic validation of message structure and constraints

### OpenSSL Integration (with `openssl` feature)

- **Key Conversion**: Convert between KMIP keys and OpenSSL keys
- **Certificate Handling**: Support for X.509 certificates
- **Cryptographic Operations**: Seamless integration with OpenSSL crypto functions
- **Format Translation**: Automatic format conversion (PEM, DER, etc.)

## KMIP Objects

### Managed Objects

- **Symmetric Keys**: AES, DES, 3DES, and other symmetric algorithms
- **Asymmetric Keys**: RSA, EC, DSA key pairs and public keys
- **Certificates**: X.509 certificates and certificate chains
- **Secret Data**: Passwords, tokens, and other secret information
- **Opaque Objects**: Binary data with custom semantics

### Attributes

- **Standard Attributes**: All KMIP-defined attributes
- **Custom Attributes**: Support for application-specific attributes
- **Validation**: Automatic attribute validation and constraint checking
- **Serialization**: Efficient attribute serialization and deserialization

## Operations

### Core Operations

- **Create**: Generate new cryptographic objects
- **Get**: Retrieve objects and their attributes
- **Destroy**: Securely delete objects
- **Locate**: Search for objects based on attributes

### Cryptographic Operations

- **Encrypt/Decrypt**: Symmetric and asymmetric encryption
- **Sign/Verify**: Digital signature operations
- **MAC**: Message Authentication Code operations
- **Hash**: Cryptographic hash operations

### Key Management

- **Import/Export**: Key import and export operations
- **Derive**: Key derivation operations
- **Wrap/Unwrap**: Key wrapping and unwrapping
- **Rekey**: Key rotation operations

## Enumerations

The crate provides two types of enumerations:

### KMIP Standard Enumerations

Enumerations that hold KMIP variant names and values from the specification:

```rust
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(
    KmipEnumSerialize,
    Deserialize,
    Copy,
    Clone,
    Debug,
    Display,
    Eq,
    PartialEq,
    EnumIter,
    strum::IntoStaticStr,
)]
pub enum CryptographicAlgorithm {
    DES = 0x0000_0001,
    THREE_DES = 0x0000_0002,
    AES = 0x0000_0003,
    RSA = 0x0000_0004,
    DSA = 0x0000_0005,
    ECDSA = 0x0000_0006,
    // ... more algorithms
}
```

Requirements for KMIP enumerations:

- Must implement `KmipEnumSerialize` trait
- Must be annotated with `#[repr(u32)]`
- Must implement `Copy` and `strum::IntoStaticStr`
- Should use `#[allow(non_camel_case_types)]` for KMIP naming

### Alternative Representation Enumerations

Enumerations that offer multiple representations of the same value:

```rust
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum LinkedObjectIdentifier {
    /// Unique Identifier of a Managed Object
    TextString(String),
    /// Unique Identifier Enumeration
    Enumeration(UniqueIdentifierEnumeration),
    /// Zero-based nth Unique Identifier in the response
    Index(i64),
}
```

These enumerations:

- Use `#[serde(untagged)]` for automatic variant selection
- Support multiple ways to represent the same logical value
- Order of variants matters for deserialization

## Usage Examples

### Creating KMIP Requests

```rust
use cosmian_kmip::kmip_2_1::{
    requests::CreateRequest,
    objects::ObjectType,
    attributes::TemplateAttribute,
};

let request = CreateRequest {
    object_type: ObjectType::SymmetricKey,
    template_attribute: TemplateAttribute::default(),
};
```

### Serialization

```rust
use cosmian_kmip::ttlv::{TTLV, TTLVType};

// Serialize to TTLV binary format
let ttlv_bytes = request.to_ttlv()?;

// Serialize to JSON
let json_string = serde_json::to_string_pretty(&request)?;
```

### OpenSSL Integration

```rust
#[cfg(feature = "openssl")]
use cosmian_kmip::openssl::convert_key;

// Convert KMIP key to OpenSSL key
let openssl_key = convert_key(&kmip_key)?;
```

## Dependencies

### Core Dependencies

- **serde**: Serialization framework
- **serde_json**: JSON serialization support
- **thiserror**: Error handling
- **uuid**: Unique identifier generation

### Optional Dependencies

- **openssl**: OpenSSL integration (with `openssl` feature)
- **num-bigint-dig**: Big integer arithmetic
- **x509-parser**: X.509 certificate parsing

### Development Dependencies

- **cosmian_logger**: Logging for tests
- **hex**: Hexadecimal encoding for tests

## Feature Flags

### XML Test Vector Parsing Strictness

The XML → TTLV helper used in tests now enforces strict KMIP enumeration and
usage mask validation by default. Unknown enumeration tokens, unknown
CryptographicUsageMask textual values, or unknown AttributeReference names
produce errors. The only tolerated deviation (for interoperability with some
public test vectors) is that a missing `type="Structure"` attribute on a
container element is still accepted and treated as a Structure.

If your custom vectors fail, ensure all textual enumeration and usage mask
tokens are valid per the KMIP specification.

- **`openssl`**: Enable OpenSSL integration and conversions
- **`non-fips`**: Enable non-FIPS cryptographic algorithms
- **`default`**: Includes commonly used features

## Building

```bash
# Basic build
cargo build

# With OpenSSL support
cargo build --features openssl

# With non-FIPS features
cargo build --features non-fips

# All features
cargo build --all-features
```

## Testing

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features openssl

# Run with logging
RUST_LOG=debug cargo test
```

## Standards Compliance

This implementation follows:

- **OASIS KMIP 1.0-2.1**: Complete protocol implementation
- **RFC Standards**: Related cryptographic standards
- **Industry Best Practices**: Secure coding and cryptographic practices

## Performance

The implementation provides:

- **Zero-Copy Deserialization**: Where possible
- **Efficient Serialization**: Optimized TTLV encoding/decoding
- **Memory Efficiency**: Minimal allocations and memory usage
- **Streaming Support**: Handle large objects efficiently

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
