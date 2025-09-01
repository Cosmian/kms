# KMIP Derive Macros

The **KMIP Derive** crate provides procedural macros for automatic serialization and deserialization of KMIP (Key Management Interoperability Protocol) data structures.

## Overview

This crate contains derive macros that automatically generate the necessary code for converting Rust data structures to and from the KMIP binary format. It simplifies the implementation of KMIP protocol support by eliminating boilerplate serialization code.

## Features

- **Automatic Serialization**: Generate KMIP serialization code from struct definitions
- **Automatic Deserialization**: Generate KMIP deserialization code from struct definitions
- **Type Safety**: Ensure compile-time correctness of KMIP message structures
- **Performance**: Generate efficient serialization code without runtime overhead

## Supported Derive Macros

### `#[derive(Serialize)]`

Automatically implements KMIP serialization for structs and enums:

```rust
use kmip_derive::Serialize;

#[derive(Serialize)]
struct MyKmipRequest {
    operation: Operation,
    unique_identifier: Option<String>,
    attributes: Vec<Attribute>,
}
```

### `#[derive(Deserialize)]`

Automatically implements KMIP deserialization for structs and enums:

```rust
use kmip_derive::Deserialize;

#[derive(Deserialize)]
struct MyKmipResponse {
    result_status: ResultStatus,
    result_reason: Option<ResultReason>,
    result_message: Option<String>,
}
```

## KMIP Protocol Support

The macros support all KMIP data types and structures:

- **Basic Types**: Integers, strings, booleans, byte arrays
- **Complex Types**: Structures, enumerations, intervals
- **Optional Fields**: Proper handling of optional KMIP attributes
- **Arrays**: Support for repeated elements
- **Nested Structures**: Complex hierarchical data structures

## Code Generation

The macros generate highly optimized code that:

- Follows KMIP binary encoding specifications
- Handles endianness correctly
- Validates data types and constraints
- Provides detailed error messages for invalid data
- Maintains compatibility across KMIP versions

## Usage

Add the derive macros to your KMIP data structures:

```rust
use kmip_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRequest {
    pub object_type: ObjectType,
    pub template_attribute: TemplateAttribute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateResponse {
    pub object_type: ObjectType,
    pub unique_identifier: String,
}
```

## Error Handling

The generated code provides comprehensive error handling:

- **Type Validation**: Ensures data matches expected KMIP types
- **Size Validation**: Validates field sizes and array lengths
- **Format Validation**: Checks KMIP message format compliance
- **Detailed Errors**: Provides specific error messages for debugging

## Dependencies

- **quote**: Token stream generation for procedural macros
- **syn**: Rust code parsing and manipulation

## Integration

This crate is used by the `cosmian_kmip` crate to automatically generate serialization code for all KMIP message types. It's an internal implementation detail that enables the seamless handling of KMIP protocol messages.

## Performance

The generated code is highly optimized:

- Zero-copy deserialization where possible
- Minimal memory allocations
- Efficient binary format handling
- Compile-time optimization

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
