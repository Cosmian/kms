# Cosmian KMS Client Utilities

The **Client Utilities** crate provides shared utilities and helper functions used by both the WebAssembly (WASM) client and the Rust KMS client library.

## Overview

This crate contains common functionality that is shared across different client implementations of the Cosmian KMS. It provides utilities for request building, response parsing, data formatting, and other client-side operations.

## Features

- **Request Building**: Helper functions to construct KMIP requests
- **Response Parsing**: Utilities to parse and validate KMIP responses
- **Data Conversion**: Format conversion utilities for keys, certificates, and other objects
- **Configuration Management**: Client configuration handling
- **Error Handling**: Standardized error types for client operations
- **Cross-Platform Support**: Compatible with both native Rust and WebAssembly targets

## Key Components

### Request Utilities

- **KMIP Request Builders**: Construct properly formatted KMIP requests
- **Parameter Validation**: Validate request parameters before sending
- **Batch Operations**: Support for batch request construction

### Response Utilities

- **Response Parsers**: Parse KMIP responses into usable data structures
- **Error Extraction**: Extract and format error information from responses
- **Data Extraction**: Extract cryptographic objects from responses

### Data Format Utilities

- **PEM/DER Conversion**: Convert between different key and certificate formats
- **Base64 Encoding/Decoding**: Handle base64 data encoding
- **JSON Serialization**: Convert objects to/from JSON format

### Configuration

- **Client Configuration**: Manage client connection settings
- **Authentication Tokens**: Handle authentication token management
- **Server Discovery**: Utilities for server endpoint discovery

## Supported Formats

- **Keys**: RSA, EC, symmetric keys in various formats (PEM, DER, JSON)
- **Certificates**: X.509 certificates and certificate chains
- **KMIP Objects**: Native KMIP object serialization/deserialization

## Usage

This crate is designed to be used by:

- The `kms_client` crate for native Rust applications
- The `wasm` crate for browser-based applications
- Custom client implementations

## Dependencies

- `cosmian_kmip` - KMIP protocol implementation
- `cosmian_kms_access` - Access control types
- `cosmian_config_utils` - Configuration utilities
- `base64` - Base64 encoding/decoding
- `pem` - PEM format handling
- `serde` - Serialization framework

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
