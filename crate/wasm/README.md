# Cosmian KMS Client WASM

The **WASM** crate provides WebAssembly bindings for the Cosmian KMS client, enabling KMS operations directly in web browsers and other WebAssembly environments.

## Overview

This crate exposes the Cosmian KMS client functionality to JavaScript and WebAssembly environments. It provides a comprehensive interface for performing cryptographic operations, key management, and secure communication with the KMS server from web applications.

## Features

### WebAssembly Integration

- **Browser Compatible**: Runs directly in web browsers without plugins
- **Node.js Support**: Compatible with Node.js environments
- **TypeScript Bindings**: Auto-generated TypeScript definitions
- **Async Operations**: Non-blocking operations with Promise-based API

### Cryptographic Operations

- **Key Management**: Generate, import, export, and manage cryptographic keys
- **Encryption/Decryption**: Symmetric and asymmetric encryption operations
- **Digital Signatures**: Create and verify digital signatures
- **Certificate Operations**: Handle X.509 certificates and PKI operations

### Supported Formats

- **Keys**: RSA, EC, symmetric keys in various formats (PEM, DER, JSON)
- **Certificates**: X.509 certificates and certificate chains
- **Data Formats**: Base64, hexadecimal, and binary data handling

### Build Commands

At root directory:

```bash
# Build for web browsers
bash ./github/scripts/build_ui.sh
```

## Security Considerations

### Browser Environment

- **Secure Random**: Uses browser's crypto.getRandomValues()
- **Memory Safety**: WebAssembly provides memory isolation
- **HTTPS Only**: Should only be used over HTTPS connections
- **Cross-Origin**: Respects browser's same-origin policy

### Key Management

- **Client-Side Storage**: Keys should be managed securely
- **Session Management**: Proper authentication token handling
- **Data Validation**: All inputs are validated before processing

## Dependencies

### Core Dependencies

- **cosmian_kms_client_utils**: Shared client utilities
- **wasm-bindgen**: Rust-WebAssembly bindings
- **js-sys**: JavaScript API bindings
- **serde-wasm-bindgen**: Serialization for WebAssembly

### Format Support

- **base64**: Base64 encoding/decoding
- **pem**: PEM format handling
- **x509-cert**: X.509 certificate parsing

## Performance

The WASM implementation provides:

- **Fast Execution**: Near-native performance for cryptographic operations
- **Small Binary Size**: Optimized WebAssembly output
- **Efficient Memory Usage**: Minimal memory footprint
- **Async Operations**: Non-blocking operations for better UX

## Browser Compatibility

- **Modern Browsers**: Chrome 57+, Firefox 52+, Safari 11+, Edge 16+
- **WebAssembly Support**: Requires WebAssembly 1.0 support
- **Crypto API**: Requires Web Crypto API for secure random generation
- **Async/Await**: Requires Promise and async/await support

## License

This crate is part of the Cosmian KMS project and is licensed under the Business Source License 1.1 (BUSL-1.1).
