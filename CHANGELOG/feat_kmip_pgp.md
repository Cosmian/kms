## Breaking Changes

### Crypto
- OpenPGP version 3 and version 5 keys are no longer supported; use version 4 or 6 transferable keys.
- Require Rust 1.88 or newer to build the OpenPGP implementation (rPGP 0.21.0).

## Features

### CLI
- Add `pgp-secret-binary` and `pgp-public-binary` formats for GnuPG-compatible OpenPGP key exports.

### Web UI
- Offer binary OpenPGP key export alongside ASCII-armored secret and public key formats.

### REST API
- Add an authenticated endpoint for converting OpenPGP keys to binary packet format, enabling server-side binary exports in the Web UI.

## Documentation

### CLI
- Document CKMS support for GnuPG/OpenPGP transferable keys in armored and binary import formats, with GnuPG-compatible armored and binary exports.

## Bug Fixes

### KMIP
- Support revoking and destroying OpenPGP keys through KMIP lifecycle operations.

### Crypto
- Preserve signed OpenPGP encryption subkey metadata when constructing recipient packets, restoring GnuPG decryption interoperability.
- Normalize RSA secret-key factors in generated OpenPGP keys for GnuPG interoperability.
- Use rPGP 0.21.0 without its default bzip2 feature, avoiding Nettle and libclang as PGP build dependencies.
- Decrypt DEFLATE-compressed OpenPGP messages; preserve v4 GnuPG compatibility and v6 recipient packet profiles.
