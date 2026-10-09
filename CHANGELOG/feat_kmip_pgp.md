## Breaking Changes

### Crypto
- OpenPGP version 3 and version 5 keys are no longer supported; use version 4 or 6 transferable keys.
- Require Rust 1.88 or newer to build the OpenPGP implementation (rPGP 0.21.0).

## Features

### CLI
- Add `pgp-secret-binary` and `pgp-public-binary` formats for GnuPG-compatible OpenPGP key exports.

### PKCS#11
- Discover RSA private keys and certificates tagged `gnupg-card` (override with `COSMIAN_PKCS11_GNUPG_KEY_TAG`) so `gnupg-pkcs11-scd` can use them as a GnuPG smartcard; `mise run test:gnupg` now also runs the smartcard tests backed by a SoftHSM2 KEK.

### Web UI
- Offer binary OpenPGP key export alongside ASCII-armored secret and public key formats; the armored-to-binary conversion runs in the browser (WASM), with no extra server round-trip.

## Documentation

### CLI
- Document CKMS support for GnuPG/OpenPGP transferable keys in armored and binary import formats, with GnuPG-compatible armored and binary exports.

### PKCS#11
- Document using `libcosmian_pkcs11` as the backend of `gnupg-pkcs11-scd` to expose KMS-managed RSA keys as a GnuPG smartcard.

## Bug Fixes

### KMIP
- Support revoking and destroying OpenPGP keys through KMIP lifecycle operations.

### PKCS#11
- Sign `CKM_RSA_PKCS` input that is a DER `DigestInfo` (SHA-1/256/384/512) as a pre-computed digest instead of hashing it a second time, producing standard RSASSA-PKCS1-v1_5 signatures for callers such as `gnupg-pkcs11-scd` and OpenSSH.

### Crypto
- Preserve signed OpenPGP encryption subkey metadata when constructing recipient packets, restoring GnuPG decryption interoperability.
- Normalize RSA secret-key factors in generated OpenPGP keys for GnuPG interoperability.
- Use rPGP 0.21.0 without its default bzip2 feature, avoiding Nettle and libclang as PGP build dependencies.
- Decrypt DEFLATE-compressed OpenPGP messages; preserve v4 GnuPG compatibility and v6 recipient packet profiles.
