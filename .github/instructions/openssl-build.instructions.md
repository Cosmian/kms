---
name: 'OpenSSL Build'
description: 'Keep the OpenSSL build script, provider init, CBOM, and SBOM in sync when upgrading OpenSSL'
applyTo: 'crate/crypto/build.rs'
---

# OpenSSL upgrade sync

An OpenSSL version bump must be reflected in the build script, the provider init, and the bills of
materials.

## Checklist

- [ ] `crate/crypto/build.rs` — version, download URL, SHA-256 hash updated
- [ ] `crate/server/src/openssl_providers.rs` — provider init verified compatible
- [ ] `cbom/cbom.cdx.json` — Cryptographic Bill of Materials updated
- [ ] `sbom/` — Software Bill of Materials updated

> Rule 4.17 of `/kms-sync-rules`.
