---
name: 'OpenSSL Build'
description: 'Keep the OpenSSL build script, provider init, CBOM, and SBOM in sync when upgrading OpenSSL'
applyTo: 'crate/crypto/build.rs'
---

# OpenSSL upgrade sync

An OpenSSL version bump must be reflected in the build script, the provider init, and the bills of
materials.

## Checklist

- [ ] `crate/crypto/build.rs` — main OpenSSL (`OPENSSL_MAIN_VERSION`, currently 3.6.5) and/or CMVP FIPS provider (`OPENSSL_FIPS_VERSION`, currently 3.1.2) version, download URL, and SHA-256 hash updated
- [ ] `nix/common.nix` and `nix/openssl.nix` — Nix OpenSSL version/hashes kept in sync if applicable
- [ ] `crate/server/src/openssl_providers.rs` — provider init verified compatible
- [ ] `cbom/cbom.cdx.json` — Cryptographic Bill of Materials updated
- [ ] `sbom/` — Software Bill of Materials updated

> Rule 4.17 of `/kms-sync-rules`.
