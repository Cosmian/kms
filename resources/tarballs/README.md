# OpenSSL Tarballs

This directory contains OpenSSL source tarballs for offline Nix builds.

## Files

`openssl-<version>.tar.gz`, one per entry of [`crate/crypto/openssl_versions.json`](../../crate/crypto/openssl_versions.json),
the single source of truth for the OpenSSL versions and SHA-256 hashes:

- `main`: the OpenSSL the KMS links against (runtime/library);
- `fips`: the newest CMVP-validated OpenSSL FIPS provider, built separately and loaded at runtime.

`crate/crypto/build.rs`, `nix/openssl.nix`, the packaging scripts (`.mise/lib/openssl.sh`) and the Windows FIPS provider
script all read that file. To bump a version, edit it (version and SHA-256), then regenerate the Nix vendor hashes if needed.

## Usage

The Nix derivation in `nix/openssl.nix` automatically uses the local tarball if present, otherwise it downloads
`https://package.cosmian.com/openssl/openssl-<version>.tar.gz`. `mise run package` downloads missing tarballs once
(`one_shot_fetch_openssl` in `.mise/scripts/package/package_common.sh`) so later steps can run offline.

**Hash Validation**: the build fails if the local tarball's SHA-256 does not match the pinned hash. This ensures integrity
and prevents builds with corrupted or modified source files.

## Verification

```bash
sha256sum openssl-<version>.tar.gz
# compare with: jq -r '.[].sha256' ../../crate/crypto/openssl_versions.json
```

## Error Handling

If the local tarball has an incorrect hash, the build fails with an error message like:

```text
error: Local OpenSSL tarball hash mismatch!
Expected: <pinned hash>
Actual:   [actual_hash]
Please verify the integrity of ./resources/tarballs/openssl-<version>.tar.gz
```

In this case, either:

1. Re-download the official tarball, or
2. Remove the local tarball to let Nix fetch it from the internet
