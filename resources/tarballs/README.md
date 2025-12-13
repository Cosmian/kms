# OpenSSL Tarballs

This directory contains OpenSSL source tarballs for offline Nix builds.

## Files

- `openssl-3.1.2.tar.gz`: OpenSSL 3.1.2 source tarball (SHA256: a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539)

## Usage

The Nix derivation in `nix/openssl-3_1_2.nix` will automatically use the local tarball if present, otherwise it will fall back to downloading from the internet.

**Hash Validation**: The build will fail if the local tarball's SHA256 hash does not match the expected official hash. This ensures integrity and prevents builds with corrupted or modified source files.

This enables offline builds when network access is limited or for reproducible builds that don't depend on external downloads.

## Verification

To verify the integrity of the tarball:

```bash
sha256sum openssl-3.1.2.tar.gz
```

Expected hash: `a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539`

## Error Handling

If the local tarball has an incorrect hash, the build will fail with an error message like:

```text
error: Local OpenSSL tarball hash mismatch!
Expected: a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539
Actual:   [actual_hash]
Please verify the integrity of ./resources/tarballs/openssl-3.1.2.tar.gz
```

In this case, either:

1. Re-download the official tarball, or
2. Remove the local tarball to let Nix fetch it from the internet
