# Nix Build System for Cosmian KMS

This directory contains the Nix-based build system for reproducible builds of Cosmian KMS.

## Quick Start

### Building

```bash
# Build in debug mode (FIPS variant)
bash .github/scripts/nix.sh build

# Build in release mode (FIPS variant)
DEBUG_OR_RELEASE=release bash .github/scripts/nix.sh build

# Build non-FIPS variant
FEATURES=non-fips bash .github/scripts/nix.sh build
```

### Running

#### Non-FIPS Builds

Non-FIPS builds work out of the box without any additional setup:

```bash
# Build non-FIPS
FEATURES=non-fips bash .github/scripts/nix.sh build

# Run directly (no additional setup needed)
./target/debug/cosmian_kms --info
```

#### FIPS Builds

FIPS builds require OpenSSL runtime files to be installed:

```bash
# 1. Build FIPS variant
bash .github/scripts/nix.sh build

# 2. Install OpenSSL config files to /usr/local/lib/openssl (requires sudo, one-time setup)
nix-shell --keep NIX_OPENSSL_OUT shell.nix --run "bash nix/scripts/setup_openssl_runtime.sh"

# 3. Run the KMS server with OPENSSL_CONF set
OPENSSL_CONF=/usr/local/lib/openssl/openssl.cnf ./target/debug/cosmian_kms --info
```

## Important Notes

### OPENSSLDIR Configuration

The binary is compiled with `OPENSSLDIR=/usr/local/lib/openssl` (not a `/nix/store` path). This means:

1. The `--info` output shows: `OPENSSLDIR: "/usr/local/lib/openssl"`
2. At runtime, OpenSSL will look for config files in `/usr/local/lib/openssl`
3. You must run `setup_openssl_runtime.sh` to install the required files
4. You must set `OPENSSL_CONF=/usr/local/lib/openssl/openssl.cnf` when running the binary

### Why OPENSSL_CONF is Required

Even though the binary is compiled with `OPENSSLDIR=/usr/local/lib/openssl`, the statically-linked OpenSSL library has some internal paths that were set during compilation in the nix environment. Setting `OPENSSL_CONF` explicitly ensures the runtime uses the correct configuration files.

### Files Installed by setup_openssl_runtime.sh

The setup script installs these files to `/usr/local/lib/openssl/`:

- `openssl.cnf` - Main OpenSSL configuration
- `fipsmodule.cnf` - FIPS provider configuration with integrity MAC
- `ossl-modules/fips.so` - FIPS provider module
- `ossl-modules/legacy.so` - Legacy algorithms provider module

## Testing

```bash
# Run sqlite tests
bash .github/scripts/nix.sh test sqlite

# Run other tests (requires appropriate services running)
bash .github/scripts/nix.sh test mysql
bash .github/scripts/nix.sh test psql
bash .github/scripts/nix.sh test redis
```

## Packaging

All packaging scripts now reuse the common build logic from `build.sh` and `common.sh`:

```bash
# Build Debian package (FIPS variant)
bash .github/scripts/nix.sh package deb

# Build Debian package (non-FIPS variant)
FEATURES=non-fips bash .github/scripts/nix.sh package deb

# Build RPM package (FIPS variant)
bash .github/scripts/nix.sh package rpm

# Build RPM package (non-FIPS variant)
FEATURES=non-fips bash .github/scripts/nix.sh package rpm

# Build DMG package on macOS (FIPS variant)
bash .github/scripts/nix.sh package dmg

# Build DMG package on macOS (non-FIPS variant)
FEATURES=non-fips bash .github/scripts/nix.sh package dmg
```

## Files

- `shell.nix` - Main Nix shell environment definition
- `openssl-3_1_2-fips.nix` - OpenSSL 3.1.2 FIPS build derivation
- `scripts/build.sh` - Build script (reused by all packaging scripts)
- `scripts/common.sh` - Shared functions for build and packaging
- `scripts/setup_openssl_runtime.sh` - Runtime setup script for FIPS builds
- `scripts/test_*.sh` - Test scripts for different databases
- `scripts/package_*.sh` - Packaging scripts (DEB, RPM, DMG)
