# Nix: OpenSSL 3.1.2 (FIPS) for KMS

This folder provides:

- `openssl-3_1_2-fips.nix`: static OpenSSL 3.1.2 with FIPS provider
- `shell-hook.sh`: minimal env for reproducible builds
- `build.sh`: builds and validates KMS inside nix-shell
- `test.sh`: runs tests inside nix-shell with multi-database support
- Package build scripts for different package types

## Building

Use the unified `nix.sh` wrapper from the repository root:

```bash
# Build the KMS server
bash .github/scripts/nix.sh build

# Build with specific options
DEBUG_OR_RELEASE=release FEATURES=non-fips bash .github/scripts/nix.sh build
```

## Testing

The testing system has been split into separate scripts for each test type:

```bash
# Run SQLite tests (always available, default)
bash .github/scripts/nix.sh test sqlite

# Run MySQL tests (requires MySQL server running)
bash .github/scripts/nix.sh test mysql

# Run PostgreSQL tests (requires PostgreSQL server running)
bash .github/scripts/nix.sh test psql

# Run Redis-findex tests (requires Redis server, non-FIPS only)
FEATURES=non-fips bash .github/scripts/nix.sh test redis

# Run Google CSE tests (requires credentials)
bash .github/scripts/nix.sh test google_cse

# Run HSM tests (Linux only, requires Utimaco and SoftHSM2)
bash .github/scripts/nix.sh test hsm

# Run tests with specific configuration
DEBUG_OR_RELEASE=release bash .github/scripts/nix.sh test sqlite
```

## Packaging

The packaging system has been split into separate scripts for each package type. The FIPS vs non-FIPS variant is determined by the `FEATURES` environment variable:

- If `FEATURES` is set (e.g., `FEATURES=non-fips`): builds non-FIPS variant
- If `FEATURES` is empty or unset: builds FIPS variant

### Debian Packages

```bash
# Build FIPS DEB package
bash .github/scripts/nix.sh package DEB

# Build non-FIPS DEB package
FEATURES=non-fips bash .github/scripts/nix.sh package DEB
```

### RPM Package

```bash
# Build FIPS RPM package (Red Hat, Fedora, CentOS)
bash .github/scripts/nix.sh package RPM

# Build non-FIPS RPM package
FEATURES=non-fips bash .github/scripts/nix.sh package RPM
```

### macOS DMG Package

```bash
# Build FIPS DMG package (macOS only)
bash .github/scripts/nix.sh package DMG

# Build non-FIPS DMG package
FEATURES=non-fips bash .github/scripts/nix.sh package DMG
```

## Package Scripts

Individual package scripts are located in this directory:

- `package_deb.sh` - Debian package (FIPS or non-FIPS based on FEATURES)
- `package_rpm.sh` - RPM package (FIPS or non-FIPS based on FEATURES)
- `package_dmg.sh` - macOS DMG package (FIPS or non-FIPS based on FEATURES)

These scripts are meant to be called through `nix.sh` which sets up the proper nix-shell environment with OpenSSL 3.1.2.

## Test Scripts

Individual test scripts are located in this directory:

- `test_sqlite.sh` - SQLite tests (always available)
- `test_mysql.sh` - MySQL tests (requires MySQL server)
- `test_psql.sh` - PostgreSQL tests (requires PostgreSQL server)
- `test_redis.sh` - Redis-findex tests (requires Redis, non-FIPS only)
- `test_google_cse.sh` - Google CSE tests (requires credentials)
- `test_hsm.sh` - HSM tests (Linux only, requires Utimaco and SoftHSM2)

These scripts are meant to be called through `nix.sh` which sets up the proper nix-shell environment.
