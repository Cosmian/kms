# Cosmian KMS

Cosmian KMS is a high-performance, open-source FIPS 140-3 compliant Key Management System written in Rust. The repository contains a KMS server (`cosmian_kms`) and supporting libraries for cryptographic operations, database management, and various integrations.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

- **Bootstrap and build the repository:**
    - System requires Rust nightly toolchain (nightly-2025-03-31)
    - OpenSSL 3.0.13+ is required (system OpenSSL 3.0.13 works, OpenSSL 3.2.0 preferred)
    - Build server: `cd crate/server && cargo build --features non-fips` -- takes 2-3 minutes. NEVER CANCEL.
    - Build server (release): `cd crate/server && cargo build --release --features non-fips` -- takes 8-12 minutes. NEVER CANCEL. Set timeout to 20+ minutes.
    - The CLI binary `cosmian` is NOT in this repository - it's in a separate repository (<https://github.com/Cosmian/cli>)

- **Test the code:**
    - Basic crypto tests: `cd crate/crypto && cargo test --features non-fips` -- takes 35 seconds. Some tests may fail due to missing FIPS modules (expected).
    - Full test suite has dependency issues with missing test certificates - use crypto crate tests for validation
    - Set `KMS_TEST_DB=sqlite` environment variable for database tests
    - Set `RUST_LOG="error,cosmian_kms_server=info,cosmian_kms_cli=info"` for logging control

- **Run the KMS server:**
    - ALWAYS build first using the bootstrap steps above
    - Debug mode: `/home/runner/work/kms/kms/target/debug/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data`
    - Release mode: `/home/runner/work/kms/kms/target/release/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data`
    - Server listens on <http://0.0.0.0:9998> by default
    - Server supports multiple database backends: sqlite, postgresql, mysql, redis-findex

- **Docker usage:**
    - Quick start: `docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest`
    - Pre-built Docker images are available at ghcr.io/cosmian/kms:latest
    - Docker build from source requires missing OpenSSL setup script - use pre-built images instead
    - Docker images include web UI at <http://localhost:9998/ui>

## Validation

- **CRITICAL**: Always manually test server functionality after making changes by starting the server and verifying it responds to HTTP requests
- Test server startup: Start server with `--database-type sqlite --sqlite-path /tmp/test-db`
- Test API responses: `curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1` should return KMIP validation error (confirms server is working)
- Test server version: `./target/release/cosmian_kms --version` should show version 5.7.0
- You can build and run the server, but the CLI must be obtained from the separate Cosmian CLI repository
- Always run `cargo fmt --check` before committing (takes 3 seconds)
- Clippy requires installation: `rustup component add --toolchain nightly-2025-03-31-x86_64-unknown-linux-gnu clippy`

## Common tasks

The following are outputs from frequently run commands. Reference them instead of viewing, searching, or running bash commands to save time.

### Repo root structure

```text
.cargo/                  # Cargo configuration
.github/                 # CI/CD workflows and scripts
crate/                   # Rust workspace crates
  server/                # KMS server binary crate
  cli/                   # CLI library crate (binary is separate repo)
  crypto/                # Cryptographic operations
  kmip/                  # KMIP protocol implementation
  client_utils/          # Client utilities
  kms_client/            # KMS client library
  access/                # Access control
  interfaces/            # Database and HSM interfaces
  server_database/       # Database management
  hsm/                   # HSM integrations (proteccio, utimaco, softhsm2)
documentation/           # Project documentation
docker-compose.yml       # Development services (postgres, mysql, redis)
Dockerfile              # Container build (requires missing OpenSSL script)
README.md               # Project documentation
Cargo.toml              # Workspace configuration
rust-toolchain.toml     # Rust toolchain: nightly-2025-03-31
```

### Key build commands and timing

```bash
# Initial dependency check (6 minutes with network issues, 2 minutes normally)
cargo check

# Server debug build (2-3 minutes)
cd crate/server && cargo build --features non-fips

# Server release build (8-12 minutes) - NEVER CANCEL
cd crate/server && cargo build --release --features non-fips

# Crypto tests (35 seconds)
cd crate/crypto && cargo test --features non-fips

# Format check (3 seconds)
cargo fmt --check
```

### Server startup and validation

```bash
# Start server (debug)
./target/debug/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data

# Start server (release)
./target/release/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data

# Test server is responding
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1
# Expected response: "Invalid Request: missing field `tag` at line 1 column 2"

# Check version
./target/release/cosmian_kms --version
# Expected: "cosmian_kms_server 5.7.0"
```

### Docker quick start

```bash
# Pull and run pre-built image (includes UI)
docker pull ghcr.io/cosmian/kms:latest
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest

# Access UI
curl http://localhost:9998/ui
# Expected: HTML content with KMS web interface
```

## Important notes

- **TIMING**: Builds are much faster than expected in original documentation (8-12 min for release vs 45+ min mentioned elsewhere)
- **CLI**: The `cosmian` CLI binary is NOT built from this repository - it's in <https://github.com/Cosmian/cli>
- **OpenSSL**: System OpenSSL 3.0.13 works fine, though 3.2.0 is preferred for FIPS compliance
- **Docker**: Building from source fails due to missing `.github/reusable_scripts/get_openssl_binaries.sh` - use pre-built images
- **FIPS vs non-FIPS**: Default is FIPS mode, use `--features non-fips` for broader algorithm support
- **Database**: SQLite is simplest for development, but PostgreSQL, MySQL, and Redis are supported
- **Tests**: Some crypto tests fail due to missing FIPS modules - this is expected in development environment
- **UI**: Only available in Docker images, not in local builds without additional setup
- **Workspace**: Always build from individual crate directories (`crate/server`, `crate/cli`) not from workspace root
