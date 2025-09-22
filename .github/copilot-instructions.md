# Cosmian KMS

Cosmian KMS is a high-performance, open-source FIPS 140-3 compliant Key Management System written in Rust. The repository contains the KMS server (`cosmian_kms_server`) and supporting libraries for cryptographic operations, database management, and various integrations.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

- **Bootstrap and build the repository:**

    - First, initialize git submodules: `git submodule update --recursive --init`
    - System requires Rust nightly toolchain (nightly-2025-09-15) with rustfmt and clippy components
    - OpenSSL 3.2.0 is REQUIRED (not 3.0.13+) for proper FIPS compliance and static linking
    - OpenSSL must be installed to `/usr/local/openssl` using `.github/reusable_scripts/get_openssl_binaries.sh`
    - Build process follows CI workflow: `bash .github/scripts/cargo_build.sh`
    - Environment variables required: `OPENSSL_DIR=/usr/local/openssl`, `TARGET=x86_64-unknown-linux-gnu`, `DEBUG_OR_RELEASE=debug|release`
    - For non-FIPS builds: `FEATURES=non-fips`
    - The CLI binary `cosmian` IS built in this repository and included in build artifacts

- **UI and Packaging:**

    - UI is built on Ubuntu distributions using `bash .github/scripts/build_ui.sh`
    - UI files are located in `crate/server/ui` directory
    - Release builds create Debian packages via `cargo deb --target $TARGET -p cosmian_kms_server`
    - RPM packages created via `cargo generate-rpm --target $TARGET -p crate/server`
    - Packages support both FIPS and non-FIPS variants

- **Testing and validation:**

    - Multi-database testing: sqlite, postgresql, mysql, redis-findex
    - Database environment variables: `KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms`, `KMS_MYSQL_URL=mysql://kms:kms@localhost:3306/kms`, `KMS_SQLITE_PATH=data/shared`
    - MySQL tests are currently disabled (skipped in CI)
    - Redis-findex tests skipped in FIPS mode (not supported)
    - Debug builds only test sqlite; release builds test all enabled databases
    - macOS runners only support sqlite tests (no docker containers)
    - HSM testing on Ubuntu with Utimaco: `HSM_USER_PASSWORD="12345678" cargo test -p utimaco_pkcs11_loader --target $TARGET --features utimaco`
    - Logging control: `RUST_LOG="cosmian_kms_cli=error,cosmian_kms_server=error,cosmian_kmip=error,test_kms_server=error"`
    - Test execution: `cargo test --workspace --lib --target $TARGET $RELEASE $FEATURES -- --nocapture $SKIP_SERVICES_TESTS`

- **Build artifacts and binaries:**

    - Primary binaries: `cosmian`, `cosmian_kms`, `cosmian_findex_server`
    - Binary locations: `target/$TARGET/$DEBUG_OR_RELEASE/` (e.g., `target/x86_64-unknown-linux-gnu/debug/`)
    - Release builds include benchmarks: `cargo bench --target $TARGET $FEATURES --no-run`
    - Static linking verified (no dynamic OpenSSL dependencies): `ldd cosmian_kms | grep ssl` should fail
    - Version verification: `cosmian_kms --info` must show OpenSSL 3.2.0
    - Binary tests: `cargo test --workspace --bins --target $TARGET $RELEASE $FEATURES`

- **Run the KMS server:**

    - ALWAYS build first using the build script above
    - Debug mode: `./target/x86_64-unknown-linux-gnu/debug/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data`
    - Release mode: `./target/x86_64-unknown-linux-gnu/release/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data`
    - Server listens on <http://0.0.0.0:9998> by default
    - Supported databases: sqlite, postgresql, mysql, redis-findex (redis-findex not available in FIPS mode)

- **Docker usage:**
    - Development with services: `docker compose up -d` (starts postgresql, mysql, redis)
    - Production: `docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest`
    - Pre-built images include UI at <http://localhost:9998/ui>
    - Local Docker builds use the same OpenSSL setup as CI

## Validation

- **CRITICAL**: Always manually test server functionality after making changes by starting the server and verifying it responds to HTTP requests
- Test server startup: Start server with `--database-type sqlite --sqlite-path /tmp/test-db`
- Test API responses: `curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1` should return KMIP validation error (confirms server is working)
- Test server version: `./target/x86_64-unknown-linux-gnu/release/cosmian_kms --version` should show version 5.9.0
- OpenSSL validation: `./target/x86_64-unknown-linux-gnu/release/cosmian_kms --info` should show OpenSSL 3.2.0
- Static linking check: `ldd ./target/x86_64-unknown-linux-gnu/release/cosmian_kms | grep ssl` should return empty (no dynamic OpenSSL)
- Always run `cargo fmt --check` before committing (takes 3 seconds)
- Clippy requires installation: `rustup component add --toolchain nightly-2025-09-15-x86_64-unknown-linux-gnu clippy`

## Common tasks

The following are outputs from frequently run commands. Reference them instead of viewing, searching, or running bash commands to save time.

### Repo root structure

```text
.cargo/                  # Cargo configuration
.github/                 # CI/CD workflows and scripts
  scripts/               # Build scripts (cargo_build.sh, build_ui.sh)
  reusable_scripts/      # OpenSSL setup scripts
crate/                   # Rust workspace crates
  server/                # KMS server binary crate
    ui/                  # Web UI files (built by build_ui.sh)
  cli/                   # CLI binary crate (cosmian)
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
Dockerfile              # Container build
README.md               # Project documentation
Cargo.toml              # Workspace configuration
rust-toolchain.toml     # Rust toolchain: nightly-2025-09-15
```

### Key build commands and timing

```bash
# Full CI build process (includes UI, packaging, multi-database tests)
git submodule update --recursive --init
export OPENSSL_DIR=/usr/local/openssl
export TARGET=x86_64-unknown-linux-gnu
export DEBUG_OR_RELEASE=debug  # or release
export FEATURES=non-fips       # optional, for non-FIPS builds

# OpenSSL setup (required first)
sudo mkdir -p /usr/local/openssl/ssl /usr/local/openssl/lib64/ossl-modules
sudo chown -R $USER /usr/local/openssl
bash .github/reusable_scripts/get_openssl_binaries.sh
bash .github/scripts/cargo_build.sh


# UI build (Ubuntu only)
bash .github/scripts/build_ui.sh

# Individual builds (after OpenSSL setup)
rustup target add x86_64-unknown-linux-gnu
cargo build --target x86_64-unknown-linux-gnu --features non-fips
cargo build --target x86_64-unknown-linux-gnu --release --features non-fips

# Multi-database testing
export KMS_TEST_DB=sqlite  # or postgresql, mysql, redis-findex
cargo test --workspace --lib --target x86_64-unknown-linux-gnu --features non-fips

# HSM testing (Ubuntu only)
bash .github/reusable_scripts/test_utimaco.sh
HSM_USER_PASSWORD="12345678" cargo test -p utimaco_pkcs11_loader --target x86_64-unknown-linux-gnu --features utimaco

# Packaging (release builds only)
cargo install cargo-deb cargo-generate-rpm
cargo deb --target x86_64-unknown-linux-gnu -p cosmian_kms_server
cargo generate-rpm --target x86_64-unknown-linux-gnu -p crate/server

# Format check (3 seconds)
cargo fmt --check
```

### Server startup and validation

```bash
# Start server (debug)
./target/x86_64-unknown-linux-gnu/debug/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data

# Start server (release)
./target/x86_64-unknown-linux-gnu/release/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data

# Test server is responding
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1
# Expected response: "Invalid Request: missing field `tag` at line 1 column 2"

# Check version and OpenSSL
./target/x86_64-unknown-linux-gnu/release/cosmian_kms --version
# Expected: "cosmian_kms_server 5.9.0"

./target/x86_64-unknown-linux-gnu/release/cosmian_kms --info
# Expected: Output containing "OpenSSL 3.2.0"

# Verify static linking (should return empty)
ldd ./target/x86_64-unknown-linux-gnu/release/cosmian_kms | grep ssl
```

### Docker quick start

```bash
# Pull and run pre-built image (includes UI)
docker pull ghcr.io/cosmian/kms:latest
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest

# Development with services
docker compose up -d

# Access UI
curl http://localhost:9998/ui
# Expected: HTML content with KMS web interface
```

## Important notes

- **OpenSSL Version**: OpenSSL 3.2.0 is mandatory, not 3.0.13+. The build verifies this specific version.
- **Static Linking**: All binaries must be statically linked with OpenSSL. CI verifies no dynamic OpenSSL dependencies.
- **Build Artifacts**: Three primary binaries are built: `cosmian`, `cosmian_kms`, `cosmian_findex_server`
- **Target Architecture**: CI uses `x86_64-unknown-linux-gnu` target explicitly, not default target
- **Database Testing**: Only sqlite works in debug mode and on macOS. Full database testing requires release builds on Linux.
- **FIPS vs non-FIPS**: Redis-findex database support is not available in FIPS mode
- **UI Building**: UI is only built on Ubuntu distributions and requires separate build script
- **Packaging**: Debian and RPM packages are created as part of release builds with proper FIPS/non-FIPS variants
- **HSM Support**: Utimaco HSM testing is included but only runs on Ubuntu with specific setup
- **MySQL**: MySQL database tests are currently disabled in CI
- **Workspace**: Build from workspace root using cargo_build.sh script, not individual crate directories
