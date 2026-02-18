# Cosmian KMS — Build and Test Guide

Cosmian KMS is a high-performance, open-source FIPS 140-3 compliant Key Management System written in Rust.

## Quick start

```bash
# Initialize git submodules (required after clone)
git submodule update --init --recursive

# Build the project (FIPS mode is default)
cargo build --release

# Run tests (FIPS mode is default)
cargo test

# For non-FIPS mode (includes additional algorithms)
cargo build --release --features non-fips
cargo test --features non-fips
```

## Testing

```bash
# Run all tests (FIPS mode is default)
cargo test-fips
cargo test-non-fips

# Run Clippy on all code paths
cargo clippy-all

# Run tests for a specific package
cargo test -p cosmian_kms_server
cargo test -p cosmian_kms_cli
```

Environment variables for DB tests:

- `KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms`
- `KMS_MYSQL_URL=mysql://kms:kms@localhost:3306/kms`
- `KMS_SQLITE_PATH=data/shared`

Notes:

- MySQL tests are currently disabled in CI
- Redis-findex tests are skipped in FIPS mode
- FIPS mode is the default; use `--features non-fips` for non-approved algorithms
- Start database backends with `docker compose up -d` before running DB tests

## Running the server

After building, you can run the server manually:

```bash
cargo run --release --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data
```

Or run the compiled binary directly:

```bash
./target/release/cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data
```

Basic API probe:

```bash
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1
```

Expected response is a KMIP validation error, confirming the server is alive.

## Repository layout (high level)

```text
.github/                # CI workflows and scripts
crate/                  # Rust workspace crates (server, cli, crypto, …)
pkg/                    # Packaging metadata (deb/rpm service files, configs)
documentation/          # Documentation and guides
resources/              # Configuration files and resources
test_data/              # Test fixtures and data
ui/                     # Web UI source
```

## Tips

- Format/lints: run `cargo fmt --check` and `cargo clippy` to check code style
- Use `cargo build --release` for optimized builds
- Run `cargo test` frequently to ensure changes don't break functionality

## Docker

```bash
docker pull ghcr.io/cosmian/kms:latest
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
```

Images include the UI at `http://localhost:9998/ui`.
