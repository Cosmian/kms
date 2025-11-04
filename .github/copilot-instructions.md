# Cosmian KMS — Nix-first build, test, and packaging

Cosmian KMS is a high-performance, open-source FIPS 140-3 compliant Key Management System written in Rust.

This repository is maintained to be reproducible, deterministic, and offline-friendly. All build, test, and packaging is orchestrated via a single entrypoint:

- Build and package: `bash .github/scripts/nix.sh package [deb|rpm|dmg]`
- Run tests: `bash .github/scripts/nix.sh test [all|sqlite|mysql|psql|redis|google_cse|hsm]`
- Generate SBOM: `bash .github/scripts/nix.sh sbom`

Always reference these instructions first; only fall back to ad‑hoc commands when troubleshooting discrepancies.

## Why Nix?

- Pinned nixpkgs for hermetic, reproducible environments
- Native deterministic verification in the derivation (installCheckPhase)
- Pinned Rust toolchain (1.90.0) from Nix — no rustup downloads
- Pinned OpenSSL 3.1.2 with static linking (no dynamic OpenSSL at runtime)
- One-command packaging for DEB/RPM/DMG with smoke tests

## Quick start

```bash
# Build default packages for your platform (Linux → deb+rpm, macOS → dmg)
bash .github/scripts/nix.sh package

# Build a specific format/variant
bash .github/scripts/nix.sh --variant fips package deb
bash .github/scripts/nix.sh --variant non-fips package rpm

# Build and test on SQLite only
bash .github/scripts/nix.sh test sqlite

# Run tests (defaults to 'all' - run 'docker compose up -d' first for DB backends)
bash .github/scripts/nix.sh test
```

Artifacts are placed under `result-deb-<variant>/`, `result-rpm-<variant>/`, and `result-dmg-<variant>/`.

## Determinism and native hash enforcement

The KMS server derivation computes the SHA-256 of the output binary and compares it to a strict, platform-specific file `nix/expected-hashes/<variant>.<system>.sha256` during `installCheckPhase` (for example: `fips.aarch64-darwin.sha256`, `non-fips.x86_64-linux.sha256`). Any mismatch or missing file fails the build. Packaging scripts also enforce the expected hash when reusing prebuilt results to ensure drift is caught early.

To update an expected hash after a legitimate change:

```bash
# macOS (Apple Silicon)
nix-build -A kms-server-fips -o result-server-fips
sha256sum result-server-fips/bin/cosmian_kms | cut -d' ' -f1 > nix/expected-hashes/fips.aarch64-darwin.sha256

# Linux x86_64
nix-build -A kms-server-non-fips -o result-server-non-fips
sha256sum result-server-non-fips/bin/cosmian_kms | cut -d' ' -f1 > nix/expected-hashes/non-fips.x86_64-linux.sha256
```

## Offline packaging

The first run can prewarm the Nix store (pinned nixpkgs, tools) and the Cargo registry cache. Subsequent runs can be fully offline:

- Nix: store prewarmed and reused; builds run with empty `substituters`
- Cargo: registry and crate sources cached in `target/cargo-offline-home` and packaging runs with `CARGO_NET_OFFLINE=true`
- OpenSSL: `resources/tarballs/openssl-3.1.2.tar.gz` must exist locally (script fetches it once if online)
- Signing: packages are signed with GPG

Verification: disconnect network, then re-run `bash .github/scripts/nix.sh package deb` — it should succeed and produce the same artifact hash.

## Package signing

Packages can be cryptographically signed with GPG:

```bash
# Generate signing key (one-time setup)
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash nix/scripts/generate_signing_key.sh

# Sign packages during build
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash .github/scripts/nix.sh package deb

# Verify signatures
gpg --import nix/signing-keys/cosmian-kms-public.asc
gpg --verify result-deb-fips/cosmian_kms_server_5.11.1_amd64.deb.asc
```

Signing uses GPG with `--pinentry-mode loopback` for non-interactive operation in CI environments. See `nix/signing-keys/README.md` for details.

## Testing

```bash
# Typical flows
bash .github/scripts/nix.sh test              # all tests supported on your OS
bash .github/scripts/nix.sh test sqlite       # sqlite-only (macOS/Linux)
bash .github/scripts/nix.sh test psql         # requires local PostgreSQL
bash .github/scripts/nix.sh test redis        # non-FIPS only

# HSM tests (Linux only)
bash .github/scripts/nix.sh test hsm          # softhsm2 + utimaco + proteccio
bash .github/scripts/nix.sh test hsm softhsm2 # single backend
```

Environment variables for DB tests:

- `KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms`
- `KMS_MYSQL_URL=mysql://kms:kms@localhost:3306/kms`
- `KMS_SQLITE_PATH=data/shared`

Notes:

- MySQL tests are currently disabled in CI
- Redis-findex tests are skipped in FIPS mode
- On macOS, only sqlite tests run (no DB containers)

## Validation and smoke tests

Packaging runs include a smoke test that extracts the artifact and runs `cosmian_kms --info` to verify OpenSSL 3.1.2 and static linkage. You can also run the server manually (after building or unpacking a package):

```bash
./cosmian_kms --database-type sqlite --sqlite-path /tmp/kms-data
```

Basic API probe:

```bash
curl -s -X POST -H "Content-Type: application/json" -d '{}' http://localhost:9998/kmip/2_1
```

Expected response is a KMIP validation error, confirming the server is alive.

## SBOM Generation

Generate a comprehensive Software Bill of Materials (SBOM) using sbomnix:

```bash
# Generate SBOM for FIPS variant
bash .github/scripts/nix.sh sbom

# Generate SBOM for non-FIPS variant
bash .github/scripts/nix.sh --variant non-fips sbom
```

The SBOM generation uses [sbomnix](https://github.com/tiiuae/sbomnix), a specialized tool for creating comprehensive SBOMs for Nix-based projects.

Generated artifacts (in repository root):

- `SBOM-<variant>.md` - Human-readable summary report
- `SBOM-<variant>-cdx.json` - CycloneDX JSON format (industry standard)
- `SBOM-<variant>-spdx.json` - SPDX format (ISO/IEC 5962:2021)
- `SBOM-<variant>.csv` - CSV format for spreadsheet analysis
- `SBOM-<variant>-graph.dot` - Dependency graph (Graphviz format)
- `SBOM-<variant>-graph.svg` - Visual dependency graph (if graphviz available)
- `SBOM-<variant>-vulns.csv` - Vulnerability report (if vulnix available)

The SBOM includes:

- Complete Nix store dependency graph
- Runtime and build-time dependencies
- License information for all components
- Package versions and provenance
- Cryptographic hashes for verification

These artifacts can be imported into SBOM management tools like Dependency-Track for continuous vulnerability monitoring and license compliance tracking.

## Repository layout (high level)

```text
.github/                # Orchestrator scripts (nix.sh), CI, and helpers
nix/                    # Nix derivations, scripts, expected hashes
crate/                  # Rust workspace crates (server, cli, crypto, …)
pkg/                    # Packaging metadata (deb/rpm service files, configs)
resources/tarballs/     # OpenSSL 3.1.2 tarball (local copy for offline)
result-*/               # Symlinks to build/package results
```

## Tips

- Format/lints: run `cargo fmt --check` and clippy inside the Nix environment if needed
- If repeated packaging triggers rebuilds, set `NO_PREWARM=1` for faster reuse-only runs
- If a package fails due to hash mismatch, update the relevant file in `nix/expected-hashes/` only after reviewing the change

## Docker

```bash
docker pull ghcr.io/cosmian/kms:latest
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
```

Images include the UI at `http://localhost:9998/ui`.
