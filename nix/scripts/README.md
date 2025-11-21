# Nix Scripts Documentation

Helper scripts for building, packaging, and maintaining Cosmian KMS with Nix.

## Quick Reference

| Task | Command |
|------|---------|
| **Update all hashes** | `bash .github/scripts/nix.sh update-hashes` |
| **Update vendor hash only** | `bash .github/scripts/nix.sh update-hashes --vendor-only` |
| **Update binary hashes only** | `bash .github/scripts/nix.sh update-hashes --binary-only` |
| **Update non-FIPS variant** | `bash .github/scripts/nix.sh --variant non-fips update-hashes` |
| **Package DEB (FIPS)** | `bash .github/scripts/nix.sh package deb` |
| **Package RPM (non-FIPS)** | `bash .github/scripts/nix.sh --variant non-fips package rpm` |
| **Package DMG (macOS)** | `bash .github/scripts/nix.sh package dmg` |
| **Generate signing key** | `bash nix/scripts/generate_signing_key.sh` |

**Note**: Hash management is now integrated into the main `nix.sh` script. The standalone `update_all_hashes.sh` script is still available for direct use if needed.

## Hash Management

### update_all_hashes.sh

**Status**: Standalone script (integrated into `nix.sh` as `update-hashes` subcommand)

Automatically updates all expected hashes for the current platform after dependency or code changes.

**Usage:**

```bash
# Via nix.sh (recommended - auto-passes variant flag)
bash .github/scripts/nix.sh update-hashes
bash .github/scripts/nix.sh update-hashes --vendor-only
bash .github/scripts/nix.sh update-hashes --binary-only
bash .github/scripts/nix.sh --variant non-fips update-hashes

# Direct script call (alternative - requires explicit --variant flag)
bash nix/scripts/update_all_hashes.sh
bash nix/scripts/update_all_hashes.sh --vendor-only
bash nix/scripts/update_all_hashes.sh --binary-only
bash nix/scripts/update_all_hashes.sh --variant fips
bash nix/scripts/update_all_hashes.sh --binary-only --variant non-fips
```

**When to use:**

| Scenario | Command | What it updates |
|----------|---------|-----------------|
| Added/updated Rust dependencies | `--vendor-only` | `cargoHash` in `kms-server.nix` |
| Changed source code | `--binary-only` | Expected hashes in `expected-hashes/` |
| Both dependency and code changes | (no flags) | All hashes |
| Switched to new platform | (no flags) | All hashes for current architecture |

**Platform support:**

- `x86_64-linux` (Intel/AMD Linux)
- `aarch64-linux` (ARM64 Linux)
- `aarch64-darwin` (Apple Silicon macOS)

**Example workflow:**

```bash
# 1. Update dependencies
cargo update

# 2. Update vendor hash (using integrated command)
bash .github/scripts/nix.sh update-hashes --vendor-only

# 3. Make code changes
vim crate/server/src/main.rs

# 4. Update binary hashes
bash .github/scripts/nix.sh update-hashes --binary-only

# 5. Verify
bash .github/scripts/nix.sh build

# 6. Commit
git add nix/
git commit -m "Update dependencies and hashes for x86_64-linux"
```

## Packaging Scripts

### package_common.sh

Shared packaging logic used by DEB/RPM/DMG wrappers.

**Features:**

- Idempotent (reuses existing builds)
- Offline-capable (after prewarm)
- GPG signing support
- Hash verification
- Smoke testing

### package_deb.sh

Creates Debian packages (.deb) for both FIPS and non-FIPS variants.

**Usage:**

```bash
bash nix/scripts/package_deb.sh --variant fips
bash nix/scripts/package_deb.sh --variant non-fips
```

**Output:**

- `result-deb-fips/cosmian_kms_server_*.deb`
- `result-deb-non-fips/cosmian-kms-server_*.deb`

### package_rpm.sh

Creates RPM packages for Red Hat-based distributions.

**Usage:**

```bash
bash nix/scripts/package_rpm.sh --variant fips
bash nix/scripts/package_rpm.sh --variant non-fips
```

**Output:**

- `result-rpm-fips/cosmian_kms_server_fips-*.rpm`
- `result-rpm-non-fips/cosmian_kms_server-*.rpm`

### package_dmg.sh

Creates macOS installer DMG packages (macOS only).

**Usage:**

```bash
bash nix/scripts/package_dmg.sh --variant fips
bash nix/scripts/package_dmg.sh --variant non-fips
```

**Output:**

- `result-dmg-fips/Cosmian KMS Server_*_arm64.dmg`
- `result-dmg-non-fips/Cosmian KMS Server_*_arm64.dmg`

## Signing Scripts

### generate_signing_key.sh

Generates a GPG signing key for package signatures.

**Usage:**

```bash
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash nix/scripts/generate_signing_key.sh
```

**Creates:**

- `nix/signing-keys/cosmian-kms-public.asc` (distribute to users)
- `nix/signing-keys/cosmian-kms-private.asc` (keep secret)
- `nix/signing-keys/key-id.txt` (GPG key ID)

See `nix/signing-keys/README.md` for details.

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `NO_PREWARM` | Skip prewarm phase (faster repeat builds) | unset |
| `CARGO_HOME` | Cargo cache directory | `target/cargo-offline-home` |
| `CARGO_NET_OFFLINE` | Prevent network access | unset |
| `GPG_SIGNING_KEY_PASSPHRASE` | GPG key passphrase for signing | unset |
| `NIXPKGS_STORE` | Path to pinned nixpkgs | auto-detected |

## Troubleshooting

### Hash mismatch during build

```bash
# Update the mismatched hash (via nix.sh)
bash .github/scripts/nix.sh update-hashes

# Or update specific component
bash .github/scripts/nix.sh update-hashes --vendor-only
bash .github/scripts/nix.sh update-hashes --binary-only

# Alternative: standalone script
bash nix/scripts/update_all_hashes.sh
```

### Network errors during offline build

```bash
# Ensure prewarm completed
bash .github/scripts/nix.sh package deb

# Then set offline mode
export NO_PREWARM=1
export CARGO_NET_OFFLINE=true
bash .github/scripts/nix.sh package deb
```

### GPG signing fails

```bash
# Check key exists
ls -l nix/signing-keys/

# Regenerate if needed
export GPG_SIGNING_KEY_PASSPHRASE='your-passphrase'
bash nix/scripts/generate_signing_key.sh

# Test signature
gpg --import nix/signing-keys/cosmian-kms-public.asc
gpg --verify result-deb-fips/*.deb.asc
```

## Development Workflow

### Making code changes

```bash
# 1. Make changes
vim crate/server/src/core/operations.rs

# 2. Update binary hashes only
bash .github/scripts/nix.sh update-hashes --binary-only

# 3. Test
bash .github/scripts/nix.sh build
bash .github/scripts/nix.sh test sqlite

# 4. Package
bash .github/scripts/nix.sh package deb
```

### Updating dependencies

```bash
# 1. Update Cargo.lock
cargo update
# or
cargo update -p some-specific-crate

# 2. Update vendor hash
bash .github/scripts/nix.sh update-hashes --vendor-only

# 3. Rebuild binaries and update hashes
bash .github/scripts/nix.sh update-hashes --binary-only

# 4. Test
bash .github/scripts/nix.sh build
```

### Cross-platform hash updates

Run on each platform to update platform-specific hashes:

```bash
# On Linux x86_64
bash .github/scripts/nix.sh update-hashes

# On Linux ARM64
bash .github/scripts/nix.sh update-hashes

# On macOS Apple Silicon
bash .github/scripts/nix.sh update-hashes
```

Commit all platform-specific hash files to the repository.

## See Also

- `nix/README.md` - Main Nix documentation
- `nix/signing-keys/README.md` - Package signing details
- `.github/copilot-instructions.md` - Build system overview
