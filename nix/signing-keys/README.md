# Package Signing Keys

This directory contains GPG keys used to cryptographically sign Cosmian KMS packages (DEB, RPM, DMG).

## Key Generation

Generate a signing key pair:

```bash
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash nix/scripts/generate_signing_key.sh
```

This creates:

- `cosmian-kms-public.asc` - Public key for signature verification (safe to distribute)
- `cosmian-kms-private.asc` - Private key for signing (encrypted with passphrase)
- `key-id.txt` - GPG key ID used by packaging scripts

## Signing Packages

Packages are automatically signed during the packaging process if:

1. A signing key exists (`key-id.txt` is present)
2. `GPG_SIGNING_KEY_PASSPHRASE` environment variable is set

```bash
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash .github/scripts/nix.sh package deb
```

Each package will have a corresponding `.asc` signature file:

- `cosmian_kms_server_5.11.1_amd64.deb`
- `cosmian_kms_server_5.11.1_amd64.deb.asc` ← GPG signature

## Verifying Signatures

Import the public key:

```bash
gpg --import nix/signing-keys/cosmian-kms-public.asc
```

Verify a package signature:

```bash
# Debian package
gpg --verify result-deb-fips/cosmian_kms_server_5.11.1_amd64.deb.asc

# RPM package
gpg --verify result-rpm-fips/cosmian_kms_server_fips-5.11.1.x86_64.rpm.asc

# DMG package
gpg --verify result-dmg-fips/Cosmian\ KMS\ Server_5.11.1_arm64.dmg.asc
```

Expected output:

```text
gpg: Signature made ...
gpg: Good signature from "Cosmian KMS Release <tech@cosmian.com>"
```

## Implementation Details

The signing implementation uses a single unified function:

- **Unified Function**: `sign_packages()` in `nix/scripts/package_common.sh`
    - Handles both directory patterns (for batch DEB/RPM signing)
    - Handles single files (for DMG signing)
    - Automatically detects whether target is a file or directory
    - Uses `--pinentry-mode loopback` for non-interactive signing (CI/automation)
    - **Verifies each signature immediately after creation** to catch signing failures early
- **Usage in DEB/RPM**: Called directly from `collect_deb()` and `collect_rpm()`
- **Usage in DMG**: Sourced dynamically from `package_dmg.sh` via process substitution
- All create detached ASCII-armored signatures (`.asc` files) using GPG

**Technical Details**:

- Key Type: RSA 4096-bit
- Signature Format: Detached ASCII-armored (`.asc` files)
- GPG Flags: `--batch --yes --pinentry-mode loopback --passphrase-fd 0`
- The `--pinentry-mode loopback` flag enables non-interactive signing in CI/automated builds
- Each signature is automatically verified after creation to ensure integrity

## Security Notes

- **Never commit `cosmian-kms-private.asc`** to version control
- Store `GPG_SIGNING_KEY_PASSPHRASE` securely (CI secrets, password manager)
- The private key is encrypted with a passphrase for additional security
- Ensure proper file permissions (`chmod 600`) on the private key
- Rotate keys periodically and update public key distribution channels
- For production releases, consider using hardware security modules (HSM) or managed signing services

## Key Rotation

To rotate keys:

1. Generate a new key pair:

   ```bash
   export GPG_SIGNING_KEY_PASSPHRASE='new-secure-passphrase'
   bash nix/scripts/generate_signing_key.sh --email tech@cosmian.com
   ```

2. Archive old keys:

   ```bash
   mv cosmian-kms-public.asc cosmian-kms-public-YYYYMMDD.asc
   mv cosmian-kms-private.asc cosmian-kms-private-YYYYMMDD.asc
   ```

3. Distribute new public key to users
4. Update documentation with new key fingerprint

## Distribution

Publish the public key (`cosmian-kms-public.asc`) to:

- GitHub releases
- Package repository metadata
- Project documentation
- Public keyservers (optional): `gpg --send-keys <KEY-ID>`
