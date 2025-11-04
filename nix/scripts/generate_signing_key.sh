#!/usr/bin/env bash
# Generate a GPG key pair for signing Cosmian KMS packages
# Usage: bash nix/scripts/generate_signing_key.sh [--name "NAME"] [--email "EMAIL"]
#
# Creates a GPG key and exports it to nix/signing-keys/ for package signing.
# The private key is encrypted with a passphrase stored in GPG_SIGNING_KEY_PASSPHRASE env var.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Defaults
NAME="${COSMIAN_SIGNING_NAME:-Cosmian KMS Release}"
EMAIL="${COSMIAN_SIGNING_EMAIL:-tech@cosmian.com}"

while [ $# -gt 0 ]; do
  case "$1" in
  --name)
    NAME="$2"
    shift 2
    ;;
  --email)
    EMAIL="$2"
    shift 2
    ;;
  -h | --help)
    echo "Usage: $0 [--name 'NAME'] [--email 'EMAIL']"
    echo "Generates a GPG key for package signing."
    echo "Set GPG_SIGNING_KEY_PASSPHRASE env var for key encryption."
    exit 0
    ;;
  *) shift ;;
  esac
done

# Check for passphrase
if [ -z "${GPG_SIGNING_KEY_PASSPHRASE:-}" ]; then
  echo "ERROR: GPG_SIGNING_KEY_PASSPHRASE environment variable must be set" >&2
  echo "Example: export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'" >&2
  exit 1
fi

KEYS_DIR="$REPO_ROOT/nix/signing-keys"
mkdir -p "$KEYS_DIR"

# Generate batch file for unattended key generation
BATCH_FILE=$(mktemp)
trap 'rm -f "$BATCH_FILE"' EXIT

cat >"$BATCH_FILE" <<EOF
%echo Generating Cosmian KMS package signing key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $NAME
Name-Email: $EMAIL
Expire-Date: 0
Passphrase: $GPG_SIGNING_KEY_PASSPHRASE
%commit
%echo Key generation complete
EOF

echo "Generating GPG key pair for: $NAME <$EMAIL>"
gpg --batch --gen-key "$BATCH_FILE"

# Get the key ID
KEY_ID=$(gpg --list-keys --with-colons "$EMAIL" | awk -F: '/^pub/ {print $5}' | head -1)
if [ -z "$KEY_ID" ]; then
  echo "ERROR: Failed to locate generated key" >&2
  exit 1
fi

echo "Generated key ID: $KEY_ID"

# Export public key (for verification)
gpg --armor --export "$KEY_ID" >"$KEYS_DIR/cosmian-kms-public.asc"
echo "Exported public key: $KEYS_DIR/cosmian-kms-public.asc"

# Export private key (encrypted with passphrase)
gpg --armor --export-secret-keys "$KEY_ID" >"$KEYS_DIR/cosmian-kms-private.asc"
chmod 600 "$KEYS_DIR/cosmian-kms-private.asc"
echo "Exported private key: $KEYS_DIR/cosmian-kms-private.asc (encrypted)"

# Store key ID for scripts
echo "$KEY_ID" >"$KEYS_DIR/key-id.txt"
echo "Stored key ID: $KEYS_DIR/key-id.txt"

echo ""
echo "============================================="
echo "GPG key pair generated successfully"
echo "============================================="
echo "Key ID: $KEY_ID"
echo "Public key: $KEYS_DIR/cosmian-kms-public.asc"
echo "Private key: $KEYS_DIR/cosmian-kms-private.asc (KEEP SECURE)"
echo ""
echo "To sign packages, ensure GPG_SIGNING_KEY_PASSPHRASE is set in your environment."
echo "To verify signatures: gpg --import $KEYS_DIR/cosmian-kms-public.asc"
echo "============================================="
