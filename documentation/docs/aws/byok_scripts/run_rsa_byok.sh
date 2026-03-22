#!/bin/bash
set -e

usage() {
    echo "Usage: $0 <key_size_in_bits> [aws_key_description]"
    echo ""
    echo "  key_size_in_bits    RSA key size: 2048, 3072 or 4096"
    echo "  aws_key_description Description for the AWS KMS key (optional)"
    echo ""
    echo "  Environment variables:"
    echo "    COSMIAN_KMS_CLI   Path to the cosmian binary (default: cosmian)"
    echo ""
    echo "Example:"
    echo "  $0 2048"
    echo "  $0 2048 'My RSA BYOK Key'"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

KEY_SIZE="$1"
if [ "$KEY_SIZE" != "2048" ] && [ "$KEY_SIZE" != "3072" ] && [ "$KEY_SIZE" != "4096" ]; then
    echo "Error: key_size_in_bits must be 2048, 3072 or 4096"
    usage
fi

# Configuration
AWS_KEY_DESC="${2:-Cosmian KMS external RSA-${KEY_SIZE} key material}"
COSMIAN_KMS_CLI="${COSMIAN_KMS_CLI:-cosmian}"
WRAPPING_ALGO="RSA_AES_KEY_WRAP_SHA_256"
WRAPPING_KEY_SPEC="RSA_4096"

# Temporary working directory, cleaned up on exit
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "======================================"
echo "  AWS KMS RSA-${KEY_SIZE} BYOK Auto Flow  "
echo "======================================"

echo "[1/7] Creating AWS KMS Key (EXTERNAL origin, RSA_${KEY_SIZE}, SIGN_VERIFY)..."
KEY_ARN=$(aws kms create-key \
    --origin EXTERNAL \
    --key-spec "RSA_${KEY_SIZE}" \
    --key-usage SIGN_VERIFY \
    --description "$AWS_KEY_DESC" \
    --query KeyMetadata.Arn \
    --output text)
echo "  -> Created AWS KMS Key ARN: $KEY_ARN"

echo "[2/7] Creating Cosmian KMS RSA-${KEY_SIZE} private key material..."
COSMIAN_KEY_ID=$($COSMIAN_KMS_CLI kms rsa keys create \
    --size_in_bits "$KEY_SIZE" |
    grep -oP '(?<=Private key unique identifier: )\S+')
if [ -z "$COSMIAN_KEY_ID" ]; then
    echo "Error: could not extract Cosmian private key ID from output"
    exit 1
fi
echo "  -> Created Cosmian RSA key: $COSMIAN_KEY_ID"

echo "[3/7] Getting AWS Import Parameters..."
# For RSA key material, wrapping algorithm MUST be RSA_AES_KEY_WRAP_SHA_256
aws kms get-parameters-for-import \
    --key-id "$KEY_ARN" \
    --wrapping-algorithm $WRAPPING_ALGO \
    --wrapping-key-spec $WRAPPING_KEY_SPEC >"$WORK_DIR/step3_params.json"
echo "  -> Saved wrapping parameters"

echo "[4/7] Decoding Import Token and KEK..."
jq -r '.ImportToken' "$WORK_DIR/step3_params.json" | base64 -d >"$WORK_DIR/token.bin"
jq -r '.PublicKey' "$WORK_DIR/step3_params.json" | base64 -d >"$WORK_DIR/kek.bin"
echo "  -> Decoded token and KEK"

echo "[5/7] Importing AWS KEK into Cosmian KMS..."
COSMIAN_KEK_ID=$($COSMIAN_KMS_CLI kms aws byok import \
    --kek-file "$WORK_DIR/kek.bin" \
    --wrapping-algorithm $WRAPPING_ALGO \
    --key-arn "$KEY_ARN" |
    grep -oP '(?<=Unique identifier: )\S+')
echo "  -> Imported KEK with ID: $COSMIAN_KEK_ID"

echo "[6/7] Exporting (wrapping) RSA key material from Cosmian KMS..."
$COSMIAN_KMS_CLI kms aws byok export \
    "$COSMIAN_KEY_ID" \
    "$COSMIAN_KEK_ID" \
    "$WORK_DIR/token.bin" \
    "$WORK_DIR/EncryptedKeyMaterial.bin" >/dev/null
echo "  -> Generated encrypted key material"

echo "[7/7] Importing wrapped RSA key material to AWS KMS..."
aws kms import-key-material \
    --key-id "$KEY_ARN" \
    --encrypted-key-material "fileb://$WORK_DIR/EncryptedKeyMaterial.bin" \
    --import-token "fileb://$WORK_DIR/token.bin" \
    --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE >/dev/null
echo "  -> Successfully imported RSA key material to AWS KMS!"

echo "======================================"
echo "          BYOK Flow Complete!         "
echo "======================================"
echo "  AWS Key ARN:      $KEY_ARN"
echo "  Cosmian Key ID:   $COSMIAN_KEY_ID"
echo "  Cosmian KEK ID:   $COSMIAN_KEK_ID"
echo "======================================"
