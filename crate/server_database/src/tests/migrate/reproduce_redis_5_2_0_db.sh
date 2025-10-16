#!/bin/bash
# related test: from_5_2_0_to_5_9_0 on crate/server_database/src/tests/redis_migration_tests.rs

set -e # Exit immediately if a command exits with a non-zero status

COSMIAN_CLI="target/debug/cosmian" # This file is made to be run from the root of the cli repo after building it **with all features**.

echo "Creating test keys in KMS..."

# 1. mt_rsa - RSA key pair with tags: cat, fox
echo "Creating RSA key pair: mt_rsa"
$COSMIAN_CLI kms rsa keys create -t cat -t fox mt_rsa

# 2. mt_normal_aes - AES symmetric key with tags: cat, dog, cow
echo "Creating AES key: mt_normal_aes"
$COSMIAN_CLI kms sym keys create -t cat -t dog -t cow mt_normal_aes

# Grant permissions to mt_normal_user
echo "Granting permissions on mt_normal_aes to mt_normal_user"
$COSMIAN_CLI kms access-rights grant mt_normal_user get encrypt decrypt -i mt_normal_aes

# 3. Covercrypt key pair - will use actual IDs from output
echo "Creating Covercrypt master key pair"

# Create temporary JSON file with access structure specifications
TEMP_JSON=$(mktemp)
cat > "$TEMP_JSON" << 'EOF'
{
    "Security Level::<": [
        "Protected",
        "Confidential",
        "Top Secret::+"
    ],
    "Department": [
        "R&D",
        "HR",
        "MKG",
        "FIN"
    ]
}
EOF

CC_OUTPUT=$($COSMIAN_CLI kms cc keys create-master-key-pair -s "$TEMP_JSON" -t cat -t dog)
CC_SK_ID=$(echo "$CC_OUTPUT" | grep -oP 'Private key unique identifier: \K[^\s]+')
CC_PK_ID=$(echo "$CC_OUTPUT" | grep -oP 'Public key unique identifier: \K[^\s]+')

# Clean up temporary file
rm "$TEMP_JSON"

echo "Covercrypt private key ID: $CC_SK_ID"
echo "Covercrypt public key ID: $CC_PK_ID"

# Grant all permissions to mt_owner on Covercrypt keys
echo "Granting all permissions on Covercrypt keys to mt_owner"
$COSMIAN_CLI kms access-rights grant mt_owner get create destroy encrypt decrypt import export -i "$CC_SK_ID"
$COSMIAN_CLI kms access-rights grant mt_owner get create destroy encrypt decrypt import export -i "$CC_PK_ID"

echo ""
echo "Summary of created keys:"
echo "========================"
echo "1. mt_rsa && mt_rsa_pk (RSA key pair) - tags: cat, fox"
echo "   Permissions: -"
echo ""
echo "2. mt_normal_aes (AES) - tags: cat, dog, cow"
echo "   Permissions: mt_normal_user can get, encrypt, decrypt"
echo ""
echo "3. Covercrypt keys - tags: cat, dog"
echo "   Private key ID: $CC_SK_ID"
echo "   Public key ID: $CC_PK_ID"
echo "   Permissions: mt_owner has all permissions"
