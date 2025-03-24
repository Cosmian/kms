#!/bin/bash

set -ex

# Run servers and Redis instance
docker compose up -d
sleep 5

export COSMIAN_CLI_FORMAT=json
COSMIAN="cargo run --bin cosmian -- -c test_data/configs/cosmian_for_bash.toml"

# Create the seed key
seed_key_id=$($COSMIAN kms sym keys create | jq -r '.unique_identifier')
echo "seed_key_id: $seed_key_id"

# Create the key encryption key
kek_id=$($COSMIAN kms sym keys create | jq -r '.unique_identifier')
echo "kek_id: $kek_id"

# Create the index ID
index_id=$($COSMIAN findex permissions create | sed 's/Created Index ID: //')
echo "index_id: $index_id"

# Encrypt and index the data
$COSMIAN findex encrypt-and-index --seed-key-id "$seed_key_id" --index-id "$index_id" --kek-id "$kek_id" --csv test_data/datasets/smallpop.csv

# Search and decrypt the data
expected_line=$($COSMIAN findex search-and-decrypt --seed-key-id "$seed_key_id" --index-id "$index_id" --kek-id "$kek_id" --keyword "Southborough" | sed 's/Decrypted records: //')
echo "expected_line: $expected_line"

# Check the result
if [[ "$expected_line" != "[\"SouthboroughMAUnited States9686\"]" ]]; then
  echo "Test failed: unexpected result"
  exit 1
else
  echo "Test passed: local encryption"
fi

# Generate the HMAC key
hmac_key_id=$($COSMIAN kms sym keys create | jq -r '.unique_identifier')
echo "hmac_key_id: $hmac_key_id"

# Generate the AES-XTS-512 key
aes_xts_key_id=$($COSMIAN kms sym keys create | jq -r '.unique_identifier')
echo "aes_xts_key_id: $aes_xts_key_id"

# Encrypt and index the data
$COSMIAN findex encrypt-and-index --hmac-key-id "$hmac_key_id" --aes-xts-key-id "$aes_xts_key_id" --index-id "$index_id" --kek-id "$kek_id" --csv test_data/datasets/smallpop.csv

# Search and decrypt the data
expected_line=$($COSMIAN findex search-and-decrypt --hmac-key-id "$hmac_key_id" --aes-xts-key-id "$aes_xts_key_id" --index-id "$index_id" --kek-id "$kek_id" --keyword "Southborough" | sed 's/Decrypted records: //')
echo "expected_line: $expected_line"

# Check the result
if [[ "$expected_line" != "[\"SouthboroughMAUnited States9686\"]" ]]; then
  echo "Test failed: unexpected result"
  exit 1
else
  echo "Test passed"
fi

exit 0
