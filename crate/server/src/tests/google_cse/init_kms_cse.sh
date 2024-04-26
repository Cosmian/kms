#!/bin/sh

set -ex

PWD=$(pwd)

export KMS_CLI_FORMAT=json

### Content of ~/.cosmian/kms.json.cse.blue
###
KMS_CLI_CONF="{
  \"kms_server_url\": \"https://cse.cosmian.com/\",
  \"kms_access_token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IjY3MTk2NzgzNTFhNWZhZWRjMmU3MDI3NGJiZWE2MmRhMmE4YzRhMTIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDI5NjU4MTQxNjkwOTQzMDMxMTIiLCJoZCI6ImNvc21pYW4uY29tIiwiZW1haWwiOiJibHVlQGNvc21pYW4uY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJUbzAxMFF1ZHBVeVprQ0huVlZaRUpBIiwiaWF0IjoxNzE3MDY4NjkzLCJleHAiOjE3MTcwNzIyOTN9.gn1mQZkEIlOJ4ReLW9f9lq2vosHDdDIp6voyTFYFrfEKUJY9U3aH8JIg9Rn5VbLqx7RWCOHD1cVaoUGtLTrRo4kgHE4fNOaGS0cqKmKncH_5BHMxQ6AYtwHIloMNEoiNzuR5U-BcsvFnLT_Vr3Gf8LQqJZd9jQ3ypKot3Q8GGBtrQefG_a-4buP80SOJK4shM1ZJUiZ-qJvPCYtAT5YzWeXsHX-MG6R8MFT1WYBNVWVvS-EhDkMXNFtc_ek8MEthIZ2Cc6fi_zsYhLXA6Po-SNfJxgA6flhAkk1tzgkLMIqh2NTQIKvbUR_AnT2_z9BKilR1g_OMqNRNmQa2C1v6gg\",
  \"kms_database_secret\": \"eyJncm91cF9pZCI6MTY5NjE5MjAzMzQ1MDY0MDQxNjY1ODIyNzgwNjczNDY1ODkyNjcyLCJrZXkiOiJhN2EyNWY2YWUxMzExODMyYTBiYmRkZDNjMjk3ZjhjYTAxZTg4OWEzNzFlNjNhZmMyNjU4MDc2NzE1MmQ4YTA2In0=\",
  \"oauth2_conf\": {
    \"client_id\": \"996739510374-au9fdbgp72dacrsag267ckg32jf3d3e2.apps.googleusercontent.com\",
    \"client_secret\": \"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\",
    \"authorize_url\": \"https://accounts.google.com/o/oauth2/v2/auth\",
    \"token_url\": \"https://oauth2.googleapis.com/token\",
    \"scopes\": [
      \"openid\",
      \"email\"
    ]
  }
}"

cp ~/.cosmian/kms.json ~/.cosmian/kms.json.old
echo "$KMS_CLI_CONF" >~/.cosmian/kms.json

cargo run --bin ckms login
cargo run --bin ckms sym keys revoke -k google_cse "revoke google_cse key"
cargo run --bin ckms sym keys destroy -t google_cse
cargo run --bin ckms sym keys import -t google_cse "$PWD/documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json" google_cse

# For Google workspace CSE demo
cargo run --bin ckms access-rights grant blue@cosmian.com google_cse create destroy get encrypt decrypt
cargo run --bin ckms access-rights grant green@cosmian.com google_cse create destroy get encrypt decrypt
cargo run --bin ckms access-rights grant celia@cosmian.com google_cse create destroy get encrypt decrypt
cargo run --bin ckms access-rights grant celia.corsin@cosmian.com google_cse create destroy get encrypt decrypt
cargo run --bin ckms access-rights grant bruno@cosmian.com google_cse create destroy get encrypt decrypt
cargo run --bin ckms access-rights grant bruno.grieder@cosmian.com google_cse create destroy get encrypt decrypt

# For DKE demo
RSA_KEY_IDS=$(cargo run --bin ckms rsa keys create --tag dke_key --size_in_bits 2048)
PRIVATE_KEY_ID=$(echo "$RSA_KEY_IDS" | jq -r ".private_key_unique_identifier")
PUBLIC_KEY_ID=$(echo "$RSA_KEY_IDS" | jq -r ".public_key_unique_identifier")

# on the _sk key
cargo run --bin ckms access-rights grant '*' "$PRIVATE_KEY_ID" decrypt
# on the _pk key
cargo run --bin ckms access-rights grant '*' "$PUBLIC_KEY_ID" encrypt get

rm -f sym_key_cse.json
cargo run --bin ckms sym keys export -t google_cse -f json-ttlv sym_key_cse.json
cat sym_key_cse.json
rm -f sym_key_cse.json
