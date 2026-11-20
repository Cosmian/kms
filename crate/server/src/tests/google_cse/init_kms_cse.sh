#!/bin/sh

set -ex

PWD=$(pwd)

export KMS_CLI_FORMAT=json

# Local ckms config (KMS OAuth client + gmail_api_conf); never commit credentials (#1435).
export CKMS_CONF="${CKMS_CSE_CONF:-${HOME}/.cosmian/cse.cosmian.com.toml}"

cargo run --bin ckms login oauth
# cargo run --bin ckms sym keys revoke -k google_cse "revoke google_cse key"
# cargo run --bin ckms sym keys destroy -t google_cse
#
# For Google workspace CSE demo
#
cargo run --bin ckms sym keys import -t google_cse "documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json" google_cse
cargo run --bin ckms access-rights grant '*' google_cse create destroy get encrypt decrypt
cargo run --bin ckms certificates import -f pkcs12 crate/server/src/routes/google_cse/python/openssl/int.p12 -p secret intermediate_cse_cert_chain
cargo run --bin ckms access-rights grant '*' intermediate_cse_cert_chain create destroy get encrypt decrypt

cargo run --bin ckms attributes get -i intermediate_cse_cert_chain
CA_IDS=$(cargo run --bin ckms attributes get -i intermediate_cse_cert_chain)
CA_CERT_ID=$(echo "$CA_IDS" | jq -r '.attributes."linked-issuer-certificate-id"')
CA_PRIVATE_KEY_ID=$(echo "$CA_IDS" | jq -r '.attributes."linked-private-key-id"')
cargo run --bin ckms access-rights grant '*' "$CA_CERT_ID" create destroy get encrypt decrypt
cargo run --bin ckms access-rights grant '*' "$CA_PRIVATE_KEY_ID" create destroy get encrypt decrypt

# Check cse key
rm -f sym_key_cse.json
cargo run --bin ckms sym keys export -t google_cse -f json-ttlv sym_key_cse.json
cat sym_key_cse.json
rm -f sym_key_cse.json

#
# For DKE demo
#
cargo run --bin ckms rsa keys import -f pem -t dke_key -p ms_dke_pub_key crate/server/src/tests/ms_dke/private_key.pkcs8.pem ms_dke_priv_key
cargo run --bin ckms rsa keys import -f pem -t dke_key -k ms_dke_priv_key crate/server/src/tests/ms_dke/public_key.pkcs8.pem ms_dke_pub_key

cargo run --bin ckms rsa keys export -t dke_key -t _pk -f pkcs1-pem /tmp/pub_key.pkcs1.pem
cargo run --bin ckms rsa keys export -t dke_key -t _sk -f pkcs8-pem /tmp/priv_key.pkcs1.pem

cargo run --bin ckms access-rights grant admin ms_dke_priv_key decrypt
cargo run --bin ckms access-rights grant admin ms_dke_pub_key encrypt export get
