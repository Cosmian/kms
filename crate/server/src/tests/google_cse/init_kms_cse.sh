#!/bin/sh

set -ex

PWD=$(pwd)

export KMS_CLI_FORMAT=json

### Content of ~/.cosmian/kms.toml.cse
###
CKMS_CONF="
[http_config]
server_url = \"https://cse.cosmian.com/\"
access_token = \"eyJhbGciOiJSUzI1NiIsImtpZ...-cf6ZDnK8ns1FynmAU2qA\"

[http_config.oauth2_conf]
client_id = \"996739510374-au9fdbgp72dacrsag267ckg32jf3d3e2.apps.googleusercontent.com\"
client_secret = \"XXX\"
authorize_url = \"https://accounts.google.com/o/oauth2/v2/auth\"
token_url = \"https://oauth2.googleapis.com/token\"
scopes = [\"openid\", \"email\"]

[gmail_api_conf]
type = \"service_account\"
project_id = \"bright-arc-384008\"
private_key_id = \"XXX\"
private_key = \"-----BEGIN PRIVATE KEY-----\nXXX\n-----END PRIVATE KEY-----\n\"
client_email = \"cse-for-gmail@bright-arc-384008.iam.gserviceaccount.com\"
client_id = \"XXX\"
auth_uri = \"https://accounts.google.com/o/oauth2/auth\"
token_uri = \"https://oauth2.googleapis.com/token\"
auth_provider_x509_cert_url = \"https://www.googleapis.com/oauth2/v1/certs\"
client_x509_cert_url = \"https://www.googleapis.com/robot/v1/metadata/x509/cse-for-gmail%40bright-arc-384008.iam.gserviceaccount.com\"
universe_domain = \"googleapis.com\"
"

cp ~/.cosmian/kms.toml ~/.cosmian/kms.toml.old
echo "$CKMS_CONF" >~/.cosmian/kms.toml

cargo run --bin cosmian kms login
# cargo run --bin cosmian kms sym keys revoke -k google_cse "revoke google_cse key"
# cargo run --bin cosmian kms sym keys destroy -t google_cse
#
# For Google workspace CSE demo
#
cargo run --bin cosmian kms sym keys import -t google_cse "documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json" google_cse
cargo run --bin cosmian kms access-rights grant '*' google_cse create destroy get encrypt decrypt
cargo run --bin cosmian kms certificates import -f pkcs12 crate/server/src/routes/google_cse/python/openssl/int.p12 -p secret intermediate_cse_cert_chain
cargo run --bin cosmian kms access-rights grant '*' intermediate_cse_cert_chain create destroy get encrypt decrypt

cargo run --bin cosmian kms -- attributes get -i intermediate_cse_cert_chain
CA_IDS=$(cargo run --bin cosmian kms -- attributes get -i intermediate_cse_cert_chain)
CA_CERT_ID=$(echo "$CA_IDS" | jq -r '.attributes."linked-issuer-certificate-id"')
CA_PRIVATE_KEY_ID=$(echo "$CA_IDS" | jq -r '.attributes."linked-private-key-id"')
cargo run --bin cosmian kms access-rights grant '*' "$CA_CERT_ID" create destroy get encrypt decrypt
cargo run --bin cosmian kms access-rights grant '*' "$CA_PRIVATE_KEY_ID" create destroy get encrypt decrypt

# Check cse key
rm -f sym_key_cse.json
cargo run --bin cosmian kms sym keys export -t google_cse -f json-ttlv sym_key_cse.json
cat sym_key_cse.json
rm -f sym_key_cse.json

#
# For DKE demo
#
cargo run --bin cosmian kms -- rsa keys import -f pem -t dke_key -p ms_dke_pub_key crate/server/src/tests/ms_dke/private_key.pkcs8.pem ms_dke_priv_key
cargo run --bin cosmian kms -- rsa keys import -f pem -t dke_key -k ms_dke_priv_key crate/server/src/tests/ms_dke/public_key.pkcs8.pem ms_dke_pub_key

cargo run --bin cosmian kms -- rsa keys export -t dke_key -t _pk -f pkcs1-pem /tmp/pub_key.pkcs1.pem
cargo run --bin cosmian kms -- rsa keys export -t dke_key -t _sk -f pkcs8-pem /tmp/priv_key.pkcs1.pem

cargo run --bin cosmian kms -- access-rights grant admin ms_dke_priv_key decrypt
cargo run --bin cosmian kms -- access-rights grant admin ms_dke_pub_key encrypt export get
