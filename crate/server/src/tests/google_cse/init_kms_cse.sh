#!/bin/sh

set -ex

PWD=$(pwd)

export KMS_CLI_FORMAT=json

### Content of ~/.cosmian/kms.json.cse
###
KMS_CLI_CONF="{
  \"kms_server_url\": \"https://cse.cosmian.com/\",
  \"kms_access_token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IjI4YTQyMWNhZmJlM2RkODg5MjcxZGY5MDBmNGJiZjE2ZGI1YzI0ZDQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTQwNzk0ODQ3NjAxNzE2ODQyMDUiLCJoZCI6ImNvc21pYW4uY29tIiwiZW1haWwiOiJlbW1hbnVlbC5jb3N0ZUBjb3NtaWFuLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiS0JvVEdIRmhLbFd4R2VLcVdlbjNBZyIsImlhdCI6MTcyNzc4NzM4MSwiZXhwIjoxNzI3NzkwOTgxfQ.U3pAak6-h-ARC91FIX_ltKjdjVqebApP_HYqebhp2OTg95XiNImGG5Vklh_4vdRVKOm8kylmpdfm8jDaf4yl0_eBPJjdYsiHZtqzp-wa-rTcN87p30bOTEiY7sDEc860GsvaXcxM28Cbcae85-CYeTNnqVBIvyWEnbRayBRyA6KknQHoz-sJfbFxhuD7nvyZxhstnQSuS19UtcUqMtckHC1-95YofgulU8XrvnsFT6unPOvP_VmV331EFIvRtA52ZyB5qrBKd4v_YMLVYM8SnHjBO29XqekqN8L8eVUUFeJgx-JTqhdAKpD1ObCcVbNqjhPZaufRS5J40q2idNCFcA\",
  \"database_secret\": \"eyJncm91cF9pZCI6MTY5NjE5MjAzMzQ1MDY0MDQxNjY1ODIyNzgwNjczNDY1ODkyNjcyLCJrZXkiOiJhN2EyNWY2YWUxMzExODMyYTBiYmRkZDNjMjk3ZjhjYTAxZTg4OWEzNzFlNjNhZmMyNjU4MDc2NzE1MmQ4YTA2In0=\",
  \"oauth2_conf\": {
    \"client_id\": \"996739510374-au9fdbgp72dacrsag267ckg32jf3d3e2.apps.googleusercontent.com\",
    \"client_secret\": \"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\",
    \"authorize_url\": \"https://accounts.google.com/o/oauth2/v2/auth\",
    \"token_url\": \"https://oauth2.googleapis.com/token\",
    \"scopes\": [
      \"openid\",
      \"email\"
    ]
  },
  \"gmail_api_conf\": {
    \"account_type\": \"service_account\",
    \"project_id\": \"bright-arc-384008\",
    \"private_key_id\": \"d0edb1d1bfb2fe5f5d9415f651ed817dc262ec39\",
    \"private_key\": \"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3+bSoSStvuzX5\nYho7BTK/cVK2guzuWpps+yg1kvVeC+Gk3Ew2zdHk20rqfnauZyMKHvagB//HSwEJ\ndj/i/lWybPPGTM32w9/EfXj7lqPR5MohVQxgI9wOHjZrceTjHRzez2zDYH1+/ZNN\nDzGrbieceuPrLfvxoAgB4elTelU92M2bNCNPuuV7wWc3ZbFZ6apIBzWzBfUphx5J\nQ3TezIrPGy42ayZRE8/YYrBRgYfbSuDzbX5J+IyhaJSW8UdOB6iMaAF2+vReTCTE\nGvru9y3iCMPQIJo69ZUe8EUSbRlbbsLrqOPRPZNqSmOJmCyRxzGhVCyjUoyVYHor\nc8hPjXsLAgMBAAECggEAVUxTnADMwFGC3VzEP6AR3twaVt+OHZbpaWTrSCeaVt/Y\nXxj6xyAXVG3uJpm6yfKstskTXLBIwWx/jxUB2utD7WWBguviRKqdSZtJKBC4ZJ0Y\nsGqfwcVuhicw4REd58T8OTvfuBg5J1NHY9+LDmoUuILrwIMCAI3LmJ/XD+q0sebU\nCmvTfJrRND+GTVmd8OWFRZoA6U3PaMW9rcI0BCZclc1ln9oL0btLa+Q/AO0fpq6n\nWwPiUGc97wV7f6SCPZSsV1qIzLMSIJU2dPaOmOjOADr2W/JckMM+qStSlXpysxy+\nGfjiViKHhavR3mtxqqzz1Lr+U0E5r5XD1J8a0LJkVQKBgQD0SLihcNQSeV/AsKtj\nqI71pMAKehRX/Cvsw82nWExSgf3VzOmoegfaJVlZcDpqPZjjrQGk3/flcbbYvjxK\nB1gk/S5OjPbHp+irrA1gt7vdHPeJP3hVtlMfxE9Zjp2z51Rd5xfme/SfGRlS50S/\nvo8ELBG6U9NtEMGX3hx4XRo0zwKBgQDAzIZihYe4LdpW1rufr3rlehb4CZwho8Ci\ny+HSk9SR270Uw+A7+HFXcPYhj3tfHTgCx4mmcsoX+6/gOZQRwsvKAns9jQi62Kit\nHPKvDR2XtWa0Xw2GNigbIF6OykxY1zdUJictL/iyIMuQR8Mcf9tIXb4RLyklUOus\nzcpNasEdBQKBgHg0pK3EcIbatPSDuwKiOh7EQD+njQUysIakXzleqMfc8YRYfg4K\nZnzA7jOllwkaYHaAdpOkJj8AcuI60j33WTdyYmwCz5i1ljeLxVV3c/k9PM2LrvI2\ncrbqCcXe+NlDFu/SPJ+NFXWIiz6RUPItmgCKkvqmLx63JRxPDqFn5vJfAoGAeeaX\nLWHaPySWwYNB3CRaow8/yJJi6o4b9ZLNdJRNue9irOdwNtrN5wigRvXufmP+DxvU\nt64qg2F6gV5Gdbhhm5dYDsHGfEUS2WnNM8sqI8rpZjAXX/2L/CLKRqQ4A5AIBqec\n66BCMXY030PQZIuevTGwRDM6Y8K3UGpJeAuAkHUCgYEAlS8PQMNlO4SukBIVaicx\n3wFAhbeVJyzc3MJqlsvAKq7HHGMLFWXN2gefnMljNxNUiIy143OkmxsVJjhkr7jS\naYx7OSgLH6ksLsqW2t+GmBpstjNH2dfuOEiGbm99TX0d9WBKPFE/DoLDqPKB7kJC\nTysd08+GiFbz0eQpsKcb2XE=\n-----END PRIVATE KEY-----\n\",
    \"client_email\": \"cse-for-gmail@bright-arc-384008.iam.gserviceaccount.com\",
    \"client_id\": \"11451932203930748464\",
    \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",
    \"token_uri\": \"https://oauth2.googleapis.com/token\",
    \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",
    \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/cse-for-gmail%40bright-arc-384008.iam.gserviceaccount.com\",
    \"universe_domain\": \"googleapis.com\"
  }
}"

cp ~/.cosmian/kms.json ~/.cosmian/kms.json.old
echo "$KMS_CLI_CONF" >~/.cosmian/kms.json

cargo run --bin ckms login
# cargo run --bin ckms sym keys revoke -k google_cse "revoke google_cse key"
# cargo run --bin ckms sym keys destroy -t google_cse
#
# For Google workspace CSE demo
#
cargo run --bin ckms sym keys import -t google_cse "documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json" google_cse
cargo run --bin ckms access-rights grant '*' google_cse create destroy get encrypt decrypt
cargo run --bin ckms certificates import -f pkcs12 crate/server/src/routes/google_cse/python/openssl/int.p12 -p secret intermediate_cse_cert_chain
cargo run --bin ckms access-rights grant '*' intermediate_cse_cert_chain create destroy get encrypt decrypt

cargo run --bin ckms -- get-attributes -i intermediate_cse_cert_chain
CA_IDS=$(cargo run --bin ckms -- get-attributes -i intermediate_cse_cert_chain)
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
cargo run --bin ckms -- rsa keys import -f pem -t dke_key -p ms_dke_pub_key crate/server/src/tests/ms_dke/private_key.pkcs8.pem ms_dke_priv_key
cargo run --bin ckms -- rsa keys import -f pem -t dke_key -k ms_dke_priv_key crate/server/src/tests/ms_dke/public_key.pkcs8.pem ms_dke_pub_key

cargo run --bin ckms -- rsa keys export -t dke_key -t _pk -f pkcs1-pem /tmp/pub_key.pkcs1.pem
cargo run --bin ckms -- rsa keys export -t dke_key -t _sk -f pkcs8-pem /tmp/priv_key.pkcs1.pem

cargo run --bin ckms -- access-rights grant admin ms_dke_priv_key decrypt
cargo run --bin ckms -- access-rights grant admin ms_dke_pub_key encrypt export get
