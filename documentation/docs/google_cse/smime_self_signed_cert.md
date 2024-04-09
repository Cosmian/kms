# S/MIME certificate guidelines

Links:

- https://support.google.com/a/answer/7300887#zippy=%2Croot-ca%2Cintermediate-ca-certificates-other-than-from-issuing-intermediate-ca%2Cintermediate-ca-certificate-that-issues-the-end-entity%2Cend-entity-certificate
- https://support.google.com/a/answer/13297070?hl=en#guidelines


## Import custom root CA

- Run generate.sh
- insert fullchain.pem (not reversed_fullchain.pem) in admin.google.com in S/MIME parameters

## Import wrapped private key

### Prepare keys for blue@cosmian.com

First, import the AES wrapping key (will wrap the RSA private key):
./ckms login
./ckms sym keys import -t google_cse documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json
./ckms rsa keys import -f pem ../../crate/server/src/routes/google_cse/python/openssl/blue.key -t gmail_blue
./ckms rsa keys export -t gmail_blue -w google_cse pk_blue -f raw
base64 -w 0 pk_blue

And (re)create keypair and identity for blue:

Credentials `google-idp-for-cse-service-account.json` comes from gcloud console.

python cse_cmd.py delete_identity --creds ~/Downloads/google-idp-for-cse-service-account.json --userid blue@cosmian.com --kpemail blue@cosmian.com
python cse_cmd.py insert_keypair --creds ~/Downloads/google-idp-for-cse-service-account.json --inkeydir wrapped_key_blue --incertdir openssl

Identifier `ANe1Bmgnt1mW_X2RkAeUxhD13VbawLSf7kqZ8rLci7ymdMV89bVtl14` comes from `insert_keypair` output command.

python cse_cmd.py insert_identity --creds ~/Downloads/google-idp-for-cse-service-account.json --userid blue@cosmian.com --kpid "ANe1Bmgnt1mW_X2RkAeUxhD13VbawLSf7kqZ8rLci7ymdMV89bVtl14" --kpemail blue@cosmian.com
