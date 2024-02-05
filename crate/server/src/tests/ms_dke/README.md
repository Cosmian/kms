<h1>Testing Microsoft Double Key Encryption</h1>

## Prerequisites

Follow the instructions in the main Documentation to configure the tenant for DKE.

Create a sensitivity label in the Microsoft Purview compliance portal, and publish it to the tenant.
The sensitivity label must be configured to uaw Double Key Encryption with an URL set to
`https://dke.acme.com/ms_dke/dke_key` where

- `dke.acme.com` is the address of the comsian KMS server.
- `ms_dke` is the root of REST path for the DKE services.
- `dke_key` is the name of a tag set for the RSA key pair to use for DKE.

## Start the Cosmian KMS server

The cosmian KMS server must be started behind a reverse proxy that exposes a valid TLS certificate on `dke.acme.com`
and which maps the path `/ms_dke` to the corresponding path of the Cosmian KMS server.

Enable DKE in the Cosmian KMS server by setting the `--ms-dke` flag.

```bash
RUST_LOG="cosmian_kms_server=trace" cargo run --bin cosmian_kms_server -- --ms-dke-service-url https://dke.acme.com/ms_dke
```

## Generate a RSA key pair for DKE

Use the provided script to generate a RSA key pair for DKE.

```bash
./generate_dke_key.sh
``` 

## Import the key pair with the proper tags

Import the private key with the tag `dke_key`, with a name `ms_dke_priv_key` and a link to the (future) public
key ` ms_dke_pub_key`.

```bash
cargo run --bin ckms -- ec keys import -f pem -t dke_key -p ms_dke_priv_key crate/server/src/tests/ms_dke/private_key.pkcs8.pem ms_dke_priv_key
```

Import the public key with the tag `dke_key`, with a name `ms_dke_pub_key` and a link to the private
key ` ms_dke_priv_key`

```bash
cargo run --bin ckms -- ec keys import -f pem -t dke_key -k ms_dke_priv_key crate/server/src/tests/ms_dke/public_key.pkcs8.pem ms_dke_pub_key

```

Verify that you can export the keys using the `ckms` command line tool.

```bash
# public key
cargo run --bin ckms -- ec keys export -t dke_key -t _pk -f pkcs1-pem /tmp/pub_key.pkcs1.pem
# private key
cargo run --bin ckms -- ec keys export -t dke_key -t _sk -f pkcs8-pem /tmp/priv_key.pkcs1.pem
```

**Note**: `ec` will be replaced by `rsa` in the near future.

Verify that you can export the keys using a call to the REST API.

```shell
curl https://dke.acme.com/ms_dke/dke_key
```

The response should be similar to the following:

```json
{
  "key": {
    "kty": "RSA",
    "n": "jczTNoUDYX3VDu4UzPRf2uGTXwgZyKUz+lUbxzS3AO0/GbftvqMwu8yp3lxlwH7O9My32tNMAJXJtBSf+DiaD3xIA6HTdOa4dHvIZlIxrNeRyQLuUEu2+qdc5/x1FJmEkuG33xunFeeAUU3CNSO5X+IZ3nS3rdOIL6wwASVJKBPgM9AH95xqmxXQNOFpmbriv/c5VAqd7Ih83H8KBzowsYRNYiWqIJvFVP224p2UNNqpr0WX+QPkgoQYH5hKGRR8bj3BVYhzlEE+4/BQLp2ECfSYCe1kRYqlfSpBRHrrKhZ+VcEsYg/9zbAKPmLc4fRMR66KaG5ANpe7OseVFLHyNQ==",
    "e": 65537,
    "alg": "RS256",
    "kid": "https://dke.cosmian.com/ms_dke/dke_key/ms_dke_pub_key"
  },
  "cache": {
    "exp": "2024-01-17T15:07:06"
  }
}
```


```json
{
  "alg": "RSA-OAEP-256",
  "value": "SowuwT1RuQalev5OCYFhpGaziwOqiTgzQcRfcITsukcBOsX61SejEF91cnx8vQv/gjmovXW4qEV7PpNBKj2GMszHWmFkt877raP02yxch6w0sPEBMaNdfbLIScpsjaPAOmu/i3MAY3dPaAl4duGE3FJCb1O8G98QamB5eQXpJaKcoUGUCeE4hy4qi5k15rQWMU6EmTZ8qL37ugDGo1gRuSsYZmCriPH+sUdiOIXEBJ/UrRIeR+ENPgjBVRSw46sbfdCIee37iROdBRxffHe2p+Ntx1TGMSLhkOc+DU0p+0+cDEicmVXorUfNZCQc7Rof2pIjpUI4Qi3wBCexTnZXgw=="
}
```
```text
 ERROR cosmian_kms_server::routes] 500 Internal Server Error - Cryptographic error: Not Supported: error:0200009F:rsa routines:RSA_padding_check_PKCS1_type_2:pkcs decoding error:crypto/rsa/rsa_pk1.c:269:, error:02000072:rsa routines:rsa_ossl_private_decrypt:padding check failed:crypto/rsa/rsa_ossl.c:499:

```

## JWT

### JWKS
https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-the-signing-key-issuer
"jwks_uri": "https://login.microsoftonline.com/{example-tenant-id}/discovery/v2.0/keys",
https://login.microsoftonline.com/0388f871-53ca-4599-b1f4-642974299c20/discovery/v2.0/keys


https://login.microsoftonline.com/0388f871-53ca-4599-b1f4-642974299c20
https://login.microsoftonline.com/{example-tenant-id}