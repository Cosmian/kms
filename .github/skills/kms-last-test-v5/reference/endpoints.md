# HTTP Endpoints Reference

## Contents
- [Core endpoints](#core-endpoints)
- [Access control](#access-control)
- [Enterprise integrations](#enterprise-integrations)
- [Tokenize (non-fips)](#tokenize-non-fips)
- [JOSE REST Crypto API](#jose-rest-crypto-api)
- [JWKS endpoint](#jwks-endpoint)
- [JOSE supported algorithms](#jose-supported-algorithms)
- [JOSE error format](#jose-error-format)
- [JWKS key eligibility rules](#jwks-key-eligibility-rules)
- [curl examples](#curl-examples)

---

## Core endpoints

| Path          | Method | Auth | Purpose                      |
| ------------- | ------ | ---- | ---------------------------- |
| `/health`     | GET    | No   | Health check + DB status     |
| `/version`    | GET    | No   | Server version string        |
| `/server-info`| GET    | No   | Version, FIPS mode, HSM info |
| `/kmip/2_1`   | POST   | Yes  | Main KMIP 2.1 endpoint       |

---

## Access control

| Path                  | Method | Auth | Purpose                        |
| --------------------- | ------ | ---- | ------------------------------ |
| `/access/owned`       | GET    | Yes  | List objects owned by user     |
| `/access/obtained`    | GET    | Yes  | List access rights obtained    |
| `/access/list/{id}`   | GET    | Yes  | List accesses for object       |
| `/access/grant`       | POST   | Yes  | Grant access                   |
| `/access/revoke`      | POST   | Yes  | Revoke access                  |
| `/access/create`      | GET    | Yes  | Check create permission        |
| `/access/privileged`  | GET    | Yes  | Check privileged access        |

Other: `/download-cli` (GET/HEAD, Yes), `/ui/**` (GET, Varies), `/ui-auth/login`, `/ui-auth/logout`, `/ui-auth/oidc-callback`.

---

## Enterprise integrations

### AWS XKS

| Path                   | Method | Auth   | Purpose       |
| ---------------------- | ------ | ------ | ------------- |
| `/aws/encrypt`         | POST   | SigV4  | XKS encrypt   |
| `/aws/decrypt`         | POST   | SigV4  | XKS decrypt   |
| `/aws/health`          | GET    | SigV4  | XKS health    |
| `/aws/metadata/{keyId}`| GET    | SigV4  | Key metadata  |

### Azure EKM

| Path                           | Method | Auth | Purpose       |
| ------------------------------ | ------ | ---- | ------------- |
| `/azureekm/metadata/{keyName}` | GET    | mTLS | Key metadata  |
| `/azureekm/wrap`               | POST   | mTLS | Wrap key      |
| `/azureekm/unwrap`             | POST   | mTLS | Unwrap key    |

### Google CSE

| Path                  | Method | Auth | Purpose        |
| --------------------- | ------ | ---- | -------------- |
| `/google_cse/status`  | GET    | JWT  | CSE status     |
| `/google_cse/wrap`    | POST   | JWT  | Wrap key       |
| `/google_cse/unwrap`  | POST   | JWT  | Unwrap key     |
| `/google_cse/rewrap`  | POST   | JWT  | Re-wrap key    |
| `/google_cse/digest`  | POST   | JWT  | Hash/digest    |
| `/google_cse/certs`   | GET    | JWT  | Get certs      |

### MS DKE

| Path                                     | Method | Auth | Purpose        |
| ---------------------------------------- | ------ | ---- | -------------- |
| `/ms_dke/version`                        | GET    | No   | DKE version    |
| `/ms_dke/{keyName}/{keyVersion}`         | GET    | No   | Get public key |
| `/ms_dke/{keyName}/{keyVersion}/decrypt` | POST   | No   | Decrypt        |

---

## Tokenize (non-fips)

All `POST`, auth varies:
`/tokenize/hash`, `/tokenize/noise`, `/tokenize/word_mask`, `/tokenize/word_tokenize`, `/tokenize/word_pattern_mask`, `/tokenize/aggregate_number`, `/tokenize/aggregate_date`, `/tokenize/scale_number`

---

## JOSE REST Crypto API

| Path                         | Method | Auth | Purpose                                        |
| ---------------------------- | ------ | ---- | ---------------------------------------------- |
| `/v1/crypto/keys`            | POST   | Yes  | Generate or import a JWK-style key             |
| `/v1/crypto/keys/{kid}`      | DELETE | Yes  | Destroy a key (revoke-then-destroy)            |
| `/v1/crypto/keys/unwrap`     | POST   | Yes  | Import wrapped CEK (JWE) without plaintext     |
| `/v1/crypto/keys/{kid}/tags` | POST   | Yes  | Add user tags                                  |
| `/v1/crypto/keys/{kid}/tags` | DELETE | Yes  | Remove user tags                               |
| `/v1/crypto/keys/{kid}/tags` | GET    | Yes  | List tags                                      |
| `/v1/crypto/encrypt`         | POST   | Yes  | JWE content encryption (Flattened JSON)        |
| `/v1/crypto/decrypt`         | POST   | Yes  | JWE content decryption                         |
| `/v1/crypto/sign`            | POST   | Yes  | Detached JWS signature (RFC 7515)              |
| `/v1/crypto/verify`          | POST   | Yes  | Verify detached JWS signature                  |
| `/v1/crypto/mac`             | POST   | Yes  | HMAC compute or verify (if `mac` field present)|

---

## JWKS endpoint

| Path                        | Method | Auth | Purpose                                                   |
| --------------------------- | ------ | ---- | --------------------------------------------------------- |
| `/.well-known/jwks.json`    | GET    | No   | RFC 7517 public key set (only when `jwks_endpoint_enabled=true`) |

---

## JOSE supported algorithms

| Algorithm         | Type               | Key types | FIPS? | Notes                           |
| ----------------- | ------------------ | --------- | ----- | ------------------------------- |
| `dir`             | Key management     | `oct`     | Yes   | Direct key agreement (JWE)      |
| `RSA-OAEP`        | Key management     | `RSA`     | Yes   | RSA-OAEP SHA-1 (JWE key wrap)   |
| `RSA-OAEP-256`    | Key management     | `RSA`     | Yes   | RSA-OAEP SHA-256 (JWE key wrap) |
| `RS256/384/512`   | Signature          | `RSA`     | Yes   | PKCS#1 v1.5 (JWS)               |
| `PS256/384/512`   | Signature          | `RSA`     | Yes   | RSA-PSS (JWS)                   |
| `ES256/384/512`   | Signature          | `EC`      | Yes   | ECDSA P-256/P-384/P-521 (JWS)   |
| `HS256/384/512`   | MAC                | `oct`     | Yes   | HMAC-SHA-256/384/512            |
| `EdDSA`           | Signature          | `OKP`     | No    | Ed25519 — `non-fips` only       |
| `A128/192/256GCM` | Content encryption | `oct`     | Yes   | AES-GCM `enc` algorithms (JWE)  |

---

## JOSE error format

```json
{ "error": "BadRequest", "description": "..." }
```

| Error variant        | HTTP | Trigger                                      |
| -------------------- | ---- | -------------------------------------------- |
| `BadRequest`         | 400  | Malformed base64url, missing fields          |
| `UnsupportedAlgorithm` | 422 | Unknown JOSE algorithm identifier           |
| `Forbidden`          | 403  | Caller not authorised to use the key         |
| `NotFound`           | 404  | KMS object UID not found                     |
| `CryptoFailure`      | 422  | Wrong key type, size mismatch                |
| `DecryptionFailed`   | 422  | Uniform decryption error (oracle prevention) |
| `InternalError`      | 500  | Unexpected server error                      |

---

## JWKS key eligibility rules

- Only keys tagged `"jwks"` with `Verify` in `CryptographicUsageMask` and in `Active` or `Deactivated` state are served.
- `POST /v1/crypto/keys` auto-tags created key pairs with `"jwks"` unless `KMS_JWKS_ENDPOINT_AUTO_TAG=false`.
- Response includes `Cache-Control: no-store` and a weak `ETag` (SHA-256 of body). Clients may use `If-None-Match` for `304 Not Modified`.
- When more than `jwks_endpoint_max_keys` (default: 50) eligible keys exist, the response is truncated and `X-JWKS-Truncated: true` is set.
- The endpoint is unauthenticated — no auth middleware applied.
- Route is only registered when `jwks_endpoint_enabled = true`; disabled returns `404`.

---

## curl examples

### Raw KMIP request

```bash
curl -s -X POST http://127.0.0.1:9998/kmip/2_1 \
  -H "Content-Type: application/json" \
  -d '{
    "tag": "Create",
    "value": [
      {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
      {"tag": "Attributes", "value": [
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
        {"tag": "CryptographicLength", "type": "Integer", "value": 256}
      ]}
    ]
  }' | jq .
```

### Tokenize

```bash
curl -s -X POST http://127.0.0.1:9998/tokenize/hash \
  -H "Content-Type: application/json" \
  -d '{"data": "hello world", "method": "SHA2"}' | jq .
```

### MS DKE public key

```bash
curl -s http://127.0.0.1:9998/ms_dke/my-key-name/my-key-version | jq .
```

### JOSE full roundtrip (sign + verify + JWKS)

Requires `jwks_endpoint_enabled = true` in server config.

```bash
# Generate EC P-256 signing key pair (auto-tagged "jwks")
KID=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"EC","alg":"ES256"}' | jq -r .kid)

# Sign (detached JWS, RFC 7515)
PAYLOAD=$(echo -n '{"sub":"test","iss":"kms"}' | base64 | tr '+/' '-_' | tr -d '=')
SIGN_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/sign \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$KID\",\"alg\":\"ES256\",\"data\":\"$PAYLOAD\"}")
PROTECTED=$(echo "$SIGN_RESP" | jq -r .protected)
SIG=$(echo "$SIGN_RESP" | jq -r .signature)

# Verify
curl -s -X POST http://127.0.0.1:9998/v1/crypto/verify \
  -H "Content-Type: application/json" \
  -d "{\"protected\":\"$PROTECTED\",\"data\":\"$PAYLOAD\",\"signature\":\"$SIG\"}" | jq .
# Expected: {"kid":"...","valid":true}

# Fetch JWKS
curl -s http://127.0.0.1:9998/.well-known/jwks.json | jq .

# AES-GCM JWE roundtrip
SYM_KID=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"oct","alg":"A256GCM"}' | jq -r .kid)
PLAINTEXT=$(echo -n 'hello world' | base64 | tr '+/' '-_' | tr -d '=')
ENC_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/encrypt \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$SYM_KID\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"$PLAINTEXT\"}")
curl -s -X POST http://127.0.0.1:9998/v1/crypto/decrypt \
  -H "Content-Type: application/json" \
  -d "$ENC_RESP" | jq .
# Expected: {"kid":"...","data":"aGVsbG8gd29ybGQ"}

# HMAC compute + verify
HMAC_KID=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"oct","alg":"HS256"}' | jq -r .kid)
DATA=$(echo -n 'message to authenticate' | base64 | tr '+/' '-_' | tr -d '=')
MAC_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/mac \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$HMAC_KID\",\"alg\":\"HS256\",\"data\":\"$DATA\"}")
MAC=$(echo "$MAC_RESP" | jq -r .mac)
curl -s -X POST http://127.0.0.1:9998/v1/crypto/mac \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$HMAC_KID\",\"alg\":\"HS256\",\"data\":\"$DATA\",\"mac\":\"$MAC\"}" | jq .
# Expected: {"kid":"...","valid":true}

# Delete a key
curl -s -X DELETE http://127.0.0.1:9998/v1/crypto/keys/$KID
# Expected: HTTP 204 No Content
```
