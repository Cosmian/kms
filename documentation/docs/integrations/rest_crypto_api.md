# REST Native Crypto API (`/v1/crypto`)

The Cosmian KMS exposes a lightweight **REST Native Crypto API** under the `/v1/crypto` path.
This API follows the **JOSE** (JSON Object Signing and Encryption) conventions from
[RFC 7516 (JWE)](https://www.rfc-editor.org/rfc/rfc7516),
[RFC 7515 (JWS)](https://www.rfc-editor.org/rfc/rfc7515), and
[RFC 7518 (JWA)](https://www.rfc-editor.org/rfc/rfc7518).

Key material **never leaves the KMS**. Only ciphertext, signatures, and MACs travel over the network.

---

## Table of Contents

- [Authentication](#authentication)
- [Endpoints](#endpoints)
  - [POST /v1/crypto/encrypt](#post-v1cryptoencrypt)
  - [POST /v1/crypto/decrypt](#post-v1cryptodecrypt)
  - [POST /v1/crypto/sign](#post-v1cryptosign)
  - [POST /v1/crypto/verify](#post-v1cryptoverify)
  - [POST /v1/crypto/mac](#post-v1cryptomac)
- [Error responses](#error-responses)
- [Known limitations](#known-limitations)
- [Algorithm support matrix](#algorithm-support-matrix)

---

## Authentication

The `/v1/crypto` endpoints share the same authentication as the rest of the KMS API.
Pass a JWT bearer token, a TLS client certificate, or an API token, depending on your
server configuration. See [Authentication](../configuration/authentication.md).

---

## Endpoints

### `POST /v1/crypto/encrypt`

Encrypt plaintext using a symmetric key identified by `kid`.

**v1 supports**: `alg=dir` with `enc` in `{A128GCM, A192GCM, A256GCM}`.

#### Request body

```json
{
  "kid": "<key-uuid>",
  "alg": "dir",
  "enc": "A256GCM",
  "data": "<base64url-encoded plaintext>",
  "aad": "<base64url-encoded AAD>"   // optional
}
```

#### Response body (Flattened JWE)

```json
{
  "protected":     "<base64url JWE Protected Header>",
  "encrypted_key": "",
  "iv":            "<base64url IV>",
  "ciphertext":    "<base64url ciphertext>",
  "tag":           "<base64url GCM authentication tag>",
  "aad":           "<base64url AAD>"   // omitted when not supplied
}
```

#### Example (curl)

```bash
# 1. Create a 256-bit AES key
KEY_ID=$(ckms sym keys create -a aes -l 256 | grep 'Unique identifier' | awk '{print $NF}')

# 2. Encrypt
DATA_B64=$(printf 'Hello KMS!' | base64 | tr '+/' '-_' | tr -d '=')
curl -s -X POST https://kms.example.com/v1/crypto/encrypt \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KEY_ID\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"$DATA_B64\"}"
```

---

### `POST /v1/crypto/decrypt`

Decrypt a Flattened JWE token.

#### Request body

```json
{
  "protected":     "<base64url JWE Protected Header>",
  "encrypted_key": "",            // must be empty or absent for "dir"
  "iv":            "<base64url IV>",
  "ciphertext":    "<base64url ciphertext>",
  "tag":           "<base64url GCM authentication tag>",
  "aad":           "<base64url AAD>"  // optional; must match the value used during encryption
}
```

#### Response body

```json
{
  "kid":  "<key-uuid>",
  "data": "<base64url plaintext>"
}
```

#### Example (curl)

```bash
# Continues from the encrypt example; JWE_BODY is the encrypt response JSON
PLAINTEXT=$(curl -s -X POST https://kms.example.com/v1/crypto/decrypt \
  -H 'Content-Type: application/json' \
  -d "$JWE_BODY" | jq -r '.data' | base64 -d)
echo "$PLAINTEXT"
```

---

### `POST /v1/crypto/sign`

Sign data using an asymmetric private key. Returns a **detached JWS** (payload not included
in the response).

**Supported algorithms**: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`,
`ES256`, `ES384`, `ES512`; `EdDSA` and `MLDSA44` (non-FIPS builds only).

#### Request body

```json
{
  "kid":  "<private-key-uuid>",
  "alg":  "RS256",
  "data": "<base64url payload>"
}
```

#### Response body

```json
{
  "protected": "<base64url JWS Protected Header>",
  "signature": "<base64url signature>"
}
```

#### Example (curl)

```bash
# Create RSA-2048 key pair
KEY_IDS=$(ckms rsa keys create --size_in_bits 2048)
PRIV_ID=$(echo "$KEY_IDS" | grep 'Private key' | awk '{print $NF}')

DATA_B64=$(printf 'data to sign' | base64 | tr '+/' '-_' | tr -d '=')
curl -s -X POST https://kms.example.com/v1/crypto/sign \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$PRIV_ID\",\"alg\":\"RS256\",\"data\":\"$DATA_B64\"}"
```

---

### `POST /v1/crypto/verify`

Verify a detached JWS signature. The KMS looks up the public key from the `protected` header.

> **Required**: the JWS protected header decoded from `protected` **must** contain a `kid` field
> set to the KMS public key UUID. Requests without `kid` are rejected with `400`.
> This field is set automatically by `POST /v1/crypto/sign`.

#### Request body

```json
{
  "protected": "<base64url JWS Protected Header (contains kid + alg)>",
  "data":      "<base64url payload>",
  "signature": "<base64url signature>"
}
```

#### Response body

```json
{
  "kid":   "<public-key-uuid>",
  "valid": true   // false when the signature does not match
}
```

#### Example (curl)

```bash
# SIGN_RESP is the response from /v1/crypto/sign
curl -s -X POST https://kms.example.com/v1/crypto/verify \
  -H 'Content-Type: application/json' \
  -d "{\"protected\":$(echo $SIGN_RESP | jq .protected),\"data\":\"$DATA_B64\",\"signature\":$(echo $SIGN_RESP | jq .signature)}"
```

---

### `POST /v1/crypto/mac`

Compute or verify a MAC (Message Authentication Code).

- **Compute**: omit the `mac` field → the KMS returns the computed MAC value.
- **Verify**: include the `mac` field → the KMS returns `valid: true/false`.

**Supported algorithms**: `HS256`, `HS384`, `HS512`.

#### Request body

```json
{
  "kid":  "<key-uuid>",
  "alg":  "HS256",
  "data": "<base64url data>",
  "mac":  "<base64url MAC to verify>"  // omit to compute
}
```

#### Response body — compute

```json
{
  "kid": "<key-uuid>",
  "mac": "<base64url MAC>"
}
```

#### Response body — verify

```json
{
  "kid":   "<key-uuid>",
  "valid": true   // false when the MAC does not match
}
```

#### RFC 7515 §A.1 known-answer vector

The MAC value below is pinned by an integration test (`test_rfc7515_a1_hs256_known_answer`).
It reproduces the exact HS256 result from [RFC 7515 §Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1).

| Field | Value |
|---|---|
| Key (base64url) | `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow` |
| Data | JWS Signing Input from RFC 7515 §A.1 |
| `alg` | `HS256` |
| Expected `mac` | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` |

#### Example (curl)

```bash
# Compute MAC
DATA_B64=$(printf 'message' | base64 | tr '+/' '-_' | tr -d '=')
MAC_RESP=$(curl -s -X POST https://kms.example.com/v1/crypto/mac \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KEY_ID\",\"alg\":\"HS256\",\"data\":\"$DATA_B64\"}")
MAC_VALUE=$(echo "$MAC_RESP" | jq -r '.mac')

# Verify MAC
curl -s -X POST https://kms.example.com/v1/crypto/mac \
  -H 'Content-Type: application/json' \
  -d "{\"kid\":\"$KEY_ID\",\"alg\":\"HS256\",\"data\":\"$DATA_B64\",\"mac\":\"$MAC_VALUE\"}"
```

---

## Error responses

All endpoints return a JSON body `{ "error": "<type>", "description": "<detail>" }` with
an appropriate HTTP status code:

| Status | Meaning |
|--------|---------|
| `400`  | Bad request (malformed base64, missing field, etc.) |
| `403`  | Forbidden (key access denied) |
| `404`  | Key not found |
| `422`  | Unsupported or unknown algorithm |
| `500`  | Internal server error / cryptographic failure |

---

## Known limitations

The following JOSE features are **not yet implemented** in v1 of this API.
They are listed in the test suite (`rfc_vectors.rs`) as blocked.

| Missing feature | Blocked by |
|---|---|
| JWE `alg=RSA-OAEP` (RFC 7516 §A.1) | RSA-OAEP key management not implemented |
| JWE `alg=RSA-PKCS1-v1_5` + `enc=A128CBC-HS256` (RFC 7516 §A.2) | RSA-PKCS1v1.5 + AES-CBC not implemented |
| JWE `alg=A128KW` + `enc=A128CBC-HS256` (RFC 7516 §A.3) | AES key-wrap + AES-CBC not implemented |
| JWE `alg=dir` + `enc=A128CBC-HS256` (RFC 7516 §A.5) | AES-CBC enc not implemented |
| JWE `alg=ECDH-ES` (RFC 7518 §C) | ECDH-ES key agreement not implemented |
| JWS verify without `kid` in protected header | `kid`-less verify not yet supported |

> Full RFC 7515 §A.2/A.3/A.4 known-answer tests are deferred until kid-less
> verification is supported (current tests do round-trips with freshly generated keys).

---

## Algorithm support matrix

| Algorithm   | FIPS | Operation         |
|-------------|------|-------------------|
| `dir`       | ✓    | encrypt / decrypt |
| `A128GCM`   | ✓    | enc (with dir)    |
| `A192GCM`   | ✓    | enc (with dir)    |
| `A256GCM`   | ✓    | enc (with dir)    |
| `RS256/384/512` | ✓ | sign / verify   |
| `PS256/384/512` | ✓ | sign / verify   |
| `ES256/384/512` | ✓ | sign / verify   |
| `EdDSA`     | ✗    | sign / verify (non-FIPS) |
| `MLDSA44`   | ✗    | sign / verify (non-FIPS) |
| `HS256/384/512` | ✓ | mac compute / verify |
