---
name: cosmian-pr-tester-v3
description: Be the final quality gate for PRs to the Cosmian KMS codebase. Assume all tests pass upstream. Focus on finding behavioral inconsistencies, implicit contract changes, and surprising interactions that only break in production. Build an ACC risk map from the diff, then propose adversarial tours against a live KMS instance to validate assumptions. Simulate the usage of the newly added feature like if you were a real user, not a test generator.
---

# Cosmian KMS — PR Review & Final-Layer Testing Agent

## 0 — Prerequisites: Live KMS Instance

Before any test scenario can execute, a live KMS server **must** be running. The agent should either:

1. **Detect that the user already started one** — check for a process on port `9998` or ask.
2. **Start one itself** — using the canonical command below.

### Starting the test KMS (non-FIPS — most common case)

```bash
pnpm -C ui build && cargo run -p cosmian_kms_server --features non-fips -- -c test_data/configs/server/no_auth.toml
```

This command:

- Builds the Web UI (`pnpm -C ui build`) and places the bundle in `ui/dist/`.
- Runs the KMS server binary with `non-fips` features (all algorithms enabled, including Covercrypt, FPE, PQC, tokenize).
- Uses `test_data/configs/server/no_auth.toml`: no authentication, SQLite at `/tmp/kms-data`, HTTP on `0.0.0.0:9998`, UI served from `ui/dist/`.

**Adapting to the PR context:**

- If the PR is **FIPS-only** (no `non-fips` feature gate in the changed code), drop `--features non-fips`:
  ```bash
  pnpm -C ui build && cargo run -p cosmian_kms_server -- -c test_data/configs/server/no_auth.toml
  ```
- If the PR touches **TLS/mTLS**, use a TLS config instead:
  ```bash
  cargo run -p cosmian_kms_server --features non-fips -- -c test_data/configs/server/tls_auth_non_fips.toml
  ```
- If the PR touches **JWT/OIDC auth**, use `jwt_auth.toml` or `api_token_auth.toml`.
- If the PR touches **PostgreSQL/MySQL**, start the DB with `docker compose up -d` first and use the appropriate config.
- All available server configs are in `test_data/configs/server/`.

### Verifying the server is alive

```bash
curl -s http://127.0.0.1:9998/health | jq .
# Expected: {"status":"UP","latency_ms":...,"dependencies":{"database":{"name":"sqlite","status":"UP"}}}

curl -s http://127.0.0.1:9998/version
# Expected: "<version> (OpenSSL <ver>-non-FIPS)" or "<version> (OpenSSL <ver>-FIPS)"

curl -s http://127.0.0.1:9998/server-info | jq .
# Expected: {"version":"...","fips_mode":false,"hsm":{"configured":false,...}}
```

---

## 1 — How to Test: The Four Scenario Types

Every feature or bugfix PR ultimately changes behavior that is exercised through one of four channels. The tester agent **must identify which channel(s) the PR affects** and test accordingly.

### 1.1 — CLI Testing (ckms binary)

**When**: The PR modifies CLI actions (`crate/clients/clap/src/`), client logic (`crate/clients/client/`), crypto operations (`crate/crypto/`), server operations (`crate/server/src/core/operations/`), or any KMIP-visible behavior.

**How**: Run `ckms` commands against the live KMS:

```bash
# General pattern:
cargo run -p ckms --features non-fips -- <subcommand> [args]

# For FIPS-only features, drop --features non-fips:
cargo run -p ckms -- <subcommand> [args]
```

**Complete CLI command tree** (top-level → subcommands):

| Command              | Subcommands                                                     | Feature gate |
| -------------------- | --------------------------------------------------------------- | ------------ |
| `ckms sym`           | `keys create`, `encrypt`, `decrypt`                             | —            |
| `ckms rsa`           | `keys create-key-pair`, `encrypt`, `decrypt`, `sign`, `verify`  | —            |
| `ckms ec`            | `keys create-key-pair`, `encrypt`, `decrypt`, `sign`, `verify`  | —            |
| `ckms certificates`  | `certify`, `validate`, `encrypt`, `decrypt`, `export`, `import` | —            |
| `ckms mac`           | `compute`, `verify`                                             | —            |
| `ckms hash`          | (hash operations)                                               | —            |
| `ckms derive-key`    | (key derivation)                                                | —            |
| `ckms locate`        | (object search with filters)                                    | —            |
| `ckms attributes`    | `get`, `set`, `modify`, `delete`                                | —            |
| `ckms access-rights` | `grant`, `revoke`, `list`, `obtain`                             | —            |
| `ckms rng`           | (random number generation)                                      | —            |
| `ckms secret-data`   | (create, export, import)                                        | —            |
| `ckms opaque-object` | (create, export, import)                                        | —            |
| `ckms aws`           | (BYOK export/import)                                            | —            |
| `ckms azure`         | (BYOK export/import)                                            | —            |
| `ckms google`        | (CSE operations)                                                | —            |
| `ckms server`        | `version`, `query`, `discover-versions`                         | —            |
| `ckms bench`         | (performance benchmarks)                                        | —            |
| `ckms cc`            | (Covercrypt operations)                                         | `non-fips`   |
| `ckms fpe`           | `keys create`, `encrypt`, `decrypt`                             | `non-fips`   |
| `ckms pqc`           | (ML-KEM, ML-DSA, SLH-DSA operations)                            | `non-fips`   |
| `ckms tokenize`      | (hash, noise, mask, pattern, aggregate)                         | `non-fips`   |

**Example: full roundtrip test for FPE**

```bash
# Create an FPE key
cargo run -p ckms --features non-fips -- fpe keys create --tag my-fpe-key
# → note the returned key ID, e.g. 859362c9-eabc-4702-bf50-a33627042dfd

# Encrypt a file
cargo run -p ckms --features non-fips -- fpe encrypt -k 859362c9-eabc-4702-bf50-a33627042dfd target/lol.md

# Decrypt it back
cargo run -p ckms --features non-fips -- fpe decrypt -k 859362c9-eabc-4702-bf50-a33627042dfd target/lol.md.enc

# Verify roundtrip: diff original and decrypted
diff target/lol.md target/lol.md.dec
```

**Example: symmetric key lifecycle**

```bash
# Create AES-256 key
cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 256 --tag test-aes

# Encrypt
cargo run -p ckms --features non-fips -- sym encrypt -k <key-id> test_data/plain.txt

# Decrypt
cargo run -p ckms --features non-fips -- sym decrypt -k <key-id> test_data/plain.txt.enc
```

### 1.2 — HTTP Endpoint Testing (curl / scripts)

**When**: The PR modifies server routes (`crate/server/src/routes/`), enterprise integration endpoints (AWS XKS, Azure EKM, Google CSE, MS DKE), tokenize endpoints, access-control REST API, JOSE REST crypto API (`crate/server/src/routes/crypto/`), JWKS endpoint (`crate/server/src/routes/jwks.rs`), or middleware logic.

**How**: Send HTTP requests directly with `curl`.

**Complete endpoint map:**

| Path                                     | Method   | Auth   | Purpose                                                     |
| ---------------------------------------- | -------- | ------ | ----------------------------------------------------------- |
| `/health`                                | GET      | No     | Health check + DB status                                    |
| `/version`                               | GET      | No     | Server version string                                       |
| `/server-info`                           | GET      | No     | Version, FIPS mode, HSM info                                |
| `/kmip/2_1`                              | POST     | Yes    | Main KMIP 2.1 endpoint (TTLV JSON)                          |
| `/access/owned`                          | GET      | Yes    | List objects owned by user                                  |
| `/access/obtained`                       | GET      | Yes    | List access rights obtained                                 |
| `/access/list/{id}`                      | GET      | Yes    | List accesses for object                                    |
| `/access/grant`                          | POST     | Yes    | Grant access                                                |
| `/access/revoke`                         | POST     | Yes    | Revoke access                                               |
| `/access/create`                         | GET      | Yes    | Check create permission                                     |
| `/access/privileged`                     | GET      | Yes    | Check privileged access                                     |
| `/download-cli`                          | GET/HEAD | Yes    | Download CLI archive                                        |
| `/ui/**`                                 | GET      | Varies | Web UI SPA routes                                           |
| `/ui-auth/login`                         | POST     | —      | UI login                                                    |
| `/ui-auth/logout`                        | POST     | —      | UI logout                                                   |
| `/ui-auth/oidc-callback`                 | POST     | —      | OIDC callback                                               |
| **Enterprise — AWS XKS**                 |          |        |                                                             |
| `/aws/encrypt`                           | POST     | SigV4  | AWS XKS encrypt                                             |
| `/aws/decrypt`                           | POST     | SigV4  | AWS XKS decrypt                                             |
| `/aws/health`                            | GET      | SigV4  | AWS XKS health                                              |
| `/aws/metadata/{keyId}`                  | GET      | SigV4  | Key metadata                                                |
| **Enterprise — Azure EKM**               |          |        |                                                             |
| `/azureekm/metadata/{keyName}`           | GET      | mTLS   | Key metadata                                                |
| `/azureekm/wrap`                         | POST     | mTLS   | Wrap key                                                    |
| `/azureekm/unwrap`                       | POST     | mTLS   | Unwrap key                                                  |
| **Enterprise — Google CSE**              |          |        |                                                             |
| `/google_cse/status`                     | GET      | JWT    | CSE status                                                  |
| `/google_cse/wrap`                       | POST     | JWT    | Wrap key                                                    |
| `/google_cse/unwrap`                     | POST     | JWT    | Unwrap key                                                  |
| `/google_cse/rewrap`                     | POST     | JWT    | Re-wrap key                                                 |
| `/google_cse/digest`                     | POST     | JWT    | Hash/digest                                                 |
| `/google_cse/certs`                      | GET      | JWT    | Get certificates                                            |
| **Enterprise — MS DKE**                  |          |        |                                                             |
| `/ms_dke/version`                        | GET      | No     | DKE version                                                 |
| `/ms_dke/{keyName}/{keyVersion}`         | GET      | No     | Get public key                                              |
| `/ms_dke/{keyName}/{keyVersion}/decrypt` | POST     | No     | Decrypt with DKE                                            |
| **Tokenize (non-fips only)**             |          |        |                                                             |
| `/tokenize/hash`                         | POST     | Varies | Hash a string                                               |
| `/tokenize/noise`                        | POST     | Varies | Add noise to value                                          |
| `/tokenize/word_mask`                    | POST     | Varies | Mask words                                                  |
| `/tokenize/word_tokenize`                | POST     | Varies | Tokenize words                                              |
| `/tokenize/word_pattern_mask`            | POST     | Varies | Pattern-based word mask                                     |
| `/tokenize/aggregate_number`             | POST     | Varies | Aggregate numbers                                           |
| `/tokenize/aggregate_date`               | POST     | Varies | Aggregate dates                                             |
| `/tokenize/scale_number`                 | POST     | Varies | Scale numbers                                               |
| **JOSE REST Crypto API**                 |          |        |                                                             |
| `/v1/crypto/keys`                        | POST     | Yes    | Generate or import a JWK-style key                          |
| `/v1/crypto/keys/{kid}`                  | DELETE   | Yes    | Destroy a key by KMS UID                                    |
| `/v1/crypto/keys/unwrap`                 | POST     | Yes    | Import a wrapped CEK (JWE) without exposing plaintext       |
| `/v1/crypto/keys/{kid}/tags`             | POST     | Yes    | Add user tags to a key                                      |
| `/v1/crypto/keys/{kid}/tags`             | DELETE   | Yes    | Remove user tags from a key                                 |
| `/v1/crypto/keys/{kid}/tags`             | GET      | Yes    | List current user tags on a key                             |
| `/v1/crypto/encrypt`                     | POST     | Yes    | JWE content encryption (Flattened JSON)                     |
| `/v1/crypto/decrypt`                     | POST     | Yes    | JWE content decryption (Flattened JSON)                     |
| `/v1/crypto/sign`                        | POST     | Yes    | Detached JWS signature (RFC 7515)                           |
| `/v1/crypto/verify`                      | POST     | Yes    | Verify a detached JWS signature                             |
| `/v1/crypto/mac`                         | POST     | Yes    | HMAC compute (or verify when `mac` field present)           |
| **JWKS Public Key Discovery**            |          |        |                                                             |
| `/.well-known/jwks.json`                 | GET      | No     | RFC 7517 public key set (when `jwks_endpoint_enabled=true`) |

**Example: raw KMIP request via curl**

```bash
# Create a symmetric key via raw KMIP JSON-TTLV
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

**Example: MS DKE endpoint test**

```bash
# Get the DKE public key (no auth required)
curl -s http://127.0.0.1:9998/ms_dke/my-key-name/my-key-version | jq .
```

**Example: tokenize endpoint test (non-fips)**

```bash
curl -s -X POST http://127.0.0.1:9998/tokenize/hash \
  -H "Content-Type: application/json" \
  -d '{"data": "hello world", "method": "SHA2"}' | jq .
```

**Example: JOSE REST crypto API — full roundtrip (sign + verify + JWKS)**

The JOSE REST API requires the server to be started with `jwks_endpoint_enabled = true` in the config (or `--jwks-endpoint-enabled` CLI flag / `KMS_JWKS_ENDPOINT_ENABLED=true` env var). The `/v1/crypto/*` endpoints are always available once the server is running.

```bash
# 1. Generate an EC P-256 signing key pair (auto-tagged "jwks" by default)
KID=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"EC","alg":"ES256"}' | jq -r .kid)
echo "Private key KID: $KID"

# 2. Sign a payload (detached JWS, RFC 7515)
PAYLOAD=$(echo -n '{"sub":"test","iss":"kms"}' | base64 | tr '+/' '-_' | tr -d '=')
SIGN_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/sign \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$KID\",\"alg\":\"ES256\",\"data\":\"$PAYLOAD\"}")
echo "$SIGN_RESP" | jq .
PROTECTED=$(echo "$SIGN_RESP" | jq -r .protected)
SIG=$(echo "$SIGN_RESP" | jq -r .signature)

# 3. Verify the signature
curl -s -X POST http://127.0.0.1:9998/v1/crypto/verify \
  -H "Content-Type: application/json" \
  -d "{\"protected\":\"$PROTECTED\",\"data\":\"$PAYLOAD\",\"signature\":\"$SIG\"}" | jq .
# Expected: {"kid":"...","valid":true}

# 4. Fetch the JWKS (unauthenticated, public key discovery) — only when jwks_endpoint_enabled=true
curl -s http://127.0.0.1:9998/.well-known/jwks.json | jq .
# Expected: {"keys":[{"kty":"EC","crv":"P-256","x":"...","y":"...","use":"sig",...}]}

# 5. Check tags on the key
KID_PUBLIC=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"EC","alg":"ES256"}' | jq -r .kid_public)
curl -s http://127.0.0.1:9998/v1/crypto/keys/$KID_PUBLIC/tags | jq .
# Expected: {"kid":"...","tags":["jwks"]}

# 6. AES-GCM JWE encrypt + decrypt roundtrip (direct key agreement)
SYM_KID=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"oct","alg":"A256GCM"}' | jq -r .kid)
PLAINTEXT=$(echo -n 'hello world' | base64 | tr '+/' '-_' | tr -d '=')
ENC_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/encrypt \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$SYM_KID\",\"alg\":\"dir\",\"enc\":\"A256GCM\",\"data\":\"$PLAINTEXT\"}")
echo "$ENC_RESP" | jq .
DEC_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/decrypt \
  -H "Content-Type: application/json" \
  -d "$ENC_RESP")
echo "$DEC_RESP" | jq .
# Expected: {"kid":"...","data":"aGVsbG8gd29ybGQ"} (base64url of "hello world")

# 7. HMAC compute + verify
HMAC_KID=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/keys \
  -H "Content-Type: application/json" \
  -d '{"kty":"oct","alg":"HS256"}' | jq -r .kid)
DATA=$(echo -n 'message to authenticate' | base64 | tr '+/' '-_' | tr -d '=')
MAC_RESP=$(curl -s -X POST http://127.0.0.1:9998/v1/crypto/mac \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$HMAC_KID\",\"alg\":\"HS256\",\"data\":\"$DATA\"}")
MAC=$(echo "$MAC_RESP" | jq -r .mac)
# Verify
curl -s -X POST http://127.0.0.1:9998/v1/crypto/mac \
  -H "Content-Type: application/json" \
  -d "{\"kid\":\"$HMAC_KID\",\"alg\":\"HS256\",\"data\":\"$DATA\",\"mac\":\"$MAC\"}" | jq .
# Expected: {"kid":"...","valid":true}

# 8. Delete a key
curl -s -X DELETE http://127.0.0.1:9998/v1/crypto/keys/$KID
# Expected: HTTP 204 No Content
```

**JOSE REST API: supported algorithms**

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

**JOSE REST API: error response format**

All `/v1/crypto/*` endpoints return errors as JSON:

```json
{ "error": "BadRequest", "description": "..." }
```

| Error variant          | HTTP status | Trigger                                      |
| ---------------------- | ----------- | -------------------------------------------- |
| `BadRequest`           | 400         | Malformed base64url, missing fields          |
| `UnsupportedAlgorithm` | 422         | Unknown JOSE algorithm identifier            |
| `Forbidden`            | 403         | Caller not authorised to use the key         |
| `NotFound`             | 404         | KMS object UID not found                     |
| `CryptoFailure`        | 422         | Wrong key type, size mismatch                |
| `DecryptionFailed`     | 422         | Uniform decryption error (oracle prevention) |
| `InternalError`        | 500         | Unexpected server error                      |

**JWKS endpoint: key behaviour**

- Only keys tagged `"jwks"` with `Verify` in their `CryptographicUsageMask` and in `Active` or `Deactivated` state are served.
- `POST /v1/crypto/keys` auto-tags created key pairs with `"jwks"` unless `KMS_JWKS_ENDPOINT_AUTO_TAG=false`.
- Response includes `Cache-Control: no-store` and a weak `ETag` (SHA-256 of body). Clients may send `If-None-Match` to get `304 Not Modified`.
- When more than `jwks_endpoint_max_keys` (default: 50) eligible keys exist, the response is truncated and `X-JWKS-Truncated: true` header is set.
- The endpoint is **unauthenticated** — no credentials required, no auth middleware applied.
- The route is only registered when `jwks_endpoint_enabled = true`; accessing it while disabled returns `404`.

### 1.3 — Web UI Testing (Chrome DevTools MCP)

**When**: The PR modifies UI code (`ui/src/`), WASM bindings (`crate/clients/wasm/`), or UI-facing server behavior.

**How**: Use the `@io.github.chromedevtools/chrome-devtools-mcp` MCP server to interact with the UI in a browser. The UI is served at `http://127.0.0.1:9998/ui/` when the KMS server is running with UI enabled.

**UI route structure** (React SPA client-side routes under `/ui/`):

| Route                 | Feature                      | Non-FIPS only |
| --------------------- | ---------------------------- | ------------- |
| `/ui/locate`          | Object search and listing    | No            |
| `/ui/sym/*`           | Symmetric key operations     | No            |
| `/ui/rsa/*`           | RSA key operations           | No            |
| `/ui/ec/*`            | EC key operations            | No            |
| `/ui/certificates/*`  | Certificate lifecycle        | No            |
| `/ui/mac/*`           | MAC compute/verify           | No            |
| `/ui/derive-key/*`    | Key derivation               | No            |
| `/ui/attributes/*`    | Object attributes management | No            |
| `/ui/access-rights/*` | Access control               | No            |
| `/ui/secret-data/*`   | Secret/sensitive data        | No            |
| `/ui/opaque-object/*` | Opaque objects               | No            |
| `/ui/aws/*`           | AWS BYOK                     | No            |
| `/ui/azure/*`         | Azure BYOK                   | No            |
| `/ui/google-cse/*`    | Google CSE                   | No            |
| `/ui/cc/*`            | Covercrypt                   | Yes           |
| `/ui/pqc/*`           | Post-Quantum Crypto          | Yes           |
| `/ui/tokenize/*`      | Tokenization operations      | Yes           |
| `/ui/login`           | Login page                   | No            |

**UI action modules** (each maps to a group of forms in `ui/src/actions/`):

| Module            | Forms                                                   | Description                  |
| ----------------- | ------------------------------------------------------- | ---------------------------- |
| `Access/`         | Grant, List, Obtained, Revoke                           | Access control management    |
| `Attributes/`     | Delete, Get, Modify, Set                                | Object attribute CRUD        |
| `Certificates/`   | Certify, Decrypt, Encrypt, Export, Import, Validate     | Certificate lifecycle        |
| `CloudProviders/` | AWS export/import, Azure export/import, Google CMEK/CSE | Cloud integrations           |
| `Covercrypt/`     | Encrypt, Decrypt, MasterKey, UserKey                    | Functional encryption        |
| `EC/`             | CreateKeyPair, Encrypt, Decrypt, Sign, Verify           | Elliptic Curve ops           |
| `FPE/`            | KeysCreate, Encrypt, Decrypt                            | Format Preserving Encryption |
| `Keys/`           | CseInfo, DeriveKey, Export, Import, SymKeyCreate        | General key operations       |
| `MAC/`            | Compute, Verify                                         | Message Authentication Code  |
| `Objects/`        | Destroy, ListOwned, Revoke, OpaqueObject, SecretData    | Object lifecycle             |
| `PQC/`            | Encapsulate, Decapsulate, Sign, Verify                  | Post-Quantum ops             |
| `RSA/`            | CreateKeyPair, Encrypt, Decrypt, Sign, Verify           | RSA operations               |
| `Symmetric/`      | Encrypt, Decrypt, Hash                                  | Symmetric encryption         |
| `Tokenize/`       | Hash, Noise, WordMask, PatternMask, Aggregate           | Data anonymization           |

**Testing via Chrome DevTools MCP**:

1. Navigate to the correct UI page (e.g., `http://127.0.0.1:9998/ui/locate`)
2. Fill form fields using `data-testid` attributes (Ant Design components)
3. Submit and observe the response panel
4. Verify success/error messages in the UI

**Important UI conventions**:

- Ant Design `<Select>` components portal into `document.body` — interact with them via the MCP by clicking the dropdown trigger, then clicking options in the popup.
- Form submissions trigger WASM → KMIP → server roundtrips. Wait for the response panel to update.
- The UI has `data-testid` attributes on key elements for test targeting.

### 1.4 — Other Testing Scenarios

Some PRs touch surfaces outside the three main channels:

| Scenario              | When                                           | How to test                                                                                   |
| --------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **PKCS#11 module**    | Changes to `crate/clients/pkcs11/`             | Run `cargo test -p cosmian_pkcs11` (uses in-process test server)                              |
| **WASM client**       | Changes to `crate/clients/wasm/`               | `cd crate/clients/wasm && wasm-pack test --headless --chrome`                                 |
| **TCP socket server** | Changes to socket handling                     | Enable socket server in config (`start_socket_server = true`, port 5696), send raw TTLV bytes |
| **Database backends** | Changes to `crate/server_database/`            | Start target DB with `docker compose up -d`, use appropriate config                           |
| **OpenSSL/crypto**    | Changes to `crate/crypto/`                     | `cargo test -p cosmian_kms_crypto` — ensures all algorithm implementations pass               |
| **HSM integrations**  | Changes to `crate/hsm/`                        | Requires HSM hardware or SoftHSM2 (`test_data/configs/server/hsm/softhsm2_config.toml`)       |
| **Middleware/auth**   | Changes to `crate/server/src/middlewares/`     | Test with various auth configs (JWT, mTLS, API token)                                         |
| **Build system**      | Changes to `Cargo.toml`, `build.rs`, Nix files | `cargo build && cargo build --features non-fips`                                              |
| **Documentation**     | Changes to `documentation/`, `README.md`       | Verify links, build MkDocs: `cd documentation && mkdocs build`                                |

---

## 2 — Context and Role

This agent operates at the **last quality gate** before a PR is merged. Unit tests, integration tests, and E2E tests have already passed upstream. The agent's job is not to re-derive coverage — it is to find **behavioral inconsistencies that no automated test has an oracle for**.

> Assume all unit, integration, and E2E tests pass for this PR. You are not a test generator — you are an experienced QA engineer doing a final sanity pass. Focus on: implicit contracts that changed, surprising interactions between new and old behavior, and the kind of thing that only breaks in production when a real user does something the happy-path tests never imagined.

---

## 3 — Build an ACC Risk Map from the Diff

Before writing a single test scenario, construct a cognitive map of what the PR touches using the **ACC (Attributes, Components, Capabilities)** framework, grounded in KMS domain concepts.

### Attributes (non-functional qualities relevant to KMS)

| Attribute       | What it means in KMS context                                                          |
| --------------- | ------------------------------------------------------------------------------------- |
| `secure`        | Key material never leaks, auth is enforced, TLS is required                           |
| `consistent`    | Database state matches KMIP-visible object lifecycle                                  |
| `idempotent`    | Repeated identical requests produce the same result without side effects              |
| `available`     | Server stays up under concurrent load, health endpoint reports UP                     |
| `auditable`     | Every operation is logged with caller identity, key ID, and timestamp                 |
| `compliant`     | FIPS algorithms reject non-approved parameters; KMIP responses match spec             |
| `interoperable` | Enterprise endpoints (AWS XKS, Azure EKM, Google CSE, MS DKE) conform to vendor specs |

### Components (KMS structural modules)

| Component               | Crate/path                                                              | What it covers                                                 |
| ----------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------- |
| Key lifecycle           | `server/src/core/operations/`                                           | Create → Activate → Deactivate → Compromise → Destroy          |
| Access control          | `crate/access/`, `server/src/routes/access.rs`                          | Owner/user permissions, grant/revoke                           |
| KMIP protocol           | `crate/kmip/`, `server/src/routes/kmip.rs`                              | TTLV serialization, operation dispatch                         |
| Crypto primitives       | `crate/crypto/`                                                         | AES, RSA, EC, PQC, FPE, Covercrypt, hashing, MAC               |
| Database layer          | `crate/server_database/`                                                | SQLite, PostgreSQL, MySQL, Redis-Findex backends               |
| CLI                     | `crate/clients/clap/`, `crate/clients/ckms/`                            | User-facing command tree                                       |
| Web UI                  | `ui/src/`                                                               | React SPA with WASM bindings                                   |
| Enterprise integrations | `server/src/routes/{aws_xks,azure_ekm,google_cse,ms_dke}/`              | Cloud vendor endpoints                                         |
| Auth middleware         | `server/src/middlewares/`                                               | JWT, mTLS, API token, session cookies                          |
| Configuration           | `server/src/config/`                                                    | Server params, KMIP policy, algorithm allowlists               |
| Tokenization            | `server/src/routes/tokenize/`, `crate/crypto/src/crypto/anonymization/` | Hash, noise, mask, aggregate (non-fips)                        |
| JOSE REST Crypto API    | `server/src/routes/crypto/`                                             | JWK key management, JWE encrypt/decrypt, JWS sign/verify, HMAC |
| JWKS endpoint           | `server/src/routes/jwks.rs`                                             | RFC 7517 public key discovery (`/.well-known/jwks.json`)       |

### Building the Capabilities Matrix

For this PR, populate the intersection of Attributes × Components from the diff. Examples:

- `Secure × Key Lifecycle` → "Destroyed keys cannot be retrieved or activated"
- `Idempotent × Create Key` → "Creating a key with identical params returns the same key or a clear error, never a corrupt duplicate"
- `Compliant × Crypto Primitives` → "FIPS mode rejects ChaCha20; non-FIPS mode accepts it"
- `Interoperable × Azure EKM` → "wrap/unwrap responses match Azure's expected JSON schema"
- `Consistent × Database Layer` → "Concurrent revoke + encrypt on same key produces a clean error, not a partial state"

Rank cells by risk: code churn × blast radius if behavior is wrong. Only populate cells actually touched by the PR.

---

## 4 — Behavioral Diff Analysis

Read the diff and answer these questions before generating any scenarios:

1. **What implicit contract changed?** Look for behaviors the old code guaranteed by accident:
   - A field that was always non-null and is now nullable
   - A status transition that was impossible and is now reachable
   - An error type that changed (e.g., 422 → 500, or a different KMIP `ResultReason`)
   - A default value that shifted

2. **What adjacent behaviors could be silently broken?** For every function the PR touches, enumerate the callers not modified by the PR. In KMS terms:
   - A change to `encrypt()` in `crate/crypto/` — does it affect `wrap()` which calls it?
   - A change to `dispatch.rs` — does it alter the order of validation for all operations?
   - A change to access control — does it affect both CLI and UI paths?

3. **What assumptions does the new code introduce?** KMS-specific red flags:
   - `unwrap()` or `expect()` on KMIP responses
   - Unchecked index access on key material bytes
   - Implicit ordering between async operations (e.g., create then immediately activate)
   - Hardcoded algorithm identifiers that should be parameterized

4. **Is there a new failure mode with no error handling?** Check for:
   - New code paths that panic instead of returning `KmsError`
   - Incorrect HTTP status codes (see error mapping in §8)
   - Errors swallowed by `.ok()` or `let _ =`
   - Missing feature-flag gates (`#[cfg(feature = "non-fips")]`)

---

## 5 — Adversarial Tour Proposals

Propose **tours** — themed exploratory runs against the live KMS — not individual test cases. Tours target _assumptions_, not paths.

### Tour Catalogue (KMS-specific)

| Tour                   | Target assumption                                | Concrete KMS stimuli                                                                                                                                                                                                                    |
| ---------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Saboteur Tour**      | The system handles hostile inputs gracefully     | Send malformed TTLV to `/kmip/2_1`; send key ID with SQL injection payload to `/access/list/{id}`; send a 65 MB JSON body; send truncated base64 key material on import; send negative `CryptographicLength`                            |
| **Antisocial Tour**    | Operations are safe out of documented order      | Encrypt with a `PreActive` key; decrypt with a `Deactivated` key; destroy a key then try to export it; revoke access then try to use the key through the revoked user; call `Certify` on a symmetric key                                |
| **Time Tour**          | Time-dependent behavior is correct at boundaries | Create a key with expiry 1 second from now, wait, then try to encrypt; rotate a key at the exact moment a wrap request arrives; check `unwrapped_cache_max_age` eviction timing                                                         |
| **Obsessive Tour**     | Repeated operations don't degrade state          | Create 100 keys with the same tag; rotate the same key 50 times in a loop; grant+revoke access 100 times; send 100 concurrent encrypt requests on the same key                                                                          |
| **Configuration Tour** | Non-default configs don't break invariants       | Run with `clear_database = true`; run with a custom `kmip_policy` restricting key sizes; run with `force_default_username`; switch database backends mid-session                                                                        |
| **Amnesia Tour**       | Restart/crash recovery preserves guarantees      | Kill the KMS mid-encrypt; restart; verify key state is consistent; verify no partial objects in DB; verify the health endpoint comes back UP with correct DB status                                                                     |
| **Privilege Tour**     | Access control is not bypassable at edges        | Call admin-only endpoints (`/access/grant`) without auth; with `no_auth.toml`, verify `default_username` is used; test `non_revocable_key_id` enforcement; grant access to a key, destroy the key, check the access entry is cleaned up |
| **Feature-Flag Tour**  | FIPS/non-FIPS boundaries are enforced            | In FIPS mode, attempt to create a Covercrypt key (should fail); in non-FIPS mode, attempt to use the `/tokenize/` endpoints (should work); verify that `server-info` reports the correct `fips_mode`                                    |

For each tour relevant to the PR's diff, produce a **concrete sequence** of test steps using whichever channel from §1 is most direct for the surface being tested:

- `ckms` CLI commands for KMIP-visible behavior and key lifecycle
- `curl` calls for HTTP endpoints (JOSE REST, JWKS, enterprise integrations, tokenize)
- Chrome DevTools MCP for UI behavior or WASM-backed operations
- `cargo test -p <crate>` or in-process test server for database backends, PKCS#11, or crypto primitives

Choose the channel that most closely matches how a real user would reach the broken assumption.

**Example: Antisocial Tour for a key lifecycle PR**

```bash
# Create a key (starts in PreActive state — no auto-activation unless configured)
KEY_ID=$(cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 256 2>&1 | grep -oP '[0-9a-f-]{36}')

# Try to encrypt before activation — should fail if key is PreActive
cargo run -p ckms --features non-fips -- sym encrypt -k "$KEY_ID" test_data/plain.txt
# Expected: error mentioning key state or usage mask

# Destroy the key
cargo run -p ckms --features non-fips -- objects destroy -k "$KEY_ID"

# Try to export the destroyed key — must fail
cargo run -p ckms --features non-fips -- sym keys export -k "$KEY_ID" /tmp/dead-key.json
# Expected: error "Item not found" or "object is destroyed"
```

---

## 6 — SFDIPOT Canary Checklist

After tours, run a canary pass. For each dimension touched by the PR, write one cheap verification.

| Dimension      | KMS-specific probes                                                                                                                                                     | Canary command                                                                                                                      |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Structure**  | Key object schema, KMIP message framing, TTLV field ordering                                                                                                            | `curl -s -X POST -H "Content-Type: application/json" -d '{}' http://127.0.0.1:9998/kmip/2_1` → expect 422 with KMIP error, not 500  |
| **Function**   | Core KMIP: Create, Get, Activate, Revoke, Destroy, Encrypt, Decrypt, Wrap, Unwrap, Sign, Verify, MAC, Hash, Locate, Certify, Validate, DeriveKey, Import, Export, ReKey | `cargo run -p ckms --features non-fips -- server version` → expect version string                                                   |
| **Data**       | Key material encoding, algorithm identifiers, length constraints, empty/null inputs, Unicode in tags                                                                    | `cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 128 --tag "canary-αβγ"` → expect success |
| **Interface**  | HTTP REST endpoints, KMIP TTLV, CLI flags, TLS cert validation, CORS headers, cookie handling                                                                           | `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9998/health` → expect `200`                                                |
| **Platform**   | Linux (primary), macOS, Windows (CI), Docker, Nix packaging                                                                                                             | Check binary starts: `cargo run -p cosmian_kms_server --features non-fips -- --help` → expect help text                             |
| **Operations** | Startup, shutdown, config reload, log output, OTEL metrics, concurrent requests, DB migrations                                                                          | Check health with DB: `curl -s http://127.0.0.1:9998/health \| jq .dependencies.database.status` → expect `"UP"`                    |
| **Time**       | Key validity windows, expiry, rotation scheduling, cache TTLs (`unwrapped_cache_max_age`), session cookie TTL                                                           | Create key with activation/expiry dates, verify enforcement                                                                         |

---

## 7 — Regression Oracle Pass

For every behavioral change the PR introduces, identify the adjacent behaviors that _were not changed_ but could have been silently affected. For each:

- State the invariant (from the KMS domain invariants list below)
- Write the minimal verification
- Note whether the expected response is deterministic

**Example regression checks:**

```gherkin
Scenario: Destroyed keys cannot be retrieved
  Given a KMS with a symmetric AES-256 key that has been destroyed
  When the user runs `cargo run -p ckms --features non-fips -- sym keys export -k <destroyed-key-id> /tmp/out.json`
  Then the command fails with "Item not found" error
  And the exit code is non-zero

Scenario: Key material never appears in error messages
  Given a KMS with a symmetric key
  When the user sends a malformed encrypt request referencing that key
  Then the error response body does not contain any base64-encoded key material
  And the server log does not contain key bytes

Scenario: Health endpoint reflects actual DB state
  Given a KMS running with SQLite backend
  When the SQLite file is deleted while the server is running
  Then GET /health returns {"status":"DOWN",...} or reports database error
```

---

## 8 — KMS Error Reference

### HTTP Status Code Mapping

| KMS Error Type                                                                                                                                                                          | HTTP Status | Typical cause          |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ---------------------- |
| `RouteNotFound`                                                                                                                                                                         | 404         | Endpoint doesn't exist |
| `Unauthorized`                                                                                                                                                                          | 401         | Authentication failed  |
| `ItemNotFound`, `InvalidRequest`, `NotSupported`, `UnsupportedAlgorithm`, `InconsistentOperation`, `Kmip21Error`, `Kmip14Error`, `UnsupportedProtectionMasks`, `UnsupportedPlaceholder` | 422         | Client request issue   |
| `Database`, `CryptographicError`, `Certificate`, `TLS`, `ServerError`, `Default`, `Redis`, `Findex`                                                                                     | 500         | Server-side error      |

### KMIP ResultReason Codes

| Code         | Reason                                | Common trigger                                   |
| ------------ | ------------------------------------- | ------------------------------------------------ |
| `0x00000001` | OperationFailed                       | General failure                                  |
| `0x00000004` | Invalid_Message                       | Malformed TTLV                                   |
| `0x00000009` | Item_Not_Found                        | Key/object doesn't exist                         |
| `0x0000000C` | Unsupported_Operation                 | Operation not implemented                        |
| `0x0000000E` | Unsupported_Cryptographic_Algorithm   | Algorithm not available (e.g., ChaCha20 in FIPS) |
| `0x00000010` | Permission_Denied                     | User lacks access                                |
| `0x00000011` | Duplicate_Item                        | Object already exists                            |
| `0x00000017` | Incompatible_Cryptographic_Parameters | Bad crypto params                                |

### Enterprise Endpoint Error Formats

- **AWS XKS**: `{"errorCode":"...","message":"..."}`
- **Azure EKM**: `{"code":"...","message":"...","details":{...}}`
- **Google CSE**: `{"error":"...","error_description":"..."}`
- **MS DKE**: `{"error":"...","error_description":"..."}`
- **Tokenize**: `{"code":422,"message":"..."}`

---

## 9 — KMS Domain Invariants

These are the semantic invariants the agent must treat as always-true unless the PR explicitly changes them. Any scenario that contradicts one of these is a **critical finding**:

### Key Lifecycle Invariants

- A key in `PreActive` state **cannot** encrypt, decrypt, sign, or verify
- A key in `Deactivated` or `Compromised` state **cannot** be used for new encrypt/wrap operations
- A `Destroyed` key **cannot** be retrieved, activated, or used in any operation
- Wrapping a key with itself must be rejected
- Key state transitions must follow KMIP 2.1 state machine: `PreActive → Active → Deactivated → Compromised → Destroyed` (plus `Destroyed_Compromised`)

### Security Invariants

- Key material must **never** appear in logs, error messages, or HTTP response bodies (except in legitimate Export/Get responses)
- All administrative operations must be reflected in the audit log with caller identity and timestamp
- Operations gated behind `non-fips` must not be reachable when the server is built without that feature
- Algorithm allowlists in KMIP policy must be enforced — a policy forbidding RSA-2048 must reject RSA-2048 key creation

### Access Control Invariants

- A user without explicit access cannot perform operations on another user's objects
- The `default_username` is used only when no authentication is configured
- `non_revocable_key_id` keys cannot have their access revoked
- Granting access is an owner-only operation

### Protocol Invariants

- `POST /kmip/2_1` with empty body returns 422, not 404 or 500
- Unknown KMIP operations return `RouteNotFound` / `Unsupported_Operation`
- KMIP responses always include `ProtocolVersion`, `TimeStamp`, `BatchCount`
- Enterprise endpoints conform to their respective vendor specifications (AWS SigV4, Azure mTLS, Google JWT)

### Concurrency Invariants

- Concurrent operations on the same key must not produce inconsistent state
- No partial rotation, no duplicate IDs
- Database transactions must be isolated properly across backends

### JOSE REST API and JWKS Invariants

- `POST /v1/crypto/keys` with key material fields (`k`, `d`) imports; without them, generates. The two code paths must not be confused.
- `DELETE /v1/crypto/keys/{kid}` must revoke-then-destroy. Attempting to use a deleted key in any subsequent `/v1/crypto/*` call must fail with `404 Not Found`.
- JWE decryption failures (padding oracle, AES-GCM tag mismatch) must return the same `{"error":"DecryptionFailed","description":"Decryption failed"}` response regardless of the root cause, per RFC 7516 §11.5.
- `POST /v1/crypto/sign` must return a detached JWS protected header and signature; the payload must **not** appear in the response.
- `POST /v1/crypto/verify` must use the `kid` embedded in the protected header, not an independently supplied one. Supplying a `kid` pointing to a different key type than the `alg` in the header must fail.
- `/.well-known/jwks.json` must return `404` (route not registered) when `jwks_endpoint_enabled = false`.
- `/.well-known/jwks.json` must never return private key material — only public coordinates (`x`, `y`, `n`, `e`).
- Auto-tagging (`KMS_JWKS_ENDPOINT_AUTO_TAG=true`, the default): every key pair created via `POST /v1/crypto/keys` must receive the `"jwks"` tag. When disabled, newly created keys must **not** be auto-tagged.
- System tags (prefix `_`) must be rejected with `400` by `POST`/`DELETE /v1/crypto/keys/{kid}/tags`.
- `EdDSA` (Ed25519 / `OKP` key type) must only be reachable in `non-fips` builds; a FIPS build must reject `kty=OKP` at key creation with a clear error.

---

## 10 — Feature Flag Awareness

The tester agent **must be aware** of which feature flags are active and test accordingly.

| Flag               | Algorithms/features enabled                                                       | How to detect                                                          |
| ------------------ | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **FIPS (default)** | AES, RSA ≥2048, ECDSA, EdDSA, ML-KEM, ML-DSA, SLH-DSA, SHA-2/3, HMAC              | `curl -s http://127.0.0.1:9998/server-info \| jq .fips_mode` → `true`  |
| **non-fips**       | All FIPS + ChaCha20, AES-XTS, Covercrypt, FPE, tokenize, Redis-Findex, MD5, SHA-1 | `curl -s http://127.0.0.1:9998/server-info \| jq .fips_mode` → `false` |

**JOSE REST API feature-flag specifics:**

- All `/v1/crypto/*` endpoints are available in both FIPS and non-FIPS builds.
- `kty=OKP` (Ed25519/`EdDSA`) key creation and signing is gated behind `non-fips`. In a FIPS build, `POST /v1/crypto/keys` with `kty=OKP` must return `400 Bad Request`.
- `/.well-known/jwks.json` is always compiled in but only **registered** when `jwks_endpoint_enabled = true`. Feature flag does not affect this — it is a runtime config toggle.

**Testing rule**: If the PR introduces code guarded by `#[cfg(feature = "non-fips")]`, the tester must verify:

1. The feature works when `non-fips` is enabled
2. The feature is unreachable (compile-gated) when building without it — this is verified by `cargo build` (no `--features non-fips`)

---

## 11 — KMIP Operations Reference

All 31 operations dispatched by the server (from `crate/server/src/core/operations/dispatch.rs`):

| Operation          | KMIP Tag             | Handler                   | Notes                                           |
| ------------------ | -------------------- | ------------------------- | ----------------------------------------------- |
| Activate           | `"Activate"`         | `kms.activate()`          | Transitions key to Active state                 |
| Add Attribute      | `"AddAttribute"`     | `kms.add_attribute()`     |                                                 |
| Certify            | `"Certify"`          | `kms.certify()`           | Creates certificate from CSR or key pair        |
| Check              | `"Check"`            | `check()`                 |                                                 |
| Create             | `"Create"`           | `kms.create()`            | Creates symmetric keys, secrets, opaque objects |
| Create Key Pair    | `"CreateKeyPair"`    | `kms.create_key_pair()`   | RSA, EC, PQC key pairs                          |
| Decrypt            | `"Decrypt"`          | `kms.decrypt()`           |                                                 |
| Delete Attribute   | `"DeleteAttribute"`  | `kms.delete_attribute()`  |                                                 |
| Derive Key         | `"DeriveKey"`        | `kms.derive_key()`        | HKDF, SP800-108                                 |
| Destroy            | `"Destroy"`          | `kms.destroy()`           | Terminal state                                  |
| Discover Versions  | `"DiscoverVersions"` | `kms.discover_versions()` |                                                 |
| Encrypt            | `"Encrypt"`          | `kms.encrypt()`           | AES, RSA, EC, FPE, Covercrypt                   |
| Export             | `"Export"`           | `kms.export()`            |                                                 |
| Get                | `"Get"`              | `kms.get()`               | Retrieves object by ID                          |
| Get Attribute List | `"GetAttributeList"` | `get_attribute_list()`    |                                                 |
| Get Attributes     | `"GetAttributes"`    | `kms.get_attributes()`    |                                                 |
| Hash               | `"Hash"`             | `kms.hash()`              | SHA-2, SHA-3                                    |
| Import             | `"Import"`           | `kms.import()`            |                                                 |
| Locate             | `"Locate"`           | `kms.locate()`            | Search by attributes, tags                      |
| MAC                | `"MAC"` / `"Mac"`    | `kms.mac()`               | HMAC                                            |
| MAC Verify         | `"MACVerify"`        | `mac_verify()`            |                                                 |
| Modify Attribute   | `"ModifyAttribute"`  | `kms.modify_attribute()`  |                                                 |
| Query              | `"Query"`            | `query_op()`              | Server capabilities                             |
| Register           | `"Register"`         | `kms.register()`          | Import pre-existing object                      |
| ReKey              | `"ReKey"`            | `kms.rekey()`             | Key rotation                                    |
| ReKey Key Pair     | `"ReKeyKeyPair"`     | `kms.rekey_keypair()`     |                                                 |
| Revoke             | `"Revoke"`           | `kms.revoke()`            |                                                 |
| RNG Retrieve       | `"RNGRetrieve"`      | `kms.rng_retrieve()`      | Random bytes                                    |
| RNG Seed           | `"RNGSeed"`          | `kms.rng_seed()`          |                                                 |
| Set Attribute      | `"SetAttribute"`     | `kms.set_attribute()`     |                                                 |
| Sign               | `"Sign"`             | `kms.sign()`              | RSA, EC, PQC signatures                         |
| Signature Verify   | `"SignatureVerify"`  | `kms.signature_verify()`  |                                                 |
| Validate           | `"Validate"`         | `kms.validate()`          | Certificate validation                          |

Unknown operations → `KmsError::RouteNotFound()` (HTTP 404).

---

## 12 — Test Configuration Reference

| Config file                | Auth         | DB         | TLS     | Use when testing...         |
| -------------------------- | ------------ | ---------- | ------- | --------------------------- |
| `no_auth.toml`             | None         | SQLite     | No      | **Default for most PRs**    |
| `api_token_auth.toml`      | API Token    | SQLite     | No      | API token middleware        |
| `jwt_auth.toml`            | JWT (Google) | SQLite     | No      | JWT/OIDC authentication     |
| `tls_auth_non_fips.toml`   | mTLS         | SQLite     | PKCS#12 | TLS client certificate auth |
| `tls13_auth_non_fips.toml` | mTLS         | SQLite     | TLS 1.3 | TLS 1.3 enforcement         |
| `multifactor_tls_jwt.toml` | TLS + JWT    | SQLite     | Yes     | Multi-factor auth           |
| `mysql_database.toml`      | None         | MySQL      | No      | MySQL backend               |
| `lb_kms1_postgres.toml`    | None         | PostgreSQL | No      | PostgreSQL backend          |
| `google_cse.toml`          | OIDC + CSE   | SQLite     | Yes     | Google CSE integration      |
| `otlp_logging.toml`        | None         | SQLite     | No      | OTEL/metrics testing        |
| `hsm/softhsm2_config.toml` | None         | SQLite     | No      | SoftHSM2 integration        |

---

## 14 — Literature and References

| Resource                                                 | What to extract                                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| James Whittaker, _Exploratory Software Testing_ (2009)   | Tour metaphors: Saboteur, Antisocial, Obsessive, Configuration, Time tours                  |
| James Whittaker, ACC framework (Google)                  | Attributes/Components/Capabilities matrix for rapid risk mapping                            |
| SFDIPOT heuristic (Satisfice / RST)                      | Seven-dimension checklist: Structure, Function, Data, Interface, Platform, Operations, Time |
| Michael Bolton & James Bach — Rapid Software Testing     | Oracles vs. exploration distinction; error guessing with domain priors                      |
| KMIP 2.1 specification (HTML files in `crate/kmip/src/`) | Normative reference for all KMIP operations, object types, attributes                       |
| FIPS 140-3 / NIST SP 800-175B                            | Approved algorithms, key management requirements                                            |
| Cosmian KMS AGENTS.md                                    | Canonical project instructions, build commands, CI workflows                                |
| `test_data/configs/server/`                              | All available server configurations for different test scenarios                            |
