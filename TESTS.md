# Cosmian KMS — Test Architecture

> **1210 tests** across 8 crates · 133 `#[ignore]` · 191 `#[cfg(feature = "non-fips")]`

---

## Test Infrastructure Overview

```mermaid
flowchart TD
    subgraph TestRunners["Test Runners"]
        CT["cargo test-fips\n(FIPS mode)"]
        CNF["cargo test-non-fips\n(non-FIPS mode)"]
        PW["Playwright\n(UI E2E)"]
        VT["Vitest\n(UI Unit/Int)"]
    end

    subgraph TestInfra["Test Infrastructure"]
        TKS["test_kms_server\n(server lifecycle)"]
        TU["test_utils\n(config helpers)"]
        TV["vector_runner\n(TTLV-JSON vectors)"]
    end

    subgraph ServerUnderTest["Server Under Test"]
        KMS["cosmian_kms_server\n(Actix-web)"]
        DB["Database Backend\n(SQLite / Postgres / Redis)"]
        CR["cosmian_kms_crypto\n(OpenSSL 3.6)"]
        HSM["HSM Backend\n(SoftHSM2 / Utimaco / ...)"]
    end

    subgraph TestData["Test Data"]
        TOML["test_data/configs/server/test/*.toml\n(server configs)"]
        CERT["test_data/certificates/\n(TLS certs)"]
        XML["crate/kmip/src/.../XML/\n(KMIP normative XML vectors)"]
        VEC["test_data/vectors/\n(176 vectors: FIPS/non-FIPS regression + KAT + TLS + integration + negative)"]
        PROP["crate/kmip/src/.../proptest\n(random TTLV roundtrip)"]
    end

    CT --> TKS
    CNF --> TKS
    TKS --> KMS
    TKS --> TU
    TV --> TKS
    KMS --> DB
    KMS --> CR
    KMS --> HSM
    TKS --> TOML
    TV --> VEC
    PW --> KMS
    VT --> KMS
```

---

## Test Vector Execution Flow

```mermaid
sequenceDiagram
    participant T as Test Function
    participant R as Vector Runner
    participant S as Test Server
    participant K as KMS Server
    participant D as Database

    alt Isolated server (run_test_vector)
        T->>R: run_test_vector("vectors/fips/symmetric/aes_gcm")
        R->>R: Load manifest.toml
        R->>R: Resolve server config<br/>(default or per-vector)
        R->>S: start_test_server_from_toml(config)
        S->>S: Load TOML → ClapConfig
        S->>S: Override port = 0 (OS-assigned)
        S->>K: Start KMS on assigned port
        K->>D: Initialize SQLite DB
    else Shared server (run_test_vector_with_context)
        T->>R: run_test_vector_with_context(dir, context)
        R->>R: Load manifest.toml
        Note over R,K: Reuses pre-existing TestsContext
    end

    loop For each step in manifest
        R->>R: Load step_N_request.json
        R->>R: Substitute {{captures}}
        alt wire_format = "json"
            alt raw_request = false
                R->>R: Wrap bare op in RequestMessage envelope
            else raw_request = true
                R->>R: Use JSON as-is (batched/custom header)
            end
            R->>K: POST /kmip/2_1 (JSON TTLV)
            K-->>R: Response (JSON)
        else wire_format = "binary"
            R->>R: Wrap in RequestMessage (or raw)
            R->>R: JSON → TTLV struct → binary bytes
            R->>K: POST /kmip (application/octet-stream)
            K-->>R: Response (binary TTLV)
            R->>R: binary → TTLV struct → JSON
        end
        alt assert_success = true
            R->>R: Assert ResultStatus == "Success"
            R->>R: Assert structural fields (assert_fields)
            R->>R: Assert fields absent (assert_fields_absent)
            R->>R: Capture output variables
        else assert_success = false
            R->>R: Assert failure (HTTP error or ResultStatus != Success)
            R->>R: Optionally check assert_error_reason
            R->>R: Optionally check assert_error_contains
        end
    end

    R-->>T: Pass/Fail
```

---

## Test Inventory by Crate

### `cosmian_kms_server` — 218 tests (200 pass · 18 ignored)

| Module | Tests | Feature Gate | Description |
|--------|-------|-------------|-------------|
| **Config & Startup** | | | |
| `config/command_line/clap_config` | 11 | — | Precedence chain, file loading, env fallback, error cases |
| `config/command_line/db` | 10 | — | URL validation, password masking (PostgreSQL, MySQL) |
| `config/command_line/idp_auth_config` | 1 | — | IDP configuration extraction |
| `config/wizard` | 6 | — | TOML round-trip, self-signed PKI generation, cert validation |
| `start_kms_server` | 2 | — | Session key derivation determinism |
| **Core Operations** | | | |
| `core/kms` | 4 | — | OTLP HTTPS/HTTP acceptance and rejection |
| `core/operations/certify` | 2 | — | Serial number length validation |
| `core/operations/hash` | 2 | — | SHA-256 hash with and without correlation |
| `core/operations/mac` | 2 | — | HMAC computation and limit cases |
| `core/operations/rng_retrieve` | 1 | — | RNG returns requested length |
| `core/operations/signature_verify` | 2 | — | CS-AC-M-2-21 normative verify (KMS + OpenSSL paths) |
| `core/operations/state_utils` | 4 | — | Effective state: active, pre-active ± activation date |
| `core/otel_metrics` | 5 | — | Active users, operation recording, duration, permissions |
| `error` | 1 | — | KMS error interpolation |
| **Middleware & Routes** | | | |
| `middlewares/jwt/jwks` | 6 | — | JWKS redirect safety, key parsing, skip-invalid-keys |
| `routes/google_cse/jwt` | 1 | — | Wrap auth (ignored: requires credentials) |
| `routes/kmip` | 3 | — | Error response serialization (TTLV, binary, message) |
| `routes/ms_dke` | 2 | — | BigUint and date format parsing |
| **Integration Tests** | | | |
| `azure_ekm/integration_tests` | 4 | — | Azure EKM wrap/unwrap roundtrips (AES-KW, AES-KWP, RSA-OAEP) |
| `bulk_encrypt_decrypt_tests` | 2 | non-fips | Bulk AES encrypt/decrypt, single CBC mode |
| `cover_crypt_tests/integration_tests` | 2 | non-fips | Covercrypt lifecycle with IDs, access policy parsing |
| `cover_crypt_tests/integration_tests_bulk` | 1 | non-fips | Covercrypt bulk operations |
| `cover_crypt_tests/integration_tests_tags` | 2 | non-fips | Covercrypt re-key, tag-based tests |
| `cover_crypt_tests/unit_tests` | 5 | non-fips | Covercrypt key creation, encrypt/decrypt, JSON access, import |
| `curve_25519_tests` | 2 | non-fips | Curve25519 keypair, multiple operations |
| `derive_key_tests` | 8 | — | PBKDF2, HKDF, error cases, missing params |
| `google_cse` | 12 | mixed | Google CSE signing, encryption, JWT (8 ignored: require OAuth) |
| `health_endpoint` | 2 | — | `/health` OK, root redirect to `/ui` |
| `hsm` | 1 | — | HSM full test (ignored: requires hardware) |
| `kmip_endpoints` | 1 | non-fips | KMIP endpoint validation |
| `kmip_messages` | 3 | non-fips | MAC, encrypt, full KMIP message tests |
| `kmip_policy/basic` | 18 | non-fips | Algorithm/key-size/mode policy (11 unit + 7 E2E) |
| `kmip_policy/e2e_ecies` | 5 | non-fips | ECIES curve allowlist enforcement |
| `kmip_policy/e2e_export_wrapping` | 6 | non-fips | Key wrapping suite enforcement (AES-GCM/KW/KWP, RSA-OAEP) |
| `kmip_policy/e2e_signature` | 1 | non-fips | Signature algorithm allowlist enforcement |
| `kmip_policy/overrides` | 2 | non-fips | Policy override tightening (unit + E2E) |
| `kmip_server_tests` | 5 | non-fips | Curve25519 pairs, wrapped import, transparent keys, tenants, register |
| `locate` | 3 | — | Object location, keypair+sym, filter by ObjectType AND semantics |
| `migrate/redis_tests` | 1 | non-fips | Redis Findex migration (ignored) |
| `ms_dke` | 1 | — | MS DKE decrypt (ignored: requires external service) |
| `mtls_db` | 9 | mixed | PostgreSQL/MySQL mTLS URL parsing and connections |
| `secret_data_tests` | 3 | — | Secret data CRUD, wrapping, KEK import/export |
| `security_regression` | 4 | — | Verify no plaintext/ciphertext leaks in traces |
| `test_modify_attribute` | 1 | — | Attribute modification |
| `test_set_attribute` | 1 | — | Attribute setting |
| `test_sign` | 6 | non-fips | RSA, ECDSA (P-256/P-384/P-521/K-256), EdDSA signing |
| `test_validate` | 2 | — | Certificate validation (ignored: requires network) |
| `ttlv_tests/*` | 40 | non-fips | TTLV wire protocol: create, get, encrypt, decrypt, import, register, locate, discover versions, query, DSA, normative tests, integrations |

### `cosmian_kms_crypto` — 148 tests

| Module | Tests | Feature Gate | Description |
|--------|-------|-------------|-------------|
| `crypto/elliptic_curves/ecies` | 1 | non-fips | ECIES encrypt/decrypt P-curves |
| `crypto/elliptic_curves/operation` | 23 | non-fips | EC key generation, mask flags, algorithm checks |
| `crypto/elliptic_curves/sign` | 6 | non-fips | Ed25519, Ed448, ECDSA determinism, prehashed |
| `crypto/elliptic_curves/verify` | 1 | non-fips | EC signature verification |
| `crypto/password_derivation` | 2 | non-fips | PBKDF2 derivation |
| `crypto/pqc/hybrid_kem` | 8 | — | Hybrid KEM roundtrips, key creation |
| `crypto/pqc/ml_dsa` | 4 | — | ML-DSA-44/65/87 sign/verify |
| `crypto/pqc/ml_kem` | 13 | — | ML-KEM roundtrips, error cases |
| `crypto/pqc/mod` | 7 | — | PQC serialization, key loading |
| `crypto/pqc/slh_dsa` | 13 | — | SLH-DSA all variants + key creation |
| `crypto/rsa/ckm_rsa_aes_key_wrap` | 5 | non-fips | RSA-AES key wrapping |
| `crypto/rsa/ckm_rsa_pkcs` | 1 | non-fips | PKCS#1 v1.5 |
| `crypto/rsa/ckm_rsa_pkcs_oaep` | 1 | non-fips | RSA-OAEP |
| `crypto/rsa/operation` | 3 | non-fips | RSA key operations |
| `crypto/rsa/sign` | 5 | mixed | RSA signatures (PSS variants non-fips) |
| `crypto/symmetric/rfc3394` | 4 | — | AES key wrap (RFC 3394) |
| `crypto/symmetric/rfc5649` | 8 | — | AES key wrap with padding (RFC 5649) |
| `crypto/symmetric/symmetric_ciphers` | 1 | non-fips | ChaCha20 |
| `crypto/symmetric/tests` | 13 | non-fips | AES-GCM, AES-XTS, AES-CBC, ChaCha20, GCM-SIV |
| `crypto/wrap/tests` | 6 | non-fips | Key wrapping operations |
| `error/mod` | 1 | — | Error handling |
| `openssl/certificate` | 1 | — | Certificate operations |
| `openssl/private_key` | 11 | mixed | Private key parsing (P-192, K-256, X25519, X448 are non-fips) |
| `openssl/public_key` | 11 | mixed | Public key parsing (same non-fips variants) |
| `openssl/x509_extensions` | 3 | — | X.509 extension parsing |

### `cosmian_kmip` — 218 tests

| Module | Tests | Description |
|--------|-------|-------------|
| `ttlv/tests/kmip_2_1_tests` | 42 | KMIP 2.1 serialization roundtrips |
| `ttlv/tests/kmip_1_4_tests` | 6 | KMIP 1.4 serialization roundtrips |
| `ttlv/tests/wire_edge_cases` | 27 | Binary TTLV edge cases |
| `ttlv/tests/serialize_deserialize` | 14 | Generic TTLV serde |
| `ttlv/tests/serializer_deserializer` | 16 | TTLV serializer/deserializer pairs |
| `ttlv/tests/xml_edge_cases` | 18 | XML parsing edge cases |
| `ttlv/tests/ttlv_wire` | 2 | TTLV wire format |
| `ttlv/tests/vmware` | 7 | VMware KMIP interop |
| `ttlv/tests/mongodb` | 1 | MongoDB KMIP interop |
| `ttlv/tests/mysql` | 2 | MySQL KMIP interop |
| `ttlv/tests/covercrypt_serialize` | 1 | Covercrypt TTLV serialization |
| `ttlv/wire/ttlv_bytes_serializer` | 16 | Binary wire serialization |
| `ttlv/wire/ttlv_bytes_deserializer` | 13 | Binary wire deserialization |
| `ttlv/normalize` | 22 | TTLV normalization rules |
| `ttlv/xml/tests/` | 6 | XML mandatory/optional test vectors (KMIP 1.0/1.4/2.1) |
| `ttlv/xml/parser` | 1 | XML parser |
| `ttlv/xml/tests/ser_deser` | 2 | XML serde roundtrips |
| `ttlv/xml/tests/cs_bc_m_gcm_all` | 2 | GCM conformance suite |
| `ttlv/tests/proptest_roundtrip` | 1 | Property-based TTLV binary roundtrip (256 random cases) |
| `kmip_big_int` | 4 | BigInteger operations |
| `data_to_encrypt` | 1 | Encryption data struct |
| `kmip_2_1/extra/bulk_data` | 1 | Bulk data structures |
| `kmip_1_4/kmip_types` | 3 | KMIP 1.4 type tests |
| `kmip_1_4/kmip_attributes` | 1 | KMIP 1.4 attribute tests |
| `error/mod` | 1 | Error handling |
| `time_utils` | 1 | Time utility tests |

### `cosmian_kms_server_database` — 28 tests

| Module | Tests | Feature Gate | Description |
|--------|-------|-------------|-------------|
| `core/main_db_params` | 8 | non-fips | Connection string redaction |
| `core/unwrapped_cache` | 3 | — | LRU cache, garbage collection |
| `stores/redis/permissions` | 1 | — | Redis permission store |
| `stores/redis/redis_with_findex` | 1 | — | Redis Findex store |
| `stores/sql/pgsql` | 15 | — | PostgreSQL URL parsing, retry logic |

### `clients` — 317 tests

| Crate | Tests | Description |
|-------|-------|-------------|
| `ckms` (CLI binary) | 85 | Symmetric, RSA, EC, certificates, Covercrypt, PQC, shared ops, Google CSE, HSM, config |
| `clap` (CLI actions) | 163 | Same as ckms + AWS/Azure BYOK, XML KMIP conformance, error messages, metrics |
| `client` (HTTP client) | 38 | TLS, PKCS#12, cipher suites, OAuth, custom headers |
| `client_utils` | 2 | Vendor extension tag filtering |
| `pkcs11/module` | 11 | PKCS#11 interface, Oracle TDE |
| `pkcs11/loader` | 3 | OIDC login, migration (non-fips) |
| `pkcs11/provider` | 5 | KMS backend, key generation, SSH signing |

### `test_kms_server` — 204 tests (non-FIPS)

| Module | Tests | Feature Gate | Description |
|--------|-------|-------------|-------------|
| `test_server` | 2 | non-fips | Server startup smoke tests (default + TOML config) |
| `vector_runner` (unit) | 6 | — | Manifest parsing, placeholder substitution, assertions, capture |
| `vector_runner` (integration) | 196 | mixed | TTLV-JSON regression + KAT + TLS + negative + non-fips symmetric + binary TTLV integration replays (see §5) |

### HSM crates — 97 tests (all `#[ignore]`)

| Backend | Tests | Description |
|---------|-------|-------------|
| `softhsm2` | 22 | Full suite: AES, RSA, sign, multi-threaded, metadata |
| `utimaco` | 19 | Same suite for Utimaco HSM |
| `proteccio` | 19 | Same suite for Proteccio HSM |
| `smartcardhsm` | 18 | Same suite for SmartCard HSM |
| `crypt2pay` | 19 | Same suite for Crypt2Pay HSM |

### `cosmian_kms_access` — 0 tests

No test functions.

---

## Regression Test Vectors (TTLV-JSON)

Regression test vectors are documented in [`crate/test_kms_server/README.md`](crate/test_kms_server/README.md).
Run them with:

```bash
cargo test -p test_kms_server --features non-fips --lib vector_runner
```

---

## Server Configurations for Tests

30 TOML config files in `test_data/configs/server/test/`:

| Config File | Port | Auth | DB | TLS | Description |
|-------------|------|------|-----|-----|-------------|
| `auth_plain.toml` | 12001 | none | SQLite | no | Default for most tests |
| `cert_auth.toml` | 9999 | mTLS | SQLite | PEM | Client certificate auth |
| `auth_plain_jwt.toml` | — | JWT | SQLite | no | JWT authentication |
| `auth_https.toml` | — | none | SQLite | yes | HTTPS no auth |
| `auth_https_jwt.toml` | — | JWT | SQLite | yes | HTTPS + JWT |
| `hsm.toml` | 10001 | none | SQLite | no | Utimaco HSM |
| `kek.toml` | — | none | SQLite | no | Key encryption key |
| `privileged_users.toml` | — | none | SQLite | no | Privileged user list |
| `non_revocable.toml` | — | none | SQLite | no | Non-revocable key IDs |
| `postgres.toml` | — | none | PostgreSQL | no | PostgreSQL backend |
| `mysql.toml` | — | none | MySQL | no | MySQL backend |
| `redis_findex.toml` | — | none | Redis | no | Redis Findex backend |
| `ui.toml` | — | none | SQLite | no | UI test server |
| `smtp_notifications.toml` | — | none | SQLite | no | SMTP notifications |
| `*_mysql.toml` | — | varies | MySQL | varies | MySQL variants |
| `*_postgres.toml` | — | varies | PostgreSQL | varies | PostgreSQL variants |
| `*_redis_findex.toml` | — | varies | Redis | varies | Redis variants |

---

## Feature Flag Matrix

| Feature | Tests Gated | Effect |
|---------|-------------|--------|
| `non-fips` | 184 | Enables Covercrypt, Curve25519, PQC CLI, AES-XTS, legacy OpenSSL |
| `interop` | on by default | Enables extra KMIP interop test operations |
| `insecure` | dev/test only | Skips OAuth token expiry, allows self-signed TLS |

Tests requiring `non-fips` are gated with `#[cfg(feature = "non-fips")]` on the test module or function.

---

## Running Tests

```bash
# All FIPS tests
cargo test-fips

# All non-FIPS tests (includes FIPS + non-FIPS-only)
cargo test-non-fips

# Single crate
cargo test -p cosmian_kms_server --features non-fips

# Single test
cargo test -p cosmian_kms_server --features non-fips -- test_derive_key_pbkdf2_default

# Regression test vectors (in test_kms_server crate)
cargo test -p test_kms_server --features non-fips --lib vector_runner

# Single vector
cargo test -p test_kms_server --features non-fips --lib -- test_vec_aes_create_get

# Run vectors with response recording (writes step*_response.json files)
RECORD_VECTORS=1 cargo test -p test_kms_server --features non-fips --lib vector_runner

# UI E2E tests
cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e

# HSM tests (require hardware)
HSM_USER_PASSWORD=1234567 HSM_SLOT_ID=0 cargo test -p softhsm2_pkcs11_loader --features softhsm2 -- --ignored
```

### Coverage

Code coverage is collected with [cargo-tarpaulin](https://github.com/xd009642/tarpaulin)
(Linux only — uses ptrace):

```bash
cargo coverage   # alias defined in .cargo/config.toml
```

The alias expands to:

```bash
cargo tarpaulin --workspace --all-features --exclude-files crate/crypto/build.rs
```

> **Note**: `crate/crypto/build.rs` is excluded because it downloads and builds
> OpenSSL from source, inflating coverage time without providing meaningful results.

### Feature-flag verification

Use [cargo-hack](https://github.com/taiki-e/cargo-hack) to verify the workspace
compiles under all relevant feature combinations:

```bash
cargo hack --feature-powerset --depth 2 check --workspace
```

This catches feature-gated code that accidentally depends on another feature
without declaring it.

---

## KMIP Version Coverage

The server exposes three HTTP endpoints for KMIP requests. Each has different
version acceptance behavior:

| Endpoint | Content-Type | KMIP Versions | Notes |
|----------|-------------|---------------|-------|
| `POST /kmip/2_1` | `application/json` | Any (no version check) | Always processes as 2.1 |
| `POST /kmip` | `application/json` | **2.1, 1.4 only** | Rejects 1.0/1.1/1.2/1.3 with "only accepts KMIP 2.1 or 1.4" |
| `POST /kmip` | `application/octet-stream` | All 1.x and 2.x | Binary TTLV; applies AE-tag tweaks for 1.0/1.1/1.2 |

### Version-specific wire protocol behavior

| KMIP Version | Binary `/kmip` | JSON `/kmip` | Special handling |
|--------------|---------------|-------------|------------------|
| 1.0 | ✅ | ❌ Rejected | `perform_request_tweaks`: extracts AE tag from Data field |
| 1.1 | ✅ | ❌ Rejected | Same AE-tag tweaks as 1.0 |
| 1.2 | ✅ | ❌ Rejected | Same AE-tag tweaks as 1.0 |
| 1.3 | ✅ | ❌ Rejected | No special tweaks (processed as 1.4) |
| 1.4 | ✅ | ✅ | `handle_ttlv_1_4`: TemplateAttribute → Attributes conversion |
| 2.1 | ✅ | ✅ | `handle_ttlv_2_1`: native Attributes format |

### Test vector coverage by KMIP version

| KMIP Version | Integration vectors | XML spec files | Rust unit tests |
|--------------|-------------------|----------------|-----------------|
| 1.0 | 2 (FortiGate, MongoDB) | 84 (OASIS conformance) | 3 in `ttlv_tests/` |
| 1.1 | 2 (MySQL, VMware vCenter) | — | 2 in `ttlv_tests/` |
| 1.2 | 3 (Synology DSM, VAST Data, PyKMIP) | — | — |
| 1.3 | 2 (kmip_1_3_symmetric, kmip_1_3_asymmetric) | — | — |
| 1.4 | 2 (Veeam, Percona) | 75 (OASIS conformance) | 11 in `ttlv_tests/` |
| 2.1 | — (185+ operation vectors) | 93 (OASIS conformance) | 8 in `ttlv_tests/` |

---

## Database Backend Testing

### Architecture

Database backend tests live in `crate/server_database/src/tests/mod.rs`. They are
**store-level tests** that exercise the database pool directly (not via HTTP).

| Test function | Backend | Self-selecting env var | Compile gate |
|---------------|---------|-----------------------|--------------|
| `test_db_sqlite()` | SQLite | Always runs (uses tempfile) | — |
| `test_db_postgresql()` | PostgreSQL | `KMS_POSTGRES_URL` | — |
| `test_db_mysql()` | MySQL/MariaDB | `KMS_MYSQL_URL` | — |
| `test_db_redis_with_findex()` | Redis-Findex | `KMS_REDIS_URL` or `REDIS_HOST` | `#[cfg(feature = "non-fips")]` |
| `test_db_postgresql_multihost()` | PostgreSQL (2 instances) | `KMS_POSTGRES_MULTIHOST_URL` | `#[ignore]` |

All non-multihost tests run an identical 11-test suite:
`json_access`, `find_attributes`, `owner`, `permissions`, `tags`, `tx_and_list`,
`atomic`, `upsert`, `crud`, `list_uids_for_tags_test`,
`block_cipher_mode_migration_after_json_deserialization`.

### Self-selecting mechanism

DB tests **skip gracefully at runtime** when their connection env var is not set.
This eliminates fragile `cargo test` filter strings that could silently break on renames:

```rust
// In test_db_postgresql():
if std::env::var("KMS_POSTGRES_URL").is_err() {
    eprintln!("SKIP test_db_postgresql: KMS_POSTGRES_URL is not set");
    return Ok(());
}
```

### CI orchestration

| CI script | Sets env var | DB tests that run | Additional tests |
|-----------|-------------|-------------------|------------------|
| `test_sqlite.sh` | `KMS_SQLITE_PATH` | `test_db_sqlite` | `test_validate_with_certificates` (network) |
| `test_psql.sh` | `KMS_POSTGRES_URL` | `test_db_postgresql` + `test_db_sqlite` | `test_validate_with_certificates` |
| `test_mysql.sh` | `KMS_MYSQL_URL` | `test_db_mysql` + `test_db_sqlite` | `test_validate_with_certificates` |
| `test_redis.sh` | `KMS_REDIS_URL` | `test_db_redis_with_findex` + `test_db_sqlite` | `test_validate_with_certificates` |
| `test_percona.sh` | `KMS_MYSQL_URL` (Percona port) | `test_db_mysql` + `test_db_sqlite` | `test_validate_with_certificates` |
| `test_maria.sh` | `KMS_MYSQL_URL` (MariaDB port) | `test_db_mysql` + `test_db_sqlite` | `test_validate_with_certificates` |

### Multi-backend regression vectors

Regression test vectors (in `test_data/vectors/`) run against multiple database
backends via the `KMS_TEST_BACKENDS` environment variable. Each manifest declares
which backends it supports in a `backends` field:

```toml
backends = ["sqlite", "postgresql", "mysql", "redis-findex"]
```

The vector runner (`crate/test_kms_server/src/vector_runner.rs`) intersects the
manifest's `backends` list with the requested set from `KMS_TEST_BACKENDS`
(comma-separated, default `sqlite`). Backends whose connection env var is missing
are skipped gracefully at runtime.

```bash
# Run vectors against all available backends:
KMS_TEST_BACKENDS=sqlite,postgresql,mysql \
KMS_POSTGRES_URL=postgresql://kms:kms@127.0.0.1:5432/kms \
KMS_MYSQL_URL=mysql://kms:kms@localhost:3306/kms \
  cargo test -p test_kms_server --features non-fips --lib vector_runner
```

Backend configuration files live in `test_data/configs/server/test/`:

| Backend | Config file | Required env var |
|---------|-------------|------------------|
| `sqlite` | `auth_plain.toml` | — (always available) |
| `postgresql` | `postgres.toml` | `KMS_POSTGRES_URL` |
| `mysql` | `mysql.toml` | `KMS_MYSQL_URL` |
| `redis-findex` | `redis_findex.toml` | `KMS_REDIS_URL` |

See [`crate/test_kms_server/README.md`](crate/test_kms_server/README.md) for full
details on the vector framework and multi-backend architecture.
