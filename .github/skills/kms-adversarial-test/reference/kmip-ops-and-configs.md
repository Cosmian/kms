# KMIP Operations & Test Configurations Reference

## Contents

- [KMIP operations dispatch table](#kmip-operations-dispatch-table)
- [Test server configurations](#test-server-configurations)

---

## KMIP operations dispatch table

All 44 operations dispatched by `crate/server/src/core/operations/dispatch.rs`:

| Operation          | KMIP Tag             | Handler                                 | Notes                                                      |
| ------------------ | -------------------- | --------------------------------------- | ---------------------------------------------------------- |
| Activate           | `"Activate"`         | `kms.activate()`                        | Transitions key to Active state                            |
| Add Attribute      | `"AddAttribute"`     | `kms.add_attribute()`                   |                                                            |
| Certify            | `"Certify"`          | `kms.certify()`                         | Creates certificate from CSR or key pair                   |
| Check              | `"Check"`            | `check()`                               |                                                            |
| Create             | `"Create"`           | `kms.create()`                          | Creates symmetric keys, secrets, opaque objects            |
| Create Key Pair    | `"CreateKeyPair"`    | `kms.create_key_pair()`                 | RSA, EC, PQC key pairs                                     |
| Create Split Key   | `"CreateSplitKey"`   | `kms.create_split_key()`                | Shamir / XOR key splitting                                 |
| Decrypt            | `"Decrypt"`          | `kms.decrypt()`                         |                                                            |
| Delete Attribute   | `"DeleteAttribute"`  | `kms.delete_attribute()`                |                                                            |
| Derive Key         | `"DeriveKey"`        | `kms.derive_key()`                      | HKDF, SP800-108                                            |
| Destroy            | `"Destroy"`          | `kms.destroy()`                         | Terminal state                                             |
| Discover Versions  | `"DiscoverVersions"` | `kms.discover_versions()`               |                                                            |
| Encrypt            | `"Encrypt"`          | `kms.encrypt()`                         | AES, RSA, EC, FPE, Covercrypt                              |
| Export             | `"Export"`           | `kms.export()`                          |                                                            |
| Get                | `"Get"`              | `kms.get()`                             | Retrieves object by ID                                     |
| Get Attribute List | `"GetAttributeList"` | `get_attribute_list()`                  |                                                            |
| Get Attributes     | `"GetAttributes"`    | `kms.get_attributes()`                  |                                                            |
| Get Constraints    | `"GetConstraints"`   | `constraints::get_constraints()`        | Reads server-wide KMIP constraints                         |
| Hash               | `"Hash"`             | `kms.hash()`                            | SHA-2, SHA-3                                               |
| Import             | `"Import"`           | `kms.import()`                          |                                                            |
| Interop            | `"Interop"`          | `message::process_interop_operation()`  | KMIP interoperability test control                         |
| Join Split Key     | `"JoinSplitKey"`     | `kms.join_split_key()`                  | Reconstructs key from split shares                         |
| Locate             | `"Locate"`           | `kms.locate()`                          | Search by attributes, tags                                 |
| Log                | `"Log"`              | `message::process_log_operation()`      | Records client log message                                 |
| Login              | `"Login"`            | `login::login()`                        | Session login                                              |
| Logout             | `"Logout"`           | `login::logout()`                       | Session logout                                             |
| MAC                | `"MAC"` / `"Mac"`    | `kms.mac()`                             | HMAC, AES-CMAC, AES-GMAC                                   |
| MAC Verify         | `"MACVerify"`        | `mac_verify()`                          |                                                            |
| Modify Attribute   | `"ModifyAttribute"`  | `kms.modify_attribute()`                |                                                            |
| Ping               | `"Ping"`             | `PingResponse`                          | Liveness probe (empty response)                            |
| PKCS#11            | `"PKCS11"`           | `kms.pkcs11()`                          | Remote PKCS#11 over KMIP (requires Crypto Officer)         |
| Query              | `"Query"`            | `kms.query()`                           | Server capabilities                                        |
| ReCertify          | `"ReCertify"`        | `kms.recertify()`                       | Certificate renewal                                        |
| Register           | `"Register"`         | `kms.register()`                        | Import pre-existing object                                 |
| ReKey              | `"ReKey"`            | `kms.rekey()`                           | Key rotation                                               |
| ReKey Key Pair     | `"ReKeyKeyPair"`     | `kms.rekey_keypair()`                   |                                                            |
| Revoke             | `"Revoke"`           | `kms.revoke()`                          |                                                            |
| RNG Retrieve       | `"RNGRetrieve"`      | `kms.rng_retrieve()`                    | Random bytes                                               |
| RNG Seed           | `"RNGSeed"`          | `kms.rng_seed()`                        |                                                            |
| Set Attribute      | `"SetAttribute"`     | `kms.set_attribute()`                   |                                                            |
| Set Constraints    | `"SetConstraints"`   | `constraints::set_constraints()`        | Replaces server-wide constraints (requires Crypto Officer) |
| Sign               | `"Sign"`             | `kms.sign()`                            | RSA, EC, PQC signatures                                    |
| Signature Verify   | `"SignatureVerify"`  | `kms.signature_verify()`                |                                                            |
| Validate           | `"Validate"`         | `kms.validate()`                        | Certificate validation                                     |

Unknown operations → `KmsError::RouteNotFound()` (HTTP 404, or `ErrorReason::Operation_Not_Supported` inside KMIP batch messages).

---

## Test server configurations

All files are in `test_data/configs/server/` (initialize submodule if needed: `git submodule update --init test_data`).

| Config file                     | Auth            | DB           | TLS     | Use when testing...                                   |
| ------------------------------- | --------------- | ------------ | ------- | ----------------------------------------------------- |
| `auth/none.toml`                | None            | SQLite       | No      | **Default for most PRs**                              |
| `auth/api_token.toml`           | API Token       | SQLite       | No      | API token middleware                                  |
| `auth/jwt.toml`                 | JWT (Google)    | SQLite       | No      | JWT/OIDC authentication                               |
| `auth/multifactor_tls_jwt.toml` | TLS + JWT       | SQLite       | Yes     | Multi-factor auth (client cert + JWT)                 |
| `auth/spire_jwt_svid.toml`      | SPIFFE JWT-SVID | SQLite       | PEM     | SPIRE workload identity + UI OIDC                     |
| `auth/vault_kv.toml`            | Vault Token     | SQLite       | No      | Vault token auth + KV v2 secret store                 |
| `tls/fips.toml`                 | mTLS            | SQLite       | PEM     | TLS client certificate auth (FIPS, port 9999)         |
| `tls/non_fips.toml`             | mTLS            | SQLite       | PKCS#12 | TLS client certificate auth (non-FIPS, port 9999)     |
| `tls/tls13_non_fips.toml`       | mTLS            | SQLite       | TLS 1.3 | TLS 1.3 cipher-suite enforcement (port 10000)         |
| `db/postgres.toml`              | None            | PostgreSQL   | No      | PostgreSQL backend (also enables Google CSE test URL) |
| `db/postgres_lb_primary.toml`   | None            | PostgreSQL   | No      | Load-balanced PostgreSQL primary instance             |
| `db/mysql.toml`                 | None            | MySQL        | No      | MySQL backend (also enables Google CSE test URL)      |
| `db/redis_findex.toml`          | None            | Redis-Findex | No      | Redis-Findex backend (`non-fips` only)                |
| `rbac/crypto_officers.toml`     | mTLS            | SQLite       | PEM     | Crypto Officer RBAC and split-key ceremony            |
| `hsm/softhsm2.toml`             | None            | SQLite       | No      | SoftHSM2 PKCS#11 integration                          |
