# KMIP Operations & Test Configurations Reference

## Contents
- [KMIP operations dispatch table](#kmip-operations-dispatch-table)
- [Test server configurations](#test-server-configurations)

---

## KMIP operations dispatch table

All 31+ operations dispatched by `crate/server/src/core/operations/dispatch.rs`:

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

## Test server configurations

All files are in `test_data/configs/server/`.

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
