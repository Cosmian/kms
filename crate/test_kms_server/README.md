# test_kms_server — Vector Runner & Test Infrastructure

This crate provides the **vector runner** for TTLV-JSON regression tests and
utilities for starting isolated KMS server instances in tests.

## Running Vectors

```bash
# All vectors (non-FIPS mode includes both FIPS and non-FIPS vectors)
cargo test -p test_kms_server --features non-fips --lib vector_runner

# Single vector
cargo test -p test_kms_server --features non-fips --lib -- test_vec_aes_create_get

# Record responses (writes step*_response.json files)
RECORD_VECTORS=1 cargo test -p test_kms_server --features non-fips --lib vector_runner

# PostgreSQL backend (requires docker compose up -d)
KMS_TEST_DB=postgresql cargo test -p test_kms_server --features non-fips --lib vector_runner

# Multiple backends at once
KMS_TEST_BACKENDS=sqlite,postgresql cargo test -p test_kms_server --features non-fips --lib vector_runner
```

## Multi-Backend Testing

The vector runner supports testing against multiple database backends.

### How it works

1. Each vector runs against **all four backends** by default (`sqlite`,
   `postgresql`, `mysql`, `redis-findex`) — no per-manifest `backends` field needed.
2. The runner reads `KMS_TEST_BACKENDS` (comma-separated) or `KMS_TEST_DB` (single
   value, used by CI) to select which backends to test.
3. Backends without their required connection env var are **skipped gracefully**.
4. A **singleton server per backend** (`OnceCell`) is shared across all vectors in
   a test run — no per-test server start/stop overhead.
5. Vectors with a custom `server_config` (e.g. cert_auth, TLS) start a dedicated
   server instance instead of using the singleton.

### Backend → config mapping

| Backend | Config TOML | Required env var |
|---------|-------------|------------------|
| `sqlite` | `auth_plain.toml` | — (always available) |
| `postgresql` | `postgres.toml` | `KMS_POSTGRES_URL` |
| `mysql` | `mysql.toml` | `KMS_MYSQL_URL` |
| `redis-findex` | `redis_findex.toml` | `KMS_REDIS_URL` or `REDIS_HOST` |

### CI integration

CI scripts set `KMS_TEST_DB` to select a single backend:

- `test_sqlite.sh` → (default, no env var)
- `test_psql.sh` → `KMS_TEST_DB=postgresql`
- `test_mysql.sh` → `KMS_TEST_DB=mysql`
- `test_redis.sh` → `KMS_TEST_DB=redis`

---

## Regression Test Vectors (TTLV-JSON)

All regression vectors use a uniform **TTLV-JSON** format. Each vector is a directory
under `test_data/vectors/` containing a `manifest.toml` and one JSON step file
per KMIP operation. The vector runner uses singleton shared servers and
replays the steps sequentially.

**211 vectors** across 7 categories:

| Category | Vector Directory Name | KMIP Operations | Steps |
|----------|-----------------------|-----------------|-------|
| **Symmetric** | | | |
| Symmetric | `aes_create_get` | Create, Get | 2 |
| Symmetric | `aes_encrypt_decrypt` | Create, Encrypt, Decrypt, Revoke, Destroy | 5 |
| Symmetric | `aes128_encrypt_decrypt` | Create, Encrypt (AES-128-GCM), Decrypt | 3 |
| Symmetric | `aes256_cbc_encrypt_decrypt` | Create, Encrypt (AES-256-CBC), Decrypt | 3 |
| Symmetric | `aes128_cbc_encrypt_decrypt` | Create, Encrypt (AES-128-CBC), Decrypt | 3 |
| Symmetric | `aes192_gcm_encrypt_decrypt` | Create, Encrypt (AES-192-GCM), Decrypt | 3 |
| Symmetric | `aes192_cbc_encrypt_decrypt` | Create, Encrypt (AES-192-CBC), Decrypt | 3 |
| Symmetric | `aes128_ecb_encrypt_decrypt` | Create, Encrypt (AES-128-ECB, no padding, no nonce), Decrypt | 3 |
| Symmetric | `aes256_ecb_encrypt_decrypt` | Create, Encrypt (AES-256-ECB, no padding, no nonce), Decrypt | 3 |
| Symmetric | `aes256_gcm_aad_encrypt_decrypt` | Create, Encrypt (AES-256-GCM + AAD), Decrypt | 3 |
| Symmetric | `aes256_gcm_siv_encrypt_decrypt` | Create, Encrypt (AES-256-GCM-SIV), Decrypt | 3 |
| Symmetric | `aes128_gcm_siv_encrypt_decrypt` | Create, Encrypt (AES-128-GCM-SIV), Decrypt | 3 |
| Symmetric | `aes192_ecb_encrypt_decrypt` | Create, Encrypt (AES-192-ECB, no padding), Decrypt | 3 |
| Symmetric | `aes256_cbc_no_padding_encrypt_decrypt` | Create, Encrypt (AES-256-CBC, no padding), Decrypt | 3 |
| Symmetric | `aes128_xts_encrypt_decrypt` | Create, Encrypt (AES-128-XTS), Decrypt | 3 |
| Symmetric | `aes256_xts_encrypt_decrypt` | Create, Encrypt (AES-256-XTS), Decrypt | 3 |
| Symmetric | `chacha20_encrypt_decrypt` | Create, Encrypt (ChaCha20 pure stream), Decrypt | 3 |
| Symmetric | `chacha20_poly1305_encrypt_decrypt` | Create, Encrypt (ChaCha20-Poly1305 AEAD), Decrypt | 3 |
| **Asymmetric** | | | |
| Asymmetric | `rsa_create_encrypt_decrypt` | CreateKeyPair (RSA-2048), Encrypt (OAEP/SHA-256), Decrypt | 3 |
| Asymmetric | `rsa4096_encrypt_decrypt` | CreateKeyPair (RSA-4096), Encrypt (OAEP/SHA-256), Decrypt | 3 |
| Asymmetric | `rsa2048_oaep_sha384_encrypt_decrypt` | CreateKeyPair (RSA-2048), Encrypt (OAEP/SHA-384), Decrypt | 3 |
| Asymmetric | `rsa2048_oaep_sha512_encrypt_decrypt` | CreateKeyPair (RSA-2048), Encrypt (OAEP/SHA-512), Decrypt | 3 |
| Asymmetric | `rsa2048_pkcs1v15_encrypt_decrypt` | CreateKeyPair (RSA-2048), Encrypt (PKCS#1 v1.5), Decrypt | 3 |
| Asymmetric | `ec_p256_sign_verify` | CreateKeyPair (P-256), Sign (ECDSA), SignatureVerify | 3 |
| Asymmetric | `ec_p384_sign_verify` | CreateKeyPair (P-384), Sign (ECDSA), SignatureVerify | 3 |
| Asymmetric | `ec_p521_sign_verify` | CreateKeyPair (P-521), Sign (ECDSA), SignatureVerify | 3 |
| Asymmetric | `rsa2048_pkcs1v15_sha256_sign` | CreateKeyPair (RSA-2048), Sign (PKCS#1 v1.5 SHA-256), SignatureVerify | 3 |
| Asymmetric | `rsa2048_pss_sha256_sign` | CreateKeyPair (RSA-2048), Sign (PSS-SHA256), SignatureVerify | 3 |
| Asymmetric | `rsa2048_pss_sha384_sign` | CreateKeyPair (RSA-2048), Sign (PSS-SHA384), SignatureVerify | 3 |
| Asymmetric | `rsa2048_pss_sha512_sign` | CreateKeyPair (RSA-2048), Sign (PSS-SHA512), SignatureVerify | 3 |
| Asymmetric | `eddsa_ed25519_sign` | CreateKeyPair (Ed25519), Sign (EdDSA), SignatureVerify | 3 |
| Asymmetric | `eddsa_ed448_sign` | CreateKeyPair (Ed448), Sign (EdDSA), SignatureVerify | 3 |
| Asymmetric | `ec_k256_sign_verify` | CreateKeyPair (secp256k1), Sign (ECDSA), SignatureVerify | 3 |
| Asymmetric | `rsa4096_pss_sha256_sign` | CreateKeyPair (RSA-4096), Sign (PSS-SHA256), SignatureVerify | 3 |
| Asymmetric | `rsa2048_pss_sha1_sign` | CreateKeyPair (RSA-2048), Sign (PSS-SHA1), SignatureVerify | 3 |
| Asymmetric | `ec_p256_ecies_encrypt_decrypt` | CreateKeyPair (P-256), Encrypt (ECIES), Decrypt | 3 |
| Asymmetric | `rsa2048_aes_key_wrap` | CreateKeyPair (RSA-2048), Encrypt (RSA-AES key wrap), Decrypt | 3 |
| **PQC** | | | |
| PQC | `ml_dsa_44_sign_verify` | CreateKeyPair (ML-DSA-44), Sign, SignatureVerify | 3 |
| PQC | `ml_dsa_65_sign_verify` | CreateKeyPair (ML-DSA-65), Sign, SignatureVerify | 3 |
| PQC | `ml_dsa_87_sign_verify` | CreateKeyPair (ML-DSA-87), Sign, SignatureVerify | 3 |
| PQC | `ml_kem_512_encap_decap` | CreateKeyPair (ML-KEM-512), Encrypt (encapsulate), Decrypt (decapsulate) | 3 |
| PQC | `ml_kem_768_encap_decap` | CreateKeyPair (ML-KEM-768), Encrypt (encapsulate), Decrypt (decapsulate) | 3 |
| PQC | `ml_kem_1024_encap_decap` | CreateKeyPair (ML-KEM-1024), Encrypt (encapsulate), Decrypt (decapsulate) | 3 |
| PQC | `slh_dsa_sha2_128s_sign_verify` | CreateKeyPair (SLH-DSA-SHA2-128s), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_sha2_128f_sign_verify` | CreateKeyPair (SLH-DSA-SHA2-128f), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_sha2_192s_sign_verify` | CreateKeyPair (SLH-DSA-SHA2-192s), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_sha2_192f_sign_verify` | CreateKeyPair (SLH-DSA-SHA2-192f), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_sha2_256s_sign_verify` | CreateKeyPair (SLH-DSA-SHA2-256s), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_sha2_256f_sign_verify` | CreateKeyPair (SLH-DSA-SHA2-256f), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_shake_128s_sign_verify` | CreateKeyPair (SLH-DSA-SHAKE-128s), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_shake_128f_sign_verify` | CreateKeyPair (SLH-DSA-SHAKE-128f), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_shake_192s_sign_verify` | CreateKeyPair (SLH-DSA-SHAKE-192s), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_shake_192f_sign_verify` | CreateKeyPair (SLH-DSA-SHAKE-192f), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_shake_256s_sign_verify` | CreateKeyPair (SLH-DSA-SHAKE-256s), Sign, SignatureVerify | 3 |
| PQC | `slh_dsa_shake_256f_sign_verify` | CreateKeyPair (SLH-DSA-SHAKE-256f), Sign, SignatureVerify | 3 |
| **KMIP Operations** | | | |
| KMIP Operations | `activate` | Create, Check, Activate, Check, Encrypt, Destroy | 6 |
| KMIP Operations | `attribute_management` | Create, GetAttributes, SetAttribute, AddAttribute, DeleteAttribute, ModifyAttribute, GetAttributeList | 7 |
| KMIP Operations | `certify_validate` | CreateKeyPair, Certify, Validate, Destroy ×3 | 6 |
| KMIP Operations | `certify_revoke_validate` | CreateKeyPair, Certify, Validate, Revoke, Validate (invalid) | 8 |
| KMIP Operations | `certify_chain` | CreateKeyPair, Certify (root→intermediate→leaf), Validate chain | 17 |
| KMIP Operations | `check` | Create, Check, Activate, Check | 4 |
| KMIP Operations | `derive_key_pbkdf2` | Create, DeriveKey (PBKDF2-SHA256), Get | 3 |
| KMIP Operations | `derive_key_pbkdf2_sha512` | Create, DeriveKey (PBKDF2-SHA512), Get | 3 |
| KMIP Operations | `derive_key_hkdf` | Create, DeriveKey (HKDF-SHA256), Get | 3 |
| KMIP Operations | `destroy` | Create, Revoke, Destroy, Get (fail) | 4 |
| KMIP Operations | `discover_versions` | DiscoverVersions | 1 |
| KMIP Operations | `get_attribute_list` | Create, GetAttributeList, Revoke, Destroy | 4 |
| KMIP Operations | `get_attributes` | Create, GetAttributes, Revoke, Destroy | 4 |
| KMIP Operations | `hash_sha256` | Hash (SHA-256) | 2 |
| KMIP Operations | `hash_sha384` | Hash (SHA-384) | 2 |
| KMIP Operations | `hash_sha512` | Hash (SHA-512) | 2 |
| KMIP Operations | `hash_sha3_256` | Hash (SHA3-256) | 2 |
| KMIP Operations | `hash_sha3_384` | Hash (SHA3-384) | 2 |
| KMIP Operations | `hash_sha3_512` | Hash (SHA3-512) | 2 |
| KMIP Operations | `import_key` | Import, Get, Revoke, Destroy | 4 |
| KMIP Operations | `locate` | Create ×2, Locate | 3 |
| KMIP Operations | `locate_by_state` | Create ×2, Activate, Locate (active only) | 4 |
| KMIP Operations | `locate_by_tag` | Create (with vendor tag), Locate (by tag), Destroy | 3 |
| KMIP Operations | `locate_by_usage_mask` | Create (encrypt-only + sign-only), Locate (by usage mask) | 3 |
| KMIP Operations | `mac_and_verify` | Create, MAC, MACVerify, MACVerify (fail) | 4 |
| KMIP Operations | `mac_hmac_sha384` | Create, MAC (HMAC-SHA384) | 2 |
| KMIP Operations | `mac_hmac_sha512` | Create, MAC (HMAC-SHA512) | 2 |
| KMIP Operations | `mac_hmac_sha3_256` | Import, MAC (HMAC-SHA3-256) | 2 |
| KMIP Operations | `opaque_data` | Import, Get, Revoke, Destroy | 4 |
| KMIP Operations | `query` | Query | 1 |
| KMIP Operations | `register_export` | Register, Get, Export, Destroy | 4 |
| KMIP Operations | `rekey` | Create, ReKey, Encrypt | 3 |
| KMIP Operations | `rekey_keypair_ec` | CreateKeyPair (EC), ReKeyKeyPair → not supported | 3 |
| KMIP Operations | `rekey_keypair_rsa` | CreateKeyPair (RSA), ReKeyKeyPair → not supported | 3 |
| KMIP Operations | `rng_retrieve` | RNGRetrieve | 1 |
| KMIP Operations | `rng_seed` | RNGSeed | 1 |
| KMIP Operations | `secret_data` | Register, Get, Activate, Revoke, Destroy | 5 |
| **Access Control** | | | |
| Access Control | `revoke` | Create, Revoke, Encrypt (fail) | 3 |
| Access Control | `grant_access_aes` | Create, GrantAccess, Get (user), Encrypt (user), Decrypt (user) | 5 |
| Access Control | `revoke_access` | Create, GrantAccess, Get (user ok), RevokeAccess, Get (user fail) | 5 |
| Access Control | `unauthorized_access` | Create, Get (user fail — no grant) | 2 |
| Access Control | `owner_full_access` | Create, Get (owner), Encrypt (owner), Decrypt (owner) | 4 |
| Access Control | `grant_partial_permissions` | Create, GrantAccess (Get only), Get (user ok), Encrypt (user fail) | 4 |
| **Integrations** | | | |
| Integrations | `fips/integrations/synology_dsm` | Query ×4, Locate, Register, ModifyAttribute, Locate, Activate, Revoke, Destroy (binary TTLV / KMIP 1.2) | 11 |
| Integrations | `fips/integrations/veeam` | CreateKeyPair, Get ×2, Destroy ×2 (binary TTLV / KMIP 1.4) | 5 |
| Integrations | `fips/integrations/vmware_vcenter` | DiscoverVersions, Query, Create, GetAttributes, AddAttribute ×3, GetAttributes, Get (binary TTLV / KMIP 1.1) | 9 |
| Integrations | `fips/integrations/mysql` | Create, Activate, Get, Revoke, Destroy (binary TTLV / KMIP 1.1) | 5 |
| Integrations | `fips/integrations/percona` | Register, Locate, Get, Revoke, Destroy (binary TTLV / KMIP 1.4) | 5 |
| Integrations | `fips/integrations/fortigate` | Create, Locate, Get, Activate, Revoke, Destroy (binary TTLV / KMIP 1.0) | 6 |
| Integrations | `fips/integrations/vast_data` | Create, Activate, Locate, Get, GetAttributes, Revoke, Destroy (binary TTLV / KMIP 1.2) | 7 |
| Integrations | `fips/integrations/kmip_1_3_symmetric` | Create, Activate, Get, Locate, Revoke, Destroy (binary TTLV / KMIP 1.3) | 6 |
| Integrations | `fips/integrations/kmip_1_3_asymmetric` | CreateKeyPair, Get ×2, Destroy ×2 (binary TTLV / KMIP 1.3) | 5 |
| Integrations | `non-fips/integrations/mongodb` | Create, Locate, Get, Destroy (binary TTLV / KMIP 1.0) | 4 |
| Integrations | `non-fips/integrations/pykmip` | DiscoverVersions, Create, CreateKeyPair, GetAttributes, Locate, Activate, Revoke, Destroy ×3 (binary TTLV / KMIP 1.2) | 11 |
| **TLS Transport** | | | |
| TLS | `tls/server_tls` | Create, Revoke, Destroy (HTTPS server TLS) | 3 |
| TLS | `tls/mtls` | Create, Revoke, Destroy (mTLS client certificate auth) | 3 |
| **Negative** | | | |
| Negative / Protocol | `negative/empty_request` | Empty body → error | 1 |
| Negative / Protocol | `negative/missing_data_encrypt` | Encrypt without Data → error | 2 |
| Negative / Protocol | `negative/missing_data_decrypt` | Decrypt without Data → error | 2 |
| Negative / Protocol | `negative/missing_uid_encrypt` | Encrypt without UniqueIdentifier → error | 1 |
| Negative / Protocol | `negative/nonexistent_key_encrypt` | Encrypt with unknown key ID → error | 1 |
| Negative / Protocol | `negative/nonexistent_key_decrypt` | Decrypt with unknown key ID → error | 1 |
| Negative / Protocol | `negative/wrong_key_type_encrypt` | Encrypt with RSA key for AES cipher → error | 2 |
| Negative / Protocol | `negative/destroy_then_encrypt` | Destroy key then encrypt → error | 3 |
| Negative / Protocol | `negative/empty_data_encrypt` | Encrypt with empty plaintext → success | 2 |
| Negative / Protocol | `negative/invalid_iv_length` | Encrypt with wrong-length IV → error | 2 |
| Negative / Protocol | `negative/sign_with_encrypt_key` | Sign with Encrypt-mask-only key → error | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_unsupported_mode` | Unsupported BlockCipherMode → success | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_unsupported_padding` | Unsupported PaddingMethod with GCM → success | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_mode_algo_mismatch` | ChaCha20 key + AES CryptographicParameters → success | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_gcm_invalid_tag_length` | Invalid TagLength for GCM → error | 2 |
| Negative / CryptoParams | `negative/crypto_params/sign_invalid_hash` | RSA-PSS with MD5 hash → success in non-FIPS | 2 |
| Negative / CryptoParams | `negative/crypto_params/sign_rsa_with_ecdsa_algo` | RSA key + ECDSA algorithm → error | 2 |
| Negative / CryptoParams | `negative/crypto_params/decrypt_wrong_mode` | Encrypt GCM then Decrypt CBC → error | 3 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_chacha20_with_gcm_mode` | ChaCha20 key + GCM mode → success | 2 |
| Negative / CryptoParams | `negative/crypto_params/hash_unsupported_algo` | Hash with MD5 → success in non-FIPS | 1 |
| Negative / CryptoParams | `negative/crypto_params/mac_unsupported_algo` | MAC with MD5 → success in non-FIPS | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_missing_iv_cbc` | AES-CBC decrypt without IV → error | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_empty_tag_gcm` | AES-GCM decrypt with empty auth tag → error | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_truncated_ciphertext` | AES-GCM decrypt truncated ciphertext → error | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_wrong_key` | Decrypt with wrong key → error | 3 |
| Negative / Decrypt | `negative/decrypt/decrypt_corrupted_ciphertext` | AES-GCM decrypt with corrupted ciphertext+tag → error | 3 |
| Negative / RSA | `negative/rsa/rsa_encrypt_oversized_data` | RSA-OAEP encrypt data too large → error | 2 |
| Negative / RSA | `negative/rsa/rsa_decrypt_with_public_key` | RSA decrypt using public key → error | 2 |
| Negative / RSA | `negative/rsa/rsa_decrypt_garbage` | RSA decrypt random bytes → error | 2 |
| Negative / Sign | `negative/sign_verify/verify_corrupted_signature` | Verify with bit-flipped signature → error | 3 |
| Negative / Sign | `negative/sign_verify/verify_wrong_key` | Verify with wrong keypair → error | 4 |
| Negative / Sign | `negative/sign_verify/sign_with_public_key` | Sign with public key → error | 2 |
| Negative / MAC | `negative/mac/mac_with_non_hmac_key` | MAC with AES key (not HMAC) → error | 2 |
| Negative / MAC | `negative/mac/mac_verify_wrong_data` | MACVerify with tampered data → error | 3 |
| Negative / Hash | `negative/hash/hash_missing_algorithm` | Hash without HashingAlgorithm → error | 1 |
| Negative / Hash | `negative/hash/hash_init_and_final_both_true` | Hash with InitIndicator=true AND FinalIndicator=true → error | 1 |
| Negative / DeriveKey | `negative/derive_key/derive_key_pbkdf2_no_salt` | PBKDF2 without Salt → error | 2 |
| Negative / DeriveKey | `negative/derive_key/derive_key_negative_iterations` | PBKDF2 with negative iteration count → error | 2 |
| Negative / Lifecycle | `negative/lifecycle/encrypt_pre_active_key` | Encrypt with pre-active key → error | 2 |
| Negative / Lifecycle | `negative/lifecycle/create_invalid_algorithm` | Create with unknown algorithm → error | 1 |
| Negative / Lifecycle | `negative/lifecycle/create_zero_length_key` | Create with CryptographicLength=0 → error | 1 |
| Negative / Lifecycle | `negative/lifecycle/double_activate` | Activate already-active key → error | 3 |
| Negative / Lifecycle | `negative/lifecycle/deactivate_pre_active` | Activate a destroyed key → error | 5 |
| Negative / TypeMismatch | `negative/type_mismatch/import_malformed_key` | Import TransparentSymmetricKey with raw bytes → error | 1 |
| Negative / TypeMismatch | `negative/type_mismatch/encrypt_with_secret_data` | Encrypt using SecretData object → error | 2 |
| Negative / TypeMismatch | `negative/type_mismatch/revoke_already_destroyed` | Revoke a destroyed key → success | 3 |
| **non-FIPS CryptographicParameters** | | | |
| non-FIPS / GCM-SIV | `non-fips/aes128_gcm_siv_with_explicit_nonce` | Create (AES-128), Encrypt (client 12-B nonce), Decrypt | 3 |
| non-FIPS / GCM-SIV | `non-fips/aes256_gcm_siv_with_explicit_nonce` | Create (AES-256), Encrypt (client 12-B nonce), Decrypt | 3 |
| non-FIPS / GCM-SIV | `non-fips/aes128_gcm_siv_with_aad` | Create (AES-128), Encrypt (AAD + server nonce), Decrypt | 3 |
| non-FIPS / GCM-SIV | `non-fips/aes256_gcm_siv_with_aad` | Create (AES-256), Encrypt (AAD + server nonce), Decrypt | 3 |
| non-FIPS / ChaCha20 | `non-fips/chacha20_server_generated_nonce` | Create, Encrypt (server generates 8-B nonce), Decrypt | 3 |
| non-FIPS / ChaCha20 | `non-fips/chacha20_with_explicit_cryptographic_params` | Create, Encrypt (CryptographicParameters{ChaCha20} + 8-B nonce), Decrypt | 3 |
| non-FIPS / Poly1305 | `non-fips/chacha20_poly1305_with_explicit_nonce` | Create, Encrypt (AEAD + client 12-B nonce), Decrypt | 3 |
| non-FIPS / Poly1305 | `non-fips/chacha20_poly1305_with_aad` | Create, Encrypt (AEAD + AAD + server nonce), Decrypt | 3 |

---

## Known-Answer Test (KAT) Vectors (`test_data/vectors/kat/`)

KAT vectors use **published reference values** from NIST FIPS and RFC specifications to
verify bit-exact outputs. Each vector imports a known key and asserts exact ciphertext,
MAC, or derived-key values.

| Category | Vector Directory | Reference | Operations | Assert Field |
|----------|-----------------|-----------|------------|--------------|
| **Hash** | | NIST FIPS 180-4 / FIPS 202 ("abc") | | |
| Hash | `kat/hash/sha256` | FIPS 180-4 | Hash (SHA-256) | `Data` |
| Hash | `kat/hash/sha384` | FIPS 180-4 | Hash (SHA-384) | `Data` |
| Hash | `kat/hash/sha512` | FIPS 180-4 | Hash (SHA-512) | `Data` |
| Hash | `kat/hash/sha3_256` | FIPS 202 | Hash (SHA3-256) | `Data` |
| Hash | `kat/hash/sha3_384` | FIPS 202 | Hash (SHA3-384) | `Data` |
| Hash | `kat/hash/sha3_512` | FIPS 202 | Hash (SHA3-512) | `Data` |
| **MAC** | | RFC 4231 §4.2 ("Hi There", key=0x0B×32) | | |
| MAC | `kat/mac/hmac_sha256` | RFC 4231 §4.2 | Import, MAC (HMAC-SHA256) | `MACData` |
| MAC | `kat/mac/hmac_sha384` | RFC 4231 §4.2 | Import, MAC (HMAC-SHA384) | `MACData` |
| MAC | `kat/mac/hmac_sha512` | RFC 4231 §4.2 | Import, MAC (HMAC-SHA512) | `MACData` |
| MAC | `kat/mac/hmac_sha3_256` | NIST HMAC-SHA3 | Import, MAC (HMAC-SHA3-256) | `MACData` |
| MAC | `kat/mac/hmac_sha3_384` | NIST HMAC-SHA3 | Import, MAC (HMAC-SHA3-384) | `MACData` |
| MAC | `kat/mac/hmac_sha3_512` | NIST HMAC-SHA3 | Import, MAC (HMAC-SHA3-512) | `MACData` |
| MAC | `kat/mac/hmac_sha1` | RFC 2202 §3 | Import, MAC (HMAC-SHA1) | `MACData` |
| **Symmetric** | | NIST SP 800-38A / SP 800-38D | | |
| Symmetric | `kat/symmetric/aes128_ecb` | SP 800-38A F.1.1 | Import, Encrypt (AES-128-ECB) | `Data` |
| Symmetric | `kat/symmetric/aes192_ecb` | SP 800-38A F.1.3 | Import, Encrypt (AES-192-ECB) | `Data` |
| Symmetric | `kat/symmetric/aes256_ecb` | SP 800-38A F.1.5 | Import, Encrypt (AES-256-ECB) | `Data` |
| Symmetric | `kat/symmetric/aes128_cbc` | SP 800-38A F.2.1 | Import, Encrypt (AES-128-CBC, no padding) | `Data` |
| Symmetric | `kat/symmetric/aes192_cbc` | SP 800-38A F.2.3 | Import, Encrypt (AES-192-CBC, no padding) | `Data` |
| Symmetric | `kat/symmetric/aes256_cbc` | SP 800-38A F.2.5 | Import, Encrypt (AES-256-CBC, no padding) | `Data` |
| Symmetric | `kat/symmetric/aes128_gcm` | SP 800-38D TC7 | Import, Encrypt (AES-128-GCM + AAD) | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric | `kat/symmetric/aes192_gcm` | SP 800-38D TC7 | Import, Encrypt (AES-192-GCM + AAD) | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric | `kat/symmetric/aes256_gcm` | SP 800-38D TC7 | Import, Encrypt (AES-256-GCM + AAD) | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric | `kat/symmetric/chacha20_poly1305` | RFC 8439 §2.8 | Import, Encrypt (ChaCha20-Poly1305) | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric | `kat/symmetric/chacha20_pure` | RFC 7539 §2.1 | Import, Encrypt (ChaCha20 pure stream) | `Data` |
| Symmetric | `kat/symmetric/aes128_xts` | IEEE 1619-2007 | Import, Encrypt (AES-128-XTS) | `Data` |
| Symmetric | `kat/symmetric/aes256_xts` | IEEE 1619-2007 | Import, Encrypt (AES-256-XTS) | `Data` |
| Symmetric | `kat/symmetric/rfc3394_aes128_kek` | RFC 3394 §2.2.3 | Import KEK, Import key, Encrypt (AES-128 key wrap), Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc3394_aes192_kek` | RFC 3394 §2.2.3 | Import KEK, Import key, Encrypt (AES-192 key wrap), Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc3394_aes256_kek` | RFC 3394 §2.2.3 | Import KEK, Import key, Encrypt (AES-256 key wrap), Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc5649_aes128_kek` | RFC 5649 §6 | Import KEK, Encrypt (AES-128 key wrap with padding), Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc5649_aes192_kek` | RFC 5649 §6 | Import KEK, Encrypt (AES-192 key wrap with padding), Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc5649_aes256_kek` | RFC 5649 §6 | Import KEK, Encrypt (AES-256 key wrap with padding), Decrypt | `Data` |
| **Derive Key** | | RFC 5869 / RFC 8018 | | |
| Derive Key | `kat/derive_key/hkdf_sha256` | RFC 5869 §A.1 | Import, DeriveKey (HKDF-SHA256), Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/hkdf_sha384` | RFC 5869 §A.1 | Import, DeriveKey (HKDF-SHA384), Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/hkdf_sha512` | RFC 5869 §A.1 | Import, DeriveKey (HKDF-SHA512), Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/pbkdf2_sha256` | RFC 8018 §5.2 | Import, DeriveKey (PBKDF2-SHA256), Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/pbkdf2_sha384` | RFC 8018 §5.2 | Import, DeriveKey (PBKDF2-SHA384), Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/pbkdf2_sha512` | RFC 8018 §5.2 | Import, DeriveKey (PBKDF2-SHA512), Get | `KeyMaterial` |
| **Asymmetric** | | | | |
| Asymmetric | `kat/asymmetric/ed25519_eddsa_sign` | RFC 8032 §7.1 Test 2 | Import Ed25519 private key, Sign (EdDSA) | `SignatureData` |
| Asymmetric | `kat/asymmetric/rsa2048_oaep_sha256_decrypt` | NIST PKCS#1 v2.2 | Import RSA-2048 private key, Decrypt (OAEP-SHA256) | `Data` |
| **Non-FIPS Symmetric** | | RFC 8452 (AES-GCM-SIV) | | |
| Symmetric (non-FIPS) | `kat/symmetric/aes128_gcm_siv` | RFC 8452 §C.1 | Import, Encrypt (AES-128-GCM-SIV) | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric (non-FIPS) | `kat/symmetric/aes256_gcm_siv` | RFC 8452 §C.1 | Import, Encrypt (AES-256-GCM-SIV) | `Data`, `AuthenticatedEncryptionTag` |
| **Non-FIPS Asymmetric** | | RFC 8032 / RFC 6979 | | |
| Asymmetric (non-FIPS) | `kat/asymmetric/ed448_eddsa_sign` | RFC 8032 §7.4 Test 1 | Import Ed448 private key, Sign (EdDSA) | `SignatureData` |
| Asymmetric (non-FIPS) | `kat/asymmetric/secp256k1_ecdsa_sign` | RFC 6979 §A.2.5 | Import secp256k1 private key, Sign (ECDSA-SHA256) | `SignatureData` |
| **Non-FIPS Covercrypt** | | Cosmian Covercrypt v16 | | |
| Covercrypt (non-FIPS) | `kat/covercrypt_decrypt` | Self-generated USK | Import USK, Decrypt (Covercrypt single-decrypt) | `Data` |

---

## Manifest Schema (`manifest.toml`)

```toml
# Required metadata
name = "AES-256 Create and Get"
description = "Creates an AES-256 symmetric key and retrieves it via Get"

# Optional: override default server config (defaults to auth_plain.toml)
# Vectors with server_config start a dedicated server instance instead of
# using the shared singleton.
# server_config = "test_data/configs/server/test/cert_auth.toml"

# Optional: wire format — "json" (default) or "binary"
# "json" sends TTLV-JSON to /kmip/2_1
# "binary" serializes to binary TTLV and POSTed to /kmip (application/octet-stream)
# wire_format = "binary"

# Optional: KMIP protocol version (default [2, 1])
# Used to set the RequestHeader version and select KMIP 1.x vs 2.x serialization
# kmip_version = [1, 4]

# Optional: named identities for multi-user (access control) tests.
# Each identity specifies client TLS credentials for mTLS authentication.
# On macOS, PKCS#12 is required (native-tls/Security.framework doesn't support PEM identity).
# [identities.owner]
# client_cert = "test_data/certificates/client_server/owner/owner.client.acme.com.crt"
# client_key = "test_data/certificates/client_server/owner/owner.client.acme.com.key"
# client_pkcs12 = "test_data/certificates/client_server/owner/owner.client.acme.com.p12"
# client_pkcs12_password = "password"

# Steps executed sequentially against the KMS server
[[steps]]
operation = "Create"
request = "step1_request.json"
assert_success = true                   # HTTP 200 + ResultStatus check

[steps.capture]
key_id = "UniqueIdentifier"             # capture tag value for use in later steps

[[steps]]
operation = "Get"
request = "step2_request.json"          # contains {{key_id}} placeholder
assert_success = true

[steps.assert_fields]
ObjectType = "SymmetricKey"             # assert specific TTLV tags in response

# Error testing: assert failure and inspect reason
[[steps]]
operation = "Encrypt"
request = "step3_encrypt_after_revoke.json"
assert_success = false
assert_error_reason = "PermissionDenied"           # match ResultReason tag
# assert_error_contains = "partial message match"  # alternative: substring in ResultMessage

# Negative assertions: verify fields are absent from response
[steps.assert_fields_absent]
fields = ["SensitiveField"]

# Assert that a captured value appears among results (for multi-result Locate)
[steps.assert_any_field]
UniqueIdentifier = "{{key_id}}"
```

---

## Request Payloads (TTLV-JSON)

Request files are TTLV-JSON payloads. By default (`wire_format = "json"`), they
are sent directly to the `/kmip/2_1` endpoint. When `wire_format = "binary"`, the
JSON is wrapped in a `RequestMessage` envelope, serialized to binary TTLV, and
POSTed to `/kmip` with `Content-Type: application/octet-stream`.

Binary-mode integration vectors use KMIP 1.4 `TemplateAttribute` format:

```json
{
  "tag": "Create",
  "value": [
    { "tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey" },
    { "tag": "TemplateAttribute", "value": [
      { "tag": "Attribute", "value": [
        { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Algorithm" },
        { "tag": "AttributeValue", "type": "Enumeration", "value": "AES" }
      ]},
      { "tag": "Attribute", "value": [
        { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Length" },
        { "tag": "AttributeValue", "type": "Integer", "value": 256 }
      ]}
    ]}
  ]
}
```

JSON-mode vectors use KMIP 2.1 `Attributes` format:

```json
{
  "tag": "Create",
  "value": [
    { "tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey" },
    { "tag": "Attributes", "value": [
      { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES" },
      { "tag": "CryptographicLength", "type": "Integer", "value": 256 }
    ]}
  ]
}
```

Placeholders use `{{variable_name}}` syntax and are substituted from captured values:

```json
{
  "tag": "Get",
  "value": [
    { "tag": "UniqueIdentifier", "type": "TextString", "value": "{{key_id}}" }
  ]
}
```
