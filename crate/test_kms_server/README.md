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

| Backend        | Config TOML         | Required env var                |
| -------------- | ------------------- | ------------------------------- |
| `sqlite`       | `auth_plain.toml`   | — (always available)            |
| `postgresql`   | `postgres.toml`     | `KMS_POSTGRES_URL`              |
| `mysql`        | `mysql.toml`        | `KMS_MYSQL_URL`                 |
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

**649 vectors** across 16 categories (including KAT):

| Category | Vector Directory Name | KMIP Operations | Steps |
|----------|-----------------------|-----------------|-------|
| **Symmetric** | | | |
| Symmetric | `aes128_cbc_encrypt_decrypt` | Creates an AES-128 symmetric key, encrypts data with AES-CBC (PKCS5 padding), then decrypts and verifies | 3 |
| Symmetric | `aes128_ecb_encrypt_decrypt` | Creates an AES-128 symmetric key, encrypts block-aligned data with AES-ECB (no padding, no nonce), then decrypts and verifies | 3 |
| Symmetric | `aes128_encrypt_decrypt` | Creates an AES-128 key, encrypts data with AES-GCM, then decrypts | 5 |
| Symmetric | `aes128_gcm_siv_encrypt_decrypt` | Creates an AES-128 symmetric key, encrypts data with AES-GCM-SIV (nonce-misuse resistant AEAD), then decrypts and verifies | 3 |
| Symmetric | `aes128_xts_encrypt_decrypt` | Creates an AES-128-XTS key (32-byte, non-FIPS), encrypts a sector with a fixed tweak, then decrypts and verifies | 3 |
| Symmetric | `aes192_cbc_encrypt_decrypt` | Creates an AES-192 symmetric key, encrypts data with AES-CBC (PKCS5 padding), then decrypts and verifies | 3 |
| Symmetric | `aes192_ecb_encrypt_decrypt` | Creates an AES-192 symmetric key, encrypts block-aligned data with AES-ECB (no padding, no nonce), then decrypts and verifies | 3 |
| Symmetric | `aes192_gcm_encrypt_decrypt` | Creates an AES-192 symmetric key, encrypts data with AES-GCM (AEAD), then decrypts and verifies | 3 |
| Symmetric | `aes256_cbc_encrypt_decrypt` | Creates an AES-256 symmetric key, encrypts data with AES-CBC (PKCS5 padding), then decrypts and verifies | 3 |
| Symmetric | `aes256_cbc_no_padding_encrypt_decrypt` | Creates an AES-256 key, encrypts block-aligned data with CBC and no padding, then decrypts and verifies | 3 |
| Symmetric | `aes256_ecb_encrypt_decrypt` | Creates an AES-256 symmetric key, encrypts block-aligned data with AES-ECB (no padding, no nonce), then decrypts and verifies | 3 |
| Symmetric | `aes256_gcm_aad_encrypt_decrypt` | Creates an AES-256 symmetric key, encrypts data with AES-GCM and Additional Authenticated Data (AAD), then decrypts and verifies that AAD is authenticated | 3 |
| Symmetric | `aes256_gcm_siv_encrypt_decrypt` | Creates an AES-256 symmetric key, encrypts data with AES-GCM-SIV (nonce-misuse resistant AEAD), then decrypts and verifies | 3 |
| Symmetric | `aes256_xts_encrypt_decrypt` | Creates an AES-256-XTS key (64-byte, non-FIPS), encrypts a sector with a fixed tweak, then decrypts and verifies | 3 |
| Symmetric | `aes_create_get` | Creates an AES-256 symmetric key and retrieves it via Get | 2 |
| Symmetric | `aes_encrypt_decrypt` | Creates an AES-256 key, encrypts data with AES-GCM, then decrypts and verifies | 5 |
| Symmetric | `chacha20_encrypt_decrypt` | Creates a ChaCha20 key (non-FIPS), encrypts data with an 8-byte nonce, then decrypts and verifies | 3 |
| Symmetric | `chacha20_poly1305_encrypt_decrypt` | Creates a ChaCha20-Poly1305 key, encrypts data with AEAD mode, then decrypts and verifies | 3 |
| **Asymmetric** | | | |
| Asymmetric | `ec_k256_sign_verify` | Creates a secp256k1 ECDSA key pair (non-FIPS), signs data with SHA-256, verifies the signature | 3 |
| Asymmetric | `ec_p256_ecies_encrypt_decrypt` | Creates an ECDH P-256 key pair (non-FIPS), encrypts with ECIES using the public key, decrypts with the private key | 3 |
| Asymmetric | `ec_p256_sign_verify` | Creates a NIST P-256 key pair, signs data, verifies the signature | 3 |
| Asymmetric | `ec_p384_sign_verify` | Creates a NIST P-384 key pair, signs data, verifies the signature | 3 |
| Asymmetric | `ec_p521_sign_verify` | Creates a NIST P-521 key pair, signs data with ECDSA, verifies the signature | 3 |
| Asymmetric | `eddsa_ed25519_sign` | Creates an Ed25519 key pair, signs data with EdDSA, verifies the signature | 3 |
| Asymmetric | `eddsa_ed448_sign` | Creates an Ed448 key pair (non-FIPS), signs data, verifies the signature | 3 |
| Asymmetric | `ml_dsa_44_export_raw` | Creates a ML-DSA-44 key pair (PKCS8 format), exports both private and public keys as Raw format | 3 |
| Asymmetric | `ml_kem_768_export_raw` | Creates a ML-KEM-768 key pair (PKCS8 format), exports both private and public keys as Raw format | 3 |
| Asymmetric | `rsa2048_aes_key_wrap` | Creates an RSA-2048 key pair, wraps 32-byte AES key material with RSA-AES (PaddingMethod=None), then unwraps and verifies | 3 |
| Asymmetric | `rsa2048_oaep_sha384_encrypt_decrypt` | Creates an RSA-2048 key pair, encrypts data with OAEP/SHA-384, decrypts with the private key and verifies | 3 |
| Asymmetric | `rsa2048_oaep_sha512_encrypt_decrypt` | Creates an RSA-2048 key pair, encrypts data with OAEP/SHA-512, decrypts with the private key and verifies | 3 |
| Asymmetric | `rsa2048_pkcs1v15_encrypt_decrypt` | Creates an RSA-2048 key pair, encrypts data with PKCS#1 v1.5 padding (non-FIPS), decrypts with the private key and verifies | 3 |
| Asymmetric | `rsa2048_pkcs1v15_sha256_sign` | Creates an RSA-2048 key pair, signs data with PKCS#1 v1.5 (SHA-256WithRSAEncryption), verifies the signature | 3 |
| Asymmetric | `rsa2048_pss_sha1_sign` | Creates an RSA-2048 key pair, signs data with PSS-SHA1 (non-FIPS: SHA-1 signing disallowed in FIPS mode), verifies the signature | 3 |
| Asymmetric | `rsa2048_pss_sha256_sign` | Creates an RSA-2048 key pair, signs data with RSASSA-PSS (SHA-256), verifies the signature | 3 |
| Asymmetric | `rsa2048_pss_sha384_sign` | Creates an RSA-2048 key pair, signs data with RSASSA-PSS (SHA-384), verifies the signature | 3 |
| Asymmetric | `rsa2048_pss_sha512_sign` | Creates an RSA-2048 key pair, signs data with RSASSA-PSS (SHA-512), verifies the signature | 3 |
| Asymmetric | `rsa4096_encrypt_decrypt` | Creates an RSA-4096 key pair, encrypts data with the public key, decrypts with the private key | 3 |
| Asymmetric | `rsa4096_pss_sha256_sign` | Creates an RSA-4096 key pair, signs data with PSS-SHA256, verifies the signature | 3 |
| Asymmetric | `rsa_create_encrypt_decrypt` | Creates an RSA-2048 key pair, encrypts data with the public key, decrypts with the private key | 3 |
| **PQC** | | | |
| PQC | `ml_dsa_44_sign_verify` | Creates a ML-DSA-44 key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `ml_dsa_65_sign_verify` | Creates a ML-DSA-65 key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `ml_dsa_87_sign_verify` | Creates a ML-DSA-87 key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `ml_kem_1024_encap_decap` | Creates a ML-KEM-1024 key pair, encapsulates to get ciphertext + shared secret, decapsulates and verifies shared secrets match | 3 |
| PQC | `ml_kem_512_encap_decap` | Creates a ML-KEM-512 key pair, encapsulates to get ciphertext + shared secret, decapsulates and verifies shared secrets match | 3 |
| PQC | `ml_kem_768_encap_decap` | Creates a ML-KEM-768 key pair, encapsulates to get ciphertext + shared secret, decapsulates and verifies shared secrets match | 3 |
| PQC | `slh_dsa_sha2_128f_sign_verify` | Creates a SLH-DSA-SHA2-128f key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_sha2_128s_sign_verify` | Creates a SLH-DSA-SHA2-128s key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_sha2_192f_sign_verify` | Creates a SLH-DSA-SHA2-192f key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_sha2_192s_sign_verify` | Creates a SLH-DSA-SHA2-192s key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_sha2_256f_sign_verify` | Creates a SLH-DSA-SHA2-256f key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_sha2_256s_sign_verify` | Creates a SLH-DSA-SHA2-256s key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_shake_128f_sign_verify` | Creates a SLH-DSA-SHAKE-128f key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_shake_128s_sign_verify` | Creates a SLH-DSA-SHAKE-128s key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_shake_192f_sign_verify` | Creates a SLH-DSA-SHAKE-192f key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_shake_192s_sign_verify` | Creates a SLH-DSA-SHAKE-192s key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_shake_256f_sign_verify` | Creates a SLH-DSA-SHAKE-256f key pair (non-FIPS), signs data, verifies the signature | 3 |
| PQC | `slh_dsa_shake_256s_sign_verify` | Creates a SLH-DSA-SHAKE-256s key pair (non-FIPS), signs data, verifies the signature | 3 |
| **KMIP Operations** | | | |
| KMIP Operations | `activate` | Creates a pre-active key, verifies encrypt fails, activates it, encrypts successfully | 6 |
| KMIP Operations | `attribute_management` | Tests GetAttributes, SetAttribute, AddAttribute, DeleteAttribute, ModifyAttribute, GetAttributeList | 9 |
| KMIP Operations | `batch_create_get` | Sends a single JSON RequestMessage with BatchCount=2: first BatchItem creates an AES-256 key, second BatchItem gets it back. Both items must succeed. Exercises the JSON batch endpoint. | 2 |
| KMIP Operations | `batch_hash_query` | Sends a single binary KMIP RequestMessage with BatchCount=3: Hash(SHA-256), Hash(SHA-384), and Query in one binary request. All three BatchItems must succeed. Exercises the binary batch endpoint with BatchOrderOption=true and stateless independent operations. | 1 |
| KMIP Operations | `certify_chain` | Creates a 3-level X.509 chain: | 22 |
| KMIP Operations | `certify_revoke_validate` | Creates a self-signed certificate, validates it (valid), revokes it, then re-validates (invalid) | 10 |
| KMIP Operations | `certify_validate` | Creates an EC key pair, self-signs a certificate, validates it, then cleans up | 8 |
| KMIP Operations | `check` | Creates a key, checks its usage mask, activates it, checks again | 4 |
| KMIP Operations | `create_split_key_sss` | Creates an AES-256 symmetric key, splits it into 2 shares using XOR-based split knowledge | 14 |
| KMIP Operations | `create_split_key_xor` | Creates an AES-256 symmetric key, splits it into 2 shares using XOR splitting (both shares | 12 |
| KMIP Operations | `crl_validation_lifecycle` | Full CRL validation: create CA+EE cert chain, generate empty CRL (valid), revoke EE cert, regenerate CRL, validate again (invalid due to revocation in CRL) | 16 |
| KMIP Operations | `derive_key_hkdf` | Creates a base symmetric key, derives a new AES-128 key using HKDF-SHA256 | 3 |
| KMIP Operations | `derive_key_pbkdf2` | Creates a base symmetric key, derives a new AES-128 key using PBKDF2-SHA256, retrieves the derived key | 3 |
| KMIP Operations | `derive_key_pbkdf2_sha512` | Creates a base symmetric key, derives a new AES-128 key using PBKDF2-SHA512 | 3 |
| KMIP Operations | `destroy` | Creates a symmetric key, destroys it, then verifies Get fails | 4 |
| KMIP Operations | `discover_versions` | Queries supported KMIP protocol versions from the server | 1 |
| KMIP Operations | `get_attribute_list` | Creates a key and retrieves the list of its attribute names | 4 |
| KMIP Operations | `get_attributes` | Creates a symmetric key, retrieves its attributes, then cleans up | 4 |
| KMIP Operations | `hash_sha256` | Computes a SHA-256 hash of data | 1 |
| KMIP Operations | `hash_sha384` | Computes a SHA-384 hash of data | 1 |
| KMIP Operations | `hash_sha3_256` | Computes a SHA3_256 hash of data | 1 |
| KMIP Operations | `hash_sha3_384` | Computes a SHA3_384 hash of data | 1 |
| KMIP Operations | `hash_sha3_512` | Computes a SHA3_512 hash of data | 1 |
| KMIP Operations | `hash_sha512` | Computes a SHA512 hash of data | 1 |
| KMIP Operations | `import_key` | Imports an AES-256 key with explicit UID, gets it, revokes, and destroys | 4 |
| KMIP Operations | `locate` | Creates two AES keys with distinct names, then locates them by ObjectType and Name | 3 |
| KMIP Operations | `locate_by_state` | Creates two keys (one activated, one pre-active), locates only the active one by state filter | 4 |
| KMIP Operations | `locate_by_tag` | Creates a key with a Cosmian vendor tag, then locates it using the tag filter | 3 |
| KMIP Operations | `locate_by_usage_mask` | Creates keys with different usage masks (encrypt-only vs sign-only), locates by CryptographicUsageMask | 3 |
| KMIP Operations | `mac_and_verify` | Creates an HMAC key, computes a MAC, verifies it, then verifies an invalid MAC fails | 6 |
| KMIP Operations | `mac_hmac_sha384` | Creates an HMACSHA384 HMAC key, computes a MAC over data | 2 |
| KMIP Operations | `mac_hmac_sha3_256` | Imports an HMACSHA3256 HMAC key, computes a MAC over data | 2 |
| KMIP Operations | `mac_hmac_sha512` | Creates an HMACSHA512 HMAC key, computes a MAC over data | 2 |
| KMIP Operations | `opaque_data` | Imports opaque data, retrieves it, then destroys | 4 |
| KMIP Operations | `process_window_encrypt_expired_fails` | Creates an Active symmetric key, then sets its ProtectStopDate to a date in the past via SetAttribute.  An Encrypt attempt must be rejected with Wrong_Key_Lifecycle_State even though the key state is still Active. | 5 |
| KMIP Operations | `process_window_encrypt_not_yet_active_fails` | Creates an Active symmetric key, then sets its ProcessStartDate to a date far in the future via SetAttribute.  An Encrypt attempt must be rejected with Wrong_Key_Lifecycle_State even though the key state is still Active. | 5 |
| KMIP Operations | `query` | Queries server information, supported operations, and supported object types | 1 |
| KMIP Operations | `recertify_chain` | Creates a root CA (self-signed) and a leaf certificate signed by the root, then performs ReCertify on the leaf certificate. Verifies the new leaf cert has proper replacement links and Active state. | 17 |
| KMIP Operations | `recertify_old_cert_stays_active` | After ReCertify, the old certificate transitions to Deactivated state per KMIP §4.57 transition 6 (same path as ReKey). The new certificate is Active. | 12 |
| KMIP Operations | `recertify_self_signed` | Creates a self-signed certificate, performs ReCertify to rotate it, and verifies the new certificate has a fresh UID and Active state. | 11 |
| KMIP Operations | `recertify_with_links` | Verifies that ReCertify properly sets ReplacementObjectLink on the old certificate and ReplacedObjectLink on the new certificate, forming a bidirectional chain. Also verifies that the new certificate is in Active state. | 12 |
| KMIP Operations | `recertify_with_offset` | Verifies that ReCertify with Offset=0 produces an Active certificate, and ReCertify with Offset=86400 (24h future) produces a PreActive certificate. | 21 |
| KMIP Operations | `register_export` | Registers a pre-existing AES key, retrieves it with Get, exports it, then destroys | 5 |
| KMIP Operations | `rekey` | Creates an AES key, re-keys it, and verifies the new key works for encryption | 5 |
| KMIP Operations | `rekey_compromised_succeeds` | Verifies that ReKey on a Compromised key succeeds. Per the spec, Active, Deactivated, and Compromised keys can be rotated. Only PreActive and Destroyed states are rejected. | 8 |
| KMIP Operations | `rekey_deactivated_fails` | Verifies that ReKey on a Destroyed symmetric key fails with Wrong_Key_Lifecycle_State. | 4 |
| KMIP Operations | `rekey_deactivated_succeeds` | Verifies that ReKey on a Deactivated key succeeds. Per KMIP §6.1.46, Wrong_Key_Lifecycle_State is NOT listed in the Re-Key error table, meaning Deactivated keys are eligible for rotation. | 9 |
| KMIP Operations | `rekey_double_chain` | Verifies that re-keying twice creates a proper chain: K1→K2→K3. K1.ReplacementObjectLink=K2, K2.ReplacedObjectLink=K1, K2.ReplacementObjectLink=K3, K3.ReplacedObjectLink=K2. | 12 |
| KMIP Operations | `rekey_keypair_change_algo_fails` | Verifies that ReKeyKeyPair rejects a request that tries to change the cryptographic algorithm (from EC to RSA). | 4 |
| KMIP Operations | `rekey_keypair_deactivated_fails` | Verifies that ReKeyKeyPair on a Destroyed private key fails. | 6 |
| KMIP Operations | `rekey_keypair_deactivated_succeeds` | Verifies that ReKeyKeyPair on a revoked/deactivated private key succeeds. Per KMIP §6.1.47, Wrong_Key_Lifecycle_State is NOT listed in the Re-Key Key Pair error table, meaning Deactivated keys are eligible for rotation. | 10 |
| KMIP Operations | `rekey_keypair_double_chain` | Verifies that re-keying a key pair twice creates a proper chain. KP1 -> KP2 -> KP3 with correct link attributes. | 12 |
| KMIP Operations | `rekey_keypair_ec` | Verifies that ReKeyKeyPair succeeds for an EC P-256 key pair, returning new private and public key UIDs. | 7 |
| KMIP Operations | `rekey_keypair_ec_locate_by_name` | Verifies that after ReKeyKeyPair, the replacement private key inherits the Name attribute and can be found via Locate by name. | 8 |
| KMIP Operations | `rekey_keypair_ec_sign_verify` | Verifies that after ReKeyKeyPair, the new private key can sign and the new public key can verify the signature. | 8 |
| KMIP Operations | `rekey_keypair_ec_with_links` | Verifies that ReKeyKeyPair on an EC P-256 key pair properly sets ReplacementObjectLink on both old keys and ReplacedObjectLink on both new keys. | 10 |
| KMIP Operations | `rekey_keypair_kmip14` | Exercises the ReKeyKeyPair operation through the KMIP 1.4 protocol path, verifying that the V14→V21 request conversion (PrivateKeyUniqueIdentifier as required String, CommonTemplateAttribute→CommonAttributes) and V21→V14 response conversion (UniqueIdentifier→String) work correctly. This test was previously impossible because the ReKeyKeyPair V14↔V21 conversion was not implemented. | 6 |
| KMIP Operations | `rekey_keypair_kmip14_binary` | Exercises ReKeyKeyPair through the binary TTLV wire format with KMIP 1.4 protocol version. This mimics how real clients (VAST Data, Synology, FortiGate, etc.) communicate with the KMS — sending binary TTLV over HTTP. Verifies the full path: JSON→TTLV binary serialization→server parse→V14→V21 conversion→operation→V21→V14 response conversion→binary serialization→JSON assertion. | 6 |
| KMIP Operations | `rekey_keypair_ml_dsa_44` | Verifies that ReKeyKeyPair succeeds for ML-DSA-44, completing the ML-DSA trilogy (44/65/87). | 10 |
| KMIP Operations | `rekey_keypair_ml_dsa_65` | Verifies that ReKeyKeyPair succeeds for ML-DSA-65. | 6 |
| KMIP Operations | `rekey_keypair_ml_dsa_87` | Verifies that ReKeyKeyPair succeeds for ML-DSA-87. | 6 |
| KMIP Operations | `rekey_keypair_ml_kem_1024` | Verifies that ReKeyKeyPair succeeds for ML-KEM-1024. | 6 |
| KMIP Operations | `rekey_keypair_ml_kem_512` | Verifies that ReKeyKeyPair succeeds for ML-KEM-512, completing the ML-KEM trilogy (512/768/1024). | 10 |
| KMIP Operations | `rekey_keypair_ml_kem_768` | Verifies that ReKeyKeyPair succeeds for ML-KEM-768. | 6 |
| KMIP Operations | `rekey_keypair_name_removed_from_old` | Verifies that after ReKeyKeyPair, the old private key no longer has the Name attribute. | 7 |
| KMIP Operations | `rekey_keypair_no_public_link_fails` | Verifies that ReKeyKeyPair fails when the private key has no PublicKeyLink. | 5 |
| KMIP Operations | `rekey_keypair_old_key_still_active` | Verifies that after ReKeyKeyPair, the old private key transitions to Deactivated | 7 |
| KMIP Operations | `rekey_keypair_p384` | Verifies that ReKeyKeyPair succeeds for this key type. | 6 |
| KMIP Operations | `rekey_keypair_p521` | Verifies that ReKeyKeyPair succeeds for this key type. | 6 |
| KMIP Operations | `rekey_keypair_rsa` | Verifies that ReKeyKeyPair succeeds for an RSA-2048 key pair, returning new private and public key UIDs. | 7 |
| KMIP Operations | `rekey_keypair_rsa4096` | Verifies that ReKeyKeyPair succeeds for this key type. | 6 |
| KMIP Operations | `rekey_keypair_rsa_encrypt_decrypt` | Verifies that after ReKeyKeyPair, the new public key can encrypt and the new private key can decrypt. | 8 |
| KMIP Operations | `rekey_keypair_rsa_old_decrypts` | After ReKeyKeyPair, the old private key is Deactivated but can still decrypt ciphertext encrypted with the old public key. Processing operations (Decrypt) accept Deactivated state per KMIP §3.31. | 8 |
| KMIP Operations | `rekey_keypair_rsa_sign_verify` | Verifies that after ReKeyKeyPair on an RSA-2048 key pair, the new private key can sign and the new public key can verify the signature (RSA-PSS SHA-256). | 12 |
| KMIP Operations | `rekey_keypair_rsa_with_links` | Verifies that ReKeyKeyPair on an RSA-2048 key pair properly sets ReplacementObjectLink and ReplacedObjectLink. | 8 |
| KMIP Operations | `rekey_keypair_slh_dsa_sha2_128f` | Verifies that ReKeyKeyPair succeeds for SLH-DSA-SHA2-128F. | 6 |
| KMIP Operations | `rekey_keypair_with_offset` | Verifies that ReKeyKeyPair with an Offset parameter correctly applies date computation on the replacement key pair. | 7 |
| KMIP Operations | `rekey_keypair_with_offset_state` | Verifies that ReKeyKeyPair with Offset=0 produces Active keys, and ReKeyKeyPair with Offset=86400 (24h future) produces PreActive keys. | 20 |
| KMIP Operations | `rekey_kmip14` | Exercises the ReKey operation through the KMIP 1.4 protocol path, verifying that the V14→V21 request conversion and V21→V14 response conversion work correctly. KMIP 1.4 uses TemplateAttribute containers and a required (non-optional) UniqueIdentifier. The ReKey response must return a new UniqueIdentifier as a plain String (not wrapped in UniqueIdentifier enum). | 7 |
| KMIP Operations | `rekey_locate_by_name` | Verifies that after ReKey, the replacement key inherits the Name attribute and can be found via Locate by name. This is the critical behavior for VAST Data and similar EKM integrations that poll by name after rotation. | 9 |
| KMIP Operations | `rekey_mac_keyset` | Complex MAC key rotation test: | 10 |
| KMIP Operations | `rekey_manual_clears_interval` | After a manual ReKey, x-rotate-interval must be set to 0 on the new key. This forces the operator to re-arm the rotation policy explicitly, preventing accidental automatic rotation of the new key. | 8 |
| KMIP Operations | `rekey_manual_clears_offset` | After a manual ReKey, x-rotate-offset must NOT be inherited by the new key. The spec states the value is 'None (not inherited for manual rekey)'. | 8 |
| KMIP Operations | `rekey_name_removed_from_old` | Verifies that after ReKey, the old key no longer has the Name attribute (it was transferred to the replacement key). | 7 |
| KMIP Operations | `rekey_old_key_decrypt_succeeds` | After ReKey, the old key is Deactivated. Per KMIP §3.31 the old key can still be used for Decrypt (processing operations accept Deactivated state). This test encrypts before rotation, then decrypts with the OLD key UID after rotation. | 8 |
| KMIP Operations | `rekey_old_key_still_decrypts` | Verifies that after ReKey, the old key is Deactivated (KMIP §4.57 transition 6) and can no longer be used for encryption. | 7 |
| KMIP Operations | `rekey_with_links` | Verifies that ReKey properly sets ReplacementObjectLink on the old key and ReplacedObjectLink on the new key, forming a bidirectional chain. | 8 |
| KMIP Operations | `rekey_with_offset` | Verifies that ReKey with an Offset parameter correctly computes the replacement key's Activation Date as InitializationDate + Offset. | 7 |
| KMIP Operations | `rekey_with_offset_state` | Verifies that ReKey with Offset=0 produces an Active key, and ReKey with Offset=86400 (24h future) produces a PreActive key. | 13 |
| KMIP Operations | `rekey_wrapped_deactivated_succeeds` | Creates a wrapping key and a wrapped dependent key, verifies wrapping, revokes the dependent, then verifies that ReKey on the deactivated wrapped key succeeds per KMIP §6.1.46. | 12 |
| KMIP Operations | `rekey_wrapped_key` | Creates a wrapping key and a wrapped dependent key, then re-keys the wrapped key. Verifies the new key has fresh material, is still wrapped, and works for encryption. | 13 |
| KMIP Operations | `rekey_wrapping_key` | Creates a wrapping key, creates a dependent key wrapped by it, then re-keys the wrapping key and verifies the dependent key was automatically re-wrapped and still works for encryption. | 13 |
| KMIP Operations | `rekey_wrapping_key_double_chain` | Creates a wrapping key K0 with two wrapped dependants. Rotates K0 → K1, then K1 → K2. Verifies the full link chain (K0 → K1 → K2) and that both dependants are re-wrapped each time and still work for encryption. | 24 |
| KMIP Operations | `rekey_wrapping_key_with_links` | Creates a wrapping key and two dependent wrapped keys. Re-keys the wrapping key and verifies: (1) dependants are actually wrapped, (2) bidirectional replacement links on the wrapping keys, (3) both dependants are re-wrapped and still work for encryption. | 18 |
| KMIP Operations | `rng_retrieve` | Retrieves 32 random bytes from the server RNG | 1 |
| KMIP Operations | `rng_seed` | Seeds the server RNG with entropy and verifies the response | 1 |
| KMIP Operations | `secret_data` | Registers a password as SecretData, retrieves it with Get, then destroys | 5 |
| KMIP Operations (non-FIPS) | `non-fips/rekey_keypair_covercrypt` | Verifies that ReKeyKeyPair on a Covercrypt master secret key with a RekeyAccessPolicy action performs an in-place attribute-level rekey, returning the same UIDs (no new key pair is created). | 6 |
| KMIP Operations (non-FIPS) | `non-fips/rekey_keypair_ed25519` | Verifies that ReKeyKeyPair succeeds for ed25519. | 6 |
| KMIP Operations (non-FIPS) | `non-fips/rekey_keypair_secp256k1` | Verifies that ReKeyKeyPair succeeds for secp256k1. | 6 |
| KMIP Operations (non-FIPS) | `non-fips/rekey_keypair_x25519` | Verifies that ReKeyKeyPair succeeds for x25519. | 6 |
| **Serialization** | | | |
| Serialization | `attributes_preservation` | Creates an AES key with multiple attributes (name, algorithm, length, usage mask), retrieves it with Get, and verifies all attributes are preserved through DB serialization | 3 |
| Serialization | `create_encrypt_decrypt_roundtrip` | Creates an AES-256 key, encrypts data, then decrypts — verifies key material survives DB serialization through KMIP3: prefixed object storage | 3 |
| Serialization | `create_locate_roundtrip` | Creates an AES key with a unique name, then Locates it by name — verifies attributes survive DB serialization (kmip_3_0 JSON format) and json_extract queries work | 2 |
| Serialization | `import_destroy_reimport` | Imports a key with explicit UID, destroys it, then re-imports with the same UID — verifies lifecycle state transitions work correctly with the new serialization format | 6 |
| Serialization | `rsa_sign_verify_roundtrip` | Creates an RSA-2048 key pair, signs data with private key, verifies with public key — verifies asymmetric key material and attributes survive DB serialization | 3 |
| **K8s Plugin** | | | |
| K8s Plugin | `dek_wrap_unwrap` | Simulates the exact sequence performed by kubernetes-kms-plugin when kube-apiserver | 5 |
| **Access Control** | | | |
| Access Control | `crypto_officer_role_allowed_ops` | CryptoOfficer can perform lifecycle operations: Create, Locate, GetAttributes, Destroy. | 4 |
| Access Control | `grant_access_aes` | Owner creates AES key, grants user access, user can Get/Encrypt/Decrypt, owner destroys key | 7 |
| Access Control | `grant_partial_permissions` | Owner grants only Get; user Get succeeds and Encrypt is denied | 6 |
| Access Control | `operator_role_blocked_lifecycle` | Operator role cannot perform lifecycle operations (Create, CreateKeyPair) without explicit Create grant. | 2 |
| Access Control | `owner_full_permissions` | Owner performs Get/Encrypt/Decrypt/Revoke/Destroy without grants | 6 |
| Access Control | `privilege_escalation_activate_without_permission` | Owner creates a PreActive AES key, grants user only Encrypt. User's Activate attempt is denied because Encrypt grant does not imply Activate permission. | 6 |
| Access Control | `privilege_escalation_destroy_without_permission` | Owner creates AES key, grants user only Get. Get acts as wildcard for crypto ops but NOT for Destroy — user's Destroy attempt is denied. | 7 |
| Access Control | `privilege_escalation_non_owner_grant` | Owner creates AES key, user (non-owner) attempts to grant themselves access — must be denied because user does not own the key | 5 |
| Access Control | `privilege_escalation_rekey_without_permission` | Owner creates AES key, grants user only Get. User's ReKey attempt is denied because Get wildcard does NOT apply to lifecycle-mutating operations like ReKey. | 7 |
| Access Control | `privilege_escalation_self_grant` | Owner creates AES key, then attempts to grant themselves additional permissions — which must be denied | 4 |
| Access Control | `revoke_access` | Owner grants user Get, revokes it, user can no longer Get | 7 |
| Access Control | `revoke_key_lifecycle` | Creates a symmetric key, revokes it, then verifies it cannot be used for encryption | 3 |
| Access Control | `unauthorized_access` | Owner creates AES key and ungranted user cannot Get it | 4 |
| **HSM (requires SoftHSM2 + `HSM_SLOT_ID`)** | | | |
| HSM / KEK Baseline | `hsm/hsm_resident_encrypt` | Creates a new AES-256 key on a KMS server with SoftHSM2 KEK enabled. | 3 |
| HSM / KEK Baseline | `hsm/hsm_resident_sign` | Creates an EC P-256 key pair on a KMS server with SoftHSM2 KEK enabled. | 2 |
| HSM / KEK Create | `hsm/kek_aes256_create_encrypt` | Creates a new AES-256 key on a KMS server with SoftHSM2 KEK enabled. | 3 |
| HSM / KEK Bootstrap | `hsm/kek_bootstrap_self_create` | Regression test for the self-wrap bug introduced by PR #968. | 6 |
| HSM / KEK Create | `hsm/kek_ec_p256_create_sign` | Creates an EC P-256 keypair on a KMS server with SoftHSM2 KEK enabled. | 2 |
| HSM / KEK Create | `hsm/kek_ed25519_create_sign` | Creates an Ed25519 keypair on a KMS server with SoftHSM2 KEK enabled. | 2 |
| HSM / KEK | `hsm/kek_encrypt_decrypt` | Imports an AES-256 key into a KMS server backed by a SoftHSM2 KEK. | 3 |
| HSM / KEK ReKey | `hsm/kek_rekey_kek` | Creates a dedicated HSM KEK ('hsm::<slot>::vec_kek_rekey') and a DB AES DEK that is explicitly wrapped at rest by that KEK. Re-keys the KEK itself — the HSM rotation generates new key material and a new UID, then automatically re-wraps all dependent DB keys (rewrap_dependants). Verifies via GetAttributes that the DEK's WrappingKeyLink now points to the new KEK UID, and confirms encrypt still works after the rotation. Fully cleans up (DEK + both KEK generations) for idempotent reruns. | 12 |
| HSM / KEK ReKey | `hsm/kek_rekey_wrapped` | Creates an AES-256 key in a KMS server backed by a SoftHSM2 KEK. The key is auto-wrapped by the HSM-resident KEK at rest. Re-keys the wrapped key (unwrap from KEK, generate new material, re-wrap). Verifies the new key works for encryption. | 9 |
| HSM / KEK Negative | `hsm/kek_rsa1024_rejected` | Attempts to create an RSA-1024 keypair on a server with KEK enabled. | 1 |
| HSM / KEK Create | `hsm/kek_rsa2048_create_sign` | Creates an RSA-2048 keypair on a KMS server with SoftHSM2 KEK enabled. | 2 |
| HSM / KEK Create | `hsm/kek_sign_verify` | Imports an Ed25519 private key into a KMS server backed by a SoftHSM2 KEK. | 2 |
| HSM / Negative | `hsm/no_kek_baseline` | Imports the same AES-256 key as kek_encrypt_decrypt scenario but on a plain SQLite | 3 |
| HSM / Permissions | `hsm/permissions/admin_create_encrypt_destroy` | HSM admin (<o<wner.client@acme.co>m>) creates an AES-256 key directly in the HSM, | 5 |
| HSM / Permissions | `hsm/permissions/admin_grant_encrypt_decrypt` | HSM admin creates an AES-256 key in the HSM, grants Encrypt and Decrypt | 6 |
| HSM / Permissions | `hsm/permissions/admin_grant_revoke` | HSM admin creates an AES key, grants Encrypt to user, user can encrypt, | 7 |
| HSM / Permissions | `hsm/permissions/cannot_grant_destroy` | HSM admin creates an AES key in the HSM, then attempts to grant Destroy to | 4 |
| HSM / Permissions | `hsm/permissions/get_not_wildcard` | HSM admin creates an AES-256 key in the HSM, grants only Get to | 6 |
| HSM / Permissions | `hsm/permissions/locate_visibility` | HSM admin creates two AES keys in the HSM. Grants user Encrypt on only the | 10 |
| HSM / Permissions | `hsm/permissions/user_cannot_create` | Non-admin user (<u<ser.client@acme.co>m>) attempts to create an AES key directly | 1 |
| HSM / Permissions | `hsm/permissions/user_cannot_destroy` | HSM admin creates an AES key, then non-admin user (<u<ser.client@acme.co>m>) | 4 |
| HSM / Permissions | `hsm/permissions/user_cannot_encrypt` | HSM admin creates an AES key in the HSM. Non-admin user (<u<ser.client@acme.co>m>) | 4 |
| HSM / Permissions | `hsm/permissions/user_cannot_grant` | HSM admin creates an AES key in the HSM. Non-admin user (<u<ser.client@acme.co>m>) | 4 |
| HSM / Resident Encrypt | `hsm/resident_aes128_create_encrypt` | Creates an AES-128 key directly on the HSM (key material lives in the HSM token). | 5 |
| HSM / Resident Encrypt | `hsm/resident_aes256_create_encrypt` | Creates an AES-256 key directly on the HSM (key material lives in the HSM token). | 5 |
| HSM / Resident Encrypt | `hsm/resident_aes256_encrypt_cbc` | Creates an AES-256 key on the HSM, then encrypts and decrypts with AES-CBC mode. | 5 |
| HSM / Resident Negative | `hsm/resident_aes256_encrypt_ecb_rejected` | Creates an AES-256 key on the HSM, then attempts to encrypt with ECB mode. | 4 |
| HSM / Resident Negative | `hsm/resident_ec_p256_rejected` | Attempts to create an EC P-256 keypair with an HSM-resident UID. | 1 |
| HSM / Resident Negative | `hsm/resident_ec_p384_rejected` | Attempts to create an EC P-384 keypair with an HSM-resident UID. | 1 |
| HSM / Resident Negative | `hsm/resident_ed25519_rejected` | Attempts to create an Ed25519 keypair with an HSM-resident UID. | 1 |
| HSM / Resident Keyset | `hsm/resident_keyset_double_rotation` | Tests HSM keyset traversal across a 3-generation chain: | 12 |
| HSM / Resident Keyset | `hsm/resident_keyset_full_lifecycle` | Full HSM keyset lifecycle test covering all three decrypt-addressing variants: | 12 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_addressing` | Creates an HSM-resident key, assigns a keyset name (rotate_name = "ks-addr"), | 15 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_basic` | Creates an HSM-resident AES-256 key without a keyset (no rotate_name), encrypts | 9 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_consecutive` | Creates gen-0 key, rekeys twice (gen-1, gen-2), encrypts once per generation, | 17 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_duplicate_rekey` | Creates an HSM-resident key WITHOUT a keyset name (no rotate_name). Re-keys it | 10 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_encrypt_gen_select` | Encrypts with the keyset base UID before rotation (targets gen-0, the only/latest key) | 15 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_rekey_by_hsm_uid` | Verifies that an HSM-resident keyset can be rotated 3 consecutive times using the | 13 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_rekey_by_keyset_name` | Verifies that an HSM-resident keyset can be rotated 3 consecutive times using the | 13 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_rekey_by_name` | Verifies that ReKey can be addressed via the keyset name (not just the direct UID). | 10 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_rekey_non_latest` | Verifies that re-keying a non-latest keyset member is transparently redirected to | 13 |
| HSM / Resident Keyset | `hsm/resident_keyset_no_kek_uid_lifecycle` | Creates a resident AES-256 HSM key, assigns a rotate_name, rekeys the latest | 18 |
| HSM / Resident Keyset | `hsm/resident_keyset_rekey_and_decrypt` | Full HSM keyset rotation test: | 9 |
| HSM / Resident Negative | `hsm/resident_keyset_rotate_name_bare_rejected` | For HSM keys, the keyset name (rotate_name) must be the key's full base UID (hsm::<model>::<slot>::<key_id>). A bare name without the hsm:: prefix is rejected because it would be ambiguous across HSM slots. | 4 |
| HSM / Resident Negative | `hsm/resident_keyset_rotate_name_gen_suffix_rejected` | For HSM keys, the keyset name must be the base UID without any @N generation suffix. Setting rotate_name to 'hsm::slot::key@1' must be rejected. | 4 |
| HSM / Resident Keyset | `hsm/resident_keyset_set_rotate_name` | Creates an AES-256 key directly on the HSM, assigns a rotate_name via SetAttribute | 6 |
| HSM / Resident Negative | `hsm/resident_non_aes_rejected` | Attempts to create a 3DES symmetric key directly on the HSM. | 1 |
| HSM / Resident Negative | `hsm/resident_rsa1024_rejected` | Attempts to create an RSA-1024 keypair with an HSM-resident UID. | 1 |
| HSM / Resident Encrypt | `hsm/resident_rsa2048_encrypt_oaep_sha1` | Creates an RSA-2048 keypair on the HSM, then encrypts with RSA-OAEP-SHA1 | 7 |
| HSM / Resident Encrypt | `hsm/resident_rsa2048_encrypt_oaep_sha256` | Creates an RSA-2048 keypair on the HSM, then attempts to encrypt with RSA-OAEP-SHA256. | 6 |
| HSM / Resident Encrypt | `hsm/resident_rsa2048_encrypt_pkcs1v15` | Creates an RSA-2048 keypair on the HSM, then encrypts with RSA-PKCS#1v1.5 | 7 |
| HSM / Resident Negative | `hsm/resident_rsa2048_sign_dsa_rejected` | Creates an RSA-2048 keypair on the HSM then attempts to sign using DSAWithSHA256. | 6 |
| HSM / Resident Negative | `hsm/resident_rsa2048_sign_ecdsa_rejected` | Creates an RSA-2048 keypair on the HSM then attempts to sign using ECDSAWithSHA256. | 6 |
| HSM / Resident Sign | `hsm/resident_rsa2048_sign_pkcs1v15` | Creates an RSA-2048 keypair on the HSM and signs with raw PKCS#1 v1.5 | 6 |
| HSM / Resident Sign | `hsm/resident_rsa2048_sign_sha1` | Creates an RSA-2048 keypair on the HSM and signs with SHA1WithRSA (CKM_SHA1_RSA_PKCS). | 6 |
| HSM / Resident Sign | `hsm/resident_rsa2048_sign_sha256` | Creates an RSA-2048 keypair on the HSM and signs with SHA256WithRSA (CKM_SHA256_RSA_PKCS). | 6 |
| HSM / Resident Sign | `hsm/resident_rsa2048_sign_sha384` | Creates an RSA-2048 keypair on the HSM and signs with SHA384WithRSA (CKM_SHA384_RSA_PKCS). | 6 |
| HSM / Resident Sign | `hsm/resident_rsa2048_sign_sha512` | Creates an RSA-2048 keypair on the HSM and signs with SHA512WithRSA (CKM_SHA512_RSA_PKCS). | 6 |
| HSM / Resident Sign | `hsm/resident_rsa4096_create_sign` | Creates an RSA-4096 keypair directly on the HSM via CreateKeyPair. | 6 |
| HSM / Negative | `hsm/wrong_prefix` | Attempts to encrypt using a key ID with an invalid HSM slot prefix (hsm::99::nonexistent). | 1 |
| **Integrations** | | | |
| Integrations | `fips/integrations/fortigate` | Simulates FortiOS KMIP 1.0 batched key lookup: Register named AES-128 and HMAC-SHA1 keys → Activate → Batched Locate×4 with UsernamePassword Authentication → Revoke → Destroy. Matches real FortiOS TRACES_40F_1.txt traces (BatchCount=4, BatchOrderOption=true, MaximumItems=1 per Locate, KMIP 1.0 TemplateAttribute). | 17 |
| Integrations | `fips/integrations/fortigate_credential_type` | Non-regression for GitHub issue #824 (FortiOS 7.6.0 / FortiGate 40F support). FortiGate sends CredentialType as a raw numeric enumeration (0x00000001) rather than the symbolic name "UsernameAndPassword". The server previously failed with "missing field `CredentialType`" because the Authentication/Credential structure was not being deserialized correctly. This test sends a KMIP 1.0 Locate request with Authentication containing the numeric CredentialType value and verifies the server processes it successfully. | 5 |
| Integrations | `fips/integrations/fortigate_locate_filter` | Non-regression for GitHub issue #824 comment (FortiOS 7.6 / FortiGate 40F). FortiGate sends KMIP 1.0 Locate requests filtered on the Name attribute to resolve IPsec keys (ENC and AUTH, both directions). The bug caused the server to return the same UniqueIdentifier for all Locate requests regardless of the requested NameValue. This test creates two keys with different names matching the FortiGate naming pattern, locates each by name using KMIP 1.0 TemplateAttribute, and verifies each Locate returns the correct (distinct) key. | 10 |
| Integrations | `fips/integrations/fortigate_locate_get` | Simulates the real FortiOS KMIP 1.0 IPsec key retrieval flow observed in production traces (assii4.txt): Register named AES-128 (ENC) and HMAC-SHA1-160 (AUTH) symmetric keys from the same tunnel pair (FORTIGATE1-FORTIGATE2) → Activate → Batched Locate×2 with UsernamePassword Authentication → Batched Get×2 to retrieve full key material → Revoke → Destroy. Covers the two-phase lookup pattern: first Locate by name to resolve UIDs, then Get by UID to retrieve raw key blocks (FortiOS 7.6 / FortiGate 40F). Key material extracted from assii4.txt production traces. | 10 |
| Integrations | `fips/integrations/fortigate_locate_many_similar_names` | Non-regression for strict name filtering under FortiGate IPsec key patterns. Creates 8 keys with names that share a very long common prefix and differ only in the last few characters (ENC/AUTH, algorithm, key length, tunnel direction). Locates each individually with MaximumItems=1 and verifies that ONLY the exact-match key is returned — proving no aggregation or truncation occurs. assert_count=1 combined with assert_any_field proves exactly one result was returned and it matches the expected key. | 40 |
| Integrations | `fips/integrations/fortigate_locate_multi_tunnel` | Non-regression verifying that keys from different IPsec tunnels are strictly isolated during Locate. Creates 6 keys across 3 tunnel configurations (alpha forward, beta forward, alpha reverse) and verifies each Locate returns only the key for its specific tunnel — no cross-tunnel contamination. Tests that: (1) different tunnel names (alpha vs beta) don't interfere, (2) same tunnel name in different direction (fw1-fw2 vs fw2-fw1) stays isolated, (3) same direction but different type (ENC vs AUTH) returns the correct type. | 30 |
| Integrations | `fips/integrations/fortigate_locate_no_match` | Non-regression proving the server uses EXACT name matching (not substring, prefix, or LIKE). Registers two keys with FortiGate naming patterns, then attempts Locate with: (1) a substring of an existing name, (2) a superstring of an existing name, (3) a completely non-existent name. All three must return success with zero UniqueIdentifiers — proving no partial/fuzzy matching occurs. | 11 |
| Integrations | `fips/integrations/kmip_1_3_asymmetric` | Tests KMIP 1.3 binary wire format with an RSA key pair lifecycle: CreateKeyPair (RSA-2048, Sign/Verify) → Get (public) → Get (private) → Destroy private → Destroy public. KMIP 1.3 is processed identically to 1.4 (no special tweaks unlike 1.0/1.1/1.2). | 5 |
| Integrations | `fips/integrations/kmip_1_3_symmetric` | Tests KMIP 1.3 binary wire format with a full symmetric key lifecycle: Create AES-256 key → Activate → Get → Locate (by name) → Revoke → Destroy. KMIP 1.3 is processed identically to 1.4 (no special tweaks unlike 1.0/1.1/1.2). | 6 |
| Integrations | `fips/integrations/kmip_3_0_asymmetric` | Creates EC P-256 key pair, signs, and verifies using KMIP 3.0 binary wire format | 7 |
| Integrations | `fips/integrations/kmip_3_0_discover_versions` | Queries supported KMIP protocol versions using KMIP 3.0 binary wire format | 1 |
| Integrations | `fips/integrations/kmip_3_0_hash` | Computes SHA-256 hash using KMIP 3.0 binary wire format | 1 |
| Integrations | `fips/integrations/kmip_3_0_locate_get` | Creates a symmetric key, locates it by attributes, and retrieves it using KMIP 3.0 JSON wire format | 4 |
| Integrations | `fips/integrations/kmip_3_0_mac` | Creates HMAC-SHA256 key, computes MAC, and verifies it using KMIP 3.0 binary wire format | 6 |
| Integrations | `fips/integrations/kmip_3_0_query` | Queries server operations and objects using KMIP 3.0 JSON wire format | 1 |
| Integrations | `fips/integrations/kmip_3_0_symmetric` | Creates AES-256 key, encrypts, decrypts, and destroys using KMIP 3.0 binary wire format | 6 |
| Integrations | `fips/integrations/mysql` | Simulates MySQL Enterprise Transparent Data Encryption (TDE) KMIP 1.1 protocol: Create AES-256 key → Activate → Get → Revoke → Destroy. | 5 |
| Integrations | `fips/integrations/percona` | Simulates the Percona PostgreSQL TDE KMIP 1.4 protocol: Register (AES-128 symmetric key) → Locate (by ObjectType + Name) → Get. Mirrors crate/server/src/tests/ttlv_tests/integrations/postgres.rs exactly. | 5 |
| Integrations | `fips/integrations/synology_dsm` | Replays the exact KMIP 1.2 operation sequence observed from Synology DSM 7.x during encrypted volume creation: Query ×4 → Locate (empty) → Register (SecretData/Password with OperationPolicyName) → ModifyAttribute (rename to volume UUID) → Locate (find) → Activate → GetAttributeList → GetAttributes → Get → Revoke → Destroy. Mirrors crate/server/src/tests/ttlv_tests/integrations/synology_dsm.rs exactly. | 14 |
| Integrations | `fips/integrations/vast_data` | Replays the exact KMIP 1.4 operation sequence observed in VAST Data production logs (June 2026): DiscoverVersions → Create AES-256 (with OperationPolicyName) → AddAttribute (Name) → AddAttribute (ObjectGroup) → AddAttribute (OperationPolicyName) → Activate → Locate by name → Get (plaintext) → GetAttributes (State + ActivationDate) → ReKey → Locate (find rotated key) → Get (new key material) → GetAttributes (verify Active + OperationPolicyName preserved after rotation) → Revoke old → Destroy old → Revoke new → Destroy new. VAST uses HTTP POST to /kmip with KMIP 1.4 binary TTLV and mTLS authentication. Covers the ReKey bug fix (issue #845): VAST sends ReKey and expects a new UUID returned. Covers the OperationPolicyName persistence fix: OPN must survive AddAttribute and ReKey. | 17 |
| Integrations | `fips/integrations/veeam` | Replays the KMIP 1.4 operation sequence from Veeam Backup & Replication: CreateKeyPair (RSA-2048, Sign/Verify) → Get (public key) → Get (private key) → Destroy private → Destroy public. Mirrors crate/server/src/tests/ttlv_tests/integrations/veeam.rs exactly. | 5 |
| Integrations | `fips/integrations/vmware_vcenter` | Simulates the VMware vCenter KMIP 1.1 protocol for VM encryption key management: DiscoverVersions → Query → Create (AES-256) → GetAttributes → AddAttribute (x-Product_Version, x-Vendor, x-Product) → GetAttributes → Get. Mirrors crate/server/src/tests/ttlv_tests/integrations/vmware.rs exactly. | 9 |
| Integrations | `non-fips/integrations/edb_tde_key_rotation` | Simulates EDB Postgres TDE master key rotation: | 12 |
| Integrations | `non-fips/integrations/edb_tde_pykmip_variant` | Simulates the EDB Postgres TDE workflow using the pykmip variant: | 6 |
| Integrations | `non-fips/integrations/edb_tde_thales_variant` | Simulates the EDB Postgres TDE workflow using AES-256-CBC KMIP Encrypt/Decrypt: | 6 |
| Integrations | `non-fips/integrations/mongodb` | Simulates MongoDB Queryable Encryption KMIP 1.0 key management: Create AES-256 → Locate → Get → Destroy. Mirrors crate/server/src/tests/ttlv_tests/get_1_0.rs (Percona Server for MongoDB KMIP 1.0). | 4 |
| Integrations | `non-fips/integrations/pykmip` | Simulates the PyKMIP client KMIP 1.2 protocol sequence: DiscoverVersions → Create (AES-256) → CreateKeyPair (RSA-2048) → GetAttributes → Locate → Activate → Revoke → Destroy (symmetric + RSA pair). | 11 |
| **TLS Transport** | | | |
| TLS | `tls/mtls` | Verifies the KMS can be reached over HTTPS with mutual TLS (client certificate required) | 3 |
| TLS | `tls/server_tls` | Verifies the KMS can be reached over HTTPS with server-TLS only (self-signed cert, no mTLS) | 3 |
| **OPA Policy Engine** | | | |
| OPA | `opa/mode_disabled` | OPA not configured; KMS legacy permission logic applies. Creates an AES key, retrieves it, and destroys it. | 3 |
| OPA | `opa/mode_enforcing_allowed` | OPA enforcing mode; JWT with CryptoOfficer role from auth server; Create then Get allowed by is_owner=true (OPA + KMS both pass). | 3 |
| OPA | `opa/mode_enforcing_auditor_create_denied` | OPA enforcing mode. A user holding the `Auditor` role attempts to create a | 1 |
| OPA | `opa/mode_enforcing_co_get_attributes_allowed` | OPA enforcing mode. A `CryptoOfficer` in realm `kms-opa-test` (the default owner / JWT | 3 |
| OPA | `opa/mode_enforcing_denied` | OPA enforcing mode; owner (mTLS cert) creates AES key; ungranted user (different cert, no roles) is denied Get. | 3 |
| OPA | `opa/mode_enforcing_empty_roles_denied` | OPA enforcing mode. A bearer token with an empty `roles` claim (and no domain) | 1 |
| OPA | `opa/mode_enforcing_native_co_cert_allowed` | OPA enforcing mode. A client authenticated via mTLS (cert CN = <owner.client@acme.com>) | 2 |
| OPA | `opa/mode_enforcing_unknown_role_denied` | OPA enforcing mode. A bearer token carrying an unrecognised role `Hacker` | 1 |
| OPA | `opa/mode_enforcing_wrong_domain` | OPA enforcing (dual-gate) mode — multi-tenant isolation. | 3 |
| OPA | `opa/mode_exclusive_allowed` | OPA exclusive mode; JWT with CryptoOfficer role from auth server; Create then Get allowed by is_owner=true. | 3 |
| OPA | `opa/mode_exclusive_auditor_destroy_denied` | OPA exclusive mode. The CryptoOfficer (default JWT client, owner) creates an AES key. | 3 |
| OPA | `opa/mode_exclusive_auditor_get_attributes_allowed` | OPA exclusive mode. The CryptoOfficer (default JWT client, owner) creates an AES key. | 3 |
| OPA | `opa/mode_exclusive_auditor_wrong_domain` | OPA exclusive mode — multi-tenant isolation. | 3 |
| OPA | `opa/mode_exclusive_denied` | OPA exclusive mode; owner (mTLS cert) creates AES key; ungranted user (different cert, no roles) is denied Get. | 3 |
| OPA | `opa/mode_exclusive_domain_admin_wrong_domain` | OPA exclusive mode. The CryptoOfficer from realm `kms-opa-test` (default JWT client, | 3 |
| OPA | `opa/mode_exclusive_native_co_cert_denied` | OPA exclusive mode. A client authenticated via mTLS (cert CN = <owner.client@acme.com>) | 1 |
| OPA | `opa/mode_exclusive_other_domain_allowed` | OPA exclusive mode. A CryptoOfficer from realm `kms-opa-other` (domain=kms-opa-other) | 3 |
| OPA | `opa/mode_exclusive_super_admin_cross_domain` | OPA exclusive mode — SuperAdmin cross-domain positive test. | 3 |
| OPA | `opa/mode_exclusive_user_role_denied` | OPA exclusive mode. The CryptoOfficer (default JWT client, owner) creates an AES key. | 3 |
| OPA | `opa/mode_exclusive_user_wrong_domain` | OPA exclusive mode — multi-tenant isolation. | 3 |
| OPA | `opa/mode_exclusive_wrong_domain` | OPA exclusive mode. The CryptoOfficer from realm `kms-opa-test` (default JWT client, | 3 |
| **Negative** | | | |
| Negative / Activate | `negative/activate/item_not_found` | Tests that Activate returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Activate | `negative/activate/wrong_key_lifecycle_state` | Tests that Activate returns Wrong_Key_Lifecycle_State error as per KMIP spec | 3 |
| Negative / AddAttribute | `negative/add_attribute/item_not_found` | Tests that Add Attribute returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / AddAttribute | `negative/add_attribute/read_only_attribute` | Tests that Add Attribute returns Read_Only_Attribute error as per KMIP spec | 2 |
| Negative / Certify | `negative/certify/invalid_object_type` | Tests that Certify returns Invalid_Object_Type error as per KMIP spec | 2 |
| Negative / Certify | `negative/certify/item_not_found` | Tests that Certify returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Check | `negative/check/item_not_found` | Tests that Check returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Create | `negative/create/invalid_attribute` | Tests that Create returns Invalid_Attribute error as per KMIP spec | 1 |
| Negative / Create | `negative/create/invalid_attribute_value` | Tests that Create returns Invalid_Attribute_Value error as per KMIP spec | 1 |
| Negative / Create | `negative/create/invalid_field` | Tests that Create returns Invalid_Field error as per KMIP spec | 1 |
| Negative / Create | `negative/create/invalid_message` | Tests that Create returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Create | `negative/create/read_only_attribute` | Tests that Create returns Read_Only_Attribute error as per KMIP spec | 2 |
| Negative / CreateKeyPair | `negative/create_key_pair/invalid_attribute` | Tests that Create Key Pair returns Invalid_Attribute error as per KMIP spec | 1 |
| Negative / CreateKeyPair | `negative/create_key_pair/invalid_attribute_value` | Tests that Create Key Pair returns Invalid_Attribute_Value error as per KMIP spec | 1 |
| Negative / CreateKeyPair | `negative/create_key_pair/invalid_message` | Tests that Create Key Pair returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Protocol | `negative/create_split_key_parts_less_than_threshold` | A CreateSplitKey request where split_key_parts < split_key_threshold must be rejected. | 3 |
| Negative / Protocol | `negative/create_split_key_threshold_too_low` | A CreateSplitKey request with split_key_threshold = 1 must be rejected by the server. | 3 |
| Negative / CryptoParams | `negative/crypto_params/decrypt_wrong_mode` | Tests that decryption fails when using CBC mode to decrypt data that was encrypted with GCM | 3 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_chacha20_with_gcm_mode` | Documents that ChaCha20Poly1305 key with BlockCipherMode GCM succeeds — server routes to AES-256-GCM since GCM mode overrides the key's algorithm | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_gcm_invalid_tag_length` | Tests that AES-GCM encryption fails with an invalid authentication tag length | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_mode_algo_mismatch` | Documents that encryption succeeds when CryptographicParameters algorithm differs from key algorithm — server uses the key's actual algorithm, ignoring algorithm field in CryptographicParameters | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_unsupported_mode` | Tests that AES encryption fails with an unsupported BlockCipherMode | 2 |
| Negative / CryptoParams | `negative/crypto_params/encrypt_unsupported_padding` | Documents that AES-GCM encryption ignores unsupported PaddingMethod (GCM handles padding internally) | 2 |
| Negative / CryptoParams | `negative/crypto_params/hash_unsupported_algo` | Tests that hashing fails when using an unsupported algorithm (MD5) | 1 |
| Negative / CryptoParams | `negative/crypto_params/mac_unsupported_algo` | Tests that MAC computation fails when using an unsupported hashing algorithm (MD5) | 2 |
| Negative / CryptoParams | `negative/crypto_params/sign_invalid_hash` | Documents that RSA-PSS signing with MD5 succeeds in non-FIPS mode (OpenSSL allows MD5 in legacy mode) | 2 |
| Negative / CryptoParams | `negative/crypto_params/sign_rsa_with_ecdsa_algo` | Tests that signing an RSA key with ECDSA digital signature algorithm fails | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_corrupted_ciphertext` | Tests that AES-GCM decryption fails when ciphertext and tag are fabricated | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_empty_tag_gcm` | Tests that AES-GCM decryption fails when AuthenticatedEncryptionTag is missing | 3 |
| Negative / Decrypt | `negative/decrypt/decrypt_missing_iv_cbc` | When IVCounterNonce is absent from a CBC Decrypt request the KMS must return | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_truncated_ciphertext` | Tests that AES-GCM decryption fails when ciphertext is too short (1 byte) | 2 |
| Negative / Decrypt | `negative/decrypt/decrypt_wrong_key` | Tests that AES-GCM decryption fails when using a different key than the one used for encryption | 4 |
| Negative / Decrypt | `negative/decrypt/invalid_message` | Tests that Decrypt returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Decrypt | `negative/decrypt/wrong_key_lifecycle_state` | Tests that Decrypt returns Wrong_Key_Lifecycle_State error as per KMIP spec | 2 |
| Negative / DeleteAttribute | `negative/delete_attribute/item_not_found` | Tests that Delete Attribute returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / DeriveKey | `negative/derive_key/derive_key_negative_iterations` | Tests that PBKDF2 key derivation fails when IterationCount is negative | 2 |
| Negative / DeriveKey | `negative/derive_key/derive_key_pbkdf2_no_salt` | Tests that PBKDF2 key derivation fails when Salt is not provided | 2 |
| Negative / Destroy | `negative/destroy/item_not_found` | Tests that Destroy returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Destroy | `negative/destroy/wrong_key_lifecycle_state` | Tests that Destroy returns Wrong_Key_Lifecycle_State error as per KMIP spec | 3 |
| Negative / Protocol | `negative/destroy_then_encrypt` | Tests that encrypt fails when the key has been destroyed | 5 |
| Negative / Protocol | `negative/duplicate_tags_encrypt` | Creates two AES-256 keys with the same tag ["dup-test-enc"], then attempts | 7 |
| Negative / Protocol | `negative/empty_data_encrypt` | Tests that GCM encryption with empty data succeeds (GCM allows empty plaintext) | 2 |
| Negative / Protocol | `negative/empty_request` | Tests that the server handles an empty JSON body gracefully | 1 |
| Negative / Encrypt | `negative/encrypt/bad_cryptographic_parameters` | Tests that Encrypt returns Bad_Cryptographic_Parameters error as per KMIP spec | 3 |
| Negative / Encrypt | `negative/encrypt/incompatible_cryptographic_usage_mask` | Tests that Encrypt returns Incompatible_Cryptographic_Usage_Mask error as per KMIP spec | 3 |
| Negative / Encrypt | `negative/encrypt/invalid_field` | Tests that Encrypt returns Invalid_Field error as per KMIP spec | 3 |
| Negative / Encrypt | `negative/encrypt/invalid_message` | Tests that Encrypt returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Encrypt | `negative/encrypt/invalid_object_type` | Tests that Encrypt returns Invalid_Object_Type error as per KMIP spec | 3 |
| Negative / Encrypt | `negative/encrypt/unsupported_cryptographic_parameters` | Tests that Encrypt returns Unsupported_Cryptographic_Parameters error as per KMIP spec | 3 |
| Negative / Encrypt | `negative/encrypt/wrong_key_lifecycle_state` | Tests that Encrypt returns Wrong_Key_Lifecycle_State error as per KMIP spec | 2 |
| Negative / Export | `negative/export/item_not_found` | Tests that Export returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Export | `negative/export/key_format_type_not_supported` | Tests that Export returns Key_Format_Type_Not_Supported error as per KMIP spec | 2 |
| Negative / Get | `negative/get/item_not_found` | Tests that Get returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Get | `negative/get/key_format_type_not_supported` | Tests that Get returns Key_Format_Type_Not_Supported error as per KMIP spec | 2 |
| Negative / GetAttributeList | `negative/get_attribute_list/item_not_found` | Tests that Get Attribute List returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / GetAttributes | `negative/get_attributes/item_not_found` | Tests that Get Attributes returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Hash | `negative/hash/hash_init_and_final_both_true` | Tests that Hash operation fails when both InitIndicator and FinalIndicator are set to true | 1 |
| Negative / Hash | `negative/hash/hash_missing_algorithm` | Tests that Hash operation fails when CryptographicParameters has no HashingAlgorithm | 1 |
| Negative / Import | `negative/import/invalid_message` | Tests that Import returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Protocol | `negative/invalid_iv_length` | Tests that AES-CBC encryption fails when an IV with incorrect length (8 bytes instead of 16) is provided | 2 |
| Negative / Lifecycle | `negative/lifecycle/create_hsm_key_without_hsm` | Attempts to create an AES-256 key with an HSM-prefixed UID (hsm::0::no_hsm_key) | 1 |
| Negative / Lifecycle | `negative/lifecycle/create_invalid_algorithm` | Tests that key creation fails when specifying an unsupported cryptographic algorithm | 1 |
| Negative / Lifecycle | `negative/lifecycle/create_zero_length_key` | Tests that key creation fails when CryptographicLength is set to zero | 1 |
| Negative / Lifecycle | `negative/lifecycle/deactivate_pre_active` | Tests that activating a destroyed key fails | 5 |
| Negative / Lifecycle | `negative/lifecycle/double_activate` | Tests that activating an already-active key fails | 3 |
| Negative / Lifecycle | `negative/lifecycle/encrypt_pre_active_key` | Tests that encryption fails when using a key that has not been activated (no ActivationDate) | 2 |
| Negative / Lifecycle | `negative/lifecycle/reactivate_deactivated` | Tests that activating a deactivated (revoked) key fails | 4 |
| Negative / MAC | `negative/mac/item_not_found` | Tests that MAC returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / MAC | `negative/mac/mac_verify_wrong_data` | Tests that MAC verification returns Invalid when data does not match the MAC | 3 |
| Negative / MAC | `negative/mac/mac_with_non_hmac_key` | Tests that MAC operation fails when using an AES key without proper HMAC algorithm parameters | 2 |
| Negative / MAC | `negative/mac/wrong_key_lifecycle_state` | Tests that MAC returns Wrong_Key_Lifecycle_State error as per KMIP spec | 2 |
| Negative / MAC | `negative/mac_verify/item_not_found` | Tests that MAC Verify returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / MAC | `negative/mac_verify/wrong_key_lifecycle_state` | Tests that MAC Verify returns Wrong_Key_Lifecycle_State error as per KMIP spec | 2 |
| Negative / Protocol | `negative/missing_data_decrypt` | Tests that decrypt fails when no Data field is provided | 2 |
| Negative / Protocol | `negative/missing_data_encrypt` | Tests that encrypt fails when no Data field is provided | 2 |
| Negative / Protocol | `negative/missing_uid_encrypt` | Tests that encrypt fails when no UniqueIdentifier is provided | 1 |
| Negative / ModifyAttribute | `negative/modify_attribute/item_not_found` | Tests that Modify Attribute returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / ModifyAttribute | `negative/modify_attribute/read_only_attribute` | Tests that Modify Attribute returns Read_Only_Attribute error as per KMIP spec | 2 |
| Negative / Protocol | `negative/nonexistent_key_decrypt` | Tests that decrypt fails when referencing a key ID that does not exist | 1 |
| Negative / Protocol | `negative/nonexistent_key_encrypt` | Tests that encrypt fails when referencing a key ID that does not exist | 1 |
| Negative / Protocol | `negative/recertify_missing_uid` | Tests that ReCertify fails — ReCertify is a KMIP 1.4 operation not supported in KMIP 2.1 | 1 |
| Negative / Protocol | `negative/recertify_nonexistent` | Tests that ReCertify fails when the certificate UID does not exist in the database | 1 |
| Negative / Protocol | `negative/recertify_not_a_certificate` | Tests that ReCertify fails when given a symmetric key instead of a certificate | 4 |
| Negative / Register | `negative/register/invalid_attribute` | Tests that Register returns Invalid_Attribute error as per KMIP spec | 1 |
| Negative / Register | `negative/register/invalid_attribute_value` | Tests that Register returns Invalid_Attribute_Value error as per KMIP spec | 1 |
| Negative / Register | `negative/register/invalid_message` | Tests that Register returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Protocol | `negative/rekey_keypair_non_latest` | Tests that ReKeyKeyPair on a retired (non-latest) keyset member is rejected. | 7 |
| Negative / Protocol | `negative/rekey_keypair_preactive_fails` | Creates an EC P-256 key pair without ActivationDate (enters PreActive state), then verifies that ReKeyKeyPair on a PreActive private key is rejected. Only Active keys can be rotated. | 5 |
| Negative / Protocol | `negative/rekey_offset_preactive_cannot_encrypt` | When ReKey uses Offset=86400, the new key enters PreActive state. A PreActive key must not be usable for Encrypt operations. | 6 |
| Negative / Protocol | `negative/rekey_preactive_fails` | Creates a symmetric key without ActivationDate (enters PreActive state), then verifies that ReKey on a PreActive key is rejected. Only Active keys can be rotated. | 4 |
| Negative / Revoke | `negative/revoke/item_not_found` | Tests that Revoke returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / RSA | `negative/rsa/rsa_decrypt_garbage` | Tests that RSA-OAEP decryption fails when ciphertext is random garbage data | 2 |
| Negative / RSA | `negative/rsa/rsa_decrypt_with_public_key` | Tests that RSA decryption fails when attempting to use a public key for decryption | 2 |
| Negative / RSA | `negative/rsa/rsa_encrypt_oversized_data` | Tests that RSA-OAEP encryption fails when plaintext exceeds modulus size limit | 2 |
| Negative / SetAttribute | `negative/set_attribute/hsm_rotate_offset_rejected` | Tests that SetAttribute rotate_offset on an HSM-resident key is rejected | 4 |
| Negative / SetAttribute | `negative/set_attribute/item_not_found` | Tests that Set Attribute returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / SetAttribute | `negative/set_attribute/read_only_attribute` | Tests that Set Attribute returns Read_Only_Attribute error as per KMIP spec | 2 |
| Negative / SetAttribute | `negative/set_attribute/readonly_rotate_date` | x-rotate-date is a server-managed read-only attribute. Any attempt to set it via SetAttribute must be rejected with Attribute_Read_Only. | 4 |
| Negative / SetAttribute | `negative/set_attribute/readonly_rotate_generation` | x-rotate-generation is a server-managed read-only attribute. Any attempt to set it via SetAttribute must be rejected with Attribute_Read_Only. | 4 |
| Negative / Sign | `negative/sign/invalid_message` | Tests that Sign returns Invalid_Message error as per KMIP spec | 1 |
| Negative / Sign | `negative/sign/item_not_found` | Tests that Sign returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Sign | `negative/sign/wrong_key_lifecycle_state` | Tests that Sign returns Wrong_Key_Lifecycle_State error as per KMIP spec | 2 |
| Negative / Sign | `negative/sign_verify/sign_with_public_key` | Tests that signing fails when attempting to use a public key instead of private key | 2 |
| Negative / Sign | `negative/sign_verify/verify_corrupted_signature` | Tests that signature verification returns Invalid when the signature is fabricated | 3 |
| Negative / Sign | `negative/sign_verify/verify_wrong_key` | Tests that signature verification returns Invalid when verifying with a different key pair | 4 |
| Negative / Protocol | `negative/sign_with_encrypt_key` | Tests that signing fails when the private key only has Decrypt usage mask (no Sign permission) | 2 |
| Negative / SignatureVerify | `negative/signature_verify/item_not_found` | Tests that Signature Verify returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / SignatureVerify | `negative/signature_verify/wrong_key_lifecycle_state` | Tests that Signature Verify returns Wrong_Key_Lifecycle_State error as per KMIP spec | 2 |
| Negative / TypeMismatch | `negative/type_mismatch/encrypt_with_secret_data` | Tests that encryption fails when attempting to use a Secret Data object instead of a cryptographic key | 2 |
| Negative / TypeMismatch | `negative/type_mismatch/import_malformed_key` | Tests that importing a key with mismatched key material size and declared CryptographicLength fails | 1 |
| Negative / TypeMismatch | `negative/type_mismatch/revoke_already_destroyed` | Documents that the server allows revoking a key that has already been destroyed (surprising but accepted behavior) | 4 |
| Negative / Validate | `negative/validate/item_not_found` | Tests that Validate returns Item_Not_Found error as per KMIP spec | 1 |
| Negative / Protocol | `negative/wrong_key_type_encrypt` | Tests that encrypt fails when using a private key (wrong key type for encryption) | 2 |
| **non-FIPS CryptographicParameters** | | | |
| non-FIPS / GCM-SIV | `non-fips/aes128_gcm_siv_with_aad` | Creates an AES-128 key, encrypts with additional authenticated data (AAD) using AES-GCM-SIV (server-generated nonce), then decrypts with the same AAD and verifies the plaintext | 3 |
| non-FIPS / GCM-SIV | `non-fips/aes128_gcm_siv_with_explicit_nonce` | Creates an AES-128 key, encrypts with a client-provided 12-byte nonce using AES-GCM-SIV, then decrypts and verifies the plaintext | 3 |
| non-FIPS / GCM-SIV | `non-fips/aes256_gcm_siv_with_aad` | Creates an AES-256 key, encrypts with additional authenticated data (AAD) using AES-GCM-SIV (server-generated nonce), then decrypts with the same AAD and verifies the plaintext | 3 |
| non-FIPS / GCM-SIV | `non-fips/aes256_gcm_siv_with_explicit_nonce` | Creates an AES-256 key, encrypts with a client-provided 12-byte nonce using AES-GCM-SIV, then decrypts and verifies the plaintext | 3 |
| non-FIPS / Poly1305 | `non-fips/chacha20_poly1305_with_aad` | Creates a ChaCha20-Poly1305 key, encrypts with additional authenticated data (AAD) using AEAD mode (server-generated nonce), then decrypts with the same AAD and verifies the plaintext | 3 |
| non-FIPS / Poly1305 | `non-fips/chacha20_poly1305_with_explicit_nonce` | Creates a ChaCha20-Poly1305 key, encrypts with a client-provided 12-byte nonce using AEAD mode, then decrypts and verifies the plaintext | 3 |
| non-FIPS / ChaCha20 | `non-fips/chacha20_server_generated_nonce` | Creates a ChaCha20 key, encrypts without specifying a nonce (server generates an 8-byte nonce), captures the nonce from the response, then decrypts and verifies the plaintext | 3 |
| non-FIPS / ChaCha20 | `non-fips/chacha20_with_explicit_cryptographic_params` | Creates a ChaCha20 key, encrypts with an explicit CryptographicParameters block specifying the ChaCha20 algorithm and a client-provided 8-byte nonce, then decrypts and verifies the plaintext | 3 |
| **Keyset Resolution** | | | |
| Keyset | `keyset_chain_skips_expired_window` | Creates a symmetric key (gen-0), sets a rotate_name, encrypts with the gen-0 UID, then performs a ReKey to create gen-1.  Sets ProtectStopDate in the past on gen-1 (the newest key in the chain).  Decrypts with the bare keyset name. | 9 |
| Keyset / Decrypt | `keyset_decrypt_at_first` | Creates a symmetric key, assigns a rotate_name, encrypts with the original key UID, performs a ReKey, then decrypts using name@first. Verifies that @first resolves to gen-0 for decryption. | 8 |
| Keyset / Decrypt | `keyset_decrypt_at_generation_n` | Creates a symmetric key, assigns a rotate_name, encrypts with gen-0 UID, performs two ReKey operations, then decrypts using name@0. Verifies that @0 resolves to gen-0 for decryption even after multiple rotations. | 11 |
| Keyset / Decrypt | `keyset_decrypt_at_latest` | Decrypt using name@latest resolves to the single latest key rather than walking the chain. After rotation, encrypts with the new key, then decrypts using name@latest which should find the new key directly. | 8 |
| Keyset / Decrypt | `keyset_decrypt_double_rotation` | Tests try-each-key across a 3-generation chain: | 11 |
| Keyset / Decrypt | `keyset_decrypt_try_each` | The primary keyset try-each-key test: | 8 |
| Keyset | `keyset_ec_sign_verify_chain` | Tests keyset-based Sign resolution with EC key pairs: | 10 |
| Keyset / Encrypt | `keyset_encrypt_at_first` | Creates a symmetric key with a rotate_name, encrypts using name@first while gen-0 is Active, then performs ReKey (gen-0 → Deactivated per §4.57). Verifies @first resolved to gen-0 by decrypting with the original key UID after rotation (Decrypt accepts Deactivated keys per KMIP §3.31). | 8 |
| Keyset / Encrypt | `keyset_encrypt_at_generation_n` | Creates a symmetric key, assigns a rotate_name, performs two ReKey operations (gen-0→gen-1→gen-2). Encrypts with name@1 while gen-1 is still Active (between rotations), then verifies by decrypting with the gen-1 UID after the second rotation (Decrypt accepts Deactivated keys). | 11 |
| Keyset / Encrypt | `keyset_encrypt_bare_name` | Creates a symmetric key with rotate_name set, then encrypts using only the bare keyset name (no @version suffix). For Encrypt operations, bare keyset names resolve to the latest key (SingleLatest mode). | 5 |
| Keyset / Encrypt | `keyset_encrypt_expired_window_fails` | Creates a symmetric key, assigns a rotate_name, then sets ProtectStopDate in the past on the key (the only/latest key in the chain).  An Encrypt with the bare keyset name must fail. | 5 |
| Keyset / Encrypt | `keyset_encrypt_latest` | Creates a symmetric key, assigns a rotate_name via SetAttribute, then encrypts data using the keyset name@latest syntax. Verifies that keyset resolution correctly finds the latest key. | 5 |
| Keyset / Encrypt | `keyset_encrypt_latest_after_rotation` | After rotation, encrypting by the bare keyset name must use the new key: | 8 |
| Keyset | `keyset_gen0_via_address` | After creating a keyset and rotating it once, verifies that the gen-0 key | 9 |
| Keyset | `keyset_getattributes_resolution` | Verifies that after ReKey, RotateGeneration is correctly set: | 7 |
| Keyset | `keyset_mac_verify_chain` | Tests the TryEach chain-walk for MACVerify via keyset name: | 7 |
| Keyset | `keyset_uid_scheme` | Verifies the deterministic UID scheme for SQL keysets: | 9 |
| Negative / Keyset | `negative/keyset_addattribute_uid_mismatch_fails` | Verifies that adding rotate_name via AddAttribute is rejected when the attribute value does not equal the key's UID. Mirrors the SetAttribute enforcement for the same keyset-name invariant. | 4 |
| Negative / Keyset | `negative/keyset_create_no_uid_with_rotate_name_fails` | Verifies that a Create request that specifies rotate_name but omits UniqueIdentifier is rejected. Without an explicit UID equal to the keyset name, the server would assign a random UUID, violating the gen-0 UID invariant. | 1 |
| Negative / Keyset | `negative/keyset_create_uid_mismatch_fails` | Verifies that a Create request where rotate_name does not equal the supplied UniqueIdentifier is rejected. The invariant is: gen-0 UID must equal the keyset name. | 1 |
| Negative / Keyset | `negative/keyset_invalid_generation` | Creates a symmetric key with a rotate_name, then attempts to encrypt using name@99 which references a nonexistent generation. The operation must fail. | 4 |
| Negative / Keyset | `negative/keyset_rotate_name_at_rejected` | Verifies that setting a rotate_name containing '@' is rejected with an InvalidRequest error, since '@' is reserved for keyset versioning syntax. | 4 |
| Negative / Keyset | `negative/keyset_setattribute_uid_mismatch_fails` | Verifies that setting rotate_name via SetAttribute is rejected when the attribute value does not equal the key's UID. SQL keys require gen-0 UID to equal the keyset name — this invariant must be enforced at SetAttribute time. | 4 |
| Negative / Keyset | `negative/rekey_non_latest_hsm` | Tests that Re-Key on a retired (non-latest) HSM key is transparently redirected | 10 |
| Negative / Keyset | `negative/rekey_non_latest_sql` | Tests that Re-Key on a retired (non-latest) SQL-backed key is rejected. | 7 |

---

## Known-Answer Test (KAT) Vectors (`test_data/vectors/kat/`)

KAT vectors use **published reference values** from NIST FIPS and RFC specifications to
verify bit-exact outputs. Each vector imports a known key and asserts exact ciphertext,
MAC, or derived-key values.

| Category | Vector Directory | Reference | Operations | Assert Field |
|----------|-----------------|-----------|------------|--------------|
| **Asymmetric** | | RFC 8032 / NIST PKCS#1 / RFC 6979 | | |
| Asymmetric | `kat/asymmetric/ed25519_eddsa_sign` | RFC 8032 §7.1 | Import, Sign | `SignatureData` |
| Asymmetric (non-FIPS) | `kat/asymmetric/ed448_eddsa_sign` | RFC 8032 §7.4 | Import, Sign | `SignatureData` |
| Asymmetric | `kat/asymmetric/rsa2048_oaep_sha256_decrypt` | NIST PKCS#1 v2.2 | Import, Decrypt | `Data` |
| Asymmetric (non-FIPS) | `kat/asymmetric/secp256k1_ecdsa_sign` | RFC 6979 §A.2.5 | Import, Sign | `SignatureData` |
| **Covercrypt** | | Cosmian Covercrypt v16 | | |
| Covercrypt Decrypt (non-FIPS) | `kat/covercrypt_decrypt` | Self-generated USK | Import, Decrypt | `Data` |
| **Derive Key** | | RFC 5869 / RFC 8018 | | |
| Derive Key | `kat/derive_key/hkdf_sha256` | RFC 5869 §A.1 | Import, DeriveKey, Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/hkdf_sha384` | RFC 5869 §A.1 | Import, DeriveKey, Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/hkdf_sha512` | RFC 5869 §A.1 | Import, DeriveKey, Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/pbkdf2_sha256` | RFC 8018 §5.2 | Import, DeriveKey, Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/pbkdf2_sha384` | RFC 8018 §5.2 | Import, DeriveKey, Get | `KeyMaterial` |
| Derive Key | `kat/derive_key/pbkdf2_sha512` | RFC 8018 §5.2 | Import, DeriveKey, Get | `KeyMaterial` |
| **Hash** | | NIST FIPS 180-4 / FIPS 202 | | |
| Hash | `kat/hash/sha256` | FIPS 180-4 | Hash | `Data` |
| Hash | `kat/hash/sha384` | FIPS 202 | Hash | `Data` |
| Hash | `kat/hash/sha3_256` | FIPS 202 | Hash | `Data` |
| Hash | `kat/hash/sha3_384` | FIPS 202 | Hash | `Data` |
| Hash | `kat/hash/sha3_512` | FIPS 202 | Hash | `Data` |
| Hash | `kat/hash/sha512` | FIPS 180-4 | Hash | `Data` |
| **MAC** | | RFC 4231 / RFC 2202 / NIST HMAC-SHA3 | | |
| Mac | `kat/mac/hmac_sha1` | RFC 2202 §3 | Import, Mac | `MACData` |
| Mac | `kat/mac/hmac_sha256` | RFC 4231 §4.2 | Import, Mac | `MACData` |
| Mac | `kat/mac/hmac_sha384` | RFC 4231 §4.2 | Import, Mac | `MACData` |
| Mac | `kat/mac/hmac_sha3_256` | NIST HMAC-SHA3 | Import, Mac | `MACData` |
| Mac | `kat/mac/hmac_sha3_384` | NIST HMAC-SHA3 | Import, Mac | `MACData` |
| Mac | `kat/mac/hmac_sha3_512` | NIST HMAC-SHA3 | Import, Mac | `MACData` |
| Mac | `kat/mac/hmac_sha512` | RFC 4231 §4.2 | Import, Mac | `MACData` |
| **Recertify** | |  | | |
| Recertify | `kat/recertify/replacement_and_replaced_links` |  | CreateKeyPair, Activate, Certify, ReCertify, GetAttributes, GetAttributes, Destroy, Revoke, Destroy, Destroy, Revoke, Destroy |  |
| Recertify | `kat/recertify/rotate_generation_counter` |  | CreateKeyPair, Activate, Certify, ReCertify, GetAttributes, GetAttributes, Destroy, Revoke, Destroy, Destroy, Revoke, Destroy | `RotateGeneration` |
| Recertify | `kat/recertify/rotate_latest_flag` |  | CreateKeyPair, Activate, Certify, ReCertify, GetAttributes, GetAttributes, Destroy, Revoke, Destroy, Destroy, Revoke, Destroy | `RotateLatest` |
| Recertify | `kat/recertify/state_transitions` |  | CreateKeyPair, Activate, Certify, ReCertify, GetAttributes, GetAttributes, Destroy, Revoke, Destroy, Destroy, Revoke, Destroy | `State` |
| **Rekey** | |  | | |
| Rekey | `kat/rekey/deactivated_accepts_decrypt` |  | Create, Encrypt, ReKey, Decrypt, Destroy, Revoke, Destroy | `Data` |
| Rekey | `kat/rekey/deactivated_rejects_encrypt` |  | Create, Encrypt, ReKey, Encrypt, Destroy, Revoke, Destroy |  |
| Rekey | `kat/rekey/keyset_uid` |  | Create, ReKey, ReKey, Destroy, Destroy, Revoke, Destroy | `UniqueIdentifier` |
| Rekey | `kat/rekey/replacement_and_replaced_links` |  | Create, ReKey, GetAttributes, GetAttributes, Destroy, Revoke, Destroy | `LinkedObjectIdentifier` |
| Rekey | `kat/rekey/rotate_generation_counter` |  | Create, ReKey, ReKey, GetAttributes, GetAttributes, GetAttributes, Destroy, Destroy, Revoke, Destroy | `RotateGeneration` |
| Rekey | `kat/rekey/rotate_interval_cleared` |  | Create, SetAttribute, GetAttributes, ReKey, GetAttributes, Destroy, Revoke, Destroy | `RotateInterval` |
| Rekey | `kat/rekey/rotate_latest_flag` |  | Create, ReKey, GetAttributes, GetAttributes, Destroy, Revoke, Destroy | `RotateLatest` |
| Rekey | `kat/rekey/state_transitions` |  | Create, ReKey, GetAttributes, GetAttributes, Destroy, Revoke, Destroy | `State` |
| **Rekey_Keypair** | |  | | |
| Rekey Keypair | `kat/rekey_keypair/old_pk_deactivated_accepts_verify` |  | CreateKeyPair, ReKeyKeyPair, Sign, SignatureVerify, Destroy, Destroy, Revoke, Destroy, Revoke, Destroy |  |
| Rekey Keypair | `kat/rekey_keypair/old_sk_deactivated_rejects_sign` |  | CreateKeyPair, Sign, ReKeyKeyPair, Sign, Destroy, Destroy, Revoke, Destroy, Revoke, Destroy |  |
| Rekey Keypair | `kat/rekey_keypair/replacement_links` |  | CreateKeyPair, ReKeyKeyPair, GetAttributes, GetAttributes, GetAttributes, GetAttributes, Destroy, Destroy, Revoke, Destroy, Revoke, Destroy |  |
| Rekey Keypair | `kat/rekey_keypair/rotate_generation_counter` |  | CreateKeyPair, ReKeyKeyPair, GetAttributes, GetAttributes, GetAttributes, GetAttributes, Destroy, Destroy, Revoke, Destroy, Revoke, Destroy | `RotateGeneration` |
| Rekey Keypair | `kat/rekey_keypair/rotate_latest_flag` |  | CreateKeyPair, ReKeyKeyPair, GetAttributes, GetAttributes, GetAttributes, GetAttributes, Destroy, Destroy, Revoke, Destroy, Revoke, Destroy | `RotateLatest` |
| Rekey Keypair | `kat/rekey_keypair/state_transitions` |  | CreateKeyPair, ReKeyKeyPair, GetAttributes, GetAttributes, GetAttributes, GetAttributes, Destroy, Destroy, Revoke, Destroy, Revoke, Destroy | `State` |
| **Symmetric** | | NIST SP 800-38A / SP 800-38D / RFC 8439 / RFC 7539 / RFC 3394 / RFC 5649 | | |
| Symmetric | `kat/symmetric/aes128_cbc` | SP 800-38A | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes128_ecb` | SP 800-38A | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes128_gcm` | SP 800-38D TC7 | Import, Encrypt, Decrypt | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric (non-FIPS) | `kat/symmetric/aes128_gcm_siv` | RFC 8452 §C.1 | Import, Encrypt, Decrypt | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric (non-FIPS) | `kat/symmetric/aes128_xts` | IEEE 1619-2007 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes192_cbc` | SP 800-38A | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes192_ecb` | SP 800-38A | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes192_gcm` | SP 800-38D TC7 | Import, Encrypt, Decrypt | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric | `kat/symmetric/aes256_cbc` | SP 800-38A | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes256_ecb` | SP 800-38A | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/aes256_gcm` | SP 800-38D TC7 | Import, Encrypt, Decrypt | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric (non-FIPS) | `kat/symmetric/aes256_gcm_siv` | RFC 8452 §C.1 | Import, Encrypt, Decrypt | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric (non-FIPS) | `kat/symmetric/aes256_xts` | IEEE 1619-2007 | Import, Encrypt, Decrypt | `Data` |
| Symmetric (non-FIPS) | `kat/symmetric/chacha20_poly1305` | RFC 8439 §2.8 | Import, Encrypt, Decrypt | `Data`, `AuthenticatedEncryptionTag` |
| Symmetric (non-FIPS) | `kat/symmetric/chacha20_pure` | RFC 7539 §2.1 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc3394_aes128_kek` | RFC 3394 §2.2.3 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc3394_aes192_kek` | RFC 3394 §2.2.3 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc3394_aes256_kek` | RFC 3394 §2.2.3 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc5649_aes128_kek` | RFC 5649 §6 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc5649_aes192_kek` | RFC 5649 §6 | Import, Encrypt, Decrypt | `Data` |
| Symmetric | `kat/symmetric/rfc5649_aes256_kek` | RFC 5649 §6 | Import, Encrypt, Decrypt | `Data` |

---

## Manifest Schema (`manifest.toml`)

```toml
# Required metadata
name = "AES-256 Create and Get"
description = "Creates an AES-256 symmetric key and retrieves it via Get"

# Optional: override default server config (defaults to auth_plain.toml)
# Vectors with server_config start a dedicated server instance instead of
# using the shared singleton.
# server_config = "test_data/configs/server/cert_auth.toml"

# Optional: wire format — "json" (default) or "binary"
# "json" sends TTLV-JSON to /kmip/2_1
# "binary" serializes to binary TTLV and POSTed to /kmip (application/octet-stream)
# wire_format = "binary"

# Optional: KMIP protocol version (default [2, 1])
# Used to set the RequestHeader version and select KMIP 1.x / 2.x / 3.x serialization
# kmip_version = [3, 0]

# Optional: named identities for multi-user (access control) tests.
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

# Batch requests: raw_request = true sends a complete RequestMessage as-is
[[steps]]
operation = "Batch Create+Query"
request = "step_batch.json"             # must be a full RequestMessage JSON
raw_request = true
assert_success = true                   # asserts ALL BatchItem ResultStatus == Success

# Error testing: assert failure and inspect reason
[[steps]]
operation = "Encrypt"
request = "step_encrypt_after_revoke.json"
assert_success = false
assert_error_reason = "PermissionDenied"          # match ResultReason tag
# assert_error_contains = "partial message match" # alternative: substring in ResultMessage

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

When `raw_request = true`, the file IS the complete `RequestMessage` (used for
batch requests and integration vectors requiring custom headers).

Binary-mode integration vectors use KMIP 1.x `TemplateAttribute` format:

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
