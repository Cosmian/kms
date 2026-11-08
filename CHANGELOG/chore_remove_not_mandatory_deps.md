## Build

### Dependencies
- Remove the `fs4`, `etcetera`, `itertools`, `num-bigint` and `actix-rt` workspace dependencies in favor of the standard library and crates already in the workspace, and delete the unused `lazy_static`, `num-format`, `rand_core` and `tiny-keccak` declarations; no dependency is added or upgraded
- Replace `num_bigint::BigUint` with `num_bigint_dig::BigUint` in the public `cosmian_kms_crypto::crypto::fpe` API (`Integer::encrypt_big`, `decrypt_big`, `max_value`); ciphertexts and the KMIP/CLI wire formats are unchanged
- Replace the `aes-kw`, `argon2`, `aes-gcm-siv`, `hmac`, `subtle`, `sha3`, `p256`, `pkcs1` and `const-oid` workspace dependencies, and the direct `sha2` dependency of `cosmian_kms_server`, with the linked OpenSSL 3.6.5 (Argon2id via `EVP_KDF`, AES-GCM-SIV via the default provider, HMAC/SHA-2/SHA-3 and `memcmp::eq`) and `der`; Argon2id key derivation and AES-GCM-SIV ciphertexts and tags are byte-identical (pinned by tests)
- `cosmian_pkcs11_module::traits::PublicKey::rsa_public_key` now returns `openssl::rsa::Rsa<Public>` and `ec_p256_public_key` an `openssl::ec::EcKey<Public>`; `ModuleError::Pkcs1DerError` is renamed `ModuleError::Der`; the unused `DataObject::data_hash` is removed
