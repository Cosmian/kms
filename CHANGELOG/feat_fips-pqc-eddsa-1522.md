## Features

### Crypto
- Expose ML-KEM-512/768/1024, ML-DSA-44/65/87, the 12 SLH-DSA parameter sets, `X25519MLKEM768`, Ed25519 and Ed448 in FIPS builds: the OpenSSL FIPS provider 3.5.9 (CMVP #5586) serves them. `X448MLKEM1024` (rejected with an explicit error), `ConfigurableKEM`, standalone X25519/X448, secp256k1 and P-192 stay non-FIPS ([#1522](https://github.com/Cosmian/kms/issues/1522))

### Server
- `CreateKeyPair`, `Sign`, `SignatureVerify`, `Encrypt`/`Decrypt` (KEM), `Export`, `Certify` (RFC 9881, 9909, 9935), JOSE (`EdDSA`, `ML-DSA-44`, `OKP` Ed25519/Ed448), JWKS, SSH certificates, SPIRE transit keys, SCEP and the HSM EdDSA paths now accept these algorithms in FIPS builds. A FIPS build no longer refuses `CreateKeyPair` for Ed25519 and Ed448 ([#1522](https://github.com/Cosmian/kms/issues/1522))
- The `DEFAULT` KMIP policy of a FIPS build allows `Ed25519`, `MLKEM_512/768/1024`, `X25519MLKEM768` and `MLDSA_44/65/87`
- Google CSE refuses `RSA/ECB/PKCS1Padding` decryption in FIPS builds from KMS code, since the 3.5.9 FIPS provider accepts RSA PKCS#1 v1.5 decryption

### CLI
- `ckms pqc`, PQC and EdDSA `certify` algorithms, Ed25519/Ed448 signing, the benchmarks, the PKCS#11 capability checks and the WASM algorithm lists are available in FIPS builds; `x448-ml-kem-1024` and the `ConfigurableKEM` algorithms are not offered there. The `ckms` integration tests now run in FIPS builds ([#1522](https://github.com/Cosmian/kms/issues/1522))

### UI
- The PQC pages and menu are shown in FIPS mode ([#1522](https://github.com/Cosmian/kms/issues/1522))

## Bug Fixes

### CLI
- `ckms pkcs11 verify` no longer builds a KMS client before loading the library under test: in a FIPS build that client loaded the FIPS module in the CLI process, where the library's own statically linked OpenSSL then found no ciphers and `C_GetInterfaceList` returned `CKR_FUNCTION_FAILED`. `ckms pkcs11 capabilities` and `bench` still need a client in the CLI process and remain affected in FIPS builds ([#1522](https://github.com/Cosmian/kms/issues/1522))

## Refactor

### Crypto
- Replace the hand-written `extern "C"` block and the hybrid and ML-KEM KEM encapsulate/decapsulate duplicates with shared safe-signature functions, and generate seeded ML-KEM/ML-DSA keys through `EVP_PKEY_fromdata` (so the provider's pairwise consistency test runs on import); the remaining `unsafe` (`EVP_PKEY_Q_keygen`, `EVP_PKEY_fromdata`, raw hybrid key loading, `EVP_PKEY_encapsulate`/`decapsulate`) waits for rust-openssl bindings ([#894](https://github.com/Cosmian/kms/issues/894), [#1251](https://github.com/Cosmian/kms/issues/1251))

## Documentation

- Document ML-KEM, ML-DSA, SLH-DSA, `X25519MLKEM768`, Ed25519 and Ed448 as FIPS-mode algorithms (algorithms, KMIP policy, PKI, RNG, HSM support and the 5.x to 6.0 upgrade notes)

---

Fixes #1522
