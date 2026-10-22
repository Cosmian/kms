## Security

### Crypto
- Draw every key, nonce/IV and secret token from `KmsRng` (OpenSSL AES-256 CTR-DRBG, 256-bit strength, fail-closed) instead of `openssl::rand::rand_bytes`, `CsRng` or `rand::rng()`: symmetric keys and nonces, key wrapping (AES-GCM nonce, `CKM_RSA_AES_KEY_WRAP` KEK), split-key shares, OpenPGP, ECIES `SalsaSealBox` (seed), JOSE CEK/IV, AWS XKS IV, Redis object and ceremony-record nonces (the latter was compiled in FIPS builds too), UI login PKCE/CSRF/nonce tokens and the ephemeral session cookie key.
- Add a workspace `clippy.toml` that bans `rand_bytes`, `CsRng` and `StdRng`/`ThreadRng`; retained uses carry an inline justification.

### PKCS#11
- `C_GenerateRandom` is served by `Backend::generate_random` (`KmsRng` by default, KMIP `RNGRetrieve` for the Cosmian provider) instead of `rand::rng()`; the provider draws generated key bytes from `KmsRng`.

## Breaking Changes

### Crypto
- HSM-session AES-GCM nonces and AES-CBC IVs now come from `KmsRng` instead of the OS RNG.
- `random_nonce`, `random_key`, `ckm_rsa_aes_key_wrap`, `wrap_object_with_key`, `xor_split`, `ecies_encrypt`, `generate_openpgp_secret_key`, `openpgp_encrypt` and `openpgp_sign_detached` now take a `&KmsRng`; `Secret::new_random` is removed.

## Features

### KMIP
- `Query` with `QueryRNGs` reports the real generator (DRBG, CTR, AES-256).

## Documentation

### Compliance
- Document the remaining randomness exceptions (non-secret anonymization values, OpenSSL-internal key generation, Covercrypt) and add ADR 2026-10-10.
